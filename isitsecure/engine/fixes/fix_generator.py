"""LLM-powered fix generator for security findings.

Takes a finding + the source file content, asks the LLM to generate
a fixed version, and returns a unified diff.

SRP: This class generates fixes. It does not run scans, read files
     from disk, or apply patches.

DIP: Depends on LLMClientProtocol, not any concrete LLM implementation.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
from dataclasses import dataclass, field
from difflib import unified_diff

from isitsecure.engine.fixes.prompts import FixPrompts
from isitsecure.engine.models import DeepFinding
from isitsecure.llm.protocol import LLMClientProtocol

logger = logging.getLogger(__name__)


@dataclass
class FixResult:
    """Result of a fix generation attempt."""

    finding_id: str
    file_path: str
    success: bool
    original_code: str = ""
    fixed_code: str = ""
    diff: str = ""
    explanation: str = ""
    error: str = ""


@dataclass
class FixPlan:
    """Collection of fixes for an entire scan."""

    fixes: list[FixResult] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    total_findings: int = 0

    @property
    def fixed_count(self) -> int:
        return sum(1 for f in self.fixes if f.success)

    @property
    def failed_count(self) -> int:
        return sum(1 for f in self.fixes if not f.success)


@dataclass
class FileFixPlan:
    """Fixes chained per file — one final content per changed file.

    Unlike FixPlan (independent per-finding rewrites of the same file, where
    applying more than one clobbers the others), this chains all findings in
    a file so every fix accumulates into a single final version.
    """

    files: dict[str, str] = field(default_factory=dict)  # file_path -> fixed content
    results: list[FixResult] = field(default_factory=list)  # per-finding results
    skipped: list[str] = field(default_factory=list)
    total_findings: int = 0

    @property
    def fixed_count(self) -> int:
        return sum(1 for r in self.results if r.success)


# A reply that elides code instead of writing it out ("# ... rest of file
# unchanged ...") would be written over the user's file and, because the
# re-scan cannot flag code that no longer exists, then "verified" as fixed.
_ELISION_RES = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        # a bare "..." / "......" / ellipsis char, optionally behind a comment leader
        r"^\s*(?:#|//|/\*|\*|--|<!--|;|%)?\s*(?:\.{3,}|…)\s*(?:\*/|-->)?\s*$",
        # a comment/line announcing elided content: "... rest of file", "... unchanged"
        r"^\s*(?:#|//|/\*|\*|--|<!--|;|%)?\s*(?:\.{3,}|…)\s*"
        r"(?:\(?\s*)(?:rest|remaining|remainder|existing|previous|unchanged|other|same|more)\b",
        r"^\s*(?:#|//|/\*|\*|--|<!--|;|%)\s*.*\b(?:rest|remainder)\s+of\s+"
        r"(?:the\s+)?(?:file|code|function|class|module|handler|implementation)\b",
        r"^\s*(?:#|//|/\*|\*|--|<!--|;|%)\s*.*(?:\.{3}|…).*\b(?:unchanged|existing|"
        r"same\s+as\s+(?:before|above|original)|omitted|elided|truncated)\b",
        r"^\s*(?:#|//|/\*|\*|--|<!--|;|%)\s*(?:the\s+)?(?:rest|remaining|existing|previous)\b"
        r".{0,40}\b(?:unchanged|omitted|elided|same|remains?)\b",
    )
)
# Whole-reply shrink floor: a security fix rarely deletes 40%+ of a file.
_MIN_LENGTH_RATIO = 0.6
_MIN_LENGTH_CHECK_CHARS = 400


def find_elision(original: str, fixed: str) -> str | None:
    """Return the first placeholder line in ``fixed`` that is not in ``original``.

    Lines already present in the original (a real ``...`` or a comment that
    genuinely says "rest of the file") are not placeholders.
    """
    existing = {line.strip() for line in original.splitlines()}
    for line in fixed.splitlines():
        stripped = line.strip()
        if stripped and stripped not in existing and any(r.match(line) for r in _ELISION_RES):
            return stripped[:80]
    return None


def syntax_error(file_path: str, original: str, fixed: str) -> str | None:
    """A syntax error introduced by ``fixed``, or None.

    Cheap, dependency-free checkers only (Python via ``ast``, JSON via
    ``json``); every other language is skipped. If the original itself does not
    parse, nothing is claimed.
    """
    ext = os.path.splitext(file_path)[1].lower()
    if ext in (".py", ".pyi"):
        def check(text: str) -> str | None:
            try:
                ast.parse(text)
            except (SyntaxError, ValueError) as exc:
                return str(exc)
            return None
    elif ext == ".json":
        def check(text: str) -> str | None:
            try:
                json.loads(text)
            except ValueError as exc:
                return str(exc)
            return None
    else:
        return None
    if check(original) is not None:
        return None
    return check(fixed)


def _split_keepends(text: str) -> list[str]:
    r"""Split on LF only, keeping terminators (``str.splitlines`` also splits on
    VT, FF, U+2028 and friends, which git does not treat as line breaks)."""
    if not text:
        return []
    parts = text.split("\n")
    lines = [p + "\n" for p in parts[:-1]]
    if parts[-1]:
        lines.append(parts[-1])
    return lines


class FixGenerator:
    """Generates code fixes for security findings using LLM.

    Implements the find→fix loop:
    1. Read the finding (what's wrong, where, what severity)
    2. Read the source file content
    3. Ask the LLM to generate a fixed version
    4. Parse the response and produce a unified diff

    Args:
        llm_client: LLM client implementing LLMClientProtocol (DIP).
    """

    MAX_FILE_SIZE = 50_000  # Skip files larger than 50KB
    MAX_CONCURRENT_FIXES = 3

    def __init__(self, llm_client: LLMClientProtocol) -> None:
        self._llm = llm_client

    async def generate_fix(
        self,
        finding: DeepFinding,
        file_content: str,
    ) -> FixResult:
        """Generate a fix for a single finding.

        Args:
            finding: The security finding to fix.
            file_content: Full content of the source file.

        Returns:
            FixResult with diff and explanation.
        """
        file_path = finding.code_location.file_path if finding.code_location else ""

        if not file_path or not file_content:
            return FixResult(
                finding_id=finding.id,
                file_path=file_path,
                success=False,
                error="No source file available for this finding",
            )

        if len(file_content) > self.MAX_FILE_SIZE:
            return FixResult(
                finding_id=finding.id,
                file_path=file_path,
                success=False,
                error=f"File too large ({len(file_content)} bytes)",
            )

        try:
            system_prompt = FixPrompts.SYSTEM_PROMPT
            user_prompt = FixPrompts.build_fix_prompt(finding, file_content)

            response = await self._llm.generate_with_system(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=8192,
            )

            return self._parse_response(finding, file_path, file_content, response)

        except Exception as e:
            logger.warning("Fix generation failed for %s: %s", finding.id, e)
            return FixResult(
                finding_id=finding.id,
                file_path=file_path,
                success=False,
                error=str(e),
            )

    async def generate_fix_plan(
        self,
        findings: list[DeepFinding],
        file_contents: dict[str, str],
    ) -> FixPlan:
        """Generate fixes for multiple findings.

        Args:
            findings: List of findings to fix (typically critical + high).
            file_contents: Mapping of file_path → content.

        Returns:
            FixPlan with all fix results.
        """
        import asyncio

        plan = FixPlan(total_findings=len(findings))
        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_FIXES)

        async def _fix_one(finding: DeepFinding) -> FixResult | None:
            file_path = finding.code_location.file_path if finding.code_location else ""
            content = file_contents.get(file_path, "")

            if not file_path or not content:
                plan.skipped.append(
                    f"{finding.title} — no source file (DAST-only finding)"
                )
                return None

            async with semaphore:
                return await self.generate_fix(finding, content)

        tasks = [_fix_one(f) for f in findings]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, FixResult):
                plan.fixes.append(result)
            elif isinstance(result, Exception):
                logger.warning("Fix generation error: %s", result)

        return plan

    async def generate_file_fixes(
        self,
        findings: list[DeepFinding],
        file_contents: dict[str, str],
        on_file_done=None,
    ) -> FileFixPlan:
        """Generate fixes grouped by file, CHAINING multiple findings per file.

        For each file, findings are fixed sequentially — each fix is applied to
        the previous fix's output — so every finding's fix survives in one final
        version (no clobbering). Files are processed concurrently.

        Args:
            findings: Findings to fix.
            file_contents: Mapping of file_path → original content.
            on_file_done: Optional callback(done, total, path). May be sync or
                async; awaited if it returns a coroutine.
        """
        import asyncio
        from collections import defaultdict

        plan = FileFixPlan(total_findings=len(findings))

        by_file: dict[str, list[DeepFinding]] = defaultdict(list)
        for finding in findings:
            fp = finding.code_location.file_path if finding.code_location else ""
            if fp:
                by_file[fp].append(finding)
            else:
                plan.skipped.append(f"{finding.title} — no source file (DAST-only finding)")

        total = len(by_file)
        done = 0
        lock = asyncio.Lock()
        sem = asyncio.Semaphore(self.MAX_CONCURRENT_FIXES)

        async def _fix_file(path: str, group: list[DeepFinding]) -> None:
            nonlocal done
            content = file_contents.get(path, "")
            if not content:
                plan.skipped.append(f"{path} — source not available")
            else:
                async with sem:
                    current = content
                    changed = False
                    for finding in group:
                        res = await self.generate_fix(
                            self._without_stale_lines(finding) if changed else finding,
                            current,
                        )
                        plan.results.append(res)
                        if res.success and res.fixed_code:
                            current = res.fixed_code
                            changed = True
                    if changed:
                        plan.files[path] = current
            async with lock:
                done += 1
                if on_file_done is not None:
                    r = on_file_done(done, total, path)
                    if asyncio.iscoroutine(r):
                        await r

        await asyncio.gather(*[_fix_file(p, g) for p, g in by_file.items()])
        return plan

    @staticmethod
    def _without_stale_lines(finding: DeepFinding) -> DeepFinding:
        """Copy of ``finding`` with line numbers dropped.

        Once an earlier fix in the same file changed the content, the scan's
        line numbers no longer point at the right code; the prompt then names
        only the file instead of misdirecting the model.
        """
        loc = finding.code_location
        if loc is None:
            return finding
        updates = {"line_number": None}
        if hasattr(loc, "line_end"):
            updates["line_end"] = None
        return finding.model_copy(update={"code_location": loc.model_copy(update=updates)})

    def _parse_response(
        self,
        finding: DeepFinding,
        file_path: str,
        original_content: str,
        response: str,
    ) -> FixResult:
        """Parse LLM response to extract fixed code and explanation."""
        explanation = self._extract_explanation(response)

        # Work in LF; restore the file's own newline style on the way out.
        crlf = "\r\n" in original_content
        if crlf and original_content.count("\r\n") != original_content.count("\n"):
            return FixResult(
                finding_id=finding.id, file_path=file_path, success=False,
                original_code=original_content, explanation=explanation,
                error="File has mixed line endings; not auto-fixing",
            )
        original_lf = original_content.replace("\r\n", "\n")

        raw, ambiguous = self._extract_raw_block(response)
        if not raw and self._is_cut_off(response):
            return FixResult(
                finding_id=finding.id, file_path=file_path, success=False,
                original_code=original_content, explanation=explanation,
                error=(
                    "The model's reply was cut off at its output limit before the file "
                    f"was complete ({len(original_content)} chars is too large to rewrite "
                    "whole in one reply); not applying. Fix this one by hand or split "
                    "the file."
                ),
            )
        if ambiguous:
            # Several blocks, or fences inside the file. Only trust the
            # outermost reading when the original file itself has fences.
            raw = self._extract_outermost_block(response) if "```" in original_lf else ""
            if not raw:
                return FixResult(
                    finding_id=finding.id, file_path=file_path, success=False,
                    original_code=original_content, explanation=explanation,
                    error="Could not extract fixed code from LLM response (ambiguous code fences)",
                )
        fixed_lf = raw.replace("\r\n", "\n")
        # Preserve the original's trailing newline exactly.
        trail = len(original_lf) - len(original_lf.rstrip("\n"))
        fixed_lf = fixed_lf.rstrip("\n") + "\n" * trail
        if not fixed_lf.strip():
            fixed_lf = ""

        if not fixed_lf:
            return FixResult(
                finding_id=finding.id,
                file_path=file_path,
                success=False,
                original_code=original_content,
                explanation=explanation,
                error="Could not extract fixed code from LLM response",
            )

        # Truncation guard: a reply far shorter than the file is almost
        # certainly cut off (or a stub), never a real fix.
        if (len(original_lf) >= _MIN_LENGTH_CHECK_CHARS
                and len(fixed_lf) < _MIN_LENGTH_RATIO * len(original_lf)):
            return FixResult(
                finding_id=finding.id, file_path=file_path, success=False,
                original_code=original_content, explanation=explanation,
                error="LLM reply looks truncated (much shorter than the file); not applying",
            )

        placeholder = find_elision(original_lf, fixed_lf)
        if placeholder:
            return FixResult(
                finding_id=finding.id, file_path=file_path, success=False,
                original_code=original_content, explanation=explanation,
                error=(
                    f"LLM reply elides code with a placeholder ({placeholder!r}); "
                    "not applying a partial file"
                ),
            )

        broken = syntax_error(file_path, original_lf, fixed_lf)
        if broken:
            return FixResult(
                finding_id=finding.id, file_path=file_path, success=False,
                original_code=original_content, explanation=explanation,
                error=f"LLM reply is not valid syntax for this file ({broken}); not applying",
            )

        fixed_code = fixed_lf.replace("\n", "\r\n") if crlf else fixed_lf

        # "No change" is judged on LF-normalised text; the diff itself is built
        # from the real bytes (CRLF included) so `git apply` accepts it.
        diff = (
            self._generate_diff(file_path, original_content, fixed_code)
            if original_lf != fixed_lf else ""
        )

        if not diff:
            return FixResult(
                finding_id=finding.id,
                file_path=file_path,
                success=False,
                original_code=original_content,
                fixed_code=fixed_code,
                explanation=explanation,
                error="Fix produced no changes (code unchanged)",
            )

        return FixResult(
            finding_id=finding.id,
            file_path=file_path,
            success=True,
            original_code=original_content,
            fixed_code=fixed_code,
            diff=diff,
            explanation=explanation,
        )

    @staticmethod
    def _is_cut_off(response: str) -> bool:
        """True when the reply opened a code fence that never closed -- the
        signature of hitting the output-token limit mid-file."""
        fence_re = re.compile(r"^[ \t]*```([\w+#.-]*)[ \t]*\r?\n?$")
        fences = [l for l in response.splitlines() if fence_re.match(l)]
        return bool(fences) and not any(not fence_re.match(l).group(1) for l in fences[1:])

    @staticmethod
    def _extract_code_block(response: str) -> str:
        """Extract the first fenced code block from the response (stripped)."""
        code, _ = FixGenerator._extract_raw_block(response)
        return code.strip()

    @staticmethod
    def _extract_raw_block(response: str) -> tuple[str, bool]:
        """Extract the fenced block verbatim (no stripping).

        Returns ``(code, ambiguous)``. Fence lines carrying a language tag
        nest (a file may itself contain fenced examples); a bare fence line
        closes the block. ``ambiguous`` is True when more fence lines follow
        the chosen close, i.e. the reply holds several blocks or the file
        contains bare fences, so the true end of the file is uncertain.
        """
        lines = response.splitlines(keepends=True)
        fence_re = re.compile(r"^[ \t]*```([\w+#.-]*)[ \t]*\r?\n?$")
        opener = None
        for i, line in enumerate(lines):
            if fence_re.match(line):
                opener = i
                break
        if opener is not None:
            depth = 0
            closers: list[int] = []
            for j in range(opener + 1, len(lines)):
                m = fence_re.match(lines[j])
                if not m:
                    continue
                if m.group(1):
                    depth += 1
                elif depth > 0:
                    depth -= 1
                else:
                    closers.append(j)
            if closers:
                body = "".join(lines[opener + 1:closers[0]])
                later_fences = any(fence_re.match(l) for l in lines[closers[0] + 1:])
                return body, later_fences
            # Unclosed fence: the reply was cut off — treat as unusable.
            return "", False

        # Fallback: look for FIXED_CODE markers
        pattern2 = r"FIXED_CODE_START\n(.*?)FIXED_CODE_END"
        match2 = re.search(pattern2, response, re.DOTALL)
        if match2:
            return match2.group(1), False

        return "", False

    @staticmethod
    def _extract_outermost_block(response: str) -> str:
        """First opening fence to the LAST bare fence line (for files that
        themselves contain fences)."""
        lines = response.splitlines(keepends=True)
        fence_re = re.compile(r"^[ \t]*```([\w+#.-]*)[ \t]*\r?\n?$")
        idx = [i for i, l in enumerate(lines) if fence_re.match(l)]
        if len(idx) < 2:
            return ""
        last = next((i for i in reversed(idx) if not fence_re.match(lines[i]).group(1)), None)
        if last is None or last <= idx[0]:
            return ""
        return "".join(lines[idx[0] + 1:last])

    @staticmethod
    def _extract_explanation(response: str) -> str:
        """Extract explanation text from before/after the code block."""
        # Take everything before the first code block
        parts = re.split(r"```", response)
        if parts:
            explanation = parts[0].strip()
            # Also check for text after the last code block
            if len(parts) >= 3:
                after = parts[-1].strip()
                if after:
                    explanation = f"{explanation}\n\n{after}" if explanation else after
            return explanation
        return ""

    @staticmethod
    def _generate_diff(file_path: str, original: str, fixed: str) -> str:
        """Unified diff between original and fixed code, accepted by ``git apply``.

        Lines keep their own terminators (CRLF files stay CRLF), header and hunk
        lines end in LF, and a last line without a newline gets git's
        ``\\ No newline at end of file`` marker.
        """
        diff_lines = list(unified_diff(
            _split_keepends(original),
            _split_keepends(fixed),
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="\n",
        ))
        if not diff_lines:
            return ""
        out: list[str] = []
        for line in diff_lines:
            out.append(line)
            if not line.endswith("\n"):
                out.append("\n\\ No newline at end of file\n")
        return "".join(out)


# ---------------------------------------------------------------------------
# Safe source IO for the fix flows
# ---------------------------------------------------------------------------

_BOM = b"\xef\xbb\xbf"


def resolve_fix_target(repo_path: str, rel_path: str) -> str:
    """Resolve a finding's file path inside the repo, or raise ValueError.

    Finding paths come from scanned content / LLM output: refuse absolute or
    ``..`` escapes (via ``resolve_within``) and anything inside ``.git/``.
    """
    from isitsecure.engine.shared.safe_path import resolve_within

    def _has_git(path: str) -> bool:
        # casefold: on case-insensitive filesystems (macOS, Windows) ``.GIT``
        # and ``.Git`` are the real git directory.
        return ".git" in [p.casefold() for p in path.replace("\\", "/").split("/")]

    if _has_git(rel_path):
        raise ValueError(f"Refusing to touch .git metadata: {rel_path!r}")
    target = resolve_within(repo_path, rel_path)
    real_repo = os.path.realpath(repo_path)
    if _has_git(os.path.relpath(target, real_repo)):
        raise ValueError(f"Refusing to touch .git metadata: {rel_path!r}")
    # Belt and braces for odd spellings the name check cannot see: refuse when
    # the target, or any existing ancestor inside the repo, IS the repo's .git.
    git_dir = os.path.join(real_repo, ".git")
    if os.path.exists(git_dir):
        probe = target
        while probe != real_repo and len(probe) > len(real_repo):
            try:
                if os.path.exists(probe) and os.path.samefile(probe, git_dir):
                    raise ValueError(f"Refusing to touch .git metadata: {rel_path!r}")
            except OSError:
                pass
            probe = os.path.dirname(probe)
    return target


def read_source_file(repo_path: str, rel_path: str) -> str | None:
    """Read a repo file for fixing: strict UTF-8, newlines untouched.

    Returns None (file is unfixable) when the path is refused, missing, or the
    bytes are not valid UTF-8 -- never a lossy decode.
    """
    try:
        target = resolve_fix_target(repo_path, rel_path)
        if not os.path.isfile(target):
            return None
        with open(target, "rb") as fh:
            return fh.read().decode("utf-8")
    except (ValueError, OSError, UnicodeDecodeError):
        return None


def write_source_file(repo_path: str, rel_path: str, content: str) -> None:
    """Write fixed content back as UTF-8 with its newlines exactly as given.

    Atomic (temp file + rename, permission bits kept), so a crash mid-write never
    leaves a truncated source file.
    """
    # Imported here: safe_apply imports resolve_fix_target from this module.
    from isitsecure.engine.fixes.safe_apply import atomic_write_bytes, encode_for_write

    target = resolve_fix_target(repo_path, rel_path)
    atomic_write_bytes(target, encode_for_write(target, content))
