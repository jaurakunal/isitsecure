"""LLM-powered fix generator for security findings.

Takes a finding + the source file content, asks the LLM to generate
a fixed version, and returns a unified diff.

SRP: This class generates fixes. It does not run scans, read files
     from disk, or apply patches.

DIP: Depends on LLMClientProtocol, not any concrete LLM implementation.
"""

from __future__ import annotations

import logging
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
                        res = await self.generate_fix(finding, current)
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

    def _parse_response(
        self,
        finding: DeepFinding,
        file_path: str,
        original_content: str,
        response: str,
    ) -> FixResult:
        """Parse LLM response to extract fixed code and explanation."""
        # Extract code block from response
        fixed_code = self._extract_code_block(response)
        explanation = self._extract_explanation(response)

        if not fixed_code:
            return FixResult(
                finding_id=finding.id,
                file_path=file_path,
                success=False,
                original_code=original_content,
                explanation=explanation,
                error="Could not extract fixed code from LLM response",
            )

        # Generate unified diff
        diff = self._generate_diff(file_path, original_content, fixed_code)

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
    def _extract_code_block(response: str) -> str:
        """Extract the first fenced code block from the response."""
        # Match ```language\n...code...\n```
        pattern = r"```(?:\w+)?\s*\n(.*?)```"
        match = re.search(pattern, response, re.DOTALL)
        if match:
            return match.group(1).strip()

        # Fallback: look for FIXED_CODE markers
        pattern2 = r"FIXED_CODE_START\n(.*?)FIXED_CODE_END"
        match2 = re.search(pattern2, response, re.DOTALL)
        if match2:
            return match2.group(1).strip()

        return ""

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
        """Generate a unified diff between original and fixed code."""
        original_lines = original.splitlines(keepends=True)
        fixed_lines = fixed.splitlines(keepends=True)

        diff_lines = list(unified_diff(
            original_lines,
            fixed_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="",
        ))

        if not diff_lines:
            return ""

        return "\n".join(diff_lines)
