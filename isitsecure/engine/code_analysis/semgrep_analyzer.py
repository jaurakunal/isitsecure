"""Semgrep-based taint/dataflow SAST analyzer (#4).

A deterministic injection floor beneath the LLM code reviewer: runs Semgrep with
isitsecure's own taint/sink rule packs over the cloned repo and maps the results
to ``CodeFinding``s. Rules target framework/library APIs (sources) and dangerous
library sinks, so they apply to any app on a supported stack — not per-app.

Best-effort and self-contained:
* If the ``semgrep`` binary isn't installed (the optional ``[taint]`` extra), the
  analyzer no-ops and returns ``[]`` — the LLM layer still runs, as today. A
  normal scan does NOT treat that as a failure (the extra is optional), but a
  fix-verification re-scan does (``require_semgrep()``): an absent finding is no
  evidence of a fix when the scanner that raised it never ran.
* A crash/timeout/empty output in Semgrep never fails the scan; it logs, records
  a scanner failure (``semgrep_taint: ...``) so the report is marked incomplete
  and the verifier says "could not verify", and returns ``[]``.
* A repo with no language covered by a rule pack is NOT an error.

SRP: this class runs Semgrep and shapes findings. It does not decide severity
policy (the rules do) or triage (that's the triage service).
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import json
import logging
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.code_analysis.shared_utils import iter_repo_files
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.shared.scanner_runner import record_scanner_failure

logger = logging.getLogger(__name__)

_RULES_DIR = Path(__file__).parent / "semgrep_rules"
_SCAN_TIMEOUT_S = 120.0

# Set by the fix-verification re-scan: a missing semgrep binary is then a
# scanner failure (the optional extra's absence must not read as "fixed").
_semgrep_required: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "isitsecure_semgrep_required", default=False
)


@contextlib.contextmanager
def require_semgrep():
    """Within this block, a missing semgrep is recorded as a scanner failure."""
    token = _semgrep_required.set(True)
    try:
        yield
    finally:
        _semgrep_required.reset(token)


@dataclass(frozen=True)
class _RulePack:
    """A shipped rule pack and the repo file extensions that activate it."""

    name: str                    # for logging
    filename: str                # under semgrep_rules/
    extensions: tuple[str, ...]  # a repo file with one of these enables the pack


# Registry of shipped packs. Selected per scan (#94) so a JS-only repo never loads
# the Python rules and vice-versa — fewer rules parsed, no cross-stack surprises.
# Today selection is by language (file extension); when packs are split per
# framework (e.g. Next.js vs Express), add a `frameworks` field and match on
# RepoSnapshot.framework here.
_RULE_PACKS: tuple[_RulePack, ...] = (
    _RulePack("javascript/typescript", "injection-js.yaml",
              (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")),
    _RulePack("python", "injection-python.yaml", (".py",)),
    _RulePack("java", "injection-java.yaml", (".java",)),
    _RulePack("kotlin", "injection-kotlin.yaml", (".kt",)),
    _RulePack("go", "injection-go.yaml", (".go",)),
)

# Dirs semgrep ignores by default; skipping them bounds the language-detection
# walk without ever under-selecting (semgrep wouldn't scan them either).
_WALK_SKIP_DIRS = frozenset({"node_modules", ".git"})

_SEVERITY_MAP = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
}
# Fallback when a rule lacks an explicit isitsecure-severity.
_SEMGREP_SEVERITY_MAP = {
    "ERROR": SeverityLevel.HIGH,
    "WARNING": SeverityLevel.MEDIUM,
    "INFO": SeverityLevel.LOW,
}


class SemgrepAnalyzer:
    """Run Semgrep taint rules over a repo and return injection findings."""

    scanner_name = "semgrep_taint"

    def __init__(self, rules_dir: Path = _RULES_DIR) -> None:
        self._rules_dir = rules_dir

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        packs = self._select_packs(repo)
        if not packs:
            return []  # no rule pack covers this repo's languages (not an error)
        semgrep = self._find_semgrep()
        if not semgrep:
            logger.debug("semgrep not installed — skipping taint analysis (isitsecure[taint])")
            if _semgrep_required.get():
                record_scanner_failure(
                    self.scanner_name, "semgrep is not installed (pip install isitsecure[taint])"
                )
            return []

        raw = await self._run_semgrep(semgrep, repo.clone_path, packs)
        if raw is None:
            return []  # _run_semgrep already recorded why
        return self._to_findings(raw, repo)

    # -- internals --------------------------------------------------------

    @staticmethod
    def _find_semgrep() -> str | None:
        """Locate semgrep — prefer the binary in our own venv, then PATH.

        With `pip install isitsecure[taint]`, semgrep's console script installs
        next to the running interpreter; that dir isn't necessarily on PATH.
        """
        candidate = Path(sys.executable).parent / "semgrep"
        if candidate.is_file():
            return str(candidate)
        return shutil.which("semgrep")

    def _select_packs(self, repo: RepoSnapshot) -> list[Path]:
        """Pick the rule packs whose languages appear in the repo (#94).

        Language presence is read from the actual on-disk tree (what semgrep will
        scan) — NOT the curated ``file_index``, which drops oversized files and
        skip-dirs semgrep would still scan. Over-selecting a pack is harmless;
        under-selecting would silently lose findings, so we err toward inclusion.
        """
        present = self._extensions_on_disk(repo.clone_path)
        selected: list[Path] = []
        for pack in _RULE_PACKS:
            if not any(ext in present for ext in pack.extensions):
                continue
            path = self._rules_dir / pack.filename
            if not path.is_file():
                logger.warning("semgrep_taint: rule pack %s missing — skipping", pack.filename)
                continue
            selected.append(path)
        if selected:
            logger.debug("semgrep_taint: selected packs %s", [p.name for p in selected])
        return selected

    @staticmethod
    def _extensions_on_disk(clone_path: str) -> set[str]:
        """Extensions present under ``clone_path`` that any rule pack cares about.

        Case-sensitive (mirrors semgrep, which skips e.g. ``.PY``). Walk stops
        early once every wanted extension has been seen. Symlinks are not
        counted: semgrep itself never follows them (verified against the real
        binary, in and out of a git work tree), so a symlinked file outside the
        clone is neither scanned nor able to reach a finding's snippet.
        """
        wanted = {ext for pack in _RULE_PACKS for ext in pack.extensions}
        found: set[str] = set()
        try:
            for path in iter_repo_files(
                clone_path, skip_dirs=frozenset(_WALK_SKIP_DIRS)
            ):
                ext = os.path.splitext(path.name)[1]
                if ext in wanted:
                    found.add(ext)
                    if found >= wanted:
                        return found
        except OSError:  # unreadable tree — let semgrep decide, select nothing here
            return found
        return found

    async def _run_semgrep(
        self, semgrep: str, clone_path: str, packs: list[Path]
    ) -> dict | None:
        cmd = [semgrep, "scan"]
        for pack in packs:
            cmd += ["--config", str(pack)]
        cmd += [
            "--json", "--quiet",
            "--metrics", "off",       # no telemetry
            "--disable-version-check",
            clone_path,
        ]
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=_SCAN_TIMEOUT_S
                )
            except TimeoutError:
                logger.warning("semgrep timed out after %ss — skipping", _SCAN_TIMEOUT_S)
                record_scanner_failure(
                    self.scanner_name, f"semgrep timed out after {_SCAN_TIMEOUT_S:.0f}s"
                )
                return None
            if not stdout:
                logger.warning("semgrep produced no output: %s", (stderr or b"").decode()[:200])
                record_scanner_failure(self.scanner_name, "semgrep produced no output")
                return None
            data = json.loads(stdout)
            if not isinstance(data, dict):
                record_scanner_failure(self.scanner_name, "semgrep output was not a JSON object")
                return None
            return data
        except asyncio.CancelledError:
            # Outer scan timeout/cancel — reap in finally, then propagate.
            raise
        except Exception as exc:  # never fail the scan over the taint layer
            logger.warning("semgrep run failed: %s", exc)
            record_scanner_failure(self.scanner_name, "semgrep crashed or printed invalid output")
            return None
        finally:
            # Guarantee the (heavy) semgrep child is killed and reaped on ANY exit
            # path — timeout, crash, or outer cancellation — never left orphaned.
            if proc is not None and proc.returncode is None:
                proc.kill()
                try:
                    await proc.wait()
                except BaseException:  # noqa: BLE001, S110 - SIGKILL sent; best-effort reap
                    pass

    def _to_findings(self, raw: dict, repo: RepoSnapshot) -> list[CodeFinding]:
        root = Path(repo.clone_path)
        findings: list[CodeFinding] = []
        seen: set[tuple] = set()
        for r in raw.get("results", []):
            extra = r.get("extra", {})
            meta = extra.get("metadata", {})
            try:
                rel = str(Path(r["path"]).resolve().relative_to(root.resolve()))
            except (ValueError, KeyError):
                rel = r.get("path", "")
            line = (r.get("start") or {}).get("line")
            category = self._category(meta)
            # Collapse *same-class* overlaps (e.g. the sqli sink rule and the sqli
            # taint rule both firing on one line) while keeping genuinely distinct
            # classes on the same line (e.g. reflected-XSS and SSRF). All rules map
            # to FindingCategory.INJECTION_RISK, so we key on the rule's vuln class.
            key = (rel, line, self._rule_class(r.get("check_id", "")))
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=self._severity(meta, extra),
                    category=category,
                    title=self._title(extra),
                    description=extra.get("message", "").strip(),
                    file_path=rel,
                    line_number=line,
                    line_end=(r.get("end") or {}).get("line"),
                    code_snippet=(extra.get("lines") or "").strip()[:500],
                    confidence=0.85,
                )
            )
        return findings

    # Rule id → vuln class, so the sqli sink + sqli taint rules dedup together but
    # different classes on the same line don't. Substring match on our rule ids.
    _RULE_CLASSES = ("sqli", "reflected-xss", "dom-xss", "ssrf", "path-traversal",
                     "command", "ssti")

    @classmethod
    def _rule_class(cls, check_id: str) -> str:
        for c in cls._RULE_CLASSES:
            if c in check_id:
                return c
        return check_id  # unknown rule → treat as its own class (no collapsing)

    @staticmethod
    def _category(meta: dict) -> FindingCategory:
        try:
            return FindingCategory(meta.get("category", "injection_risk"))
        except ValueError:
            return FindingCategory.INJECTION_RISK

    @staticmethod
    def _severity(meta: dict, extra: dict) -> SeverityLevel:
        explicit = _SEVERITY_MAP.get(str(meta.get("isitsecure-severity", "")).lower())
        if explicit:
            return explicit
        return _SEMGREP_SEVERITY_MAP.get(
            str(extra.get("severity", "ERROR")).upper(), SeverityLevel.HIGH
        )

    @staticmethod
    def _title(extra: dict) -> str:
        msg = extra.get("message", "").strip()
        # First sentence / up to the em-dash makes a tidy title.
        for sep in (" — ", ". "):
            if sep in msg:
                return msg.split(sep)[0].strip()[:120]
        return msg[:80] or "Injection risk (Semgrep)"
