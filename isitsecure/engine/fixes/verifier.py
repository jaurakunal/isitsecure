"""Re-scan-to-verify: confirm that applied fixes actually removed the findings.

After a fix is written to disk, re-run a code-only SAST scan over the fixed
code and check whether each fixed finding's signature is gone. Only
rule-based SAST findings can be verified this way — a code-only re-scan can't
reproduce LLM-review or DAST findings, so those are reported as
"not verifiable" rather than falsely counted as resolved.

Verification is best-effort: "no longer detected" means the scanner that
raised the finding no longer raises it, not a formal proof of correctness.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from isitsecure.engine.models import DeepFinding

logger = logging.getLogger(__name__)

# Findings from these scanners can't be reproduced by a rule-based code-only
# re-scan (they need an LLM), so we don't claim to verify them.
LLM_SCANNERS = {
    "llm_code_reviewer",
    "semantic_rule_verifier",
    "llm_business_logic_scanner",
}


class RescanFailed(RuntimeError):
    """The code-only re-scan aborted without producing a report (e.g. the
    repository could not be ingested). The check did not run."""


class RescanFindings(list):
    """Re-scan findings plus the report's ``scanner_errors`` (``"name: reason"``).

    A plain ``list`` subclass so callers that only want the findings are
    unaffected; honest callers read ``scanner_errors`` too.
    """

    scanner_errors: list[str]

    def __init__(self, findings=(), scanner_errors=()):
        super().__init__(findings)
        self.scanner_errors = list(scanner_errors)


def failed_scanner_names(scanner_errors) -> tuple[set[str], bool]:
    """Names of scanners that failed/timed out, and whether any entry could not
    be mapped to a scanner name (then nothing may be trusted as "gone")."""
    names: set[str] = set()
    unmapped = False
    for entry in scanner_errors or []:
        name, sep, _reason = str(entry).partition(": ")
        name = name.strip()
        if sep and name and " " not in name:
            names.add(name)
        else:
            unmapped = True
    return names, unmapped


def failure_blocks(scanner_name: str, failed: set[str], unmapped: bool) -> bool:
    """True when a scanner failure means a missing finding proves nothing."""
    return unmapped or scanner_name in failed


@dataclass
class VerifyResult:
    resolved: int = 0
    still_present: int = 0
    unverifiable: int = 0
    still_present_titles: list[str] = field(default_factory=list)
    error: str = ""
    # True when the re-scan itself failed/aborted: the check did not run, so
    # nothing may be claimed as resolved.
    could_not_verify: bool = False

    @property
    def checked(self) -> int:
        return self.resolved + self.still_present

    def to_dict(self) -> dict:
        return {
            "resolved": self.resolved,
            "still_present": self.still_present,
            "unverifiable": self.unverifiable,
            "checked": self.checked,
            "still_present_titles": self.still_present_titles[:10],
            "error": self.error,
            "could_not_verify": self.could_not_verify,
        }


def sig_obj(f: DeepFinding) -> tuple:
    cat = f.category.value if hasattr(f.category, "value") else str(f.category)
    fp = f.code_location.file_path if f.code_location else ""
    return (f.scanner_name, cat, fp, f.title)


def _sig_dict(d: dict) -> tuple:
    loc = d.get("code_location") or {}
    return (d.get("scanner_name"), str(d.get("category")), loc.get("file_path", ""), d.get("title"))


def is_verifiable(f: DeepFinding) -> bool:
    return bool(
        f.code_location
        and f.code_location.file_path
        and f.scanner_name not in LLM_SCANNERS
    )


async def _rescan_sast_findings(repo_path: str) -> list[dict]:
    """Run a code-only SAST scan (no LLM) over a local repo path."""
    from isitsecure.engine.enums import ScanMode
    from isitsecure.engine.factory import (
        create_deep_security_scan_agent,
        create_repo_ingestion_service,
    )

    repo_service = create_repo_ingestion_service()
    agent = create_deep_security_scan_agent(
        llm_client=None,
        judgment_llm_client=None,
        repo_ingestion_service=repo_service,
    )
    report = None
    last_message = ""
    async for event in agent.scan(
        repo_url=f"file://{repo_path}",
        scan_mode=ScanMode.CODE_ONLY,
    ):
        data = getattr(event, "data", None)
        if isinstance(data, dict) and data.get("error"):
            last_message = str(getattr(event, "message", "") or "")
        if isinstance(data, dict) and "report" in data:
            report = data["report"]
    if report is None:
        # No report means the scan never ran (ingestion failure/abort). An
        # empty list here would read as "every finding is gone".
        raise RescanFailed(last_message or "the re-scan produced no report")
    return RescanFindings(report.get("findings", []), report.get("scanner_errors") or [])


async def verify_findings_resolved(
    repo_path: str,
    fixed_findings: list[DeepFinding],
) -> VerifyResult:
    """Re-scan `repo_path` and report which fixed findings are gone.

    `fixed_findings` are the findings whose files were successfully rewritten.
    """
    result = VerifyResult()
    verifiable = [f for f in fixed_findings if is_verifiable(f)]
    result.unverifiable = len(fixed_findings) - len(verifiable)
    if not verifiable:
        return result

    try:
        rescan = await _rescan_sast_findings(repo_path)
    except Exception as e:  # best-effort — never fail the fix over verification
        logger.warning("Fix verification re-scan failed: %s", e)
        result.error = str(e)
        result.could_not_verify = True
        result.unverifiable += len(verifiable)
        return result

    present = {_sig_dict(d) for d in rescan}
    failed, unmapped = failed_scanner_names(getattr(rescan, "scanner_errors", []))
    blocked = 0
    for f in verifiable:
        if sig_obj(f) in present:
            result.still_present += 1
            result.still_present_titles.append(f.title)
        elif failure_blocks(f.scanner_name, failed, unmapped):
            # The scanner that raised it did not complete: absence is not proof.
            blocked += 1
        else:
            result.resolved += 1
    if blocked:
        result.unverifiable += blocked
        result.error = (
            "re-scan scanner(s) failed or timed out: "
            + ", ".join(sorted(failed) or ["unknown"])
            + f"; {blocked} finding(s) could not be verified"
        )
        result.could_not_verify = blocked == len(verifiable)
    return result
