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


@dataclass
class VerifyResult:
    resolved: int = 0
    still_present: int = 0
    unverifiable: int = 0
    still_present_titles: list[str] = field(default_factory=list)
    error: str = ""

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
        }


def _sig_obj(f: DeepFinding) -> tuple:
    cat = f.category.value if hasattr(f.category, "value") else str(f.category)
    fp = f.code_location.file_path if f.code_location else ""
    return (f.scanner_name, cat, fp, f.title)


def _sig_dict(d: dict) -> tuple:
    loc = d.get("code_location") or {}
    return (d.get("scanner_name"), str(d.get("category")), loc.get("file_path", ""), d.get("title"))


def _is_verifiable(f: DeepFinding) -> bool:
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
    async for event in agent.scan(
        repo_url=f"file://{repo_path}",
        scan_mode=ScanMode.CODE_ONLY,
    ):
        data = getattr(event, "data", None)
        if isinstance(data, dict) and "report" in data:
            report = data["report"]
    return report.get("findings", []) if report else []


async def verify_findings_resolved(
    repo_path: str,
    fixed_findings: list[DeepFinding],
) -> VerifyResult:
    """Re-scan `repo_path` and report which fixed findings are gone.

    `fixed_findings` are the findings whose files were successfully rewritten.
    """
    result = VerifyResult()
    verifiable = [f for f in fixed_findings if _is_verifiable(f)]
    result.unverifiable = len(fixed_findings) - len(verifiable)
    if not verifiable:
        return result

    try:
        rescan = await _rescan_sast_findings(repo_path)
    except Exception as e:  # best-effort — never fail the fix over verification
        logger.warning("Fix verification re-scan failed: %s", e)
        result.error = str(e)
        result.unverifiable += len(verifiable)
        return result

    present = {_sig_dict(d) for d in rescan}
    for f in verifiable:
        if _sig_obj(f) in present:
            result.still_present += 1
            result.still_present_titles.append(f.title)
        else:
            result.resolved += 1
    return result
