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

from isitsecure.engine.identity import (
    _discriminator,
    compute_fingerprint,
    finding_fingerprint,
    legacy_fingerprint,
)
from isitsecure.engine.fixes.parse_check import unparseable_files
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
    # Findings whose old location is clean but an equivalent finding (same
    # scanner/title/flagged code) now appears in ANOTHER file: the code may just
    # have moved. Counted as unverifiable, never as resolved.
    possibly_moved_titles: list[str] = field(default_factory=list)
    # Files that no longer parse after the fix: the scanners (tree-sitter) skip
    # them silently, so their findings vanish without being fixed.
    unparseable_files: dict[str, str] = field(default_factory=dict)
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
            "possibly_moved_titles": self.possibly_moved_titles[:10],
            "unparseable_files": dict(list(self.unparseable_files.items())[:10]),
            "error": self.error,
            "could_not_verify": self.could_not_verify,
        }


def sig_obj(f: DeepFinding) -> tuple:
    cat = f.category.value if hasattr(f.category, "value") else str(f.category)
    fp = f.code_location.file_path if f.code_location else ""
    return (f.scanner_name, cat, fp, f.title)


def rescan_fingerprints(d: dict) -> tuple[str, str]:
    """``(v2, legacy)`` fingerprints of a re-scan finding dict.

    The report carries the v2 value as ``fingerprint``; the legacy value
    (scanner, category, file, title) is recomputed so findings can be matched
    against originals under either identity scheme.
    """
    loc = d.get("code_location") or {}
    legacy = compute_fingerprint(
        scanner_name=d.get("scanner_name") or "",
        category=d.get("category"),
        title=d.get("title") or "",
        file_path=loc.get("file_path") or None,
        endpoint_url=d.get("endpoint_url"),
        http_method=d.get("http_method"),
    )
    return (d.get("fingerprint") or legacy, legacy)


def _dict_discriminator(d: dict) -> str:
    """The per-instance discriminator (flagged source line) of a finding dict."""
    try:
        return _discriminator(DeepFinding.model_validate(d))
    except Exception:  # noqa: BLE001 - malformed dict: no discriminator
        return ""


def finding_as_rescan_dict(f: DeepFinding) -> dict:
    """A re-scan finding object in the dict shape :func:`classify_against_rescan` reads."""
    d = f.model_dump(mode="json")
    d["fingerprint"] = finding_fingerprint(f)
    return d


def classify_against_rescan(
    originals: list[DeepFinding],
    rescan: list[dict],
    *,
    context: list[DeepFinding] | None = None,
) -> tuple[list[DeepFinding], list[DeepFinding], list[DeepFinding]]:
    """Split ``originals`` into ``(still_present, possibly_moved, gone)``.

    The single definition of "is this finding fixed?" shared by the fix flow, the
    CLI/MCP ``verify`` and per-finding re-verify.

    An original is *resolved* only when no remaining finding matches ANY of its
    known fingerprints (current v2 or legacy). Each remaining finding can account
    for ONE original (multiset semantics: 2 old with one signature, 1 remaining =>
    1 resolved); v2 matches are made first so the instance that is really still
    there stays present even if a sibling was fixed.

    ``context`` is every original finding of the same report, including ones not
    being asked about (e.g. findings whose fix was not applied). They take part in
    the matching -- they are the likelier owners of a remaining finding -- but are
    not reported.

    An original with no match at its own location is ``possibly_moved`` when a
    remaining finding that no other original accounts for, with the same
    scanner/category/title and the same (non-empty) flagged line, sits in a
    different file.
    """
    asked = {id(f) for f in originals}
    everyone = [f for f in (context or []) if id(f) not in asked]
    everyone += originals
    # Findings the caller is not asking about claim remaining entries first.
    everyone.sort(key=lambda f: id(f) in asked)

    entries = [(rescan_fingerprints(d), d) for d in rescan]
    free = [True] * len(entries)
    by_v2: dict[str, list[int]] = {}
    by_legacy: dict[str, list[int]] = {}
    for idx, ((v2, legacy), _d) in enumerate(entries):
        by_v2.setdefault(v2, []).append(idx)
        by_legacy.setdefault(legacy, []).append(idx)

    def claim(candidates: list[int]) -> bool:
        for idx in candidates:
            if free[idx]:
                free[idx] = False
                return True
        return False

    still_ids: set[int] = set()
    for f in everyone:
        if claim(by_v2.get(finding_fingerprint(f), [])):
            still_ids.add(id(f))
    for f in everyone:
        if id(f) not in still_ids and claim(by_legacy.get(legacy_fingerprint(f), [])):
            still_ids.add(id(f))

    moved_ids: set[int] = set()
    for f in everyone:
        if id(f) in still_ids:
            continue
        disc = _discriminator(f)
        if not disc:
            continue
        cat = f.category.value if hasattr(f.category, "value") else str(f.category)
        here = f.code_location.file_path if f.code_location else ""
        for idx, (_fps, d) in enumerate(entries):
            if (
                free[idx]
                and d.get("scanner_name") == f.scanner_name
                and str(d.get("category")) == cat
                and d.get("title") == f.title
                and ((d.get("code_location") or {}).get("file_path") or "") != here
                and _dict_discriminator(d) == disc
            ):
                free[idx] = False
                moved_ids.add(id(f))
                break

    still = [f for f in originals if id(f) in still_ids]
    moved = [f for f in originals if id(f) in moved_ids]
    gone = [f for f in originals if id(f) not in still_ids and id(f) not in moved_ids]
    return still, moved, gone


def is_verifiable(f: DeepFinding) -> bool:
    return bool(
        f.code_location
        and f.code_location.file_path
        and f.scanner_name not in LLM_SCANNERS
    )


async def _rescan_sast_findings(repo_path: str) -> list[dict]:
    """Run a code-only SAST scan (no LLM) over a local repo path."""
    from isitsecure.engine.code_analysis.semgrep_analyzer import require_semgrep
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
    # A verification re-scan must not read a missing optional semgrep as "fixed".
    with require_semgrep():
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
    *,
    context: list[DeepFinding] | None = None,
) -> VerifyResult:
    """Re-scan `repo_path` and report which fixed findings are gone.

    `fixed_findings` are the findings whose files were successfully rewritten.
    `context` is every finding of the scan (including ones whose fix was not
    applied): they still count when matching what remains in the re-scan.
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

    failed, unmapped = failed_scanner_names(getattr(rescan, "scanner_errors", []))
    still, moved, gone = classify_against_rescan(verifiable, list(rescan), context=context)
    # Absent because its scanner failed/timed out/never ran: not proof of a fix.
    blocked_f = [f for f in gone if failure_blocks(f.scanner_name, failed, unmapped)]
    blocked = len(blocked_f)
    blocked_ids = {id(f) for f in blocked_f}
    gone = [f for f in gone if id(f) not in blocked_ids]
    # A finding vanishing from a file that no longer parses is not a fix.
    broken = unparseable_files(
        repo_path, [f.code_location.file_path for f in gone if f.code_location]
    )
    if broken:
        result.unparseable_files = broken
        kept = []
        for f in gone:
            if f.code_location and f.code_location.file_path in broken:
                result.unverifiable += 1
            else:
                kept.append(f)
        gone = kept
    for f in still:
        result.still_present += 1
        result.still_present_titles.append(f.title)
    for f in moved:
        result.unverifiable += 1
        result.possibly_moved_titles.append(f.title)
    result.resolved += len(gone)
    if blocked:
        result.unverifiable += blocked
        result.error = (
            "re-scan scanner(s) failed or timed out: "
            + ", ".join(sorted(failed) or ["unknown"])
            + f"; {blocked} finding(s) could not be verified"
        )
        result.could_not_verify = blocked == len(verifiable)
    return result
