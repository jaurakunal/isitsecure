"""Per-finding re-verification (#53) — is this one finding fixed now?

The fix-flow verifier (``fixes/verifier.py``) re-scans a whole repo and only
handles SAST findings. This module re-checks *specific* findings — SAST **and**
DAST — and returns a definitive fixed / still-present verdict per finding:

- **SAST** (has ``code_location``): one code-only re-scan of the repo; a finding
  is fixed when its fingerprint no longer appears.
- **DAST** (has ``endpoint_url``): reconstruct the endpoint against the target and
  re-run *the scanner that raised it*; fixed when it no longer raises the same
  fingerprint. Host/port/query are re-based onto the given target, which is
  exactly why the fingerprint is host-agnostic.
- Everything else (LLM-review findings, special scanners not in the standard DAST
  set) is reported ``unverifiable`` rather than falsely claimed fixed.

Identity is the shared :func:`isitsecure.engine.identity.finding_fingerprint`.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlparse

from isitsecure.engine.fixes.verifier import LLM_SCANNERS
from isitsecure.engine.identity import finding_fingerprint
from isitsecure.engine.models import DeepFinding

logger = logging.getLogger(__name__)

# A re-verify tool must NEVER falsely claim "fixed". A single-endpoint re-probe
# can only faithfully reproduce a finding when the finding doesn't depend on
# crawl-derived state (multi-request flows like stored XSS) or on a tested
# parameter we can't recover. So FIXED/STILL_PRESENT is claimed only for a
# conservative allowlist; everything else degrades to UNVERIFIABLE.
#
# Endpoint-level: reproducible from URL + method alone (checks the endpoint or
# its response, not an injected parameter).
_ENDPOINT_REVERIFIABLE = {
    "security_headers_scanner",
    "cors_scanner",
    "source_map_scanner",
    "http_probe_scanner",
    "csrf_scanner",
}
# Parameter-level: reproducible only when the tested parameter is recovered from
# ``request_payload`` (a clean ``param=value``). SSTI/XSS store a raw payload or
# put the param in the title, so param recovery fails and they fall through to
# UNVERIFIABLE rather than a false FIXED.
_PARAM_REVERIFIABLE = {
    "active_injection_scanner",
}
# A recovered token only counts as a real parameter name if it looks like one
# (not a raw ``' OR 1=1`` / XML / canary payload).
_PARAM_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\[\]-]{0,39}$")


class VerifyStatus(StrEnum):
    FIXED = "fixed"
    STILL_PRESENT = "still_present"
    UNVERIFIABLE = "unverifiable"
    ERROR = "error"


@dataclass
class Verdict:
    finding: DeepFinding
    status: VerifyStatus
    detail: str = ""


def _is_sast(f: DeepFinding) -> bool:
    return bool(
        f.code_location and f.code_location.file_path
        and f.scanner_name not in LLM_SCANNERS
    )


def _is_dast(f: DeepFinding) -> bool:
    return bool(f.endpoint_url and f.scanner_name not in LLM_SCANNERS)


def _param_names_from_payload(payload: str | None) -> list[str]:
    """Best-effort recover the tested parameter name(s) from a finding's
    ``request_payload`` (``param=value`` for query/body, or a JSON object).

    Only tokens that actually look like parameter names are returned — a raw
    injection payload (``' OR 1=1``, XML, an XSS canary) yields ``[]`` so the
    caller can treat it as unrecoverable rather than fabricate a bogus param.
    """
    if not payload:
        return []
    text = payload.strip()
    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return []
        candidates = [str(k) for k in obj] if isinstance(obj, dict) else []
    else:
        candidates = [text.split("=", 1)[0].strip()]
    return [c for c in candidates if _PARAM_NAME_RE.match(c)]


def _endpoint_for(finding: DeepFinding, target_url: str, params: list[str]):
    """Reconstruct a DiscoveredEndpoint pointing at ``target_url`` with the
    finding's path/query (and the recovered tested params), so the scanner
    re-probes the same place in the app."""
    from isitsecure.engine.enums import EndpointMethod
    from isitsecure.engine.models import DiscoveredEndpoint

    orig = urlparse(finding.endpoint_url or "")
    base = urlparse(target_url)
    url = f"{base.scheme}://{base.netloc}{orig.path or '/'}"
    if orig.query:
        url += f"?{orig.query}"
    method_str = (finding.http_method or "GET").upper()
    try:
        method = EndpointMethod(method_str)
    except ValueError:
        method = EndpointMethod.GET
    return DiscoveredEndpoint(url=url, method=method, query_param_names=params)


async def _sast_present_fingerprints(repo_path: str) -> set[str]:
    """Fingerprints still raised by a code-only re-scan of ``repo_path``."""
    from isitsecure.engine.fixes.verifier import _rescan_sast_findings
    rescan = await _rescan_sast_findings(repo_path)
    return {d["fingerprint"] for d in rescan if d.get("fingerprint")}


def _dast_scanners_by_name() -> dict:
    """Map scanner_name -> a standalone DAST scanner instance (deep depth so the
    full scanner set is available). No LLM — re-verification is deterministic."""
    from isitsecure.engine.enums import ScanDepth
    from isitsecure.engine.factory import create_deep_security_scan_agent
    agent = create_deep_security_scan_agent(depth=ScanDepth.DEEP)
    return {s.scanner_name: s for s in agent._dast_scanners}


async def _reverify_dast(finding: DeepFinding, target_url: str, scanners: dict) -> Verdict:
    name = finding.scanner_name
    scanner = scanners.get(name)
    # Only re-probe when a single-endpoint re-run can FAITHFULLY reproduce the
    # finding — otherwise a non-reproduction is not evidence of a fix.
    if scanner is None or name not in _ENDPOINT_REVERIFIABLE | _PARAM_REVERIFIABLE:
        return Verdict(finding, VerifyStatus.UNVERIFIABLE,
                       "can't be reproduced by a single-endpoint re-probe — re-verify manually")
    params = _param_names_from_payload(finding.request_payload)
    if name in _PARAM_REVERIFIABLE and not params:
        return Verdict(finding, VerifyStatus.UNVERIFIABLE,
                       "couldn't recover the tested parameter — re-verify manually")
    try:
        endpoint = _endpoint_for(finding, target_url, params)
        results = await scanner.scan([endpoint], snapshot=None)
    except Exception as exc:  # noqa: BLE001 — a probe failure is a verdict, not a crash
        logger.warning("Re-verify probe failed for %s: %s", finding.fingerprint, exc)
        return Verdict(finding, VerifyStatus.ERROR, str(exc))
    target_fp = finding_fingerprint(finding)
    if any(finding_fingerprint(r) == target_fp for r in results):
        return Verdict(finding, VerifyStatus.STILL_PRESENT)
    return Verdict(finding, VerifyStatus.FIXED)


async def reverify_findings(
    findings: list[DeepFinding],
    *,
    target_url: str | None = None,
    repo_path: str | None = None,
) -> list[Verdict]:
    """Re-check each finding and return a verdict, preserving input order."""
    sast = [f for f in findings if _is_sast(f)]
    dast = [f for f in findings if not _is_sast(f) and _is_dast(f)]

    verdict_by_id: dict[str, Verdict] = {}

    # SAST — one shared re-scan for all of them.
    if sast:
        if not repo_path:
            for f in sast:
                verdict_by_id[f.id] = Verdict(
                    f, VerifyStatus.UNVERIFIABLE, "no repo path given (--repo)"
                )
        else:
            try:
                present = await _sast_present_fingerprints(repo_path)
            except Exception as exc:  # noqa: BLE001
                logger.warning("SAST re-verify re-scan failed: %s", exc)
                for f in sast:
                    verdict_by_id[f.id] = Verdict(f, VerifyStatus.ERROR, str(exc))
            else:
                for f in sast:
                    status = (VerifyStatus.STILL_PRESENT
                              if finding_fingerprint(f) in present else VerifyStatus.FIXED)
                    verdict_by_id[f.id] = Verdict(f, status)

    # DAST — re-probe each finding's endpoint.
    if dast:
        if not target_url:
            for f in dast:
                verdict_by_id[f.id] = Verdict(f, VerifyStatus.UNVERIFIABLE, "no target URL given")
        else:
            scanners = _dast_scanners_by_name()
            for f in dast:
                verdict_by_id[f.id] = await _reverify_dast(f, target_url, scanners)

    verdicts: list[Verdict] = []
    for f in findings:
        verdicts.append(
            verdict_by_id.get(f.id)
            or Verdict(f, VerifyStatus.UNVERIFIABLE,
                       "LLM-review or non-locatable finding — cannot re-check deterministically")
        )
    return verdicts
