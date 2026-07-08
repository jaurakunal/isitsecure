"""Ground-truth schema for benchmark scoring.

A ``GroundTruthItem`` is one known vulnerability in a target app, tagged with:
- the vulnerability class and (where known) the vulnerable endpoint,
- whether it is DAST-detectable *in principle* (so out-of-scope CTF/crypto/
  business-logic items don't count against recall — they're reported
  separately), and
- a ``signature``: how a scanner finding maps to it (scanner/category/title/
  endpoint), reusing the same matching semantics as the harness.

A finding counts as detecting an item only if it matches the class signature
AND (when an endpoint is given) lands on that endpoint — this is the
true-positive-on-the-right-route check the smoke test lacked.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Signature:
    scanner: str | None = None
    scanners: tuple[str, ...] | None = None
    category: str | None = None
    title_contains: str | None = None

    def matches(self, finding: dict) -> bool:
        if self.scanner and finding.get("scanner_name") != self.scanner:
            return False
        if self.scanners and finding.get("scanner_name") not in self.scanners:
            return False
        if self.category and finding.get("category") != self.category:
            return False
        if self.title_contains and self.title_contains.lower() not in (
            finding.get("title") or ""
        ).lower():
            return False
        return True


@dataclass(frozen=True)
class GroundTruthItem:
    id: str                      # stable key (e.g. Juice Shop challenge key)
    name: str
    category: str                # the app's own category label
    vuln_class: str              # normalized: sqli, xss, idor, ssrf, ...
    dast_detectable: bool        # findable by our DAST in principle?
    signature: Signature | None = None
    endpoint_contains: str | None = None   # require the finding on this route
    auth_required: bool = False
    note: str = ""

    def detected_by(self, findings: list[dict]) -> dict | None:
        """Return the first finding that detects this item, or None."""
        if self.signature is None:
            return None
        for f in findings:
            if not self.signature.matches(f):
                continue
            if self.endpoint_contains and self.endpoint_contains.lower() not in (
                f.get("endpoint_url") or ""
            ).lower():
                continue
            return f
        return None


# --- reusable class signatures ---
# Categories are coarse and overlapping in isitsecure (open-redirect, CSRF,
# CORS, auth-bypass all use AUTH_WEAKNESS; SSRF/file-upload use INJECTION_RISK),
# so most classes match by SCANNER NAME rather than category. Verified against
# the SCANNER_NAME constants and the categories each scanner emits.
SIGNATURES: dict[str, Signature] = {
    "sqli": Signature(scanner="active_injection_scanner", title_contains="SQL injection"),
    "nosql": Signature(scanner="active_injection_scanner", title_contains="NoSQL"),
    "command": Signature(scanner="active_injection_scanner", title_contains="command"),
    "ssti": Signature(scanner="active_injection_scanner", title_contains="template"),
    "xxe": Signature(scanner="active_injection_scanner", title_contains="XXE"),
    "xss": Signature(scanners=("xss_scanner", "dom_xss_scanner")),
    "idor": Signature(category="idor"),
    "csrf": Signature(scanner="csrf_scanner"),
    "ssrf": Signature(scanner="ssrf_scanner"),
    "open_redirect": Signature(scanner="open_redirect_scanner"),
    "headers": Signature(category="missing_headers"),
    "cors": Signature(scanner="cors_scanner"),
    "info_disclosure": Signature(scanner="http_probe_scanner"),
    "exposed_data": Signature(scanner="http_probe_scanner"),
    "file_upload": Signature(scanner="file_upload_scanner"),
    "mass_assignment": Signature(scanner="mass_assignment_scanner"),
    "auth": Signature(scanner="auth_bypass_scanner"),
    "rate_limit": Signature(scanner="rate_limit_scanner"),
}
