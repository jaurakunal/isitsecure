"""Subresource Integrity (SRI) scanner.

External scripts and stylesheets loaded from CDNs should carry an
``integrity`` attribute so the browser can verify the fetched bytes match a
known hash. Without SRI, a compromised or malicious CDN can silently serve
altered code that runs with full page privileges.

This scanner is passive: it regexes the captured HTML for external CDN
``<script src>`` and ``<link rel=stylesheet href>`` tags lacking an
``integrity=`` attribute. First-party resources are excluded (SRI is far less
critical when you control the origin).

External script without SRI -> MEDIUM. External stylesheet without SRI -> LOW.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


# --- Module-local config ---
_SCANNER_NAME = "sri_scanner"
_MAX_FINDINGS = 20

# Match full <script ...> tags with a src, and <link ...> tags, so we can
# inspect the whole tag for both the URL and a possible integrity attribute.
_SCRIPT_TAG_RE = re.compile(r"<script\b[^>]*?\bsrc\s*=\s*['\"]([^'\"]+)['\"][^>]*>", re.IGNORECASE)
_LINK_TAG_RE = re.compile(r"<link\b[^>]*?>", re.IGNORECASE)

_HREF_RE = re.compile(r"""\bhref\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
_REL_STYLESHEET_RE = re.compile(
    r"""\brel\s*=\s*['"][^'"]*\bstylesheet\b[^'"]*['"]""", re.IGNORECASE
)
_INTEGRITY_RE = re.compile(r"""\bintegrity\s*=\s*['"][^'"]+['"]""", re.IGNORECASE)


class SRIScanner:
    """Detects external CDN resources missing Subresource Integrity.

    SRP: This scanner is responsible ONLY for static SRI-absence detection.
    """

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return _SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.MISSING_SRI]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Scan captured HTML for external resources missing SRI.

        Args:
            endpoints: Discovered endpoints (unused by this scanner).
            snapshot: Codebase snapshot providing HTML content.

        Returns:
            List of missing-SRI findings.
        """
        if snapshot is None:
            return []

        html = snapshot.html_content or ""
        if not html.strip():
            return []

        findings: list[DeepFinding] = []
        seen: set[str] = set()

        findings.extend(self._scan_scripts(html, snapshot, seen))
        findings.extend(self._scan_stylesheets(html, snapshot, seen))

        findings = findings[:_MAX_FINDINGS]
        logger.info("SRIScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Scripts
    # ------------------------------------------------------------------

    def _scan_scripts(
        self,
        html: str,
        snapshot: CodebaseSnapshot,
        seen: set[str],
    ) -> list[DeepFinding]:
        """Find external <script src> tags without an integrity attribute."""
        findings: list[DeepFinding] = []
        for match in _SCRIPT_TAG_RE.finditer(html):
            tag = match.group(0)
            src = match.group(1)
            if not self._is_external(src, snapshot):
                continue
            if _INTEGRITY_RE.search(tag):
                continue
            if src in seen:
                continue
            seen.add(src)
            findings.append(
                self._build_finding(
                    snapshot.url, src, "script", SeverityLevel.MEDIUM
                )
            )
        return findings

    # ------------------------------------------------------------------
    # Stylesheets
    # ------------------------------------------------------------------

    def _scan_stylesheets(
        self,
        html: str,
        snapshot: CodebaseSnapshot,
        seen: set[str],
    ) -> list[DeepFinding]:
        """Find external stylesheet <link> tags without an integrity attr."""
        findings: list[DeepFinding] = []
        for match in _LINK_TAG_RE.finditer(html):
            tag = match.group(0)
            if not _REL_STYLESHEET_RE.search(tag):
                continue
            href_match = _HREF_RE.search(tag)
            if not href_match:
                continue
            href = href_match.group(1)
            if not self._is_external(href, snapshot):
                continue
            if _INTEGRITY_RE.search(tag):
                continue
            if href in seen:
                continue
            seen.add(href)
            findings.append(
                self._build_finding(
                    snapshot.url, href, "stylesheet", SeverityLevel.LOW
                )
            )
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_external(resource_url: str, snapshot: CodebaseSnapshot) -> bool:
        """Return True only for absolute cross-origin (CDN) resources.

        Relative URLs and same-domain absolute URLs are first-party and are
        excluded — SRI matters most for resources you do not control.
        """
        parsed = urlparse(resource_url)
        if not parsed.scheme or not parsed.netloc:
            # Relative / protocol-less path -> first-party.
            return False
        return not snapshot.is_first_party_url(resource_url)

    def _build_finding(
        self,
        page_url: str,
        resource_url: str,
        kind: str,
        severity: SeverityLevel,
    ) -> DeepFinding:
        """Construct a DeepFinding for a resource missing SRI."""
        return DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.MISSING_SRI,
            severity=severity,
            title=f"External {kind} missing Subresource Integrity (SRI)",
            description=(
                f"The page {page_url} loads an external {kind} from "
                f"{resource_url} without an integrity attribute. If that CDN "
                "is compromised, the browser will execute the altered content "
                "with full page privileges. Add an SRI hash "
                "(integrity=\"sha384-...\") and crossorigin attribute."
            ),
            technical_detail=(
                f"Page: {page_url}\n"
                f"External {kind}: {resource_url}\n"
                f"integrity attribute: (absent)"
            ),
            evidence=f"External {kind} {resource_url} has no integrity attribute",
            confidence=0.9,
            scanner_name=self.scanner_name,
            endpoint_url=page_url,
            http_method="GET",
        )
