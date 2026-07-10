"""Mixed content scanner.

When an HTTPS page loads sub-resources over plain HTTP, the connection is no
longer fully secure. Active mixed content (scripts, stylesheets) can be
tampered with to fully compromise the page; passive mixed content (images)
mainly leaks the request and can be swapped by a network attacker.

This scanner is passive: it regexes the already-captured HTML (and first-party
JS) for ``http://`` resource references in resource-loading tags. It never
fetches anything and only runs when the scanned page itself is HTTPS.

Active (script/link) -> MEDIUM. Passive (img) -> LOW.
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
_SCANNER_NAME = "mixed_content_scanner"
_MAX_FINDINGS_PER_KIND = 10

# Active resources: an attacker who swaps these can run code / restyle the page.
# (tag, attribute, severity, human label)
_ACTIVE_PATTERNS = (
    (
        re.compile(r"""<script\b[^>]*?\bsrc\s*=\s*['"](http://[^'"\s>]+)""", re.IGNORECASE),
        "script[src]",
        SeverityLevel.MEDIUM,
        "active",
    ),
    (
        re.compile(
            r"""<link\b[^>]*?\bhref\s*=\s*['"](http://[^'"\s>]+)""", re.IGNORECASE
        ),
        "link[href]",
        SeverityLevel.MEDIUM,
        "active",
    ),
    (
        re.compile(
            r"""<iframe\b[^>]*?\bsrc\s*=\s*['"](http://[^'"\s>]+)""", re.IGNORECASE
        ),
        "iframe[src]",
        SeverityLevel.MEDIUM,
        "active",
    ),
)

# Passive resources: mainly leak the request / can be visually swapped.
_PASSIVE_PATTERNS = (
    (
        re.compile(r"""<img\b[^>]*?\bsrc\s*=\s*['"](http://[^'"\s>]+)""", re.IGNORECASE),
        "img[src]",
        SeverityLevel.LOW,
        "passive",
    ),
)


class MixedContentScanner:
    """Detects HTTP sub-resources loaded from an HTTPS page.

    SRP: This scanner is responsible ONLY for static mixed-content detection.
    """

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return _SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.MIXED_CONTENT]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Scan captured content for mixed content.

        Args:
            endpoints: Discovered endpoints (unused by this scanner).
            snapshot: Codebase snapshot providing HTML/JS content.

        Returns:
            List of mixed-content findings.
        """
        if snapshot is None:
            return []

        # Only relevant for HTTPS pages — an HTTP page has no mixed content.
        if urlparse(snapshot.url).scheme != "https":
            return []

        content_parts = [snapshot.html_content or ""]
        content_parts.append(snapshot.first_party_js_content or "")
        content = "\n".join(content_parts)
        if not content.strip():
            return []

        findings: list[DeepFinding] = []
        seen: set[str] = set()

        for pattern, tag_label, severity, kind in (
            *_ACTIVE_PATTERNS,
            *_PASSIVE_PATTERNS,
        ):
            matches = 0
            for match in pattern.finditer(content):
                resource_url = match.group(1)
                dedup_key = f"{tag_label}|{resource_url}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(
                    self._build_finding(
                        snapshot.url, resource_url, tag_label, severity, kind
                    )
                )
                matches += 1
                if matches >= _MAX_FINDINGS_PER_KIND:
                    break

        logger.info("MixedContentScanner: %d findings", len(findings))
        return findings

    def _build_finding(
        self,
        page_url: str,
        resource_url: str,
        tag_label: str,
        severity: SeverityLevel,
        kind: str,
    ) -> DeepFinding:
        """Construct a DeepFinding for a mixed-content reference."""
        title = f"{kind.capitalize()} mixed content ({tag_label})"
        description = (
            f"The HTTPS page {page_url} loads a resource over plain HTTP: "
            f"{resource_url}. "
        )
        if kind == "active":
            description += (
                "Active mixed content (scripts, stylesheets, frames) can be "
                "intercepted and modified by a network attacker to execute "
                "arbitrary code in the page context. Load it over HTTPS."
            )
        else:
            description += (
                "Passive mixed content leaks the request and can be swapped by "
                "a network attacker. Serve it over HTTPS."
            )

        return DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.MIXED_CONTENT,
            severity=severity,
            title=title,
            description=description,
            technical_detail=(
                f"Page: {page_url} (https)\n"
                f"Resource ({tag_label}): {resource_url}"
            ),
            evidence=f"{tag_label} references {resource_url}",
            confidence=0.9,
            scanner_name=self.scanner_name,
            endpoint_url=page_url,
            http_method="GET",
        )
