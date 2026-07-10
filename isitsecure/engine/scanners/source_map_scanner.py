"""Source map exposure scanner.

Detects publicly reachable JavaScript source maps (``.map`` files). Exposed
source maps leak original, un-minified source code — including comments,
internal file paths, and sometimes secrets embedded at build time.

Candidates come from two places:
1. ``snapshot.source_maps_found`` — maps already discovered during ingestion
   (e.g. from ``//# sourceMappingURL=`` comments).
2. Derived ``<asset.url>.map`` guesses for first-party JS assets.

Each candidate is fetched via GET and CONFIRMED to actually be a source map
by inspecting the body for source-map JSON markers (``"sources"`` /
``"mappings"``). A bare HTTP 200 is NOT enough — SPA catch-all routing
frequently returns 200 + index.html for any path, which would otherwise
produce false positives.

First-party map exposure -> HIGH. Third-party -> LOW/INFO.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from isitsecure.engine.constants import DeepScanConfig
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


# --- Module-local config (kept out of shared constants by design) ---
_SCANNER_NAME = "source_map_scanner"
_MAX_CONCURRENT = 5
_REQUEST_DELAY_SECONDS = 0.2
_HTTP_TIMEOUT_SECONDS = DeepScanConfig.HTTP_TIMEOUT_SECONDS
_MAX_CANDIDATES = 40

# Markers that confirm a body is genuinely a source map (Source Map v3).
_SOURCE_MAP_MARKERS = ('"sources":', '"mappings":')

# JS asset extensions we will derive a ".map" candidate for.
_JS_SUFFIXES = (".js", ".mjs", ".cjs")


class SourceMapScanner:
    """Detects exposed JavaScript source maps.

    SRP: This scanner is responsible ONLY for confirming reachable,
    genuine source maps and grading them by first/third-party origin.
    """

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return _SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.SOURCE_MAP_LEAK]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Confirm and report reachable source maps.

        Args:
            endpoints: Discovered endpoints (unused by this scanner).
            snapshot: Codebase snapshot providing asset/source-map info.

        Returns:
            List of source-map-leak findings.
        """
        if snapshot is None:
            return []

        candidates = self._collect_candidates(snapshot)
        if not candidates:
            logger.info("SourceMapScanner: no source map candidates")
            return []

        findings: list[DeepFinding] = []
        seen: set[str] = set()

        async with RateLimitedClient(
            max_concurrent=_MAX_CONCURRENT,
            delay_seconds=_REQUEST_DELAY_SECONDS,
            timeout_seconds=_HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            for map_url in candidates:
                if map_url in seen:
                    continue
                seen.add(map_url)
                finding = await self._verify_map(client, map_url, snapshot)
                if finding:
                    findings.append(finding)

        logger.info("SourceMapScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Candidate collection
    # ------------------------------------------------------------------

    def _collect_candidates(self, snapshot: CodebaseSnapshot) -> list[str]:
        """Build the list of candidate ``.map`` URLs to verify."""
        candidates: list[str] = []
        seen: set[str] = set()

        def _add(url: str) -> None:
            if url and url not in seen:
                seen.add(url)
                candidates.append(url)

        # 1. Maps already discovered during ingestion.
        for url in snapshot.source_maps_found:
            _add(url)

        # 2. Derive "<asset>.map" for first-party JS assets.
        for asset in snapshot.first_party_js_assets:
            derived = self._derive_map_url(asset.url)
            if derived:
                _add(derived)

        return candidates[:_MAX_CANDIDATES]

    @staticmethod
    def _derive_map_url(asset_url: str) -> str | None:
        """Return ``<asset_url>.map`` for a JS asset, else None.

        Strips any query/fragment before appending ``.map`` so the guess
        targets the actual file.
        """
        if not asset_url or asset_url.startswith("inline-script"):
            return None

        parsed = urlparse(asset_url)
        path = parsed.path.lower()
        if not any(path.endswith(suffix) for suffix in _JS_SUFFIXES):
            return None

        # Rebuild without query/fragment, then append .map
        base = asset_url.split("?", 1)[0].split("#", 1)[0]
        return f"{base}.map"

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    async def _verify_map(
        self,
        client: RateLimitedClient,
        map_url: str,
        snapshot: CodebaseSnapshot,
    ) -> DeepFinding | None:
        """GET the candidate and confirm it is a genuine source map."""
        try:
            response = await client.get(map_url)
        except Exception as exc:
            logger.debug("SourceMapScanner: fetch failed for %s: %s", map_url, exc)
            return None

        if response.status_code != 200:
            return None

        body = response.text or ""
        # Confirm the body is genuinely a source map — avoids SPA catch-all
        # 200 responses (which return index.html for any path).
        if not any(marker in body for marker in _SOURCE_MAP_MARKERS):
            return None

        is_first_party = snapshot.is_first_party_url(map_url)
        return self._build_finding(map_url, is_first_party)

    def _build_finding(self, map_url: str, is_first_party: bool) -> DeepFinding:
        """Construct a DeepFinding for a confirmed source map."""
        if is_first_party:
            severity = SeverityLevel.HIGH
            title = "First-party JavaScript source map exposed"
            description = (
                f"A source map is publicly reachable at {map_url}. Source maps "
                "reconstruct the original, un-minified source code — exposing "
                "internal file paths, comments, and any secrets embedded at "
                "build time. Disable source map generation in production or "
                "restrict access to these files."
            )
        else:
            severity = SeverityLevel.LOW
            title = "Third-party JavaScript source map exposed"
            description = (
                f"A third-party source map is reachable at {map_url}. This "
                "leaks the vendor library's original source but is lower risk "
                "than a first-party leak."
            )

        return DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.SOURCE_MAP_LEAK,
            severity=severity,
            title=title,
            description=description,
            technical_detail=(
                f"GET {map_url}\n"
                f"Response confirmed as a source map "
                f"(contains {' / '.join(_SOURCE_MAP_MARKERS)})"
            ),
            evidence=f"Source map reachable at {map_url}",
            confidence=0.95,
            scanner_name=self.scanner_name,
            endpoint_url=map_url,
            http_method="GET",
        )
