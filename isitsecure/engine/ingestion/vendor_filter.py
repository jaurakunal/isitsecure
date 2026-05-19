"""Shared vendor/framework asset filtering.

Three-layer detection:
1. Domain check: different registrable domain = third-party
2. Path prefix: well-known framework paths (/_next/, /_nuxt/, etc.)
3. Content markers: bundler runtime identifiers that survive minification
"""

import logging
import re
from urllib.parse import urlparse

from isitsecure.engine.ingestion.constants import InjectionScannerConfig

logger = logging.getLogger(__name__)


class VendorAssetFilter:
    """Classifies JS assets as vendor/framework vs. user-authored code."""

    def __init__(self, site_url: str) -> None:
        self._site_domain = self._extract_registrable_domain(site_url)

    @staticmethod
    def _extract_registrable_domain(url: str) -> str:
        """Extract the registrable domain (last 2 parts) from a URL."""
        try:
            hostname = urlparse(url).hostname or ""
        except Exception:
            return ""
        parts = hostname.lower().split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    def is_vendor_asset(self, asset_url: str, content: str) -> bool:
        """Check if an asset is vendor/framework code."""
        if asset_url.startswith("inline-script"):
            return False

        cfg = InjectionScannerConfig

        if self._is_third_party_domain(asset_url):
            return True

        if self._is_framework_path(asset_url, cfg):
            return True

        if self._has_vendor_content_markers(content, cfg):
            return True

        return False

    def _is_third_party_domain(self, asset_url: str) -> bool:
        """Check if asset is from a different domain than the scanned site."""
        try:
            hostname = urlparse(asset_url).hostname or ""
        except Exception:
            return False

        hostname_lower = hostname.lower()

        if hostname_lower in InjectionScannerConfig.THIRD_PARTY_SCRIPT_DOMAINS:
            return True

        parts = hostname_lower.split(".")
        asset_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname_lower

        if self._site_domain and asset_domain != self._site_domain:
            return True

        return False

    @staticmethod
    def _is_framework_path(
        asset_url: str,
        cfg: type[InjectionScannerConfig],
    ) -> bool:
        """Check if asset URL matches a known framework path."""
        try:
            path = urlparse(asset_url).path or ""
        except Exception:
            return False

        for prefix in cfg.FRAMEWORK_PATH_PREFIXES:
            if prefix in path:
                return True

        for pattern in cfg.FRAMEWORK_BUNDLE_PATH_PATTERNS:
            if re.search(pattern, path):
                return True

        return False

    @staticmethod
    def _has_vendor_content_markers(
        content: str,
        cfg: type[InjectionScannerConfig],
    ) -> bool:
        """Check if content contains vendor/framework runtime markers."""
        for marker in cfg.VENDOR_CONTENT_MARKERS_STRONG:
            if marker in content:
                return True

        matches = 0
        for marker in cfg.VENDOR_CONTENT_MARKERS:
            if marker in content:
                matches += 1
                if matches >= cfg.VENDOR_CONTENT_MARKER_THRESHOLD:
                    return True

        return False
