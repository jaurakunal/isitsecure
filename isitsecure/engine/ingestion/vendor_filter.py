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
    def _registrable_domain(hostname: str) -> str:
        """Registrable domain of a hostname, aware of multi-label suffixes.

        ``shop.example.co.uk`` -> ``example.co.uk`` and
        ``myapp.vercel.app`` -> ``myapp.vercel.app`` (each customer of a
        hosting platform is a different site), not ``co.uk`` / ``vercel.app``.
        """
        parts = hostname.lower().split(".")
        if len(parts) < 2:
            return hostname.lower()
        suffixes = InjectionScannerConfig.MULTI_LABEL_PUBLIC_SUFFIXES
        for size in (3, 2):
            if len(parts) > size and ".".join(parts[-size:]) in suffixes:
                return ".".join(parts[-(size + 1):])
        return ".".join(parts[-2:])

    @classmethod
    def _extract_registrable_domain(cls, url: str) -> str:
        """Extract the registrable domain from a URL."""
        try:
            hostname = urlparse(url).hostname or ""
        except Exception:
            return ""
        return cls._registrable_domain(hostname)

    @staticmethod
    def _brand_label(domain: str) -> str:
        """The label that names the site: ``example`` for ``example.co.uk``."""
        return domain.split(".", 1)[0]

    def _is_sibling_domain(self, asset_domain: str) -> bool:
        """``example-static.com`` serving ``example.com``: same brand label.

        Only for hosts under a single owner-registrable suffix; shared hosting
        domains (``x.vercel.app``) never count as siblings of each other.
        """
        site, asset = self._site_domain, asset_domain
        if site.count(".") != 1 or asset.count(".") != 1:
            return False
        a, b = self._brand_label(site), self._brand_label(asset)
        shortest = min(len(a), len(b))
        # The labels must be equal, or one must be the other plus "-suffix"
        # (example-static.com for example.com). A bare shared prefix is not
        # enough: shopify.com is not a sibling of shop.com.
        return shortest >= InjectionScannerConfig.SIBLING_LABEL_MIN_LENGTH and (
            a == b or a.startswith(b + "-") or b.startswith(a + "-")
        )

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

        asset_domain = self._registrable_domain(hostname_lower)

        if (
            self._site_domain
            and asset_domain != self._site_domain
            and not self._is_sibling_domain(asset_domain)
        ):
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

        # The application's own chunks live under the framework's prefix.
        if any(re.search(p, path) for p in cfg.FIRST_PARTY_FRAMEWORK_PATH_PATTERNS):
            return any(re.search(p, path) for p in cfg.FRAMEWORK_BUNDLE_PATH_PATTERNS)

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
