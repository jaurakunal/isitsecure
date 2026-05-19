"""Models for web application ingestion snapshots.

Inlined from the security_audit package for standalone operation.
"""

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class AssetType(str, Enum):
    """Types of web assets captured during ingestion."""

    HTML = "html"
    JAVASCRIPT = "javascript"
    CSS = "css"
    SOURCE_MAP = "source_map"
    CONFIG_FILE = "config_file"


class PageAsset(BaseModel):
    """A single asset extracted from the page."""

    url: str
    asset_type: AssetType
    content: str
    size_bytes: int
    is_external: bool = True


class HTTPHeadersData(BaseModel):
    """HTTP response headers from the target URL."""

    raw_headers: dict[str, str]
    status_code: int
    server: Optional[str] = None
    cookies: list[dict[str, Any]] = Field(default_factory=list)


class CodebaseSnapshot(BaseModel):
    """Complete snapshot of a web application captured from its URL."""

    url: str
    html_content: str
    assets: list[PageAsset] = Field(default_factory=list)
    headers: HTTPHeadersData
    source_maps_found: list[str] = Field(default_factory=list)
    probe_results: dict[str, Optional[str]] = Field(default_factory=dict)
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    capture_duration_seconds: float = 0.0

    @property
    def js_assets(self) -> list[PageAsset]:
        """Return only JavaScript assets."""
        return [a for a in self.assets if a.asset_type == AssetType.JAVASCRIPT]

    @property
    def all_js_content(self) -> str:
        """Concatenate all JavaScript content for scanning."""
        return "\n".join(a.content for a in self.js_assets)

    @property
    def all_scannable_content(self) -> str:
        """Concatenate HTML + all JS content for broad scanning."""
        parts = [self.html_content]
        parts.extend(a.content for a in self.js_assets)
        return "\n".join(parts)

    @property
    def first_party_js_assets(self) -> list[PageAsset]:
        """Return only JS assets that are NOT vendor/framework code."""
        from isitsecure.engine.ingestion.vendor_filter import VendorAssetFilter

        vendor_filter = VendorAssetFilter(site_url=self.url)
        return [
            a
            for a in self.js_assets
            if not vendor_filter.is_vendor_asset(a.url, a.content)
        ]

    @property
    def first_party_js_content(self) -> str:
        """Concatenate only first-party (non-vendor) JS content."""
        return "\n".join(a.content for a in self.first_party_js_assets)

    def is_first_party_url(self, asset_url: str) -> bool:
        """Check if an asset URL belongs to the same domain as the scanned site."""
        try:
            parsed = urlparse(asset_url)
            if not parsed.scheme:
                return True
            asset_domain = parsed.netloc.lower().removeprefix("www.")
            site_domain = urlparse(self.url).netloc.lower().removeprefix("www.")
            return asset_domain == site_domain
        except Exception:
            return True
