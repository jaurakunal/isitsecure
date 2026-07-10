"""Shared helpers for constructing CodebaseSnapshot fixtures in scanner tests."""

from __future__ import annotations

import base64
import json

from isitsecure.engine.ingestion.snapshot import (
    AssetType,
    CodebaseSnapshot,
    HTTPHeadersData,
    PageAsset,
)


def make_snapshot(
    url: str = "https://example.com",
    html_content: str = "",
    js_assets: list[tuple[str, str]] | None = None,
    source_maps_found: list[str] | None = None,
) -> CodebaseSnapshot:
    """Build a CodebaseSnapshot with crafted HTML and JS assets.

    Args:
        url: The scanned page URL.
        html_content: Raw HTML captured for the page.
        js_assets: List of (asset_url, content) tuples for JS assets.
        source_maps_found: Pre-discovered source map URLs.
    """
    assets: list[PageAsset] = []
    for asset_url, content in js_assets or []:
        assets.append(
            PageAsset(
                url=asset_url,
                asset_type=AssetType.JAVASCRIPT,
                content=content,
                size_bytes=len(content),
                is_external=False,
            )
        )

    return CodebaseSnapshot(
        url=url,
        html_content=html_content,
        assets=assets,
        headers=HTTPHeadersData(raw_headers={}, status_code=200),
        source_maps_found=source_maps_found or [],
    )


def make_jwt(role: str) -> str:
    """Build an unsigned JWT with the given role claim (header.payload.sig)."""

    def _b64(obj: dict) -> str:
        return (
            base64.urlsafe_b64encode(json.dumps(obj).encode())
            .rstrip(b"=")
            .decode()
        )

    header = _b64({"alg": "HS256", "typ": "JWT"})
    payload = _b64({"role": role, "iss": "supabase"})
    return f"{header}.{payload}.fakesignaturefakesignature"
