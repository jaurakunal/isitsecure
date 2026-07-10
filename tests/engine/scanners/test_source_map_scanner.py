"""Tests for SourceMapScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.scanners.source_map_scanner import SourceMapScanner

from tests.engine.scanners._snapshot_helpers import make_snapshot

_REAL_MAP_BODY = (
    '{"version":3,"sources":["src/app.ts"],"mappings":"AAAA,SAASA"}'
)


def _mock_response(status_code: int = 200, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def _patch_client(response: MagicMock):
    """Patch RateLimitedClient to return the given response for every GET."""
    client_instance = AsyncMock()
    client_instance.get = AsyncMock(return_value=response)
    mock_ctx = MagicMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=client_instance)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    return patch(
        "isitsecure.engine.scanners.source_map_scanner.RateLimitedClient",
        return_value=mock_ctx,
    )


class TestSourceMapScanner:
    def setup_method(self) -> None:
        self.scanner = SourceMapScanner()

    def test_scan_categories(self) -> None:
        assert self.scanner.scan_categories == [FindingCategory.SOURCE_MAP_LEAK]

    @pytest.mark.asyncio
    async def test_no_snapshot_returns_empty(self) -> None:
        assert await self.scanner.scan(endpoints=[], snapshot=None) == []

    @pytest.mark.asyncio
    async def test_no_candidates_returns_empty(self) -> None:
        snapshot = make_snapshot(js_assets=[])
        with _patch_client(_mock_response()):
            findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert findings == []

    @pytest.mark.asyncio
    async def test_first_party_confirmed_map_high(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            js_assets=[("https://example.com/static/app.js", "console.log(1)")],
        )
        with _patch_client(_mock_response(200, _REAL_MAP_BODY)):
            findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.SOURCE_MAP_LEAK
        assert findings[0].severity == SeverityLevel.HIGH
        assert findings[0].endpoint_url == "https://example.com/static/app.js.map"
        assert ".map" in findings[0].evidence

    @pytest.mark.asyncio
    async def test_source_maps_found_used_as_candidate(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            source_maps_found=["https://example.com/bundle.js.map"],
        )
        with _patch_client(_mock_response(200, _REAL_MAP_BODY)):
            findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert len(findings) == 1
        assert findings[0].endpoint_url == "https://example.com/bundle.js.map"

    @pytest.mark.asyncio
    async def test_third_party_map_low(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            source_maps_found=["https://cdn.other.com/vendor.js.map"],
        )
        with _patch_client(_mock_response(200, _REAL_MAP_BODY)):
            findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.LOW

    @pytest.mark.asyncio
    async def test_spa_catchall_200_not_flagged(self) -> None:
        """200 that returns index.html (no source-map markers) -> no finding."""
        snapshot = make_snapshot(
            url="https://example.com",
            js_assets=[("https://example.com/static/app.js", "x")],
        )
        html_body = "<!doctype html><html><body>App</body></html>"
        with _patch_client(_mock_response(200, html_body)):
            findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert findings == []

    @pytest.mark.asyncio
    async def test_404_not_flagged(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            js_assets=[("https://example.com/static/app.js", "x")],
        )
        with _patch_client(_mock_response(404, "Not Found")):
            findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert findings == []

    @pytest.mark.asyncio
    async def test_fetch_exception_handled(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            js_assets=[("https://example.com/static/app.js", "x")],
        )
        client_instance = AsyncMock()
        client_instance.get = AsyncMock(side_effect=Exception("boom"))
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=client_instance)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "isitsecure.engine.scanners.source_map_scanner.RateLimitedClient",
            return_value=mock_ctx,
        ):
            findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert findings == []
