"""Tests for MixedContentScanner."""

from __future__ import annotations

import pytest

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.scanners.mixed_content_scanner import MixedContentScanner

from tests.engine.scanners._snapshot_helpers import make_snapshot


class TestMixedContentScanner:
    def setup_method(self) -> None:
        self.scanner = MixedContentScanner()

    def test_scan_categories(self) -> None:
        assert self.scanner.scan_categories == [FindingCategory.MIXED_CONTENT]

    @pytest.mark.asyncio
    async def test_no_snapshot_returns_empty(self) -> None:
        assert await self.scanner.scan(endpoints=[], snapshot=None) == []

    @pytest.mark.asyncio
    async def test_http_page_skipped(self) -> None:
        snapshot = make_snapshot(
            url="http://example.com",
            html_content='<script src="http://cdn.com/a.js"></script>',
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert findings == []

    @pytest.mark.asyncio
    async def test_active_script_medium(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            html_content='<script src="http://cdn.evil.com/tracker.js"></script>',
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.MEDIUM
        assert findings[0].category == FindingCategory.MIXED_CONTENT
        assert "http://cdn.evil.com/tracker.js" in findings[0].evidence

    @pytest.mark.asyncio
    async def test_active_link_medium(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            html_content='<link rel="stylesheet" href="http://cdn.com/s.css">',
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_passive_img_low(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            html_content='<img src="http://cdn.com/logo.png">',
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.LOW

    @pytest.mark.asyncio
    async def test_https_resources_clean(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            html_content=(
                '<script src="https://cdn.com/a.js"></script>'
                '<img src="https://cdn.com/logo.png">'
                '<link rel="stylesheet" href="/local.css">'
            ),
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert findings == []

    @pytest.mark.asyncio
    async def test_detects_http_in_first_party_js(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            html_content="<html></html>",
            js_assets=[
                ("https://example.com/app.js", "el.innerHTML = \"<script src='http://a.com/b.js'>\"")
            ],
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert any("http://a.com/b.js" in f.evidence for f in findings)

    @pytest.mark.asyncio
    async def test_dedup_same_resource(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            html_content=(
                '<script src="http://cdn.com/a.js"></script>'
                '<script src="http://cdn.com/a.js"></script>'
            ),
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert len(findings) == 1
