"""Tests for SRIScanner."""

from __future__ import annotations

import pytest

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.scanners.sri_scanner import SRIScanner

from tests.engine.scanners._snapshot_helpers import make_snapshot


class TestSRIScanner:
    def setup_method(self) -> None:
        self.scanner = SRIScanner()

    def test_scan_categories(self) -> None:
        assert self.scanner.scan_categories == [FindingCategory.MISSING_SRI]

    @pytest.mark.asyncio
    async def test_no_snapshot_returns_empty(self) -> None:
        assert await self.scanner.scan(endpoints=[], snapshot=None) == []

    @pytest.mark.asyncio
    async def test_external_script_without_sri_medium(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            html_content='<script src="https://cdn.jsdelivr.net/npm/lib.js"></script>',
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.MISSING_SRI
        assert findings[0].severity == SeverityLevel.MEDIUM
        assert "cdn.jsdelivr.net" in findings[0].evidence

    @pytest.mark.asyncio
    async def test_external_stylesheet_without_sri_low(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            html_content='<link rel="stylesheet" href="https://cdn.com/style.css">',
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.LOW

    @pytest.mark.asyncio
    async def test_external_script_with_sri_clean(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            html_content=(
                '<script src="https://cdn.com/lib.js" '
                'integrity="sha384-abc" crossorigin="anonymous"></script>'
            ),
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert findings == []

    @pytest.mark.asyncio
    async def test_first_party_script_ignored(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            html_content=(
                '<script src="https://example.com/app.js"></script>'
                '<script src="/local.js"></script>'
            ),
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert findings == []

    @pytest.mark.asyncio
    async def test_non_stylesheet_link_ignored(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            html_content='<link rel="preconnect" href="https://cdn.com">',
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert findings == []

    @pytest.mark.asyncio
    async def test_dedup_same_src(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            html_content=(
                '<script src="https://cdn.com/a.js"></script>'
                '<script src="https://cdn.com/a.js"></script>'
            ),
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert len(findings) == 1
