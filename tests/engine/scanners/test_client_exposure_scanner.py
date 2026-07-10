"""Tests for ClientExposureScanner."""

from __future__ import annotations

import pytest

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.scanners.client_exposure_scanner import (
    ClientExposureScanner,
)

from tests.engine.scanners._snapshot_helpers import make_jwt, make_snapshot


class TestClientExposureScanner:
    def setup_method(self) -> None:
        self.scanner = ClientExposureScanner()

    def test_scan_categories(self) -> None:
        assert self.scanner.scan_categories == [FindingCategory.CLIENT_EXPOSURE]

    @pytest.mark.asyncio
    async def test_no_snapshot_returns_empty(self) -> None:
        assert await self.scanner.scan(endpoints=[], snapshot=None) == []

    @pytest.mark.asyncio
    async def test_empty_js_returns_empty(self) -> None:
        snapshot = make_snapshot(url="https://example.com", js_assets=[])
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert findings == []

    @pytest.mark.asyncio
    async def test_service_role_jwt_critical(self) -> None:
        token = make_jwt("service_role")
        snapshot = make_snapshot(
            url="https://example.com",
            js_assets=[("https://example.com/app.js", f'const k = "{token}";')],
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        sr = [f for f in findings if "service_role" in f.title]
        assert len(sr) == 1
        assert sr[0].severity == SeverityLevel.CRITICAL
        assert sr[0].category == FindingCategory.CLIENT_EXPOSURE
        # Token must be redacted, not leaked verbatim.
        assert token not in sr[0].technical_detail

    @pytest.mark.asyncio
    async def test_anon_jwt_ignored(self) -> None:
        token = make_jwt("anon")
        snapshot = make_snapshot(
            url="https://example.com",
            js_assets=[("https://example.com/app.js", f'const k = "{token}";')],
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert [f for f in findings if "service_role" in f.title] == []

    @pytest.mark.asyncio
    async def test_internal_url_low(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            js_assets=[
                ("https://example.com/app.js", 'const api = "http://localhost:3000/api";')
            ],
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        internal = [f for f in findings if "Internal" in f.title]
        assert len(internal) == 1
        assert internal[0].severity == SeverityLevel.LOW

    @pytest.mark.asyncio
    async def test_staging_url_detected(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            js_assets=[
                ("https://example.com/app.js", 'x = "https://staging-api.acme.com/v1";')
            ],
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert [f for f in findings if "Internal" in f.title]

    @pytest.mark.asyncio
    async def test_unreplaced_process_env_low(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            js_assets=[
                ("https://example.com/app.js", "const s = process.env.SECRET_API_KEY;")
            ],
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        env = [f for f in findings if "environment variable" in f.title]
        assert len(env) == 1
        assert env[0].severity == SeverityLevel.LOW
        assert "SECRET_API_KEY" in env[0].evidence

    @pytest.mark.asyncio
    async def test_public_env_prefix_ignored(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            js_assets=[
                (
                    "https://example.com/app.js",
                    "const a = process.env.NEXT_PUBLIC_URL; "
                    "const b = import.meta.env.VITE_KEY;",
                )
            ],
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert [f for f in findings if "environment variable" in f.title] == []

    @pytest.mark.asyncio
    async def test_clean_bundle_no_findings(self) -> None:
        snapshot = make_snapshot(
            url="https://example.com",
            js_assets=[
                (
                    "https://example.com/app.js",
                    'const api = "https://api.example.com"; '
                    "const pub = process.env.NEXT_PUBLIC_FOO;",
                )
            ],
        )
        findings = await self.scanner.scan(endpoints=[], snapshot=snapshot)
        assert findings == []
