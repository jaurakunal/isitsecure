"""Tests for SecurityHeadersScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from isitsecure.engine.constants import SecurityHeadersScannerConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.scanners.security_headers_scanner import (
    SecurityHeadersScanner,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# --- Helpers ---


def _make_endpoint(
    url: str = "https://example.com",
    method: EndpointMethod = EndpointMethod.GET,
) -> DiscoveredEndpoint:
    """Create a DiscoveredEndpoint for testing."""
    return DiscoveredEndpoint(url=url, method=method)


def _mock_response(
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> MagicMock:
    """Create a mock HTTP response with configurable headers."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.text = "OK"
    return resp


# Headers that represent a fully-secured server response.
_ALL_SECURE_HEADERS: dict[str, str] = {
    SecurityHeadersScannerConfig.HEADER_HSTS: "max-age=31536000; includeSubDomains",
    SecurityHeadersScannerConfig.HEADER_CONTENT_TYPE_OPTIONS: "nosniff",
    SecurityHeadersScannerConfig.HEADER_FRAME_OPTIONS: "DENY",
    SecurityHeadersScannerConfig.HEADER_CSP: "default-src 'self'; frame-ancestors 'none'",
    SecurityHeadersScannerConfig.HEADER_PERMISSIONS_POLICY: "camera=(), microphone=()",
    SecurityHeadersScannerConfig.HEADER_REFERRER_POLICY: "strict-origin-when-cross-origin",
}


class TestSecurityHeadersScanner:
    """Tests for the SecurityHeadersScanner."""

    def setup_method(self) -> None:
        self.scanner = SecurityHeadersScanner()

    # --- Basic Properties ---

    def test_scanner_name(self) -> None:
        assert self.scanner.scanner_name == SecurityHeadersScannerConfig.SCANNER_NAME

    def test_scan_categories(self) -> None:
        assert FindingCategory.MISSING_HEADERS in self.scanner.scan_categories
        assert FindingCategory.INFO_DISCLOSURE in self.scanner.scan_categories

    # --- Missing HSTS ---

    @pytest.mark.asyncio
    async def test_detects_missing_hsts(self) -> None:
        """Response without HSTS header -> finding."""
        endpoint = _make_endpoint()
        headers = {**_ALL_SECURE_HEADERS}
        del headers[SecurityHeadersScannerConfig.HEADER_HSTS]
        mock_resp = _mock_response(headers=headers)

        with patch(
            "isitsecure.engine.scanners.security_headers_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        hsts_findings = [
            f for f in findings
            if f.title == SecurityHeadersScannerConfig.TITLE_MISSING_HSTS
        ]
        assert len(hsts_findings) == 1
        assert hsts_findings[0].severity == SecurityHeadersScannerConfig.SEVERITY_MISSING_HSTS
        assert hsts_findings[0].category == FindingCategory.MISSING_HEADERS
        assert hsts_findings[0].source == FindingSource.DAST_URL

    # --- Missing X-Content-Type-Options ---

    @pytest.mark.asyncio
    async def test_detects_missing_content_type_options(self) -> None:
        """Response without X-Content-Type-Options -> finding."""
        endpoint = _make_endpoint()
        headers = {**_ALL_SECURE_HEADERS}
        del headers[SecurityHeadersScannerConfig.HEADER_CONTENT_TYPE_OPTIONS]
        mock_resp = _mock_response(headers=headers)

        with patch(
            "isitsecure.engine.scanners.security_headers_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        xcto_findings = [
            f for f in findings
            if f.title == SecurityHeadersScannerConfig.TITLE_MISSING_CONTENT_TYPE_OPTIONS
        ]
        assert len(xcto_findings) >= 1
        assert xcto_findings[0].severity == SecurityHeadersScannerConfig.SEVERITY_MISSING_CONTENT_TYPE_OPTIONS

    # --- Missing Clickjacking Protection ---

    @pytest.mark.asyncio
    async def test_detects_missing_frame_protection(self) -> None:
        """Response without X-Frame-Options AND without CSP frame-ancestors -> finding."""
        endpoint = _make_endpoint()
        headers = {
            SecurityHeadersScannerConfig.HEADER_HSTS: "max-age=31536000",
            SecurityHeadersScannerConfig.HEADER_CONTENT_TYPE_OPTIONS: "nosniff",
            SecurityHeadersScannerConfig.HEADER_PERMISSIONS_POLICY: "camera=()",
            SecurityHeadersScannerConfig.HEADER_REFERRER_POLICY: "no-referrer",
            # Explicitly NO X-Frame-Options and NO CSP with frame-ancestors
        }
        mock_resp = _mock_response(headers=headers)

        with patch(
            "isitsecure.engine.scanners.security_headers_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        frame_findings = [
            f for f in findings
            if f.title == SecurityHeadersScannerConfig.TITLE_MISSING_FRAME_PROTECTION
        ]
        assert len(frame_findings) == 1
        assert frame_findings[0].severity == SecurityHeadersScannerConfig.SEVERITY_MISSING_FRAME_PROTECTION

    @pytest.mark.asyncio
    async def test_no_finding_when_csp_has_frame_ancestors(self) -> None:
        """CSP with frame-ancestors but no X-Frame-Options -> no clickjacking finding."""
        endpoint = _make_endpoint()
        headers = {
            SecurityHeadersScannerConfig.HEADER_HSTS: "max-age=31536000",
            SecurityHeadersScannerConfig.HEADER_CONTENT_TYPE_OPTIONS: "nosniff",
            SecurityHeadersScannerConfig.HEADER_CSP: "default-src 'self'; frame-ancestors 'none'",
            SecurityHeadersScannerConfig.HEADER_PERMISSIONS_POLICY: "camera=()",
            SecurityHeadersScannerConfig.HEADER_REFERRER_POLICY: "no-referrer",
            # No X-Frame-Options, but CSP frame-ancestors is set
        }
        mock_resp = _mock_response(headers=headers)

        with patch(
            "isitsecure.engine.scanners.security_headers_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        frame_findings = [
            f for f in findings
            if f.title == SecurityHeadersScannerConfig.TITLE_MISSING_FRAME_PROTECTION
        ]
        assert len(frame_findings) == 0

    # --- Server Version Disclosure ---

    @pytest.mark.asyncio
    async def test_detects_server_version_disclosure(self) -> None:
        """Server header with version info -> finding."""
        endpoint = _make_endpoint()
        headers = {
            **_ALL_SECURE_HEADERS,
            SecurityHeadersScannerConfig.HEADER_SERVER: "nginx/1.19.0",
        }
        mock_resp = _mock_response(headers=headers)

        with patch(
            "isitsecure.engine.scanners.security_headers_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        server_findings = [
            f for f in findings
            if f.title == SecurityHeadersScannerConfig.TITLE_SERVER_VERSION_DISCLOSURE
        ]
        assert len(server_findings) == 1
        assert server_findings[0].severity == SecurityHeadersScannerConfig.SEVERITY_SERVER_VERSION_DISCLOSURE
        assert server_findings[0].category == FindingCategory.INFO_DISCLOSURE
        assert "nginx/1.19.0" in server_findings[0].evidence

    @pytest.mark.asyncio
    async def test_no_finding_for_server_without_version(self) -> None:
        """Server header without version (e.g., 'nginx') -> no finding."""
        endpoint = _make_endpoint()
        headers = {
            **_ALL_SECURE_HEADERS,
            SecurityHeadersScannerConfig.HEADER_SERVER: "nginx",
        }
        mock_resp = _mock_response(headers=headers)

        with patch(
            "isitsecure.engine.scanners.security_headers_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        server_findings = [
            f for f in findings
            if f.title == SecurityHeadersScannerConfig.TITLE_SERVER_VERSION_DISCLOSURE
        ]
        assert len(server_findings) == 0

    # --- All Headers Present ---

    @pytest.mark.asyncio
    async def test_all_headers_present_zero_findings(self) -> None:
        """All security headers present and correctly configured -> 0 findings."""
        endpoint = _make_endpoint()
        mock_resp = _mock_response(headers=_ALL_SECURE_HEADERS)

        with patch(
            "isitsecure.engine.scanners.security_headers_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        assert len(findings) == 0

    # --- Deduplication ---

    @pytest.mark.asyncio
    async def test_deduplication_same_missing_header_on_multiple_endpoints(self) -> None:
        """Same missing header on all tested endpoints -> 1 finding (server-wide)."""
        endpoints = [
            _make_endpoint(url="https://example.com/"),
            _make_endpoint(url="https://example.com/api/v1/users"),
            _make_endpoint(url="https://example.com/api/v1/items"),
        ]
        # All responses missing HSTS, everything else present
        headers = {**_ALL_SECURE_HEADERS}
        del headers[SecurityHeadersScannerConfig.HEADER_HSTS]
        mock_resp = _mock_response(headers=headers)

        with patch(
            "isitsecure.engine.scanners.security_headers_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=endpoints)

        hsts_findings = [
            f for f in findings
            if f.title == SecurityHeadersScannerConfig.TITLE_MISSING_HSTS
        ]
        assert len(hsts_findings) == 1
        assert "server-wide" in hsts_findings[0].technical_detail

    # --- Empty Endpoints ---

    @pytest.mark.asyncio
    async def test_empty_endpoints_zero_findings(self) -> None:
        """No endpoints -> 0 findings, no crash."""
        findings = await self.scanner.scan(endpoints=[])
        assert findings == []

    # --- Request Exception Handling ---

    @pytest.mark.asyncio
    async def test_handles_request_exception(self) -> None:
        """Scanner should handle HTTP exceptions gracefully."""
        endpoint = _make_endpoint()

        with patch(
            "isitsecure.engine.scanners.security_headers_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(
                side_effect=Exception("Connection refused")
            )
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        assert len(findings) == 0

    # --- X-Powered-By Disclosure ---

    @pytest.mark.asyncio
    async def test_detects_x_powered_by(self) -> None:
        """X-Powered-By header present -> finding."""
        endpoint = _make_endpoint()
        headers = {
            **_ALL_SECURE_HEADERS,
            SecurityHeadersScannerConfig.HEADER_X_POWERED_BY: "Express",
        }
        mock_resp = _mock_response(headers=headers)

        with patch(
            "isitsecure.engine.scanners.security_headers_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        powered_findings = [
            f for f in findings
            if f.title == SecurityHeadersScannerConfig.TITLE_X_POWERED_BY_PRESENT
        ]
        assert len(powered_findings) == 1
        assert powered_findings[0].category == FindingCategory.INFO_DISCLOSURE
        assert "Express" in powered_findings[0].evidence
