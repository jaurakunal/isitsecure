"""Tests for RateLimitScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from isitsecure.engine.constants import RateLimitConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.scanners.rate_limit_scanner import RateLimitScanner
from isitsecure.engine.scanners.protocols import DASTScannerProtocol
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# --- Fixtures ---


def _make_endpoint(
    url: str = "https://example.com/api/login",
    method: EndpointMethod = EndpointMethod.POST,
) -> DiscoveredEndpoint:
    """Create a DiscoveredEndpoint for testing."""
    return DiscoveredEndpoint(url=url, method=method)


def _make_response(status_code: int = 200) -> MagicMock:
    """Create a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = "OK"
    return resp


class TestRateLimitScannerProtocolCompliance:
    """Protocol compliance tests for RateLimitScanner."""

    def test_implements_dast_protocol(self) -> None:
        """RateLimitScanner should implement DASTScannerProtocol."""
        scanner = RateLimitScanner()
        assert isinstance(scanner, DASTScannerProtocol)

    def test_has_scanner_name(self) -> None:
        scanner = RateLimitScanner()
        assert isinstance(scanner.scanner_name, str)
        assert len(scanner.scanner_name) > 0

    def test_has_scan_method(self) -> None:
        scanner = RateLimitScanner()
        assert hasattr(scanner, "scan")
        assert callable(scanner.scan)


class TestRateLimitScanner:
    """Tests for the RateLimitScanner."""

    def setup_method(self) -> None:
        self.scanner = RateLimitScanner()

    # --- Basic Properties ---

    def test_scanner_name(self) -> None:
        assert self.scanner.scanner_name == RateLimitConfig.SCANNER_NAME

    def test_scan_categories(self) -> None:
        assert FindingCategory.AUTH_WEAKNESS in self.scanner.scan_categories

    # --- Critical Endpoint Filtering ---

    def test_identifies_critical_endpoints(self) -> None:
        """Endpoints with login, signup, etc. should be flagged as critical."""
        endpoints = [
            _make_endpoint(url="https://example.com/api/login"),
            _make_endpoint(url="https://example.com/api/signup"),
            _make_endpoint(url="https://example.com/api/forgot-password"),
            _make_endpoint(url="https://example.com/api/products"),
        ]
        critical = self.scanner._filter_critical_endpoints(endpoints)

        assert len(critical) == 3
        assert all(
            any(
                indicator in ep.url.lower()
                for indicator in RateLimitConfig.CRITICAL_ENDPOINT_INDICATORS
            )
            for ep in critical
        )

    # --- Rate Limit Detection ---

    @pytest.mark.asyncio
    async def test_detects_no_rate_limit(self) -> None:
        """All 200 responses -> finding (no rate limiting)."""
        endpoint = _make_endpoint()

        mock_resp = _make_response(status_code=200)

        with patch(
            "isitsecure.engine.scanners.rate_limit_scanner.httpx.AsyncClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        assert len(findings) == 1
        assert findings[0].title == RateLimitConfig.TITLE_NO_RATE_LIMIT
        assert findings[0].severity == SeverityLevel.HIGH
        assert findings[0].source == FindingSource.DAST_URL
        assert findings[0].category == FindingCategory.AUTH_WEAKNESS
        assert findings[0].confidence == RateLimitConfig.CONFIDENCE_NO_RATE_LIMIT

    @pytest.mark.asyncio
    async def test_finding_when_429_returned(self) -> None:
        """429 response -> rate limiting detected, threshold finding reported."""
        endpoint = _make_endpoint()

        mock_resp = _make_response(status_code=429)

        with patch(
            "isitsecure.engine.scanners.rate_limit_scanner.httpx.AsyncClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        # Scanner now reports the measured threshold even when 429 is returned
        threshold_findings = [
            f for f in findings
            if f.title == RateLimitConfig.TITLE_RATE_LIMIT_THRESHOLD
        ]
        assert len(threshold_findings) >= 1
        # Should NOT report "no rate limit"
        no_limit_findings = [
            f for f in findings
            if f.title == RateLimitConfig.TITLE_NO_RATE_LIMIT
        ]
        assert len(no_limit_findings) == 0

    @pytest.mark.asyncio
    async def test_skips_non_critical_endpoints(self) -> None:
        """Non-critical endpoints should not be tested."""
        endpoints = [
            _make_endpoint(url="https://example.com/api/products"),
            _make_endpoint(url="https://example.com/api/listings"),
        ]

        with patch(
            "isitsecure.engine.scanners.rate_limit_scanner.httpx.AsyncClient"
        ) as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=endpoints)

        assert len(findings) == 0
        client_instance.request.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_connection_errors(self) -> None:
        """Scanner should handle HTTP exceptions gracefully and still report."""
        endpoint = _make_endpoint()

        with patch(
            "isitsecure.engine.scanners.rate_limit_scanner.httpx.AsyncClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        # Connection errors are handled gracefully without crashing;
        # the scanner may still report findings based on the failed threshold measurement
        assert all(isinstance(f, DeepFinding) for f in findings)

    @pytest.mark.asyncio
    async def test_empty_endpoints(self) -> None:
        """Empty endpoints list -> 0 findings."""
        findings = await self.scanner.scan(endpoints=[])
        assert findings == []

    @pytest.mark.asyncio
    async def test_mixed_responses_with_429(self) -> None:
        """If at least one 429 is returned, threshold is reported (not 'no rate limit')."""
        endpoint = _make_endpoint()

        responses_200 = [_make_response(200) for _ in range(19)]
        response_429 = _make_response(429)
        all_responses = responses_200 + [response_429]

        call_count = 0

        async def side_effect(*args, **kwargs):
            nonlocal call_count
            idx = call_count % len(all_responses)
            call_count += 1
            return all_responses[idx]

        with patch(
            "isitsecure.engine.scanners.rate_limit_scanner.httpx.AsyncClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(side_effect=side_effect)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        # Should NOT report "no rate limit" since 429 was eventually returned
        no_limit_findings = [
            f for f in findings
            if f.title == RateLimitConfig.TITLE_NO_RATE_LIMIT
        ]
        assert len(no_limit_findings) == 0
