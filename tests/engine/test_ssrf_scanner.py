"""Tests for the SSRF vulnerability scanner."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.constants import SSRFConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.scanners.protocols import DASTScannerProtocol
from isitsecure.engine.scanners.ssrf_scanner import SSRFScanner
from isitsecure.engine.shared.url_utils import inject_query_param
from isitsecure.engine.enums import FindingCategory, SeverityLevel


def _make_endpoint(
    url: str = "https://example.com/api/fetch?url=https://google.com",
    method: EndpointMethod = EndpointMethod.GET,
    query_param_names: list[str] | None = None,
) -> DiscoveredEndpoint:
    """Create a test endpoint."""
    return DiscoveredEndpoint(
        url=url,
        method=method,
        query_param_names=query_param_names or [],
    )


def _make_response(
    body: str, status_code: int = 200, content_type: str = "text/html"
) -> httpx.Response:
    """Create a mock httpx.Response."""
    return httpx.Response(
        status_code=status_code,
        headers={"content-type": content_type},
        text=body,
    )


class TestSSRFScannerProtocol:
    """Protocol compliance tests."""

    def test_implements_dast_protocol(self) -> None:
        """SSRFScanner should satisfy DASTScannerProtocol."""
        scanner = SSRFScanner()
        assert isinstance(scanner, DASTScannerProtocol)

    def test_scanner_name(self) -> None:
        """scanner_name should match SSRFConfig."""
        scanner = SSRFScanner()
        assert scanner.scanner_name == SSRFConfig.SCANNER_NAME

    def test_scan_categories(self) -> None:
        """scan_categories should contain INJECTION_RISK."""
        scanner = SSRFScanner()
        assert scanner.scan_categories == [FindingCategory.INJECTION_RISK]


class TestSSRFDetection:
    """Tests for SSRF vulnerability detection."""

    @pytest.mark.asyncio
    async def test_detects_ssrf_with_aws_metadata(self) -> None:
        """Response with AWS metadata indicators should produce a finding."""
        scanner = SSRFScanner()
        endpoint = _make_endpoint()

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            if "169.254.169.254" in url or "127.0.0.1" in url or "localhost" in str(url):
                return _make_response("ami-id: i-1234567890abcdef0\ninstance-id: i-abc")
            return _make_response("OK")

        with patch(
            "isitsecure.engine.scanners.ssrf_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.title == SSRFConfig.TITLE_SSRF
        assert finding.severity == SeverityLevel.HIGH
        assert finding.confidence == SSRFConfig.CONFIDENCE_SSRF
        assert finding.source == FindingSource.DAST_URL

    @pytest.mark.asyncio
    async def test_no_finding_when_response_clean(self) -> None:
        """Clean response without indicators should produce no finding."""
        scanner = SSRFScanner()
        endpoint = _make_endpoint()

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            return _make_response("Nothing interesting here")

        with patch(
            "isitsecure.engine.scanners.ssrf_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_detects_ssrf_via_query_param_names(self) -> None:
        """Endpoint with declared URL-like query param should be tested."""
        scanner = SSRFScanner()
        endpoint = _make_endpoint(
            url="https://example.com/api/proxy",
            query_param_names=["target"],
        )

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            if "127.0.0.1" in url:
                return _make_response("<!DOCTYPE html><html>internal page</html>")
            return _make_response("OK")

        with patch(
            "isitsecure.engine.scanners.ssrf_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_no_finding_for_error_response(self) -> None:
        """4xx response should not produce a finding."""
        scanner = SSRFScanner()
        endpoint = _make_endpoint()

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            return _make_response("ami-id: fake", status_code=403)

        with patch(
            "isitsecure.engine.scanners.ssrf_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) == 0


class TestSSRFEdgeCases:
    """Edge case and error handling tests."""

    @pytest.mark.asyncio
    async def test_no_url_param_endpoints(self) -> None:
        """Endpoints without URL parameters should produce no findings."""
        scanner = SSRFScanner()
        endpoint = _make_endpoint(url="https://example.com/api/users")

        findings = await scanner.scan([endpoint])
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_empty_endpoints(self) -> None:
        """Empty endpoint list should produce no findings."""
        scanner = SSRFScanner()
        findings = await scanner.scan([])
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_handles_connection_error(self) -> None:
        """Connection error should not crash the scanner."""
        scanner = SSRFScanner()
        endpoint = _make_endpoint()

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        with patch(
            "isitsecure.engine.scanners.ssrf_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) == 0

    def test_inject_param_replaces_value(self) -> None:
        """inject_query_param should replace the param value in the URL."""
        result = inject_query_param(
            "https://example.com/api?url=https://google.com",
            "url",
            "http://127.0.0.1",
        )
        assert "url=http" in result
        assert "127.0.0.1" in result

    def test_response_indicates_ssrf_aws(self) -> None:
        """AWS metadata indicators should be detected."""
        scanner = SSRFScanner()
        assert scanner._response_indicates_ssrf("ami-id: i-12345")
        assert scanner._response_indicates_ssrf("instance-id: i-abc")

    def test_response_indicates_ssrf_gcp(self) -> None:
        """GCP metadata indicators should be detected."""
        scanner = SSRFScanner()
        assert scanner._response_indicates_ssrf("computeMetadata/v1/project")

    def test_response_indicates_ssrf_negative(self) -> None:
        """Normal responses should not be flagged."""
        scanner = SSRFScanner()
        assert not scanner._response_indicates_ssrf("Hello World")
        assert not scanner._response_indicates_ssrf('{"status":"ok"}')
