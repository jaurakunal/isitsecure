"""Tests for the file upload vulnerability scanner."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.constants import FileUploadConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.scanners.file_upload_scanner import FileUploadScanner
from isitsecure.engine.scanners.protocols import DASTScannerProtocol
from isitsecure.engine.enums import FindingCategory, SeverityLevel


def _make_endpoint(
    url: str = "https://example.com/api/upload",
    method: EndpointMethod = EndpointMethod.POST,
) -> DiscoveredEndpoint:
    """Create a test endpoint."""
    return DiscoveredEndpoint(url=url, method=method)


def _make_response(body: str = "OK", status_code: int = 200) -> httpx.Response:
    """Create a mock httpx.Response."""
    return httpx.Response(
        status_code=status_code,
        headers={"content-type": "application/json"},
        text=body,
    )


class TestFileUploadScannerProtocol:
    """Protocol compliance tests."""

    def test_implements_dast_protocol(self) -> None:
        """FileUploadScanner should satisfy DASTScannerProtocol."""
        scanner = FileUploadScanner()
        assert isinstance(scanner, DASTScannerProtocol)

    def test_scanner_name(self) -> None:
        """scanner_name should match FileUploadConfig."""
        scanner = FileUploadScanner()
        assert scanner.scanner_name == FileUploadConfig.SCANNER_NAME

    def test_scan_categories(self) -> None:
        """scan_categories should contain INJECTION_RISK."""
        scanner = FileUploadScanner()
        assert scanner.scan_categories == [FindingCategory.INJECTION_RISK]


class TestDangerousFileTypes:
    """Tests for dangerous file type detection."""

    @pytest.mark.asyncio
    async def test_detects_html_upload_accepted(self) -> None:
        """Accepting .html upload should produce a finding."""
        scanner = FileUploadScanner()
        endpoint = _make_endpoint()

        async def mock_post(url: str, **kwargs: object) -> httpx.Response:
            return _make_response('{"success":true}', status_code=200)

        with patch(
            "isitsecure.engine.scanners.file_upload_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        type_findings = [
            f for f in findings if f.title == FileUploadConfig.TITLE_UNRESTRICTED_TYPE
        ]
        assert len(type_findings) >= 1
        assert type_findings[0].severity == SeverityLevel.HIGH
        assert type_findings[0].confidence == FileUploadConfig.CONFIDENCE_UNRESTRICTED
        assert type_findings[0].source == FindingSource.DAST_URL

    @pytest.mark.asyncio
    async def test_no_finding_when_upload_rejected(self) -> None:
        """400 response should not produce a type finding."""
        scanner = FileUploadScanner()
        endpoint = _make_endpoint()

        async def mock_post(url: str, **kwargs: object) -> httpx.Response:
            return _make_response("Not allowed", status_code=400)

        with patch(
            "isitsecure.engine.scanners.file_upload_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        type_findings = [
            f for f in findings if f.title == FileUploadConfig.TITLE_UNRESTRICTED_TYPE
        ]
        assert len(type_findings) == 0


class TestPathTraversal:
    """Tests for path traversal detection."""

    @pytest.mark.asyncio
    async def test_detects_path_traversal(self) -> None:
        """Accepting path traversal filename should produce a CRITICAL finding."""
        scanner = FileUploadScanner()
        endpoint = _make_endpoint()

        async def mock_post(url: str, **kwargs: object) -> httpx.Response:
            return _make_response('{"success":true}', status_code=200)

        with patch(
            "isitsecure.engine.scanners.file_upload_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        traversal_findings = [
            f for f in findings if f.title == FileUploadConfig.TITLE_PATH_TRAVERSAL
        ]
        assert len(traversal_findings) >= 1
        assert traversal_findings[0].severity == SeverityLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_path_traversal_stops_at_first_finding(self) -> None:
        """Should report only one path traversal finding per endpoint."""
        scanner = FileUploadScanner()
        endpoint = _make_endpoint()

        async def mock_post(url: str, **kwargs: object) -> httpx.Response:
            return _make_response('{"ok":true}', status_code=200)

        with patch(
            "isitsecure.engine.scanners.file_upload_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        traversal_findings = [
            f for f in findings if f.title == FileUploadConfig.TITLE_PATH_TRAVERSAL
        ]
        # At most 1 path traversal per endpoint
        assert len(traversal_findings) == 1


class TestEdgeCases:
    """Edge case and error handling tests."""

    @pytest.mark.asyncio
    async def test_no_upload_endpoints(self) -> None:
        """Non-upload endpoints should produce no findings."""
        scanner = FileUploadScanner()
        endpoint = _make_endpoint(url="https://example.com/api/users")

        findings = await scanner.scan([endpoint])
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_empty_endpoints(self) -> None:
        """Empty endpoint list should produce no findings."""
        scanner = FileUploadScanner()
        findings = await scanner.scan([])
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_handles_connection_error(self) -> None:
        """Connection error should not crash the scanner."""
        scanner = FileUploadScanner()
        endpoint = _make_endpoint()

        async def mock_post(url: str, **kwargs: object) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        with patch(
            "isitsecure.engine.scanners.file_upload_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) == 0

    def test_detect_upload_endpoints_various_paths(self) -> None:
        """Should detect upload endpoints from various path indicators."""
        scanner = FileUploadScanner()
        endpoints = [
            _make_endpoint(url="https://example.com/api/upload"),
            _make_endpoint(url="https://example.com/api/avatar"),
            _make_endpoint(url="https://example.com/api/document/import"),
            _make_endpoint(url="https://example.com/api/users"),
        ]

        detected = scanner._detect_upload_endpoints(endpoints)
        urls = [ep.url for ep in detected]
        assert "https://example.com/api/upload" in urls
        assert "https://example.com/api/avatar" in urls
        assert "https://example.com/api/users" not in urls

    @pytest.mark.asyncio
    async def test_finding_fields_are_correct(self) -> None:
        """Finding fields should match expected values."""
        scanner = FileUploadScanner()
        endpoint = _make_endpoint(url="https://target.com/upload")

        async def mock_post(url: str, **kwargs: object) -> httpx.Response:
            return _make_response('{"ok":true}', status_code=200)

        with patch(
            "isitsecure.engine.scanners.file_upload_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) >= 1
        for f in findings:
            assert f.scanner_name == FileUploadConfig.SCANNER_NAME
            assert f.endpoint_url == "https://target.com/upload"
            assert f.http_method == "POST"
