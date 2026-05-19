"""Tests for HTTPProbeScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from isitsecure.engine.constants import HTTPProbeConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.scanners.http_probe_scanner import (
    HTTPProbeScanner,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# --- Helpers ---


def _make_endpoint(
    url: str = "https://example.com/api/v1/users",
    method: EndpointMethod = EndpointMethod.GET,
) -> DiscoveredEndpoint:
    """Create a DiscoveredEndpoint for testing."""
    return DiscoveredEndpoint(url=url, method=method)


def _mock_response(
    status_code: int = 200,
    text: str = "OK",
    headers: dict[str, str] | None = None,
) -> MagicMock:
    """Create a mock HTTP response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {"content-type": "text/html"}
    return resp


class TestHTTPProbeScanner:
    """Tests for the HTTPProbeScanner."""

    def setup_method(self) -> None:
        self.scanner = HTTPProbeScanner()

    # --- Basic Properties ---

    def test_scanner_name(self) -> None:
        assert self.scanner.scanner_name == HTTPProbeConfig.SCANNER_NAME

    def test_scan_categories(self) -> None:
        assert FindingCategory.INFO_DISCLOSURE in self.scanner.scan_categories

    # --- TRACE Method Enabled ---

    @pytest.mark.asyncio
    async def test_detects_trace_method_enabled(self) -> None:
        """TRACE request echoing back -> finding."""
        endpoint = _make_endpoint()

        async def mock_request(method, url, **kwargs):
            if method == "TRACE":
                return _mock_response(
                    status_code=200,
                    text="TRACE / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc",
                )
            if method == "OPTIONS":
                return _mock_response(
                    status_code=200,
                    headers={"allow": "GET, POST, TRACE"},
                )
            return _mock_response(status_code=200)

        async def mock_get(url, **kwargs):
            return _mock_response(status_code=404, text="Not Found")

        with patch(
            "isitsecure.engine.scanners.http_probe_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = mock_request
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        trace_findings = [
            f for f in findings
            if "TRACE" in f.title
        ]
        assert len(trace_findings) >= 1
        assert trace_findings[0].severity == SeverityLevel.HIGH
        assert trace_findings[0].source == FindingSource.DAST_URL

    # --- Host Header Injection ---

    @pytest.mark.asyncio
    async def test_detects_host_header_reflected(self) -> None:
        """Host header reflected in response body -> finding."""
        endpoint = _make_endpoint()
        evil_host = HTTPProbeConfig.FORGED_HOST

        async def mock_get(url, **kwargs):
            headers = kwargs.get("headers", {})
            for header_name in HTTPProbeConfig.HOST_HEADERS:
                if header_name in headers:
                    host = headers[header_name]
                    return _mock_response(
                        status_code=200,
                        text=f'<html><body>Welcome to {host}</body></html>',
                    )
            return _mock_response(status_code=200, text="<html>Normal</html>")

        async def mock_request(method, url, **kwargs):
            if method == "OPTIONS":
                return _mock_response(status_code=405, headers={})
            if method == "TRACE":
                return _mock_response(status_code=405)
            return _mock_response(status_code=200)

        with patch(
            "isitsecure.engine.scanners.http_probe_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            client_instance.request = mock_request
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        host_findings = [
            f for f in findings
            if "Host header injection" in f.title
        ]
        assert len(host_findings) >= 1
        assert host_findings[0].severity == SeverityLevel.HIGH
        assert host_findings[0].confidence == HTTPProbeConfig.CONFIDENCE_HOST_INJECTION

    # --- Verbose Error Page ---

    @pytest.mark.asyncio
    async def test_detects_verbose_error_page_with_stack_trace(self) -> None:
        """Error page with stack trace -> finding."""
        endpoint = _make_endpoint()

        async def mock_get(url, **kwargs):
            if "nonexistent" in url or "%00" in url:
                return _mock_response(
                    status_code=500,
                    text=(
                        "<html><body>"
                        "<h1>Internal Server Error</h1>"
                        "<pre>Traceback (most recent call last):\n"
                        '  File "/var/www/app/main.py", line 42, in handler\n'
                        "    result = process(data)\n"
                        "TypeError: expected str but got NoneType</pre>"
                        "</body></html>"
                    ),
                )
            return _mock_response(status_code=200)

        async def mock_request(method, url, **kwargs):
            if method == "OPTIONS":
                return _mock_response(status_code=405, headers={})
            if method == "TRACE":
                return _mock_response(status_code=405)
            return _mock_response(status_code=200)

        with patch(
            "isitsecure.engine.scanners.http_probe_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            client_instance.request = mock_request
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        error_findings = [
            f for f in findings
            if "Verbose error" in f.title or "error page" in f.title.lower()
        ]
        assert len(error_findings) >= 1
        assert error_findings[0].severity == SeverityLevel.MEDIUM
        assert error_findings[0].confidence == HTTPProbeConfig.CONFIDENCE_VERBOSE_ERROR

    # --- .git/HEAD Exposed ---

    @pytest.mark.asyncio
    async def test_detects_git_head_exposed(self) -> None:
        """/.git/HEAD returning ref: content -> finding."""
        endpoint = _make_endpoint()

        async def mock_get(url, **kwargs):
            if "/.git/HEAD" in url:
                return _mock_response(
                    status_code=200,
                    text="ref: refs/heads/main\n",
                )
            return _mock_response(status_code=404, text="Not Found")

        async def mock_request(method, url, **kwargs):
            if method == "OPTIONS":
                return _mock_response(status_code=405, headers={})
            if method == "TRACE":
                return _mock_response(status_code=405)
            return _mock_response(status_code=200)

        with patch(
            "isitsecure.engine.scanners.http_probe_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            client_instance.request = mock_request
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        git_findings = [
            f for f in findings
            if ".git" in f.title.lower() or "sensitive file" in f.title.lower()
        ]
        assert len(git_findings) >= 1
        assert git_findings[0].severity == SeverityLevel.HIGH
        assert git_findings[0].confidence == HTTPProbeConfig.CONFIDENCE_SENSITIVE_FILE

    # --- Directory Listing Enabled ---

    @pytest.mark.asyncio
    async def test_detects_directory_listing(self) -> None:
        """Directory listing page returned -> finding."""
        endpoint = _make_endpoint()

        async def mock_get(url, **kwargs):
            if url.endswith("/api/") or url.endswith("/static/"):
                return _mock_response(
                    status_code=200,
                    text=(
                        "<html><head><title>Index of /api/</title></head>"
                        "<body><h1>Index of /api/</h1>"
                        '<a href="../">Parent Directory</a>'
                        '<a href="users/">users/</a>'
                        "</body></html>"
                    ),
                )
            return _mock_response(status_code=404, text="Not Found")

        async def mock_request(method, url, **kwargs):
            if method == "OPTIONS":
                return _mock_response(status_code=405, headers={})
            if method == "TRACE":
                return _mock_response(status_code=405)
            return _mock_response(status_code=200)

        with patch(
            "isitsecure.engine.scanners.http_probe_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            client_instance.request = mock_request
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        listing_findings = [
            f for f in findings
            if "Directory listing" in f.title or "directory listing" in f.title.lower()
        ]
        assert len(listing_findings) >= 1
        assert listing_findings[0].severity == SeverityLevel.MEDIUM
        assert listing_findings[0].confidence == HTTPProbeConfig.CONFIDENCE_DIRECTORY_LISTING

    # --- Clean Server (No Issues) ---

    @pytest.mark.asyncio
    async def test_clean_server_zero_findings(self) -> None:
        """Server with no issues -> 0 findings."""
        endpoint = _make_endpoint()

        async def mock_get(url, **kwargs):
            # Sensitive files return 404
            return _mock_response(status_code=404, text="Not Found")

        async def mock_request(method, url, **kwargs):
            if method == "OPTIONS":
                return _mock_response(
                    status_code=200,
                    headers={"allow": "GET, POST"},  # No dangerous methods
                )
            if method == "TRACE":
                return _mock_response(status_code=405)  # TRACE rejected
            return _mock_response(status_code=200)

        with patch(
            "isitsecure.engine.scanners.http_probe_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            client_instance.request = mock_request
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        assert len(findings) == 0

    # --- Empty Endpoints ---

    @pytest.mark.asyncio
    async def test_empty_endpoints_zero_findings(self) -> None:
        """No endpoints -> 0 findings, no crash."""
        findings = await self.scanner.scan(endpoints=[])
        assert findings == []

    # --- Exception Handling ---

    @pytest.mark.asyncio
    async def test_handles_request_exception(self) -> None:
        """Scanner should handle HTTP exceptions gracefully."""
        endpoint = _make_endpoint()

        with patch(
            "isitsecure.engine.scanners.http_probe_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(
                side_effect=Exception("Connection refused")
            )
            client_instance.get = AsyncMock(
                side_effect=Exception("Connection refused")
            )
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        assert len(findings) == 0

    # --- Helper method tests ---

    def test_extract_base_url(self) -> None:
        """Should extract scheme + host from first endpoint."""
        endpoints = [
            _make_endpoint(url="https://example.com/api/v1/users"),
        ]
        base_url = HTTPProbeScanner._extract_base_url(endpoints)
        assert base_url == "https://example.com"

    def test_extract_base_url_empty(self) -> None:
        """Empty endpoints -> empty string."""
        assert HTTPProbeScanner._extract_base_url([]) == ""
