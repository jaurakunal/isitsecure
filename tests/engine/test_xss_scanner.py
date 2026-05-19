"""Tests for the active XSS scanner."""

import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from isitsecure.engine.constants import XSSConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.scanners.protocols import DASTScannerProtocol
from isitsecure.engine.scanners.xss_scanner import XSSScanner
from isitsecure.engine.shared.url_utils import inject_query_param
from isitsecure.engine.enums import AssetType, FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import (
    CodebaseSnapshot,
    HTTPHeadersData,
    PageAsset,
)


def _make_endpoint(
    url: str = "https://example.com/search",
    method: EndpointMethod = EndpointMethod.GET,
) -> DiscoveredEndpoint:
    """Create a test endpoint."""
    return DiscoveredEndpoint(url=url, method=method)


def _make_snapshot(
    url: str = "https://example.com",
    js_content: str = "",
) -> CodebaseSnapshot:
    """Create a test snapshot with optional JS content."""
    assets = []
    if js_content:
        assets.append(
            PageAsset(
                url=f"{url}/bundle.js",
                asset_type=AssetType.JAVASCRIPT,
                content=js_content,
                size_bytes=len(js_content),
                is_external=False,
            )
        )
    return CodebaseSnapshot(
        url=url,
        html_content="<html></html>",
        assets=assets,
        headers=HTTPHeadersData(raw_headers={}, status_code=200),
    )


def _make_html_response(
    body: str, status_code: int = 200, content_type: str = "text/html; charset=utf-8",
    url: str = "https://example.com",
) -> httpx.Response:
    """Create a mock httpx.Response with HTML content."""
    resp = httpx.Response(
        status_code=status_code,
        headers={"content-type": content_type},
        text=body,
        request=httpx.Request("GET", url),
    )
    resp.elapsed = datetime.timedelta(milliseconds=100)
    return resp


def _make_json_response(body: str, status_code: int = 200) -> httpx.Response:
    """Create a mock httpx.Response with JSON content."""
    resp = httpx.Response(
        status_code=status_code,
        headers={"content-type": "application/json"},
        text=body,
        request=httpx.Request("GET", "https://example.com"),
    )
    resp.elapsed = datetime.timedelta(milliseconds=100)
    return resp


class TestXSSScannerProtocol:
    """Protocol compliance tests."""

    def test_implements_dast_protocol(self) -> None:
        """XSSScanner should satisfy DASTScannerProtocol."""
        scanner = XSSScanner()
        assert isinstance(scanner, DASTScannerProtocol)

    def test_scanner_name(self) -> None:
        """scanner_name should match XSSConfig."""
        scanner = XSSScanner()
        assert scanner.scanner_name == XSSConfig.SCANNER_NAME

    def test_scan_categories(self) -> None:
        """scan_categories should contain INJECTION_RISK."""
        scanner = XSSScanner()
        assert scanner.scan_categories == [FindingCategory.INJECTION_RISK]


class TestReflectedXSS:
    """Tests for reflected XSS detection."""

    @pytest.mark.asyncio
    async def test_detects_reflected_xss_unescaped(self) -> None:
        """Canary with < > reflected unescaped should produce HIGH finding."""
        scanner = XSSScanner()
        endpoint = _make_endpoint(url="https://example.com/search?q=test")

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            # Extract the canary from the URL and reflect it unescaped
            from urllib.parse import parse_qs, urlparse

            params = parse_qs(urlparse(url).query)
            injected = params.get("q", [""])[0]
            body = f"<html><body>Results for: {injected}</body></html>"
            return _make_html_response(body)

        with patch(
            "isitsecure.engine.scanners.xss_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.severity == SeverityLevel.HIGH
        assert finding.category == FindingCategory.INJECTION_RISK
        assert finding.confidence == XSSConfig.CONFIDENCE_REFLECTED_CONFIRMED
        assert finding.scanner_name == XSSConfig.SCANNER_NAME
        assert finding.source == FindingSource.DAST_URL

    @pytest.mark.asyncio
    async def test_detects_partial_reflection(self) -> None:
        """Canary text reflected but HTML chars encoded should produce MEDIUM."""
        scanner = XSSScanner()
        endpoint = _make_endpoint(url="https://example.com/search?q=test")

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            from urllib.parse import parse_qs, urlparse

            params = parse_qs(urlparse(url).query)
            injected = params.get("q", [""])[0]
            # Encode < and > but keep the canary text
            escaped = injected.replace("<", "&lt;").replace(">", "&gt;")
            body = f"<html><body>Results for: {escaped}</body></html>"
            return _make_html_response(body)

        with patch(
            "isitsecure.engine.scanners.xss_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.severity == SeverityLevel.LOW
        assert finding.confidence == XSSConfig.CONFIDENCE_REFLECTED_POSSIBLE

    @pytest.mark.asyncio
    async def test_no_finding_when_canary_not_reflected(self) -> None:
        """Canary not in response should produce no finding."""
        scanner = XSSScanner()
        endpoint = _make_endpoint(url="https://example.com/search?q=test")

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            body = "<html><body>No results found</body></html>"
            return _make_html_response(body)

        with patch(
            "isitsecure.engine.scanners.xss_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_no_finding_for_json_response(self) -> None:
        """JSON response should not trigger reflected XSS finding."""
        scanner = XSSScanner()
        endpoint = _make_endpoint(url="https://example.com/api/search?q=test")

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            from urllib.parse import parse_qs, urlparse

            params = parse_qs(urlparse(url).query)
            injected = params.get("q", [""])[0]
            body = f'{{"results": [], "query": "{injected}"}}'
            return _make_json_response(body)

        with patch(
            "isitsecure.engine.scanners.xss_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_no_finding_for_error_response(self) -> None:
        """400+ response should be skipped."""
        scanner = XSSScanner()
        endpoint = _make_endpoint(url="https://example.com/search?q=test")

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            return _make_html_response("<html>Error</html>", status_code=404)

        with patch(
            "isitsecure.engine.scanners.xss_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_respects_max_endpoints(self) -> None:
        """Should not test more than MAX_ENDPOINTS_TO_TEST endpoints."""
        scanner = XSSScanner()
        # Create more endpoints than the limit
        endpoints = [
            _make_endpoint(url=f"https://example.com/page{i}?q=test")
            for i in range(XSSConfig.MAX_ENDPOINTS_TO_TEST + 20)
        ]

        call_count = 0

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            return _make_html_response("<html>No match</html>")

        with patch(
            "isitsecure.engine.scanners.xss_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await scanner.scan(endpoints)

        # Each endpoint with existing query params has 1 param ("q") and
        # 3 probes per param
        max_expected_calls = (
            XSSConfig.MAX_ENDPOINTS_TO_TEST * len(XSSConfig.REFLECTION_PROBES)
        )
        assert call_count <= max_expected_calls

    @pytest.mark.asyncio
    async def test_handles_request_exception_gracefully(self) -> None:
        """Should log and continue when a request fails."""
        scanner = XSSScanner()
        endpoint = _make_endpoint(url="https://example.com/search?q=test")

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        with patch(
            "isitsecure.engine.scanners.xss_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) == 0


class TestDOMXSS:
    """Tests for DOM-based XSS detection."""

    def test_detects_innerhtml(self) -> None:
        """JS with .innerHTML = should flag DOM XSS."""
        scanner = XSSScanner()
        snapshot = _make_snapshot(
            js_content='document.getElementById("output").innerHTML = userInput;'
        )

        findings = scanner._test_dom_xss(snapshot)

        assert len(findings) >= 1
        inner_html_findings = [
            f for f in findings if "innerHTML" in f.description
        ]
        assert len(inner_html_findings) == 1
        assert inner_html_findings[0].severity == SeverityLevel.LOW
        assert inner_html_findings[0].confidence == XSSConfig.CONFIDENCE_DOM_BASED

    def test_detects_eval(self) -> None:
        """JS with eval() should flag DOM XSS."""
        scanner = XSSScanner()
        snapshot = _make_snapshot(js_content='eval("alert(1)")')

        findings = scanner._test_dom_xss(snapshot)

        eval_findings = [f for f in findings if "eval" in f.description]
        assert len(eval_findings) >= 1

    def test_detects_document_write(self) -> None:
        """JS with document.write() should flag DOM XSS."""
        scanner = XSSScanner()
        snapshot = _make_snapshot(
            js_content='document.write("<script>alert(1)</script>")'
        )

        findings = scanner._test_dom_xss(snapshot)

        write_findings = [f for f in findings if "document.write" in f.description]
        assert len(write_findings) >= 1

    def test_detects_dangerously_set_inner_html(self) -> None:
        """React dangerouslySetInnerHTML should flag."""
        scanner = XSSScanner()
        snapshot = _make_snapshot(
            js_content='<div dangerouslySetInnerHTML={{__html: userContent}} />'
        )

        findings = scanner._test_dom_xss(snapshot)

        dsh_findings = [
            f for f in findings if "dangerouslySetInnerHTML" in f.description
        ]
        assert len(dsh_findings) >= 1

    def test_no_dom_xss_in_clean_js(self) -> None:
        """Clean JS without dangerous sinks should produce no findings."""
        scanner = XSSScanner()
        snapshot = _make_snapshot(
            js_content=(
                'const x = document.getElementById("output");\n'
                "x.textContent = userInput;\n"
                'console.log("safe code");'
            )
        )

        findings = scanner._test_dom_xss(snapshot)

        assert len(findings) == 0

    def test_no_dom_xss_when_no_js(self) -> None:
        """Empty JS content should produce no findings."""
        scanner = XSSScanner()
        snapshot = _make_snapshot(js_content="")

        findings = scanner._test_dom_xss(snapshot)

        assert len(findings) == 0

    def test_safe_innerhtml_static_string(self) -> None:
        """innerHTML with static string assignment should be filtered as safe."""
        scanner = XSSScanner()
        snapshot = _make_snapshot(
            js_content='element.innerHTML = "";'
        )

        findings = scanner._test_dom_xss(snapshot)

        # Safe context should be filtered out
        inner_html_findings = [
            f for f in findings if "innerHTML" in f.description
        ]
        assert len(inner_html_findings) == 0

    def test_finding_fields_are_correct(self) -> None:
        """DOM XSS findings should have correct field values."""
        scanner = XSSScanner()
        snapshot = _make_snapshot(
            url="https://target.com",
            js_content="var x = eval('code');",
        )

        findings = scanner._test_dom_xss(snapshot)

        assert len(findings) >= 1
        finding = [f for f in findings if "eval" in f.description][0]
        assert finding.source == FindingSource.DAST_URL
        assert finding.category == FindingCategory.INJECTION_RISK
        assert finding.scanner_name == XSSConfig.SCANNER_NAME
        assert finding.endpoint_url == "https://target.com"


class TestHelpers:
    """Tests for helper methods."""

    def test_get_testable_endpoints_with_params(self) -> None:
        """Endpoints with query params should be testable."""
        scanner = XSSScanner()
        ep_with_params = _make_endpoint(
            url="https://example.com/search?q=hello", method=EndpointMethod.GET
        )
        ep_post_with_params = _make_endpoint(
            url="https://example.com/api?id=1", method=EndpointMethod.POST
        )

        result = scanner._get_testable_endpoints([ep_with_params, ep_post_with_params])

        assert len(result) == 2

    def test_get_testable_endpoints_get_only(self) -> None:
        """GET endpoints without query params should be testable."""
        scanner = XSSScanner()
        ep_get = _make_endpoint(
            url="https://example.com/page", method=EndpointMethod.GET
        )
        ep_post = _make_endpoint(
            url="https://example.com/api", method=EndpointMethod.POST
        )

        result = scanner._get_testable_endpoints([ep_get, ep_post])

        assert len(result) == 1
        assert result[0].url == "https://example.com/page"

    def test_inject_param_adds_to_url(self) -> None:
        """Should add a query parameter to a URL without params."""
        result = inject_query_param(
            "https://example.com/search", "q", "test_value"
        )
        assert "q=test_value" in result
        assert result.startswith("https://example.com/search?")

    def test_inject_param_replaces_existing(self) -> None:
        """Should replace an existing parameter value."""
        result = inject_query_param(
            "https://example.com/search?q=original", "q", "injected"
        )
        assert "q=injected" in result
        assert "q=original" not in result

    def test_inject_param_preserves_other_params(self) -> None:
        """Should preserve other query parameters when injecting."""
        result = inject_query_param(
            "https://example.com/search?q=original&page=1", "q", "injected"
        )
        assert "q=injected" in result
        assert "page=1" in result

    def test_get_testable_params_from_url(self) -> None:
        """Should extract existing parameter names from URL."""
        scanner = XSSScanner()
        ep = _make_endpoint(url="https://example.com/search?q=hello&page=1")

        params = scanner._get_testable_params(ep)

        assert "q" in params
        assert "page" in params

    def test_get_testable_params_defaults(self) -> None:
        """Should use common reflectable params when URL has no params, capped at MAX."""
        scanner = XSSScanner()
        ep = _make_endpoint(url="https://example.com/page")

        params = scanner._get_testable_params(ep)

        expected = list(XSSConfig.COMMON_REFLECTABLE_PARAMS)[: XSSConfig.MAX_PARAMS_PER_ENDPOINT]
        assert params == expected

    def test_readable_sink_name(self) -> None:
        """Should convert regex pattern to readable name."""
        assert "innerHTML" in XSSScanner._readable_sink_name(r'\.innerHTML\s*=')
        assert "eval(" in XSSScanner._readable_sink_name(r'eval\s*\(')


class TestFullScan:
    """Integration-level tests for the full scan method."""

    @pytest.mark.asyncio
    async def test_scan_combines_reflected_and_dom(self) -> None:
        """scan() should return both reflected and DOM findings."""
        scanner = XSSScanner()
        endpoint = _make_endpoint(url="https://example.com/search?q=test")
        snapshot = _make_snapshot(
            url="https://example.com",
            js_content='document.getElementById("x").innerHTML = userInput;',
        )

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            from urllib.parse import parse_qs, urlparse

            params = parse_qs(urlparse(url).query)
            injected = params.get("q", [""])[0]
            body = f"<html><body>{injected}</body></html>"
            return _make_html_response(body)

        with patch(
            "isitsecure.engine.scanners.xss_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint], snapshot)

        # Should have at least 1 reflected + 1 DOM finding
        reflected = [
            f for f in findings if f.title == XSSConfig.TITLE_REFLECTED_XSS
        ]
        dom = [f for f in findings if f.title == XSSConfig.TITLE_DOM_XSS]
        assert len(reflected) >= 1
        assert len(dom) >= 1

    @pytest.mark.asyncio
    async def test_scan_without_snapshot(self) -> None:
        """scan() with no snapshot should only run reflected XSS tests."""
        scanner = XSSScanner()
        endpoint = _make_endpoint(url="https://example.com/search?q=test")

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            return _make_html_response("<html>No match</html>")

        with patch(
            "isitsecure.engine.scanners.xss_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        # No DOM findings since no snapshot
        dom = [f for f in findings if f.title == XSSConfig.TITLE_DOM_XSS]
        assert len(dom) == 0

    @pytest.mark.asyncio
    async def test_scan_empty_endpoints(self) -> None:
        """scan() with empty endpoints should return only DOM findings if any."""
        scanner = XSSScanner()
        snapshot = _make_snapshot(js_content="var x = eval('code');")

        with patch(
            "isitsecure.engine.scanners.xss_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([], snapshot)

        # Should still detect DOM XSS
        assert any(f.title == XSSConfig.TITLE_DOM_XSS for f in findings)
