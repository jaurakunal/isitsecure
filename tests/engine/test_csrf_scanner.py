"""Tests for CSRFScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from isitsecure.engine.constants import CSRFConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.scanners.csrf_scanner import CSRFScanner
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import (
    CodebaseSnapshot,
    HTTPHeadersData,
)


# --- Fixtures ---


def _make_endpoint(
    url: str = "https://example.com/api/deals",
    method: EndpointMethod = EndpointMethod.POST,
) -> DiscoveredEndpoint:
    """Create a DiscoveredEndpoint for testing."""
    return DiscoveredEndpoint(url=url, method=method)


def _make_snapshot(
    html: str = "",
    cookies: list[dict] | None = None,
    raw_headers: dict[str, str] | None = None,
) -> CodebaseSnapshot:
    """Create a minimal CodebaseSnapshot for testing."""
    return CodebaseSnapshot(
        url="https://example.com",
        html_content=html,
        headers=HTTPHeadersData(
            raw_headers=raw_headers or {},
            status_code=200,
            cookies=cookies or [],
        ),
    )


def _mock_response(status_code: int = 200, text: str = "OK") -> MagicMock:
    """Create a mock HTTP response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = {"content-type": "text/html"}
    return resp


class TestCSRFScanner:
    """Tests for the CSRFScanner."""

    def setup_method(self) -> None:
        self.scanner = CSRFScanner()

    # --- Basic Properties ---

    def test_scanner_name(self) -> None:
        assert self.scanner.scanner_name == CSRFConfig.SCANNER_NAME

    def test_scan_categories(self) -> None:
        assert FindingCategory.AUTH_WEAKNESS in self.scanner.scan_categories

    # --- Forged Origin Tests ---

    @pytest.mark.asyncio
    async def test_detects_forged_origin_accepted(self) -> None:
        """POST endpoint accepting evil origin -> finding."""
        endpoint = _make_endpoint()

        mock_response = _mock_response(status_code=200)

        with patch(
            "isitsecure.engine.scanners.csrf_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(return_value=mock_response)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        origin_findings = [
            f for f in findings
            if f.title == CSRFConfig.TITLE_FORGED_ORIGIN
        ]
        assert len(origin_findings) == 1
        assert origin_findings[0].severity == SeverityLevel.HIGH
        assert origin_findings[0].category == FindingCategory.AUTH_WEAKNESS
        assert origin_findings[0].source == FindingSource.DAST_URL
        assert CSRFConfig.FORGED_ORIGIN in origin_findings[0].description

    @pytest.mark.asyncio
    async def test_no_finding_when_origin_rejected(self) -> None:
        """POST endpoint returning 403 for evil origin -> safe."""
        endpoint = _make_endpoint()

        mock_response = _mock_response(status_code=403)

        with patch(
            "isitsecure.engine.scanners.csrf_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(return_value=mock_response)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        origin_findings = [
            f for f in findings
            if f.title == CSRFConfig.TITLE_FORGED_ORIGIN
        ]
        assert len(origin_findings) == 0

    @pytest.mark.asyncio
    async def test_skips_get_endpoints(self) -> None:
        """GET endpoints should not be tested for CSRF."""
        endpoint = _make_endpoint(method=EndpointMethod.GET)

        with patch(
            "isitsecure.engine.scanners.csrf_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        # GET is not state-changing, no requests should be made
        client_instance.request.assert_not_called()
        origin_findings = [
            f for f in findings
            if f.title == CSRFConfig.TITLE_FORGED_ORIGIN
        ]
        assert len(origin_findings) == 0

    @pytest.mark.asyncio
    async def test_handles_request_exception(self) -> None:
        """Scanner should handle HTTP exceptions gracefully."""
        endpoint = _make_endpoint()

        with patch(
            "isitsecure.engine.scanners.csrf_scanner.RateLimitedClient"
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

    # --- Cookie SameSite Tests ---

    def test_detects_missing_samesite_cookie(self) -> None:
        """Cookie without SameSite -> finding."""
        snapshot = _make_snapshot(
            cookies=[{"name": "session_token", "samesite": ""}]
        )

        findings = self.scanner._check_cookie_samesite(snapshot)

        assert len(findings) == 1
        assert findings[0].title == CSRFConfig.TITLE_MISSING_SAMESITE
        assert findings[0].severity == SeverityLevel.MEDIUM
        assert "session_token" in findings[0].description

    def test_detects_samesite_none_cookie(self) -> None:
        """Cookie with SameSite=None -> finding."""
        snapshot = _make_snapshot(
            cookies=[{"name": "auth_cookie", "samesite": "None"}]
        )

        findings = self.scanner._check_cookie_samesite(snapshot)

        assert len(findings) == 1
        assert "auth_cookie" in findings[0].description

    def test_no_finding_for_samesite_lax(self) -> None:
        """Cookie with SameSite=Lax -> safe."""
        snapshot = _make_snapshot(
            cookies=[{"name": "session_token", "samesite": "Lax"}]
        )

        findings = self.scanner._check_cookie_samesite(snapshot)

        assert len(findings) == 0

    def test_no_finding_for_samesite_strict(self) -> None:
        """Cookie with SameSite=Strict -> safe."""
        snapshot = _make_snapshot(
            cookies=[{"name": "session_token", "samesite": "Strict"}]
        )

        findings = self.scanner._check_cookie_samesite(snapshot)

        assert len(findings) == 0

    def test_no_findings_for_empty_cookies(self) -> None:
        """No cookies -> no findings."""
        snapshot = _make_snapshot(cookies=[])

        findings = self.scanner._check_cookie_samesite(snapshot)

        assert len(findings) == 0

    # --- HTML Form CSRF Token Tests ---

    def test_detects_missing_csrf_token_in_form(self) -> None:
        """HTML form without hidden CSRF field -> finding."""
        html = """
        <html><body>
        <form method="POST" action="/login">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <button type="submit">Login</button>
        </form>
        </body></html>
        """
        snapshot = _make_snapshot(html=html)

        findings = self.scanner._check_forms_for_csrf_tokens(snapshot)

        assert len(findings) == 1
        assert findings[0].title == CSRFConfig.TITLE_MISSING_CSRF
        assert findings[0].severity == SeverityLevel.MEDIUM
        assert findings[0].confidence == CSRFConfig.CONFIDENCE_NO_CSRF_TOKEN

    def test_no_finding_with_csrf_token(self) -> None:
        """Form with csrf_token field -> safe."""
        html = """
        <html><body>
        <form method="POST" action="/login">
            <input type="hidden" name="csrf_token" value="abc123" />
            <input type="text" name="username" />
            <input type="password" name="password" />
            <button type="submit">Login</button>
        </form>
        </body></html>
        """
        snapshot = _make_snapshot(html=html)

        findings = self.scanner._check_forms_for_csrf_tokens(snapshot)

        assert len(findings) == 0

    def test_no_finding_with_authenticity_token(self) -> None:
        """Form with authenticity_token (Rails-style) -> safe."""
        html = """
        <form method="POST" action="/update">
            <input type="hidden" name="authenticity_token" value="xyz" />
            <input type="text" name="name" />
        </form>
        """
        snapshot = _make_snapshot(html=html)

        findings = self.scanner._check_forms_for_csrf_tokens(snapshot)

        assert len(findings) == 0

    def test_no_finding_for_get_form(self) -> None:
        """GET form should not be checked for CSRF tokens."""
        html = """
        <form method="GET" action="/search">
            <input type="text" name="q" />
        </form>
        """
        snapshot = _make_snapshot(html=html)

        findings = self.scanner._check_forms_for_csrf_tokens(snapshot)

        assert len(findings) == 0

    def test_no_finding_for_empty_html(self) -> None:
        """Empty HTML -> no findings."""
        snapshot = _make_snapshot(html="")

        findings = self.scanner._check_forms_for_csrf_tokens(snapshot)

        assert len(findings) == 0

    def test_multiple_forms_detected(self) -> None:
        """Multiple POST forms without CSRF tokens -> multiple findings."""
        html = """
        <form method="POST" action="/login">
            <input type="text" name="user" />
        </form>
        <form method="post" action="/register">
            <input type="text" name="email" />
        </form>
        """
        snapshot = _make_snapshot(html=html)

        findings = self.scanner._check_forms_for_csrf_tokens(snapshot)

        assert len(findings) == 2

    # --- Full Scan Integration ---

    @pytest.mark.asyncio
    async def test_empty_endpoints_and_no_snapshot(self) -> None:
        """Empty input -> 0 findings, no crash."""
        findings = await self.scanner.scan(endpoints=[], snapshot=None)

        assert findings == []

    @pytest.mark.asyncio
    async def test_state_changing_methods_tested(self) -> None:
        """PUT, PATCH, DELETE endpoints should also be tested."""
        endpoints = [
            _make_endpoint(method=EndpointMethod.PUT),
            _make_endpoint(method=EndpointMethod.PATCH),
            _make_endpoint(method=EndpointMethod.DELETE),
        ]

        mock_response = _mock_response(status_code=200)

        with patch(
            "isitsecure.engine.scanners.csrf_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(return_value=mock_response)
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=endpoints)

        # All 3 state-changing endpoints should be tested
        assert client_instance.request.call_count == 3
        origin_findings = [
            f for f in findings
            if f.title == CSRFConfig.TITLE_FORGED_ORIGIN
        ]
        assert len(origin_findings) == 3
