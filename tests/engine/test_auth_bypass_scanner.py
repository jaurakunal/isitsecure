"""Tests for AuthBypassScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from isitsecure.engine.constants import AuthBypassConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.scanners.auth_bypass_scanner import (
    AuthBypassScanner,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# --- Helpers ---


def _make_endpoint(
    url: str = "https://example.com/api/login",
    method: EndpointMethod = EndpointMethod.POST,
    requires_auth: bool | None = None,
) -> DiscoveredEndpoint:
    """Create a DiscoveredEndpoint for testing."""
    return DiscoveredEndpoint(url=url, method=method, requires_auth=requires_auth)


def _make_httpx_response(
    status_code: int = 200,
    text: str = "OK",
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Create a real httpx.Response for use in mocks."""
    import datetime
    resp = httpx.Response(
        status_code=status_code,
        headers=headers or {"content-type": "application/json"},
        text=text,
        request=httpx.Request("POST", "https://example.com"),
    )
    resp.elapsed = datetime.timedelta(milliseconds=100)
    return resp


class TestAuthBypassScanner:
    """Tests for the AuthBypassScanner."""

    def setup_method(self) -> None:
        self.scanner = AuthBypassScanner()

    # --- Basic Properties ---

    def test_scanner_name(self) -> None:
        assert self.scanner.scanner_name == AuthBypassConfig.SCANNER_NAME

    def test_scan_categories(self) -> None:
        assert FindingCategory.AUTH_WEAKNESS in self.scanner.scan_categories

    # --- Username Enumeration (differential error messages) ---

    @pytest.mark.asyncio
    async def test_detects_username_enumeration_differential_messages(self) -> None:
        """Login returning 'user not found' vs 'invalid password' -> finding."""
        endpoint = _make_endpoint(url="https://example.com/api/login")

        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            payload = kwargs.get("json", {})
            email = payload.get("email", "")

            if email == AuthBypassConfig.TEST_USERNAME_NONEXISTENT:
                return _make_httpx_response(
                    status_code=401,
                    text='{"error": "User not found"}',
                )
            else:
                return _make_httpx_response(
                    status_code=401,
                    text='{"error": "Invalid password"}',
                )

        with patch(
            "isitsecure.engine.scanners.auth_bypass_scanner.httpx.AsyncClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            client_instance.request = AsyncMock(
                return_value=_make_httpx_response(status_code=401)
            )
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        enum_findings = [
            f for f in findings
            if f.title == AuthBypassConfig.TITLE_USERNAME_ENUMERATION_MESSAGE
        ]
        assert len(enum_findings) >= 1
        assert enum_findings[0].severity == SeverityLevel.HIGH
        assert enum_findings[0].category == FindingCategory.AUTH_WEAKNESS
        assert enum_findings[0].source == FindingSource.DAST_URL

    # --- Default Credentials ---

    @pytest.mark.asyncio
    async def test_detects_default_credentials_accepted(self) -> None:
        """Login accepting admin/admin -> CRITICAL finding."""
        endpoint = _make_endpoint(url="https://example.com/api/login")

        async def mock_post(url, **kwargs):
            payload = kwargs.get("json", {})
            email = payload.get("email", "")
            password = payload.get("password", "")

            if email == "admin@admin.com" and password == "admin":
                return _make_httpx_response(
                    status_code=200,
                    text='{"access_token": "eyJhbGciOiJIUzI1NiJ9.test.sig"}',
                )
            return _make_httpx_response(
                status_code=401,
                text='{"error": "Invalid credentials"}',
            )

        with patch(
            "isitsecure.engine.scanners.auth_bypass_scanner.httpx.AsyncClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            client_instance.request = AsyncMock(
                return_value=_make_httpx_response(status_code=401)
            )
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        cred_findings = [
            f for f in findings
            if f.title == AuthBypassConfig.TITLE_DEFAULT_CREDENTIALS
        ]
        assert len(cred_findings) >= 1
        assert cred_findings[0].severity == SeverityLevel.CRITICAL
        assert cred_findings[0].confidence == AuthBypassConfig.CONFIDENCE_DEFAULT_CREDS

    # --- Auth Header Bypass ---

    @pytest.mark.asyncio
    async def test_detects_auth_header_bypass(self) -> None:
        """Protected endpoint returning 2xx without auth -> finding."""
        endpoint = _make_endpoint(
            url="https://example.com/api/admin/users",
            method=EndpointMethod.GET,
            requires_auth=True,
        )

        async def mock_request(method, url, **kwargs):
            headers = kwargs.get("headers", {})
            if "Authorization" not in headers or not headers.get("Authorization", "").strip():
                # No auth or empty auth -> should return 401, but server is broken
                return _make_httpx_response(
                    status_code=200,
                    text='[{"id": 1, "name": "Admin User"}]',
                )
            return _make_httpx_response(status_code=200)

        with patch(
            "isitsecure.engine.scanners.auth_bypass_scanner.httpx.AsyncClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = AsyncMock(
                return_value=_make_httpx_response(status_code=401)
            )
            client_instance.request = mock_request
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        bypass_findings = [
            f for f in findings
            if f.title == AuthBypassConfig.TITLE_AUTH_HEADER_BYPASS
        ]
        assert len(bypass_findings) >= 1
        assert bypass_findings[0].severity == SeverityLevel.HIGH

    # --- No Login Endpoints ---

    @pytest.mark.asyncio
    async def test_no_login_endpoints_zero_findings(self) -> None:
        """No login/auth-related endpoints -> 0 findings, no crash."""
        endpoints = [
            _make_endpoint(url="https://example.com/about", method=EndpointMethod.GET),
            _make_endpoint(url="https://example.com/products", method=EndpointMethod.GET),
        ]

        findings = await self.scanner.scan(endpoints=endpoints)

        assert findings == []

    # --- Proper Auth (401 on all tests) ---

    @pytest.mark.asyncio
    async def test_proper_auth_returns_401_zero_findings(self) -> None:
        """Login endpoint always returning 401 with same message -> 0 enumeration findings."""
        endpoint = _make_endpoint(url="https://example.com/api/login")

        async def mock_post(url, **kwargs):
            return _make_httpx_response(
                status_code=401,
                text='{"error": "Invalid credentials"}',
            )

        with patch(
            "isitsecure.engine.scanners.auth_bypass_scanner.httpx.AsyncClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            client_instance.request = AsyncMock(
                return_value=_make_httpx_response(status_code=401)
            )
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        # No username enumeration: same error message and status
        enum_findings = [
            f for f in findings
            if f.title == AuthBypassConfig.TITLE_USERNAME_ENUMERATION_MESSAGE
        ]
        assert len(enum_findings) == 0

        # No default credentials accepted
        cred_findings = [
            f for f in findings
            if f.title == AuthBypassConfig.TITLE_DEFAULT_CREDENTIALS
        ]
        assert len(cred_findings) == 0

    # --- Empty Endpoints ---

    @pytest.mark.asyncio
    async def test_empty_endpoints_zero_findings(self) -> None:
        """Empty endpoint list -> 0 findings, no crash."""
        findings = await self.scanner.scan(endpoints=[])
        assert findings == []

    # --- Exception Handling ---

    @pytest.mark.asyncio
    async def test_handles_request_exception(self) -> None:
        """Scanner should handle HTTP exceptions gracefully."""
        endpoint = _make_endpoint(url="https://example.com/api/login")

        with patch(
            "isitsecure.engine.scanners.auth_bypass_scanner.httpx.AsyncClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            client_instance.request = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await self.scanner.scan(endpoints=[endpoint])

        assert len(findings) == 0

    # --- Helper method tests ---

    def test_has_differential_error_messages_true(self) -> None:
        """Different error messages for valid vs invalid user -> True."""
        body_a = '{"error": "User not found"}'
        body_b = '{"error": "Invalid password"}'
        assert AuthBypassScanner._has_differential_error_messages(body_a, body_b) is True

    def test_has_differential_error_messages_false_identical(self) -> None:
        """Identical error messages -> False."""
        body = '{"error": "Invalid credentials"}'
        assert AuthBypassScanner._has_differential_error_messages(body, body) is False

    def test_is_successful_auth_true(self) -> None:
        """200 response with access_token -> successful auth."""
        resp = _make_httpx_response(
            status_code=200,
            text='{"access_token": "eyJhbGciOiJIUzI1NiJ9.test.sig"}',
        )
        assert self.scanner._is_successful_auth(resp) is True

    def test_is_successful_auth_false_401(self) -> None:
        """401 response -> not successful auth."""
        resp = _make_httpx_response(
            status_code=401,
            text='{"error": "Invalid credentials"}',
        )
        assert self.scanner._is_successful_auth(resp) is False
