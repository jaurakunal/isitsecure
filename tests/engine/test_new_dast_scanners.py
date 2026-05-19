"""Tests for new DAST scanners: BodyParamFuzzer, RaceConditionScanner, PasswordResetScanner."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import (
    BodyParamFuzzerConfig,
    PasswordResetConfig,
    RaceConditionConfig,
)
from isitsecure.engine.enums import AuthProvider, EndpointMethod
from isitsecure.engine.models import (
    DiscoveredEndpoint,
    InterceptedRequest,
)
from isitsecure.engine.scanners.body_param_fuzzer import BodyParamFuzzer
from isitsecure.engine.scanners.password_reset_scanner import (
    PasswordResetScanner,
)
from isitsecure.engine.scanners.race_condition_scanner import (
    RaceConditionScanner,
)
from isitsecure.engine.enums import SeverityLevel


def _make_session(token: str = "test-token") -> AuthSession:
    return AuthSession(
        user_id="user-1", access_token=token, provider=AuthProvider.SUPABASE,
    )


def _make_response(status_code: int = 200, body: str = "") -> httpx.Response:
    return httpx.Response(
        status_code=status_code, text=body,
        request=httpx.Request("GET", "https://test.com"),
    )


def _make_intercepted(
    url: str = "https://example.com/api/deals",
    method: str = "POST",
    status: int = 201,
    body: str = '{"title":"Test Deal","price":100}',
) -> InterceptedRequest:
    return InterceptedRequest(
        url=url, method=method, response_status=status,
        request_body=body, request_headers={},
    )


# ===========================================================================
# Body Param Fuzzer
# ===========================================================================


class TestBodyParamFuzzer:

    def test_scanner_name(self):
        assert BodyParamFuzzer().scanner_name == BodyParamFuzzerConfig.SCANNER_NAME

    @pytest.mark.asyncio
    async def test_detects_sql_error(self):
        fuzzer = BodyParamFuzzer()
        intercepted = [_make_intercepted()]

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(
            return_value=_make_response(500, "ERROR: SQL syntax error near")
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "isitsecure.engine.scanners.body_param_fuzzer.RateLimitedClient",
            return_value=mock_client,
        ):
            findings = await fuzzer.scan(intercepted, _make_session())

        sqli = [f for f in findings if "SQL injection" in f.title]
        assert len(sqli) >= 1
        assert sqli[0].severity == SeverityLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_detects_xss_reflection(self):
        fuzzer = BodyParamFuzzer()
        intercepted = [_make_intercepted()]

        async def mock_request(method, url, **kwargs):
            content = kwargs.get("content", "")
            if "<script>" in content:
                return _make_response(200, '<script>alert(1)</script>')
            return _make_response(200, '{"ok":true}')

        mock_client = AsyncMock()
        mock_client.request = mock_request
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "isitsecure.engine.scanners.body_param_fuzzer.RateLimitedClient",
            return_value=mock_client,
        ):
            findings = await fuzzer.scan(intercepted, _make_session())

        xss = [f for f in findings if "XSS" in f.title]
        assert len(xss) >= 1

    @pytest.mark.asyncio
    async def test_skips_non_mutation_requests(self):
        fuzzer = BodyParamFuzzer()
        intercepted = [
            InterceptedRequest(
                url="https://example.com/api/deals",
                method="GET", response_status=200,
            ),
        ]

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "isitsecure.engine.scanners.body_param_fuzzer.RateLimitedClient",
            return_value=mock_client,
        ):
            findings = await fuzzer.scan(intercepted, _make_session())

        assert findings == []

    @pytest.mark.asyncio
    async def test_skips_requests_without_body(self):
        fuzzer = BodyParamFuzzer()
        intercepted = [
            InterceptedRequest(
                url="https://example.com/api/deals",
                method="POST", response_status=201,
                request_body="",
            ),
        ]

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "isitsecure.engine.scanners.body_param_fuzzer.RateLimitedClient",
            return_value=mock_client,
        ):
            findings = await fuzzer.scan(intercepted, _make_session())

        assert findings == []

    def test_has_sql_error_detection(self):
        fuzzer = BodyParamFuzzer()
        assert fuzzer._has_sql_error("ERROR: SQL syntax error") is True
        assert fuzzer._has_sql_error("pg_query failed") is True
        assert fuzzer._has_sql_error('{"data":[]}') is False

    @pytest.mark.asyncio
    async def test_skips_non_dict_json_body(self):
        fuzzer = BodyParamFuzzer()
        intercepted = [_make_intercepted(body='[1, 2, 3]')]
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "isitsecure.engine.scanners.body_param_fuzzer.RateLimitedClient",
            return_value=mock_client,
        ):
            findings = await fuzzer.scan(intercepted, _make_session())
        assert findings == []

    @pytest.mark.asyncio
    async def test_skips_invalid_json_body(self):
        fuzzer = BodyParamFuzzer()
        intercepted = [_make_intercepted(body='not json at all')]
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "isitsecure.engine.scanners.body_param_fuzzer.RateLimitedClient",
            return_value=mock_client,
        ):
            findings = await fuzzer.scan(intercepted, _make_session())
        assert findings == []

    @pytest.mark.asyncio
    async def test_detects_type_confusion(self):
        fuzzer = BodyParamFuzzer()
        intercepted = [_make_intercepted(body='{"name":"test","price":100}')]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(
            return_value=_make_response(500, "TypeError: Cannot convert")
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch(
            "isitsecure.engine.scanners.body_param_fuzzer.RateLimitedClient",
            return_value=mock_client,
        ):
            findings = await fuzzer.scan(intercepted, _make_session())
        type_findings = [f for f in findings if "Type confusion" in f.title]
        assert len(type_findings) >= 1


# ===========================================================================
# Race Condition Scanner
# ===========================================================================


class TestRaceConditionScanner:

    def test_scanner_name(self):
        assert RaceConditionScanner().scanner_name == RaceConditionConfig.SCANNER_NAME

    @pytest.mark.asyncio
    async def test_detects_race_condition(self):
        scanner = RaceConditionScanner()
        intercepted = [_make_intercepted()]

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(
                return_value=_make_response(201, '{"id":"new"}')
            )
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan(intercepted, _make_session())

        race = [f for f in findings if "race condition" in f.title.lower()]
        assert len(race) >= 1
        assert race[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_no_finding_when_all_fail(self):
        scanner = RaceConditionScanner()
        intercepted = [_make_intercepted()]

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(
                return_value=_make_response(409, "Conflict")
            )
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan(intercepted, _make_session())

        assert not [f for f in findings if "race condition" in f.title.lower()]

    @pytest.mark.asyncio
    async def test_deduplicates_by_path(self):
        scanner = RaceConditionScanner()
        intercepted = [
            _make_intercepted(url="https://example.com/api/deals"),
            _make_intercepted(url="https://example.com/api/deals"),
        ]

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.request = AsyncMock(
                return_value=_make_response(201)
            )
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan(intercepted, _make_session())

        # Should only test the endpoint once
        race = [f for f in findings if "race condition" in f.title.lower()]
        assert len(race) <= 1

    @pytest.mark.asyncio
    async def test_skips_get_requests(self):
        scanner = RaceConditionScanner()
        intercepted = [
            InterceptedRequest(
                url="https://example.com/api/deals",
                method="GET", response_status=200,
            ),
        ]

        findings = await scanner.scan(intercepted, _make_session())
        assert findings == []


# ===========================================================================
# Password Reset Scanner
# ===========================================================================


class TestPasswordResetScanner:

    def test_scanner_name(self):
        assert PasswordResetScanner().scanner_name == PasswordResetConfig.SCANNER_NAME

    def test_filter_reset_endpoints(self):
        scanner = PasswordResetScanner()
        endpoints = [
            DiscoveredEndpoint(url="https://example.com/forgot-password"),
            DiscoveredEndpoint(url="https://example.com/api/users"),
            DiscoveredEndpoint(url="https://example.com/reset-password"),
        ]
        filtered = scanner._filter_reset_endpoints(endpoints)
        assert len(filtered) == 2

    @pytest.mark.asyncio
    async def test_detects_email_enumeration(self):
        scanner = PasswordResetScanner()
        endpoint = DiscoveredEndpoint(
            url="https://example.com/forgot-password",
            method=EndpointMethod.POST,
        )

        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            email = kwargs.get("json", {}).get("email", "")
            if "not_a_real" in email:
                return _make_response(404, '{"error":"User not found"}')
            return _make_response(200, '{"message":"Reset email sent"}')

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        enum = [f for f in findings if "account existence" in f.title.lower()]
        assert len(enum) == 1
        assert enum[0].severity == SeverityLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_detects_token_leakage(self):
        scanner = PasswordResetScanner()
        endpoint = DiscoveredEndpoint(
            url="https://example.com/forgot-password",
            method=EndpointMethod.POST,
        )

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.post = AsyncMock(
                return_value=_make_response(
                    200,
                    '{"token":"eyJhbGciOiJIUzI1NiJ9.very-long-jwt-reset-token.sig"}',
                )
            )
            MockClient.return_value.__aenter__ = AsyncMock(
                return_value=client_instance
            )
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        token = [f for f in findings if "token leaked" in f.title.lower()]
        assert len(token) == 1
        assert token[0].severity == SeverityLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_no_findings_for_non_reset_endpoints(self):
        scanner = PasswordResetScanner()
        endpoint = DiscoveredEndpoint(
            url="https://example.com/api/users",
            method=EndpointMethod.GET,
        )

        findings = await scanner.scan([endpoint])
        assert findings == []

    @pytest.mark.asyncio
    async def test_detects_no_rate_limiting(self):
        scanner = PasswordResetScanner()
        endpoint = DiscoveredEndpoint(
            url="https://example.com/forgot-password",
            method=EndpointMethod.POST,
        )

        # Use direct method test to isolate rate limiting
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(
            return_value=_make_response(200, '{"ok":true}')
        )

        finding = await scanner._test_rate_limiting(mock_client, endpoint)
        assert finding is not None
        assert "rate limiting" in finding.title.lower()

    @pytest.mark.asyncio
    async def test_no_finding_when_rate_limited(self):
        scanner = PasswordResetScanner()
        endpoint = DiscoveredEndpoint(
            url="https://example.com/forgot-password",
            method=EndpointMethod.POST,
        )

        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count >= 3:
                return _make_response(429, '{"error":"too many"}')
            return _make_response(200, '{"ok":true}')

        mock_client = AsyncMock()
        mock_client.post = mock_post

        finding = await scanner._test_rate_limiting(mock_client, endpoint)
        assert finding is None


# ===========================================================================
# Shared Auth Headers
# ===========================================================================


class TestSharedAuthHeaders:

    def test_build_auth_headers(self):
        from isitsecure.engine.shared.auth_headers import build_auth_headers
        session = _make_session(token="my-token")
        headers = build_auth_headers(session)
        assert headers["Authorization"] == "Bearer my-token"
        assert "Content-Type" in headers

    def test_build_replay_headers_with_apikey(self):
        from isitsecure.engine.shared.auth_headers import build_replay_headers
        session = _make_session(token="my-token")
        intercepted = InterceptedRequest(
            url="https://example.com/api",
            method="POST", response_status=200,
            request_headers={"apikey": "anon-key-123"},
        )
        headers = build_replay_headers(session, intercepted)
        assert headers["apikey"] == "anon-key-123"

    def test_build_replay_headers_without_apikey(self):
        from isitsecure.engine.shared.auth_headers import build_replay_headers
        session = _make_session(token="my-token")
        headers = build_replay_headers(session)
        assert "apikey" not in headers
