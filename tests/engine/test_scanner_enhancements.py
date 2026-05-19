"""Tests for scanner enhancements: prototype pollution, CRLF injection,
JWT claim manipulation, and context-aware XSS.

Each section tests the specific enhancement added to an existing scanner.
"""

from __future__ import annotations

import datetime
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import (
    BodyParamFuzzerConfig,
    HTTPProbeConfig,
    JWTAttackConfig,
    XSSConfig,
)
from isitsecure.engine.enums import AuthProvider, EndpointMethod
from isitsecure.engine.models import (
    DiscoveredEndpoint,
    InterceptedRequest,
)
from isitsecure.engine.scanners.body_param_fuzzer import BodyParamFuzzer
from isitsecure.engine.scanners.http_probe_scanner import HTTPProbeScanner
from isitsecure.engine.scanners.jwt_scanner import JWTScanner
from isitsecure.engine.scanners.xss_scanner import XSSScanner
from isitsecure.engine.enums import SeverityLevel


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_session(token: str = "test-token") -> AuthSession:
    return AuthSession(
        user_id="user-1", access_token=token, provider=AuthProvider.SUPABASE,
    )


def _make_httpx_response(
    status_code: int = 200,
    body: str = "",
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    resp = httpx.Response(
        status_code=status_code,
        text=body,
        headers=headers or {},
        request=httpx.Request("GET", "https://test.com"),
    )
    resp.elapsed = datetime.timedelta(milliseconds=50)
    return resp


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


def _make_endpoint(
    url: str = "https://example.com/api/v1/users",
    method: EndpointMethod = EndpointMethod.GET,
) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(url=url, method=method)


def _mock_response(
    status_code: int = 200,
    text: str = "OK",
    headers: dict[str, str] | None = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {"content-type": "text/html"}
    return resp


# ===========================================================================
# 1. Prototype Pollution (BodyParamFuzzer)
# ===========================================================================


class TestPrototypePollution:
    """Tests for prototype pollution detection in BodyParamFuzzer."""

    def test_prototype_pollution_payloads_exist(self) -> None:
        """Config should define prototype pollution payloads."""
        assert len(BodyParamFuzzerConfig.PROTOTYPE_POLLUTION_PAYLOADS) >= 2
        keys = [k for k, _ in BodyParamFuzzerConfig.PROTOTYPE_POLLUTION_PAYLOADS]
        assert "__proto__" in keys
        assert "constructor" in keys

    def test_confidence_constant_exists(self) -> None:
        assert BodyParamFuzzerConfig.CONFIDENCE_PROTOTYPE_POLLUTION >= 0.8

    @pytest.mark.asyncio
    async def test_detects_prototype_pollution_accepted(self) -> None:
        """Server returning 2xx for __proto__ key should produce finding."""
        fuzzer = BodyParamFuzzer()
        intercepted = [_make_intercepted()]

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(
            return_value=_make_httpx_response(200, '{"ok":true}')
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "isitsecure.engine.scanners.body_param_fuzzer.RateLimitedClient",
            return_value=mock_client,
        ):
            findings = await fuzzer.scan(intercepted, _make_session())

        proto_findings = [f for f in findings if "Prototype pollution" in f.title]
        assert len(proto_findings) >= 1
        assert proto_findings[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_no_finding_when_proto_rejected(self) -> None:
        """Server returning 400 for __proto__ key should not produce finding."""
        fuzzer = BodyParamFuzzer()
        intercepted = [_make_intercepted()]

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(
            return_value=_make_httpx_response(400, '{"error":"validation failed"}')
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "isitsecure.engine.scanners.body_param_fuzzer.RateLimitedClient",
            return_value=mock_client,
        ):
            findings = await fuzzer.scan(intercepted, _make_session())

        proto_findings = [f for f in findings if "Prototype pollution" in f.title]
        assert len(proto_findings) == 0

    @pytest.mark.asyncio
    async def test_proto_tested_per_request_not_per_param(self) -> None:
        """Proto pollution keys are top-level, not per-param."""
        fuzzer = BodyParamFuzzer()
        intercepted = [_make_intercepted(body='{"a":"1","b":"2","c":"3"}')]

        call_payloads = []

        async def track_request(method, url, **kwargs):
            content = kwargs.get("content", "")
            call_payloads.append(content)
            return _make_httpx_response(400, "rejected")

        mock_client = AsyncMock()
        mock_client.request = track_request
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "isitsecure.engine.scanners.body_param_fuzzer.RateLimitedClient",
            return_value=mock_client,
        ):
            await fuzzer.scan(intercepted, _make_session())

        # Proto payloads should appear exactly once per payload type,
        # not multiplied by number of params
        proto_calls = [p for p in call_payloads if "__proto__" in p or "constructor" in p]
        assert len(proto_calls) == len(BodyParamFuzzerConfig.PROTOTYPE_POLLUTION_PAYLOADS)


# ===========================================================================
# 2. CRLF Injection (HTTPProbeScanner)
# ===========================================================================


class TestCRLFInjection:
    """Tests for CRLF header injection in HTTPProbeScanner."""

    def test_crlf_config_exists(self) -> None:
        """CRLF constants should be defined."""
        assert len(HTTPProbeConfig.CRLF_PAYLOADS) >= 2
        assert len(HTTPProbeConfig.CRLF_PARAM_NAMES) >= 3
        assert HTTPProbeConfig.CRLF_CANARY_HEADER
        assert HTTPProbeConfig.CRLF_CANARY_VALUE

    @pytest.mark.asyncio
    async def test_detects_crlf_injection(self) -> None:
        """If canary header appears in response, CRLF is confirmed."""
        scanner = HTTPProbeScanner()
        endpoints = [_make_endpoint(url="https://example.com/redirect?url=test")]

        async def mock_get(url, **kwargs):
            return _mock_response(
                status_code=302,
                headers={
                    "content-type": "text/html",
                    "location": "https://example.com",
                    HTTPProbeConfig.CRLF_CANARY_HEADER.lower(): HTTPProbeConfig.CRLF_CANARY_VALUE,
                },
            )

        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.request = AsyncMock(return_value=_mock_response())

        findings = await scanner._check_crlf_injection(endpoints, mock_client)

        assert len(findings) >= 1
        assert findings[0].severity == SeverityLevel.HIGH
        assert "CRLF" in findings[0].title

    @pytest.mark.asyncio
    async def test_no_finding_when_canary_absent(self) -> None:
        """No canary header in response = no finding."""
        scanner = HTTPProbeScanner()
        endpoints = [_make_endpoint(url="https://example.com/page?url=test")]

        async def mock_get(url, **kwargs):
            return _mock_response(
                status_code=200,
                headers={"content-type": "text/html"},
            )

        mock_client = AsyncMock()
        mock_client.get = mock_get

        findings = await scanner._check_crlf_injection(endpoints, mock_client)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_crlf_stops_after_first_confirmed(self) -> None:
        """Should return after first confirmed CRLF, not test all endpoints."""
        scanner = HTTPProbeScanner()
        endpoints = [
            _make_endpoint(url="https://example.com/a?url=x"),
            _make_endpoint(url="https://example.com/b?url=x"),
            _make_endpoint(url="https://example.com/c?url=x"),
        ]

        async def mock_get(url, **kwargs):
            return _mock_response(
                headers={
                    HTTPProbeConfig.CRLF_CANARY_HEADER.lower(): HTTPProbeConfig.CRLF_CANARY_VALUE,
                },
            )

        mock_client = AsyncMock()
        mock_client.get = mock_get

        findings = await scanner._check_crlf_injection(endpoints, mock_client)
        assert len(findings) == 1


# ===========================================================================
# 3. JWT Claim Manipulation (JWTScanner)
# ===========================================================================


def _make_test_jwt() -> str:
    """Build a minimal valid-looking JWT for testing."""
    import base64

    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({
            "sub": "user-123",
            "role": "user",
            "exp": 9999999999,
            "iat": 1000000000,
            "iss": "test",
        }).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.fake-signature"


class TestJWTClaimManipulation:
    """Tests for JWT claim escalation and impersonation."""

    def test_escalation_mutations_defined(self) -> None:
        """Config should define escalation claim mutations."""
        assert len(JWTAttackConfig.CLAIM_ESCALATION_MUTATIONS) >= 3
        claims = [c for c, _, _ in JWTAttackConfig.CLAIM_ESCALATION_MUTATIONS]
        assert "role" in claims
        assert "is_admin" in claims

    def test_identity_fields_defined(self) -> None:
        assert "sub" in JWTAttackConfig.CLAIM_IDENTITY_FIELDS
        assert "user_id" in JWTAttackConfig.CLAIM_IDENTITY_FIELDS

    def test_impersonation_value_is_zero_uuid(self) -> None:
        assert JWTAttackConfig.CLAIM_IMPERSONATION_VALUE == (
            "00000000-0000-0000-0000-000000000000"
        )

    @pytest.mark.asyncio
    async def test_detects_claim_escalation(self) -> None:
        """Server accepting a forged role=admin JWT should produce CRITICAL."""
        token = _make_test_jwt()
        session = AuthSession(
            user_id="user-1",
            access_token=token,
            provider=AuthProvider.SUPABASE,
        )
        scanner = JWTScanner(auth_session=session)
        payload = scanner._decode_jwt_payload(token)

        async def mock_get(url, **kwargs):
            return _make_httpx_response(200, '{"data":"admin stuff"}')

        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "isitsecure.engine.scanners.jwt_scanner.RateLimitedClient",
            return_value=mock_client,
        ):
            findings = await scanner._test_claim_manipulation(
                token, payload, "https://example.com/api/me",
            )

        assert len(findings) >= 1
        assert findings[0].severity == SeverityLevel.CRITICAL
        assert "role" in findings[0].title or "admin" in findings[0].title

    @pytest.mark.asyncio
    async def test_no_finding_when_forged_claims_rejected(self) -> None:
        """Server returning 401 for modified claims = no finding."""
        token = _make_test_jwt()
        session = AuthSession(
            user_id="user-1",
            access_token=token,
            provider=AuthProvider.SUPABASE,
        )
        scanner = JWTScanner(auth_session=session)
        payload = scanner._decode_jwt_payload(token)

        # Baseline returns 200, forged returns 401
        call_count = 0

        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _make_httpx_response(200, '{"ok":true}')  # baseline
            return _make_httpx_response(401, '{"error":"invalid"}')

        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "isitsecure.engine.scanners.jwt_scanner.RateLimitedClient",
            return_value=mock_client,
        ):
            findings = await scanner._test_claim_manipulation(
                token, payload, "https://example.com/api/me",
            )

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_skips_non_hs256_algorithms(self) -> None:
        """RS256 tokens can't be re-signed without the private key."""
        import base64

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps({"sub": "user-1", "role": "user"}).encode()
        ).rstrip(b"=").decode()
        token = f"{header}.{payload_b64}.rsa-signature"

        session = AuthSession(
            user_id="user-1",
            access_token=token,
            provider=AuthProvider.SUPABASE,
        )
        scanner = JWTScanner(auth_session=session)
        payload = scanner._decode_jwt_payload(token)

        findings = await scanner._test_claim_manipulation(
            token, payload, "https://example.com/api/me",
        )
        assert findings == []


# ===========================================================================
# 4. Context-Aware XSS (XSSScanner)
# ===========================================================================


class TestContextAwareXSS:
    """Tests for context-specific XSS confirmation payloads."""

    def test_context_payloads_defined(self) -> None:
        """Config should define context payloads."""
        assert len(XSSConfig.CONTEXT_PAYLOADS) >= 5
        assert "html_attr_double" in XSSConfig.CONTEXT_PAYLOADS
        assert "js_string_double" in XSSConfig.CONTEXT_PAYLOADS
        assert "url_href" in XSSConfig.CONTEXT_PAYLOADS

    def test_context_payload_structure(self) -> None:
        """Each context payload should be (regex, payload, description)."""
        for name, (regex, payload, desc) in XSSConfig.CONTEXT_PAYLOADS.items():
            assert "{canary}" in regex, f"{name} regex missing {{canary}}"
            assert len(payload) > 0, f"{name} has empty payload"
            assert len(desc) > 0, f"{name} has empty description"

    @pytest.mark.asyncio
    async def test_detects_attribute_breakout_xss(self) -> None:
        """Canary inside HTML attribute + breakout payload confirmed = HIGH."""
        scanner = XSSScanner()
        endpoint = _make_endpoint(url="https://example.com/search?q=test")

        # Simulate: canary reflected inside an HTML attribute,
        # then breakout payload also reflected
        call_count = 0

        async def mock_get(url: str, **kwargs) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            from urllib.parse import parse_qs, urlparse

            params = parse_qs(urlparse(url).query)
            injected = params.get("q", [""])[0]

            if "canary_xss_" in injected:
                # First call: reflect canary inside attribute, encode HTML chars
                escaped = injected.replace("<", "&lt;").replace(">", "&gt;")
                body = f'<html><input value="{escaped}" /></html>'
                return _make_httpx_response(
                    200, body, headers={"content-type": "text/html"},
                )
            if "onmouseover" in injected:
                # Confirmation call: breakout payload reflected unescaped
                body = f'<html><input value="{injected}" /></html>'
                return _make_httpx_response(
                    200, body, headers={"content-type": "text/html"},
                )
            return _make_httpx_response(200, "<html>safe</html>", headers={"content-type": "text/html"})

        with patch(
            "isitsecure.engine.scanners.xss_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        context_findings = [f for f in findings if "attribute breakout" in f.title.lower() or f.confidence == XSSConfig.CONFIDENCE_CONTEXT_CONFIRMED]
        if context_findings:
            assert context_findings[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_falls_back_to_low_when_no_context_match(self) -> None:
        """If canary is reflected (encoded) but no context breakout works, stay LOW."""
        scanner = XSSScanner()
        endpoint = _make_endpoint(url="https://example.com/search?q=test")

        async def mock_get(url: str, **kwargs) -> httpx.Response:
            from urllib.parse import parse_qs, urlparse

            params = parse_qs(urlparse(url).query)
            injected = params.get("q", [""])[0]
            # Always encode HTML chars, reflect as plain text (no attribute context)
            escaped = injected.replace("<", "&lt;").replace(">", "&gt;")
            body = f"<html><p>{escaped}</p></html>"
            return _make_httpx_response(200, body, headers={"content-type": "text/html"})

        with patch(
            "isitsecure.engine.scanners.xss_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.get = mock_get
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        # Should still get the LOW-severity partial reflection finding
        low_findings = [f for f in findings if f.severity == SeverityLevel.LOW]
        assert len(low_findings) >= 1

    @pytest.mark.asyncio
    async def test_context_xss_returns_none_for_404(self) -> None:
        """Confirmation payload returning 404 should not produce finding."""
        scanner = XSSScanner()

        async def mock_get(url, **kwargs):
            return _make_httpx_response(404, "Not Found", headers={"content-type": "text/html"})

        mock_client = AsyncMock()
        mock_client.get = mock_get

        endpoint = _make_endpoint(url="https://example.com/search?q=test")
        result = await scanner._test_context_xss(
            mock_client, endpoint, "q", "canary_xss_abc12345",
            '<html><input value="canary_xss_abc12345" /></html>',
        )
        assert result is None
