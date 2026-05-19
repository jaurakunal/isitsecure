"""Tests for JWTScanner."""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import JWTAttackConfig
from isitsecure.engine.enums import AuthProvider, EndpointMethod
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.scanners.jwt_scanner import JWTScanner
from isitsecure.engine.scanners.protocols import DASTScannerProtocol
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# --- Helpers ---


def _encode_jwt_part(data: dict) -> str:
    """Base64url encode a dict for JWT."""
    return base64.urlsafe_b64encode(
        json.dumps(data).encode()
    ).rstrip(b"=").decode()


def _make_jwt(
    header: dict | None = None,
    payload: dict | None = None,
    signature: str = "fakesig",
) -> str:
    """Create a fake JWT string for testing."""
    if header is None:
        header = {"alg": "HS256", "typ": "JWT"}
    if payload is None:
        payload = {"sub": "user123", "exp": 9999999999, "iat": 1000000000, "iss": "test"}
    return f"{_encode_jwt_part(header)}.{_encode_jwt_part(payload)}.{signature}"


def _make_auth_session(token: str | None = None) -> AuthSession:
    """Create a minimal AuthSession."""
    return AuthSession(
        user_id="user-123",
        access_token=token or _make_jwt(),
        provider=AuthProvider.SUPABASE,
    )


def _make_endpoint(
    url: str = "https://example.com/api/me",
    method: EndpointMethod = EndpointMethod.GET,
) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(url=url, method=method, requires_auth=True)


def _make_response(status_code: int = 200) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = '{"data": "ok"}'
    return resp


class TestJWTScannerProtocolCompliance:
    """Protocol compliance tests for JWTScanner."""

    def test_implements_dast_protocol(self) -> None:
        """JWTScanner should implement DASTScannerProtocol."""
        scanner = JWTScanner()
        assert isinstance(scanner, DASTScannerProtocol)

    def test_has_scanner_name(self) -> None:
        scanner = JWTScanner()
        assert isinstance(scanner.scanner_name, str)
        assert len(scanner.scanner_name) > 0

    def test_has_scan_method(self) -> None:
        scanner = JWTScanner()
        assert hasattr(scanner, "scan")
        assert callable(scanner.scan)


class TestJWTScanner:
    """Tests for the JWTScanner."""

    # --- Basic Properties ---

    def test_scanner_name(self) -> None:
        scanner = JWTScanner()
        assert scanner.scanner_name == JWTAttackConfig.SCANNER_NAME

    def test_scan_categories(self) -> None:
        scanner = JWTScanner()
        assert FindingCategory.AUTH_WEAKNESS in scanner.scan_categories

    # --- Missing Claims ---

    def test_detects_missing_exp(self) -> None:
        """JWT without exp claim -> finding."""
        token = _make_jwt(payload={"sub": "user123", "iat": 1000000000, "iss": "test"})
        session = _make_auth_session(token)
        scanner = JWTScanner(auth_session=session)

        payload = scanner._decode_jwt_payload(token)
        findings = scanner._check_missing_claims(payload)

        exp_findings = [f for f in findings if f.title == JWTAttackConfig.TITLE_MISSING_EXP]
        assert len(exp_findings) == 1
        assert exp_findings[0].severity == SeverityLevel.HIGH
        assert exp_findings[0].confidence == JWTAttackConfig.CONFIDENCE_MISSING_EXP

    def test_detects_missing_claims(self) -> None:
        """JWT missing iat and iss -> finding."""
        token = _make_jwt(payload={"sub": "user123", "exp": 9999999999})
        session = _make_auth_session(token)
        scanner = JWTScanner(auth_session=session)

        payload = scanner._decode_jwt_payload(token)
        findings = scanner._check_missing_claims(payload)

        claim_findings = [
            f for f in findings if f.title == JWTAttackConfig.TITLE_MISSING_CLAIMS
        ]
        assert len(claim_findings) == 1
        assert "iat" in claim_findings[0].description
        assert "iss" in claim_findings[0].description

    def test_no_finding_all_claims_present(self) -> None:
        """JWT with all required claims -> no finding."""
        token = _make_jwt(
            payload={"sub": "user123", "exp": 9999999999, "iat": 1000000000, "iss": "test"}
        )
        scanner = JWTScanner(auth_session=_make_auth_session(token))

        payload = scanner._decode_jwt_payload(token)
        findings = scanner._check_missing_claims(payload)

        assert len(findings) == 0

    # --- Algorithm None Attack ---

    @pytest.mark.asyncio
    async def test_detects_alg_none_accepted(self) -> None:
        """Server accepting alg:none JWT -> CRITICAL finding."""
        token = _make_jwt()
        session = _make_auth_session(token)
        endpoint = _make_endpoint()
        scanner = JWTScanner(auth_session=session, test_endpoint=endpoint.url)

        mock_resp = _make_response(status_code=200)

        with patch(
            "isitsecure.engine.scanners.jwt_scanner.RateLimitedClient"
        ) as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_client

            findings = await scanner.scan(endpoints=[endpoint])

        alg_none_findings = [
            f for f in findings if f.title == JWTAttackConfig.TITLE_ALG_NONE
        ]
        assert len(alg_none_findings) == 1
        assert alg_none_findings[0].severity == SeverityLevel.CRITICAL
        assert alg_none_findings[0].confidence == JWTAttackConfig.CONFIDENCE_ALG_NONE

    @pytest.mark.asyncio
    async def test_alg_none_rejected(self) -> None:
        """Server rejecting alg:none JWT -> no finding for alg:none."""
        token = _make_jwt()
        session = _make_auth_session(token)
        endpoint = _make_endpoint()
        scanner = JWTScanner(auth_session=session, test_endpoint=endpoint.url)

        mock_resp_401 = _make_response(status_code=401)

        with patch(
            "isitsecure.engine.scanners.jwt_scanner.RateLimitedClient"
        ) as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp_401)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_client

            findings = await scanner.scan(endpoints=[endpoint])

        alg_none_findings = [
            f for f in findings if f.title == JWTAttackConfig.TITLE_ALG_NONE
        ]
        assert len(alg_none_findings) == 0

    # --- Weak Secret Attack ---

    @pytest.mark.asyncio
    async def test_detects_weak_secret(self) -> None:
        """Server accepting JWT signed with weak secret -> CRITICAL finding."""
        token = _make_jwt()
        session = _make_auth_session(token)
        endpoint = _make_endpoint()
        scanner = JWTScanner(auth_session=session, test_endpoint=endpoint.url)

        mock_resp_401 = _make_response(status_code=401)
        mock_resp_200 = _make_response(status_code=200)

        call_count = 0

        async def get_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            # First call is alg:none test (reject), then weak secrets
            # Accept the 3rd weak secret
            if call_count == 1:
                return mock_resp_401  # alg:none rejected
            if call_count == 4:  # 3rd weak secret (call 2,3,4)
                return mock_resp_200
            return mock_resp_401

        with patch(
            "isitsecure.engine.scanners.jwt_scanner.RateLimitedClient"
        ) as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=get_side_effect)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_client

            findings = await scanner.scan(endpoints=[endpoint])

        weak_findings = [
            f for f in findings if f.title == JWTAttackConfig.TITLE_WEAK_SECRET
        ]
        assert len(weak_findings) == 1
        assert weak_findings[0].severity == SeverityLevel.CRITICAL
        assert weak_findings[0].confidence == JWTAttackConfig.CONFIDENCE_WEAK_SECRET

    # --- Error Handling ---

    @pytest.mark.asyncio
    async def test_handles_errors(self) -> None:
        """Scanner handles HTTP errors gracefully."""
        token = _make_jwt()
        session = _make_auth_session(token)
        endpoint = _make_endpoint()
        scanner = JWTScanner(auth_session=session, test_endpoint=endpoint.url)

        with patch(
            "isitsecure.engine.scanners.jwt_scanner.RateLimitedClient"
        ) as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_client

            findings = await scanner.scan(endpoints=[endpoint])

        # Should still have claim-based findings (no errors for passive checks)
        # but no active test findings
        alg_none_findings = [
            f for f in findings if f.title == JWTAttackConfig.TITLE_ALG_NONE
        ]
        assert len(alg_none_findings) == 0

    @pytest.mark.asyncio
    async def test_no_auth_session_returns_empty(self) -> None:
        """No auth session -> 0 findings."""
        scanner = JWTScanner()
        findings = await scanner.scan(endpoints=[_make_endpoint()])
        assert findings == []

    @pytest.mark.asyncio
    async def test_invalid_jwt_returns_empty(self) -> None:
        """Invalid JWT string -> 0 findings."""
        session = _make_auth_session(token="not-a-jwt")
        scanner = JWTScanner(auth_session=session)
        findings = await scanner.scan(endpoints=[_make_endpoint()])
        assert findings == []
