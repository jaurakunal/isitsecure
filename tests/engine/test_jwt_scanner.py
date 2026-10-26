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

        async def get_side_effect(url, headers=None, **kw):
            # Garbage-token control is rejected; everything else accepted.
            if "invalid.invalid.invalid" in (headers or {}).get("Authorization", ""):
                return _make_response(status_code=401)
            return _make_response(status_code=200)

        with patch(
            "isitsecure.engine.scanners.jwt_scanner.RateLimitedClient"
        ) as MockClient:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=get_side_effect)
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

        accepted = scanner._sign_hs256(
            scanner._decode_jwt_payload(token),
            JWTAttackConfig.COMMON_WEAK_SECRETS[2],
        )

        async def get_side_effect(url, headers=None, **kw):
            auth = (headers or {}).get("Authorization", "")
            if auth == f"Bearer {token}" or auth == f"Bearer {accepted}":
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


# --- Negative control / key confusion (B2 #5, #6) ---


class _FakeServer:
    """Tiny fake API: decides a response per Authorization header."""

    def __init__(self, handler, jwks=None) -> None:
        self._handler = handler
        self._jwks = jwks
        self.requests: list[str] = []

    def client(self) -> AsyncMock:
        async def get(url, headers=None, **kw):
            resp = MagicMock(spec=httpx.Response)
            if url.endswith("jwks.json"):
                if self._jwks is None:
                    resp.status_code, resp.text = 404, "nope"
                    resp.json = MagicMock(side_effect=ValueError("no"))
                else:
                    resp.status_code = 200
                    resp.text = json.dumps(self._jwks)
                    resp.json = lambda: self._jwks
                return resp
            auth = (headers or {}).get("Authorization", "")
            token = auth.removeprefix("Bearer ")
            self.requests.append(token)
            resp.status_code, resp.text = self._handler(token)
            return resp

        c = AsyncMock()
        c.get = AsyncMock(side_effect=get)
        c.__aenter__ = AsyncMock(return_value=c)
        c.__aexit__ = AsyncMock(return_value=None)
        return c


async def _run(server: _FakeServer, token: str | None = None):
    endpoint = _make_endpoint()
    scanner = JWTScanner(
        auth_session=_make_auth_session(token or _make_jwt()),
        test_endpoint=endpoint.url,
    )
    with patch("isitsecure.engine.scanners.jwt_scanner.RateLimitedClient") as M:
        M.return_value = server.client()
        return await scanner.scan(endpoints=[endpoint])


def _hs256_ok(tok: str, secret: bytes) -> bool:
    import hashlib
    import hmac

    try:
        h, p, s = tok.split(".")
        hdr = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    except Exception:
        return False
    if hdr.get("alg") != "HS256":
        return False
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode() == s


class TestNegativeControl:
    @pytest.mark.asyncio
    async def test_public_endpoint_ignoring_token_yields_no_forgery_findings(self) -> None:
        """Endpoint returns the same 200 for any token: no CRITICAL forgery."""
        findings = await _run(_FakeServer(lambda tok: (200, "<html>public</html>")))
        assert not [f for f in findings if f.severity == SeverityLevel.CRITICAL]

    @pytest.mark.asyncio
    async def test_real_alg_none_acceptor_still_reported(self) -> None:
        """Positive control: accepts alg=none, rejects garbage."""
        real = _make_jwt()

        def handler(tok: str):
            hdr = tok.split(".")[0]
            try:
                alg = json.loads(base64.urlsafe_b64decode(hdr + "=" * (-len(hdr) % 4))).get("alg")
            except Exception:
                return 401, "bad token"
            if alg == "none" or tok == real:
                return 200, '{"data": "ok"}'
            return 401, "bad token"

        findings = await _run(_FakeServer(handler), real)
        alg = [f for f in findings if f.title == JWTAttackConfig.TITLE_ALG_NONE]
        assert len(alg) == 1
        assert alg[0].severity == SeverityLevel.CRITICAL
        assert "control" in alg[0].evidence

    @pytest.mark.asyncio
    async def test_body_discrimination_when_control_also_2xx(self) -> None:
        """Garbage gets anonymous 200 body; forged alg=none gets the user body."""
        real = _make_jwt()

        def handler(tok: str):
            if tok == "invalid.invalid.invalid":
                return 200, '{"anonymous": true}'
            return 200, '{"user": "u1"}'

        findings = await _run(_FakeServer(handler), real)
        assert JWTAttackConfig.TITLE_ALG_NONE in [f.title for f in findings]

    @pytest.mark.asyncio
    async def test_weak_secret_positive_and_suppressed(self) -> None:
        real = _make_jwt()

        def handler(tok: str):
            if tok == real or _hs256_ok(tok, b"secret"):
                return 200, '{"data": "ok"}'
            return 401, "no"

        findings = await _run(_FakeServer(handler), real)
        weak = [f for f in findings if f.title == JWTAttackConfig.TITLE_WEAK_SECRET]
        assert len(weak) == 1
        findings = await _run(_FakeServer(lambda t: (200, "same")), real)
        assert not [f for f in findings if f.title == JWTAttackConfig.TITLE_WEAK_SECRET]

    @pytest.mark.asyncio
    async def test_claim_manipulation_requires_control_rejection(self) -> None:
        token = _make_jwt(payload={"sub": "u1", "exp": 9999999999, "iat": 1, "iss": "t"})
        findings = await _run(_FakeServer(lambda t: (200, "same")), token)
        assert not [f for f in findings if f.title.startswith("JWT claim")]

        def handler(tok: str):
            if tok == token or _hs256_ok(tok, b""):
                return 200, "ok"
            return 401, "no"

        findings = await _run(_FakeServer(handler), token)
        assert [f for f in findings if f.title.startswith("JWT claim")]


def _rsa_jwk_and_pem():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    nums = pub.public_numbers()

    def b64(i: int) -> str:
        raw = i.to_bytes((i.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    pem = pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {"kty": "RSA", "kid": "k1", "n": b64(nums.n), "e": b64(nums.e)}, pem


class TestKeyConfusion:
    @pytest.mark.asyncio
    async def test_pem_confusable_server_is_found(self) -> None:
        jwk, pem = _rsa_jwk_and_pem()
        real = _make_jwt(header={"alg": "RS256", "typ": "JWT"})

        def handler(tok: str):
            if tok == real or _hs256_ok(tok, pem):
                return 200, '{"data": "ok"}'
            return 401, "no"

        findings = await _run(_FakeServer(handler, {"keys": [jwk]}), real)
        kc = [f for f in findings if f.title == JWTAttackConfig.TITLE_KEY_CONFUSION]
        assert len(kc) == 1
        assert kc[0].severity == SeverityLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_non_confusable_server_not_reported(self) -> None:
        jwk, _ = _rsa_jwk_and_pem()
        real = _make_jwt(header={"alg": "RS256", "typ": "JWT"})
        server = _FakeServer(lambda t: (200, "ok") if t == real else (401, "no"), {"keys": [jwk]})
        titles = [f.title for f in await _run(server, real)]
        assert JWTAttackConfig.TITLE_KEY_CONFUSION not in titles
        assert JWTAttackConfig.TITLE_JWKS_EXPOSED in titles

    @pytest.mark.asyncio
    async def test_token_ignoring_server_not_reported_as_confusion(self) -> None:
        jwk, _ = _rsa_jwk_and_pem()
        server = _FakeServer(lambda t: (200, "same"), {"keys": [jwk]})
        titles = [f.title for f in await _run(server)]
        assert JWTAttackConfig.TITLE_KEY_CONFUSION not in titles

    def test_candidates_include_pem_and_skip_ec(self) -> None:
        jwk, pem = _rsa_jwk_and_pem()
        scanner = JWTScanner()
        assert pem in scanner._extract_public_key_candidates(jwk)
        assert scanner._extract_public_key_candidates({"kty": "EC", "x": "a", "y": "b"}) == []

    @pytest.mark.asyncio
    async def test_html_200_jwks_path_not_reported_as_jwks(self) -> None:
        server = _FakeServer(lambda t: (200, "<html></html>"))

        def client():
            c = AsyncMock()

            async def get(url, headers=None, **kw):
                r = MagicMock(spec=httpx.Response)
                r.status_code = 200
                r.text = "<html></html>"
                r.json = MagicMock(side_effect=ValueError("not json"))
                return r

            c.get = AsyncMock(side_effect=get)
            c.__aenter__ = AsyncMock(return_value=c)
            c.__aexit__ = AsyncMock(return_value=None)
            return c

        server.client = client
        findings = await _run(server)
        assert JWTAttackConfig.TITLE_JWKS_EXPOSED not in [f.title for f in findings]
