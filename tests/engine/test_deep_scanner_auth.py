"""Auth-awareness of the deep-only HTTP DAST scanners (#119).

#115 made the quick-depth HTTP scanners carry the authenticated session. #119
extends that to the two deep-only scanners whose targets can sit behind the
login wall (rate-limit, password-reset) while deliberately EXCLUDING
auth-bypass, whose tests depend on the absence/manipulation of auth.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from isitsecure.engine.enums import EndpointMethod, ScanDepth
from isitsecure.engine.factory import create_deep_security_scan_agent
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.auth_bypass_scanner import AuthBypassScanner
from isitsecure.engine.scanners.password_reset_scanner import PasswordResetScanner
from isitsecure.engine.scanners.rate_limit_scanner import RateLimitScanner
from isitsecure.engine.shared.auth_aware import AuthAwareScanner

_COOKIE = {"Cookie": "connect.sid=abc"}


@pytest.fixture(autouse=True)
def _no_real_sleep():
    """Stub the scanners' own asyncio.sleep so the burst/probe loops don't
    actually wait (keeps this module sub-second instead of ~28s)."""
    with patch("isitsecure.engine.scanners.rate_limit_scanner.asyncio.sleep", AsyncMock()), \
         patch("isitsecure.engine.scanners.password_reset_scanner.asyncio.sleep", AsyncMock()):
        yield


def _ep(url: str, method: EndpointMethod = EndpointMethod.POST) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(url=url, method=method)


def _mock_client_capturing(headers_sink: dict):
    """A patched httpx.AsyncClient that records its constructor kwargs and
    returns a client whose request/post yield a benign 200 response."""
    def _factory(**kwargs):
        headers_sink.update(kwargs)
        client = MagicMock()
        resp = httpx.Response(200, headers={"content-type": "text/html"}, text="ok",
                              request=httpx.Request("POST", "https://ex.com/x"))
        client.request = AsyncMock(return_value=resp)
        client.post = AsyncMock(return_value=resp)
        client.get = AsyncMock(return_value=resp)
        ctx = MagicMock()
        ctx.__aenter__ = AsyncMock(return_value=client)
        ctx.__aexit__ = AsyncMock(return_value=False)
        return ctx
    return _factory


class TestDeepScannerAuthAwareness:
    def test_rate_limit_and_password_reset_are_auth_aware_at_deep(self) -> None:
        agent = create_deep_security_scan_agent(depth=ScanDepth.DEEP)
        by_type = {type(s).__name__: s for s in agent._dast_scanners}
        assert isinstance(by_type["RateLimitScanner"], AuthAwareScanner)
        assert isinstance(by_type["PasswordResetScanner"], AuthAwareScanner)

    def test_auth_bypass_is_deliberately_not_auth_aware(self) -> None:
        """auth-bypass must NOT inherit the mixin — the orchestrator's
        hasattr(_, '_auth_headers') guard skips it, keeping its probes
        unauthenticated (a session would cause false-positive bypasses)."""
        agent = create_deep_security_scan_agent(depth=ScanDepth.DEEP)
        ab = next(s for s in agent._dast_scanners if isinstance(s, AuthBypassScanner))
        assert not isinstance(ab, AuthAwareScanner)
        assert not hasattr(ab, "_auth_headers")


class TestPasswordResetAuth:
    @pytest.mark.asyncio
    async def test_client_carries_injected_session(self) -> None:
        captured: dict = {}
        scanner = PasswordResetScanner()
        scanner._auth_headers = dict(_COOKIE)
        with patch("isitsecure.engine.scanners.password_reset_scanner.httpx.AsyncClient",
                   _mock_client_capturing(captured)):
            await scanner.scan([_ep("https://ex.com/forgot-password")], snapshot=None)
        assert captured.get("headers", {}).get("Cookie") == "connect.sid=abc"

    @pytest.mark.asyncio
    async def test_unauthenticated_client_has_no_session(self) -> None:
        captured: dict = {}
        scanner = PasswordResetScanner()  # default empty _auth_headers
        with patch("isitsecure.engine.scanners.password_reset_scanner.httpx.AsyncClient",
                   _mock_client_capturing(captured)):
            await scanner.scan([_ep("https://ex.com/forgot-password")], snapshot=None)
        assert "Cookie" not in captured.get("headers", {})


class TestRateLimitAuth:
    @pytest.mark.asyncio
    async def test_burst_client_carries_injected_session(self) -> None:
        captured: dict = {}
        scanner = RateLimitScanner()
        scanner._auth_headers = dict(_COOKIE)
        with patch("isitsecure.engine.scanners.rate_limit_scanner.httpx.AsyncClient",
                   _mock_client_capturing(captured)):
            await scanner.scan([_ep("https://ex.com/login")], snapshot=None)
        assert captured.get("headers", {}).get("Cookie") == "connect.sid=abc"

    @pytest.mark.asyncio
    async def test_unauthenticated_burst_client_has_no_session(self) -> None:
        captured: dict = {}
        scanner = RateLimitScanner()  # default empty _auth_headers
        with patch("isitsecure.engine.scanners.rate_limit_scanner.httpx.AsyncClient",
                   _mock_client_capturing(captured)):
            await scanner.scan([_ep("https://ex.com/login")], snapshot=None)
        assert "Cookie" not in captured.get("headers", {})

    @pytest.mark.asyncio
    async def test_ip_vs_user_test_does_not_leak_session_end_to_end(self) -> None:
        """The behaviour this PR exists to guarantee: even with a real session
        injected, the per-IP-vs-per-user probe must send an EMPTY Cookie (never
        the real session) at BOTH identity request sites, or the two identities
        collapse into the same authenticated user (false negative/positive)."""
        scanner = RateLimitScanner()
        scanner._auth_headers = dict(_COOKIE)

        # First identity trips 429 (so the second identity request also fires),
        # second identity is allowed (200) -> the "per-user only" finding path.
        resp_429 = httpx.Response(429, request=httpx.Request("GET", "https://ex.com/login"))
        resp_200 = httpx.Response(200, request=httpx.Request("GET", "https://ex.com/login"))
        client = MagicMock()
        client.request = AsyncMock(side_effect=[resp_429, resp_200])

        await scanner._test_ip_vs_user_rate_limit(client, _ep("https://ex.com/login",
                                                               EndpointMethod.GET))

        assert client.request.call_count == 2
        for call in client.request.call_args_list:
            sent = call.kwargs["headers"]
            assert sent.get("Cookie") == "", f"real session leaked: {sent}"
            assert "connect.sid=abc" not in str(sent)
        # Distinct synthetic identities were used.
        auths = [c.kwargs["headers"].get("Authorization") for c in client.request.call_args_list]
        assert auths[0] != auths[1]

    def test_identity_headers_strips_injected_session(self) -> None:
        """The IP-vs-user test must vary identity, so it blanks any injected
        session header and sets only its synthetic Authorization."""
        scanner = RateLimitScanner()
        scanner._auth_headers = dict(_COOKIE)
        assert scanner._identity_headers("Bearer alpha") == {
            "Cookie": "", "Authorization": "Bearer alpha",
        }

    def test_identity_headers_without_session(self) -> None:
        scanner = RateLimitScanner()  # no injected auth
        assert scanner._identity_headers("Bearer beta") == {"Authorization": "Bearer beta"}
