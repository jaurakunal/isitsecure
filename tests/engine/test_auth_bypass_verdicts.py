"""Auth-bypass scanner verdict regressions (batch D2)."""

from __future__ import annotations

import datetime
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.constants import AuthBypassConfig
from isitsecure.engine.enums import EndpointMethod, SeverityLevel
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.auth_bypass_scanner import AuthBypassScanner

SHELL = (
    "<!doctype html><html><head><title>App</title></head><body>"
    '<div id="root">bearer jwt "token"</div></body></html>'
)


def _resp(status=200, text="{}", ctype="application/json") -> httpx.Response:
    r = httpx.Response(
        status, headers={"content-type": ctype}, text=text,
        request=httpx.Request("POST", "https://example.com"),
    )
    r.elapsed = datetime.timedelta(milliseconds=5)
    return r


async def _scan(endpoint, post=None, request=None):
    with patch(
        "isitsecure.engine.scanners.auth_bypass_scanner.httpx.AsyncClient"
    ) as MockClient, patch(
        "isitsecure.engine.scanners.auth_bypass_scanner.asyncio.sleep",
        AsyncMock(),
    ):
        client = AsyncMock()
        client.post = post or AsyncMock(return_value=_resp(401, '{"error":"no"}'))
        client.request = request or AsyncMock(return_value=_resp(401, "{}"))
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        return await AuthBypassScanner().scan(endpoints=[endpoint])


LOGIN = DiscoveredEndpoint(
    url="https://example.com/api/login", method=EndpointMethod.POST
)
PROTECTED = DiscoveredEndpoint(
    url="https://example.com/api/profile", method=EndpointMethod.GET,
    requires_auth=True,
)


class TestDefaultCredentialVerdicts:
    @pytest.mark.asyncio
    async def test_spa_html_login_not_default_creds(self):
        async def post(url, **kw):
            return _resp(200, SHELL, "text/html")

        findings = await _scan(LOGIN, post=post)
        assert not [
            f for f in findings if f.title == AuthBypassConfig.TITLE_DEFAULT_CREDENTIALS
        ]

    @pytest.mark.asyncio
    async def test_json_without_token_field_not_default_creds(self):
        async def post(url, **kw):
            return _resp(200, '{"message": "bearer jwt token docs"}')

        findings = await _scan(LOGIN, post=post)
        assert not [
            f for f in findings if f.title == AuthBypassConfig.TITLE_DEFAULT_CREDENTIALS
        ]

    @pytest.mark.asyncio
    async def test_login_that_accepts_anything_not_default_creds(self):
        async def post(url, **kw):
            return _resp(200, '{"token": "abc123def456"}')

        findings = await _scan(LOGIN, post=post)
        assert not [
            f for f in findings if f.title == AuthBypassConfig.TITLE_DEFAULT_CREDENTIALS
        ]

    @pytest.mark.asyncio
    async def test_positive_control_real_default_login_is_critical(self):
        async def post(url, **kw):
            j = kw.get("json", {})
            if j.get("email") == "admin@admin.com" and j.get("password") == "admin":
                return _resp(200, '{"data": {"access_token": "eyJabc.def.ghi"}}')
            return _resp(401, '{"error": "Invalid credentials"}')

        findings = await _scan(LOGIN, post=post)
        crit = [
            f for f in findings if f.title == AuthBypassConfig.TITLE_DEFAULT_CREDENTIALS
        ]
        assert crit and crit[0].severity == SeverityLevel.CRITICAL


class TestHeaderBypassVerdicts:
    @pytest.mark.asyncio
    async def test_spa_html_200_not_bypass(self):
        request = AsyncMock(return_value=_resp(200, SHELL, "text/html"))
        findings = await _scan(PROTECTED, request=request)
        assert not [
            f for f in findings
            if f.title in (
                AuthBypassConfig.TITLE_AUTH_HEADER_BYPASS,
                AuthBypassConfig.TITLE_AUTH_NOT_ENFORCED,
            )
        ]

    @pytest.mark.asyncio
    async def test_public_json_endpoint_is_medium_not_high(self):
        request = AsyncMock(return_value=_resp(200, '{"items": [1, 2]}'))
        findings = await _scan(PROTECTED, request=request)
        assert not [
            f for f in findings if f.title == AuthBypassConfig.TITLE_AUTH_HEADER_BYPASS
        ]
        weak = [
            f for f in findings if f.title == AuthBypassConfig.TITLE_AUTH_NOT_ENFORCED
        ]
        assert weak and weak[0].severity == SeverityLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_positive_control_real_bypass_is_high(self):
        async def request(method, url, **kw):
            auth = kw.get("headers", {}).get("Authorization", "")
            if auth == AuthBypassConfig.CONTROL_INVALID_AUTH_HEADER:
                return _resp(401, '{"error": "unauthorized"}')
            return _resp(200, '{"id": 1, "email": "a@b.c"}')

        findings = await _scan(PROTECTED, request=request)
        hi = [
            f for f in findings if f.title == AuthBypassConfig.TITLE_AUTH_HEADER_BYPASS
        ]
        assert hi and hi[0].severity == SeverityLevel.HIGH


class TestLockoutVerdicts:
    @pytest.mark.asyncio
    async def test_429_after_few_attempts_is_not_missing_lockout(self):
        calls = {"n": 0}

        async def post(url, **kw):
            calls["n"] += 1
            # first 2 calls are username enumeration probes
            if calls["n"] > 5:
                return _resp(429, '{"error": "slow down"}')
            return _resp(401, '{"error": "Invalid credentials"}')

        findings = await _scan(LOGIN, post=post)
        assert not [
            f for f in findings if f.title == AuthBypassConfig.TITLE_NO_ACCOUNT_LOCKOUT
        ]

    @pytest.mark.asyncio
    async def test_positive_control_no_lockout_still_reported(self):
        async def post(url, **kw):
            return _resp(401, '{"error": "Invalid credentials"}')

        findings = await _scan(LOGIN, post=post)
        assert [
            f for f in findings if f.title == AuthBypassConfig.TITLE_NO_ACCOUNT_LOCKOUT
        ]
