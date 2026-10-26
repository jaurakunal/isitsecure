"""Body-param fuzzer verdict regressions (batch D2)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import BodyParamFuzzerConfig
from isitsecure.engine.enums import AuthProvider, SeverityLevel
from isitsecure.engine.models import InterceptedRequest
from isitsecure.engine.scanners.body_param_fuzzer import BodyParamFuzzer

URL = "https://example.com/api/notes"


def _session() -> AuthSession:
    return AuthSession(
        user_id="u", access_token="t", provider=AuthProvider.SUPABASE,
    )


def _req(**kw) -> InterceptedRequest:
    base = dict(
        url=URL, method="POST", response_status=201,
        request_body='{"text": "hello"}', request_headers={},
    )
    base.update(kw)
    return InterceptedRequest(**base)


def _resp(status: int, text: str) -> httpx.Response:
    return httpx.Response(
        status, text=text, request=httpx.Request("POST", URL),
    )


async def _run(handler, req=None):
    client = AsyncMock()
    client.request = handler
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    with patch(
        "isitsecure.engine.scanners.body_param_fuzzer.RateLimitedClient",
        return_value=client,
    ):
        return await BodyParamFuzzer().scan([req or _req()], _session())


class TestSqliVerdicts:
    @pytest.mark.asyncio
    async def test_generic_html_500_is_not_critical_sqli(self):
        async def handler(method, url, **kw):
            return _resp(500, "<h1>Internal Server Error</h1> TypeError Traceback")

        findings = await _run(handler)
        assert not [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        sqli = [f for f in findings if "SQL injection" in f.title]
        # Kept as a lower-confidence tier, not silent.
        assert sqli and all(f.severity == SeverityLevel.MEDIUM for f in sqli)
        assert all("Possible" in f.title for f in sqli)

    @pytest.mark.asyncio
    async def test_db_error_present_in_baseline_not_reported(self):
        async def handler(method, url, **kw):
            return _resp(200, "ERROR: SQL syntax in cached page")

        findings = await _run(
            handler,
            _req(response_body_preview="ERROR: SQL syntax in cached page"),
        )
        assert not [f for f in findings if "SQL injection" in f.title]

    @pytest.mark.asyncio
    async def test_positive_control_real_db_error_is_critical(self):
        async def handler(method, url, **kw):
            if "'" in kw.get("content", ""):
                return _resp(
                    500, 'error: syntax error at or near "OR" (SQLSTATE 42601)'
                )
            return _resp(200, '{"ok": true}')

        findings = await _run(handler)
        crit = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        assert crit and "SQL injection via JSON body" in crit[0].title

    def test_no_destructive_payload(self):
        for p in BodyParamFuzzerConfig.SQLI_PAYLOADS:
            assert "DROP" not in p.upper()


class TestPrototypePollutionVerdicts:
    @pytest.mark.asyncio
    async def test_ignored_unknown_key_is_not_high(self):
        async def handler(method, url, **kw):
            return _resp(200, '{"ok": true}')

        findings = await _run(handler)
        assert not [
            f for f in findings
            if f.severity == SeverityLevel.HIGH and "Prototype" in f.title
        ]

    @pytest.mark.asyncio
    async def test_echo_server_is_not_high(self):
        async def handler(method, url, **kw):
            return _resp(200, kw.get("content", ""))

        findings = await _run(handler)
        assert not [
            f for f in findings
            if f.severity == SeverityLevel.HIGH and "Prototype" in f.title
        ]

    @pytest.mark.asyncio
    async def test_positive_control_polluted_state_is_high(self):
        state = {"polluted": False}
        marker = BodyParamFuzzerConfig.PROTOTYPE_POLLUTION_MARKER

        async def handler(method, url, **kw):
            content = kw.get("content", "")
            if "__proto__" in content or "constructor" in content:
                state["polluted"] = True
            data = {"ok": True}
            if state["polluted"]:
                data["polluted"] = marker
            return _resp(200, json.dumps(data))

        findings = await _run(handler)
        high = [
            f for f in findings
            if f.severity == SeverityLevel.HIGH and "Prototype pollution" in f.title
        ]
        assert high
