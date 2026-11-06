"""Rate-limit oracle: "could not tell" is never HIGH, never silent (#276)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from isitsecure.engine.constants import RateLimitConfig
from isitsecure.engine.enums import EndpointMethod, SeverityLevel
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.rate_limit_scanner import (
    TITLE_RATE_LIMIT_INCONCLUSIVE,
    RateLimitScanner,
)

EP = DiscoveredEndpoint(url="https://example.com/api/login", method=EndpointMethod.POST)


def _resp(status: int, text: str = '{"error": "bad creds"}') -> MagicMock:
    r = MagicMock(spec=httpx.Response)
    r.status_code = status
    r.text = text
    return r


async def _no_sleep(*a, **k):
    return None


async def _scan(side_effect, endpoint=EP):
    with patch(
        "isitsecure.engine.scanners.rate_limit_scanner.asyncio.sleep", _no_sleep
    ), patch(
        "isitsecure.engine.scanners.rate_limit_scanner.httpx.AsyncClient"
    ) as MockClient:
        client = AsyncMock()
        client.request = AsyncMock(side_effect=side_effect)
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        return await RateLimitScanner().scan(endpoints=[endpoint]), client


def _titles(findings):
    return [f.title for f in findings]


def _inconclusive_info(findings):
    assert RateLimitConfig.TITLE_NO_RATE_LIMIT not in _titles(findings)
    inc = [f for f in findings if f.title == TITLE_RATE_LIMIT_INCONCLUSIVE]
    assert inc and all(f.severity == SeverityLevel.INFO for f in inc)
    return inc


@pytest.mark.asyncio
async def test_relative_url_is_inconclusive_and_sends_nothing():
    ep = DiscoveredEndpoint(url="/api/login", method=EndpointMethod.POST)
    findings, client = await _scan(lambda *a, **k: _resp(200), ep)
    client.request.assert_not_called()
    inc = _inconclusive_info(findings)
    assert "relative" in inc[0].description


@pytest.mark.asyncio
async def test_status_zero_is_not_counted_as_processed():
    findings, _ = await _scan(lambda *a, **k: _resp(0))
    inc = _inconclusive_info(findings)
    assert "status 0" in inc[0].description


@pytest.mark.asyncio
async def test_transport_error_on_first_request_is_inconclusive_not_silent():
    async def boom(*a, **k):
        raise httpx.ConnectError("refused")

    findings, _ = await _scan(boom)
    _inconclusive_info(findings)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [404, 405, 502])
async def test_missing_endpoint_or_server_error_is_not_no_rate_limit(status):
    findings, _ = await _scan(lambda *a, **k: _resp(status))
    _inconclusive_info(findings)


@pytest.mark.asyncio
async def test_get_html_shell_is_not_no_rate_limit():
    ep = DiscoveredEndpoint(url="https://example.com/login", method=EndpointMethod.GET)
    findings, _ = await _scan(
        lambda *a, **k: _resp(200, "<!doctype html><html><body>app</body></html>"), ep
    )
    inc = _inconclusive_info(findings)
    assert "SPA shell" in inc[0].description


@pytest.mark.asyncio
async def test_error_page_midway_is_inconclusive():
    calls = {"n": 0}

    async def handler(*a, **k):
        calls["n"] += 1
        return _resp(200) if calls["n"] <= 5 else _resp(503)

    findings, _ = await _scan(handler)
    inc = _inconclusive_info(findings)
    assert "5 usable" in inc[0].technical_detail


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 400, 401, 403, 422])
async def test_real_answers_without_429_still_report_high(status):
    """Recall guard: a login endpoint answering 401/400 every time is unlimited."""
    findings, _ = await _scan(lambda *a, **k: _resp(status))
    high = [f for f in findings if f.title == RateLimitConfig.TITLE_NO_RATE_LIMIT]
    assert len(high) == 1 and high[0].severity == SeverityLevel.HIGH


@pytest.mark.asyncio
async def test_post_html_answer_still_reports_high():
    """Recall guard: a server-rendered POST login answering HTML is a real answer."""
    findings, _ = await _scan(
        lambda *a, **k: _resp(200, "<html><body>invalid login</body></html>")
    )
    assert RateLimitConfig.TITLE_NO_RATE_LIMIT in _titles(findings)


@pytest.mark.asyncio
async def test_429_after_n_processed_is_threshold_info():
    calls = {"n": 0}

    async def handler(*a, **k):
        calls["n"] += 1
        return _resp(429) if calls["n"] > 7 else _resp(200)

    findings, _ = await _scan(handler)
    thr = [f for f in findings if f.title == RateLimitConfig.TITLE_RATE_LIMIT_THRESHOLD]
    assert thr and "7 requests" in thr[0].evidence


@pytest.mark.asyncio
async def test_second_identity_error_page_is_not_a_bypass():
    scanner = RateLimitScanner()
    client = AsyncMock()

    async def req(*a, **k):
        auth = k.get("headers", {}).get("Authorization", "")
        return _resp(429) if auth == RateLimitConfig.TEST_AUTH_HEADER_ALPHA else _resp(502)

    client.request = req
    assert await scanner._test_ip_vs_user_rate_limit(client, EP) is None


@pytest.mark.asyncio
async def test_burst_counts_only_processed_responses():
    scanner = RateLimitScanner()
    client = AsyncMock()
    seq = {"i": 0}

    async def req(*a, **k):
        seq["i"] += 1
        return _resp(429) if seq["i"] == 10 else _resp(503)

    client.request = req
    # 9 responses were server errors, so none counts as "succeeded before 429".
    assert await scanner._test_burst_sizes(client, EP) == []
