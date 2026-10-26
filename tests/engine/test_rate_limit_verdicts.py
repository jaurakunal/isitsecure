"""Rate-limit scanner verdict regressions (batch D2)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from isitsecure.engine.constants import RateLimitConfig
from isitsecure.engine.enums import EndpointMethod, SeverityLevel
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.rate_limit_scanner import RateLimitScanner

EP = DiscoveredEndpoint(
    url="https://example.com/api/login", method=EndpointMethod.POST
)


def _resp(status: int) -> MagicMock:
    r = MagicMock(spec=httpx.Response)
    r.status_code = status
    r.text = "OK"
    return r


async def _no_sleep(*a, **k):
    return None


async def _scan(side_effect):
    with patch(
        "isitsecure.engine.scanners.rate_limit_scanner.asyncio.sleep", _no_sleep
    ), patch(
        "isitsecure.engine.scanners.rate_limit_scanner.httpx.AsyncClient"
    ) as MockClient:
        client = AsyncMock()
        client.request = AsyncMock(side_effect=side_effect)
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        return await RateLimitScanner().scan(endpoints=[EP])


@pytest.mark.asyncio
async def test_connection_reset_after_n_requests_is_not_high():
    """A server that resets the connection after 8 requests is throttling."""
    calls = {"n": 0}

    async def handler(*a, **k):
        calls["n"] += 1
        if calls["n"] > 8:
            raise httpx.ReadError("connection reset")
        return _resp(200)

    findings = await _scan(handler)
    assert not [f for f in findings if f.title == RateLimitConfig.TITLE_NO_RATE_LIMIT]
    assert not [f for f in findings if f.severity == SeverityLevel.HIGH]
    # Observed cut-off is kept as an informational note, not silent.
    assert [f for f in findings if f.severity == SeverityLevel.INFO]


@pytest.mark.asyncio
async def test_positive_control_no_429_is_still_high():
    async def ok(*a, **k):
        return _resp(200)

    findings = await _scan(ok)
    high = [f for f in findings if f.title == RateLimitConfig.TITLE_NO_RATE_LIMIT]
    assert len(high) == 1
    assert high[0].severity == SeverityLevel.HIGH
    n = RateLimitConfig.MAX_SEQUENTIAL_REQUESTS
    assert f"{n}/{n}" in high[0].evidence


@pytest.mark.asyncio
async def test_burst_threshold_finding_is_info_not_medium():
    scanner = RateLimitScanner()
    client = AsyncMock()
    seq = {"i": 0}

    async def req(*a, **k):
        seq["i"] += 1
        return _resp(429 if seq["i"] % 5 == 0 else 200)

    client.request = req
    out = await scanner._test_burst_sizes(client, EP)
    assert out and all(f.severity == SeverityLevel.INFO for f in out)


@pytest.mark.asyncio
async def test_header_keyed_limit_finding_text_matches_trigger():
    scanner = RateLimitScanner()
    client = AsyncMock()

    async def req(*a, **k):
        auth = k.get("headers", {}).get("Authorization", "")
        if auth == RateLimitConfig.TEST_AUTH_HEADER_ALPHA:
            return _resp(429)
        return _resp(200)

    client.request = req
    f = await scanner._test_ip_vs_user_rate_limit(client, EP)
    assert f is not None
    text = (f.description + f.technical_detail).lower()
    assert "authorization" in text
    assert "not per ip" in f.description.lower()
    assert "per-user, not per-ip" not in text
