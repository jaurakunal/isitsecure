"""Tests for the consecutive-transport-failure tracker and its client hook."""

from __future__ import annotations

import httpx
import pytest
import respx

from isitsecure.engine.shared.rate_limited_client import (
    RateLimitedClient,
    TargetUnresponsiveError,
)
from isitsecure.engine.shared.target_health import (
    UNRESPONSIVE_STREAK,
    TargetHealth,
)

URL = "https://t.example/api"


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class TestTargetHealth:
    def test_threshold_is_a_named_constant(self) -> None:
        assert UNRESPONSIVE_STREAK == 3

    def test_tips_unresponsive_at_streak(self) -> None:
        h = TargetHealth()
        results = [h.note_failure(URL) for _ in range(UNRESPONSIVE_STREAK)]
        assert results == [False] * (UNRESPONSIVE_STREAK - 1) + [True]
        assert h.is_unresponsive(URL)

    def test_success_resets_streak(self) -> None:
        h = TargetHealth()
        for _ in range(UNRESPONSIVE_STREAK - 1):
            h.note_failure(URL)
        h.note_success(URL)
        h.note_failure(URL)
        assert not h.is_unresponsive(URL)

    def test_hosts_are_independent(self) -> None:
        h = TargetHealth()
        for _ in range(UNRESPONSIVE_STREAK):
            h.note_failure(URL)
        assert h.should_send("https://other.example/x")

    def test_refuses_then_probes_after_interval_and_counts(self) -> None:
        clock = _Clock()
        h = TargetHealth(probe_interval=10, clock=clock)
        for _ in range(UNRESPONSIVE_STREAK):
            h.note_failure(URL)
        assert h.should_send(URL)  # first probe goes out
        assert not h.should_send(URL)
        assert h.suppressed == 1
        clock.now = 11
        assert h.should_send(URL)  # next probe window
        h.note_success(URL)
        assert not h.is_unresponsive(URL)
        assert h.should_send(URL)


class TestRateLimitedClientHook:
    @pytest.mark.asyncio
    async def test_stops_sending_after_streak(self) -> None:
        health = TargetHealth(probe_interval=1e9)
        with respx.mock:
            route = respx.get(URL).mock(side_effect=httpx.ConnectTimeout("t"))
            async with RateLimitedClient(1, 0, 1, "ua", health=health) as c:
                for _ in range(UNRESPONSIVE_STREAK):
                    with pytest.raises(httpx.ConnectTimeout):
                        await c.get(URL)
                sent = route.call_count
                # first call after the tip is the single liveness probe
                with pytest.raises(httpx.ConnectTimeout):
                    await c.get(URL)
                # then requests are refused without touching the network
                with pytest.raises(TargetUnresponsiveError):
                    await c.get(URL)
                assert route.call_count == sent + 1
        assert health.suppressed == 1

    @pytest.mark.asyncio
    async def test_http_error_status_is_an_answer(self) -> None:
        health = TargetHealth()
        with respx.mock:
            respx.get(URL).mock(return_value=httpx.Response(503))
            async with RateLimitedClient(1, 0, 1, "ua", health=health) as c:
                for _ in range(UNRESPONSIVE_STREAK + 2):
                    assert (await c.get(URL)).status_code == 503
        assert not health.is_unresponsive(URL)

    @pytest.mark.asyncio
    async def test_no_health_is_unchanged_behaviour(self) -> None:
        with respx.mock:
            respx.get(URL).mock(side_effect=httpx.ConnectTimeout("t"))
            async with RateLimitedClient(1, 0, 1, "ua") as c:
                for _ in range(UNRESPONSIVE_STREAK + 2):
                    with pytest.raises(httpx.ConnectTimeout):
                        await c.get(URL)
