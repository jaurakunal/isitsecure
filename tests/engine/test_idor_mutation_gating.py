"""Mutation-IDOR probes write to/delete from the target, so they run ONLY under
--probe-writes, and authenticate (for the auth-gated write/delete) when a
session is available. Read/swap probes are unaffected — they stay anonymous.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.idor_scanner import IDORScanner


def _mutation_endpoint():
    return DiscoveredEndpoint(url="http://t/api/Feedbacks/1",
                             method=EndpointMethod.DELETE, has_path_params=True)


@asynccontextmanager
async def _dummy_client(*a, **k):
    c = AsyncMock()
    c.request = AsyncMock(return_value=MagicMock(status_code=404, text="",
                          headers={"content-type": "text/html"}))
    yield c


async def _run(probe_writes: bool, auth: dict | None):
    sc = IDORScanner(probe_writes=probe_writes)
    if auth:
        sc._auth_headers = auth
    captured = {}

    @asynccontextmanager
    async def spy_client(*a, **k):
        captured.setdefault("headers", []).append(k.get("extra_headers"))
        c = AsyncMock()
        c.request = AsyncMock(return_value=MagicMock(
            status_code=404, text="", headers={"content-type": "text/html"}))
        yield c

    with patch("isitsecure.engine.scanners.idor_scanner.RateLimitedClient", spy_client):
        with patch.object(sc, "_test_mutation_idor", AsyncMock(return_value=[])) as mut:
            with patch.object(sc, "_test_endpoint", AsyncMock(return_value=MagicMock())):
                await sc.scan([_mutation_endpoint()])
    return mut.call_count, captured.get("headers", [])


async def test_mutation_probes_skipped_without_probe_writes() -> None:
    calls, _ = await _run(probe_writes=False, auth={"Authorization": "Bearer T"})
    assert calls == 0


async def test_mutation_probes_run_with_probe_writes() -> None:
    calls, _ = await _run(probe_writes=True, auth=None)
    assert calls >= 1


async def test_mutation_client_carries_auth_when_available() -> None:
    calls, header_sets = await _run(probe_writes=True, auth={"Cookie": "token=T"})
    assert calls >= 1
    # one of the clients opened for mutation carried the auth headers
    assert any(h == {"Cookie": "token=T"} for h in header_sets if h)
