"""One mutation finding per endpoint, and never a 'swapped ID' finding where the
id was swapped to its own value."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx

from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.idor_scanner import IDORScanner


def _client_accepting_all_writes() -> AsyncMock:
    async def fake(m, url, **kw):
        if m == "GET":
            return httpx.Response(200, headers={"content-type": "application/json"},
                                  content=b'{"data":{"id":1,"name":"x"}}')
        # every write / canary / restore succeeds and echoes the body
        body = kw.get("content")
        try:
            sent = json.loads(body) if body else {}
        except Exception:
            sent = {}
        return httpx.Response(200, headers={"content-type": "application/json"},
                              content=json.dumps({"data": {"id": 1, "name": "x", **sent}}).encode())
    c = AsyncMock()
    c.request = AsyncMock(side_effect=fake)
    return c


async def test_one_finding_per_endpoint_no_self_swap() -> None:
    ep = DiscoveredEndpoint(url="http://t/api/Products/1",
                            method=EndpointMethod.PUT, has_path_params=True)
    findings = await IDORScanner()._test_mutation_idor(
        _client_accepting_all_writes(), ep
    )
    # Exactly one finding, and never a probe against the original id (self-swap).
    assert len(findings) == 1, [f.technical_detail for f in findings]
    assert "/api/Products/2" in findings[0].technical_detail  # swapped, not 1->1
