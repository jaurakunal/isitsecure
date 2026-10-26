"""Mass assignment: echoing endpoints are read back; transient control failure is not fatal."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.constants import MassAssignmentConfig
from isitsecure.engine.enums import EndpointMethod, SeverityLevel
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.mass_assignment_scanner import MassAssignmentScanner

BASE = "https://example.com/api/users"
EP = DiscoveredEndpoint(url=BASE, method=EndpointMethod.POST)


def _resp(body, status: int = 200):
    return httpx.Response(
        status, headers={"content-type": "application/json"}, text=json.dumps(body),
    )


async def _scan(handler):
    with patch(
        "isitsecure.engine.scanners.mass_assignment_scanner.RateLimitedClient"
    ) as MockClient:
        client = AsyncMock()
        client.request = handler
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        return await MassAssignmentScanner().scan([EP])


def _schemaless_server():
    """Persists ANY posted field and returns (and later serves) the stored object."""
    store: dict[str, dict] = {}

    async def handler(method, url, **kw):
        if method == "POST":
            obj = json.loads(kw["content"])
            oid = str(len(store) + 1)
            obj["id"] = oid
            store[oid] = obj
            return _resp(obj, 201)
        if url == BASE:
            return _resp(list(store.values()))
        return _resp(store[url.rsplit("/", 1)[1]]) if url.rsplit("/", 1)[1] in store \
            else _resp({}, 404)

    return handler


@pytest.mark.asyncio
async def test_persisting_schemaless_server_is_high():
    findings = await _scan(_schemaless_server())
    high = [f for f in findings if f.title == MassAssignmentConfig.TITLE_MASS_ASSIGNMENT]
    assert high and all(f.severity == SeverityLevel.HIGH for f in high)
    assert any('"role"' in f.request_payload for f in high)
    assert not [f for f in findings if f.title == MassAssignmentConfig.TITLE_ECHO_ONLY]


@pytest.mark.asyncio
async def test_pure_echo_server_is_one_low_note():
    async def handler(method, url, **kw):
        if method == "POST":
            return _resp({"received": json.loads(kw["content"])})
        return _resp([], 200)  # nothing is ever stored

    findings = await _scan(handler)
    assert len(findings) == 1
    assert findings[0].severity == SeverityLevel.LOW
    assert findings[0].title == MassAssignmentConfig.TITLE_ECHO_ONLY


@pytest.mark.asyncio
async def test_collection_with_preexisting_admin_is_not_read_back_proof():
    """An unrelated admin row in the collection must not count as persistence."""
    async def handler(method, url, **kw):
        if method == "POST":
            return _resp({"received": json.loads(kw["content"])})
        return _resp([{"id": 9, "role": "admin", "is_admin": True}])

    findings = await _scan(handler)
    assert not [f for f in findings if f.severity == SeverityLevel.HIGH]


@pytest.mark.asyncio
async def test_transient_control_failure_keeps_findings_with_lower_confidence():
    schemaless = {"n": 0}
    allowed = {f for f, _ in MassAssignmentConfig.ESCALATION_FIELDS}

    async def handler(method, url, **kw):
        schemaless["n"] += 1
        if schemaless["n"] == 1:  # the echo-control request
            raise httpx.ConnectError("transient")
        sent = json.loads(kw["content"])
        stored = {"id": 1}
        stored.update({k: v for k, v in sent.items() if k in allowed})
        return _resp(stored)

    findings = await _scan(handler)
    high = [f for f in findings if f.title == MassAssignmentConfig.TITLE_MASS_ASSIGNMENT]
    assert high
    assert all(f.confidence < MassAssignmentConfig.CONFIDENCE_MASS_ASSIGNMENT for f in high)
