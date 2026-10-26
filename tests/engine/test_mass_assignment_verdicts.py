"""Mass-assignment verdict regressions (batch D2)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.constants import MassAssignmentConfig
from isitsecure.engine.enums import EndpointMethod, SeverityLevel
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.mass_assignment_scanner import (
    MassAssignmentScanner,
)

EP = DiscoveredEndpoint(
    url="https://example.com/api/users", method=EndpointMethod.POST
)


def _resp(body: str, ctype: str = "application/json", status: int = 200):
    return httpx.Response(status, headers={"content-type": ctype}, text=body)


async def _scan(handler):
    with patch(
        "isitsecure.engine.scanners.mass_assignment_scanner.RateLimitedClient"
    ) as MockClient:
        client = AsyncMock()
        client.request = handler
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        return await MassAssignmentScanner().scan([EP])


@pytest.mark.asyncio
async def test_html_catch_all_not_reported():
    html = (
        "<!doctype html><html><body>role admin permissions all is_admin true"
        "</body></html>"
    )

    async def handler(method, url, **kw):
        return _resp(html, "text/html")

    assert await _scan(handler) == []


@pytest.mark.asyncio
async def test_pure_echo_endpoint_is_one_low_note_not_many_high():
    async def handler(method, url, **kw):
        return _resp(json.dumps({"received": json.loads(kw["content"])}))

    findings = await _scan(handler)
    assert not [f for f in findings if f.severity == SeverityLevel.HIGH]
    assert len(findings) == 1
    assert findings[0].severity == SeverityLevel.LOW
    assert findings[0].title == MassAssignmentConfig.TITLE_ECHO_ONLY


@pytest.mark.asyncio
async def test_positive_control_persisted_privileged_field_is_high():
    """The server merges only the privileged fields into the stored object."""
    allowed = {f for f, _ in MassAssignmentConfig.ESCALATION_FIELDS}

    async def handler(method, url, **kw):
        sent = json.loads(kw["content"])
        stored = {"id": 1, "name": "x"}
        stored.update({k: v for k, v in sent.items() if k in allowed})
        return _resp(json.dumps(stored))

    findings = await _scan(handler)
    high = [
        f for f in findings
        if f.title == MassAssignmentConfig.TITLE_MASS_ASSIGNMENT
    ]
    assert high and all(f.severity == SeverityLevel.HIGH for f in high)
