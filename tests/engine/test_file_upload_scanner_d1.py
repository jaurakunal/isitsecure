"""D1 / B1 #9: a bare 2xx is not upload acceptance."""

from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.constants import FileUploadConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.file_upload_scanner import FileUploadScanner

URL = "https://example.com/upload"


def _resp(body: str, status: int = 200, headers: dict | None = None) -> httpx.Response:
    return httpx.Response(
        status, text=body, headers={"content-type": "application/json", **(headers or {})}
    )


async def _scan(post, get=None):
    with patch("isitsecure.engine.scanners.file_upload_scanner.RateLimitedClient") as mc:
        inst = AsyncMock()
        inst.post = post
        if get is not None:
            inst.get = get
        mc.return_value.__aenter__ = AsyncMock(return_value=inst)
        mc.return_value.__aexit__ = AsyncMock(return_value=False)
        ep = DiscoveredEndpoint(url=URL, method=EndpointMethod.POST)
        return await FileUploadScanner().scan([ep])


def _titles(findings):
    return {f.title for f in findings}


@pytest.mark.asyncio
async def test_200_with_failure_body_is_not_accepted() -> None:
    async def post(url, **kw):
        return _resp('{"success": false, "error": "invalid file"}')

    assert await _scan(post) == []


@pytest.mark.asyncio
async def test_200_with_generic_success_and_no_reference_is_low_tier_only() -> None:
    """No storage evidence: only the Medium/<=0.4 tier, never High/traversal."""

    async def post(url, **kw):
        return _resp('{"success": true}')

    findings = await _scan(post)
    assert FileUploadConfig.TITLE_PATH_TRAVERSAL not in _titles(findings)
    assert findings and all(
        f.severity.value == "medium" and f.confidence <= 0.4 for f in findings
    )


@pytest.mark.asyncio
async def test_sanitising_server_not_flagged_for_traversal() -> None:
    """Server stores only the basename: echoes 'passwd', no traversal finding."""

    async def post(url, **kw):
        name = os.path.basename(kw["files"]["file"][0].replace("\\", "/"))
        return _resp(json.dumps({"success": True, "file": name}))

    findings = await _scan(post)
    assert FileUploadConfig.TITLE_PATH_TRAVERSAL not in _titles(findings)


@pytest.mark.asyncio
async def test_stored_and_served_html_is_flagged() -> None:
    """Positive control: upload really stores and serves back the .html file."""
    store: dict[str, str] = {}

    async def post(url, **kw):
        name, content, _ = kw["files"]["file"]
        store["/files/" + name] = content.decode()
        return _resp(json.dumps({"success": True, "url": "/files/" + name}))

    async def get(url, **kw):
        path = url.replace("https://example.com", "")
        if path in store:
            return httpx.Response(200, text=store[path])
        return httpx.Response(404, text="nope")

    findings = await _scan(post, get)
    type_findings = [f for f in findings if f.title == FileUploadConfig.TITLE_UNRESTRICTED_TYPE]
    assert type_findings
    assert "serves the uploaded file" in type_findings[0].evidence


@pytest.mark.asyncio
async def test_unsanitised_name_echo_flags_traversal() -> None:
    """Positive control: server echoes the raw traversal filename it stored."""

    async def post(url, **kw):
        return _resp(json.dumps({"success": True, "path": "uploads/" + kw["files"]["file"][0]}))

    findings = await _scan(post)
    assert FileUploadConfig.TITLE_PATH_TRAVERSAL in _titles(findings)
