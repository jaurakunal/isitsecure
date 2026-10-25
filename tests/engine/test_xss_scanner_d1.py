"""D1 / B1 #8: POST-body content-type gate; quote-only probes are not "confirmed"."""

from __future__ import annotations

import datetime
import json
import re
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from isitsecure.engine.constants import XSSConfig
from isitsecure.engine.models import SeverityLevel
from isitsecure.engine.scanners.endpoint_discovery import DiscoveredEndpoint, EndpointMethod
from isitsecure.engine.scanners.xss_scanner import XSSScanner


def _resp(body: str, ctype: str, method: str = "GET", status: int = 200) -> httpx.Response:
    r = httpx.Response(
        status, headers={"content-type": ctype}, text=body,
        request=httpx.Request(method, "https://example.com"),
    )
    r.elapsed = datetime.timedelta(milliseconds=5)
    return r


def _post_client(ctype: str, *, wrap_json: bool):
    async def _request(method, url, **kwargs):
        body = kwargs.get("data")
        if body is None:
            body = json.loads(kwargs.get("content") or "{}")
        text = json.dumps({"created": body}) if wrap_json else (
            "<html><body>" + "".join(str(v) for v in body.values()) + "</body></html>"
        )
        return _resp(text, ctype, "POST", 201)

    client = MagicMock()
    client.request = AsyncMock(side_effect=_request)
    client.get = AsyncMock(side_effect=lambda *a, **k: _resp("[]", "application/json"))
    return client


_EP = DiscoveredEndpoint(
    url="https://example.com/comments", method=EndpointMethod.POST,
    query_param_names=["name"],
)


@pytest.mark.asyncio
async def test_post_body_json_echo_is_not_xss() -> None:
    finding = await XSSScanner()._test_single_post_body(
        _post_client("application/json", wrap_json=True), _EP,
    )
    assert finding is None


@pytest.mark.asyncio
async def test_post_body_html_echo_still_confirmed() -> None:
    """Positive control: unescaped reflection in text/html stays HIGH confirmed."""
    finding = await XSSScanner()._test_single_post_body(
        _post_client("text/html; charset=utf-8", wrap_json=False), _EP,
    )
    assert finding is not None
    assert finding.severity == SeverityLevel.HIGH
    assert finding.confidence == XSSConfig.CONFIDENCE_POST_BODY_REFLECTED


async def _scan_get(handler):
    with patch("isitsecure.engine.scanners.xss_scanner.RateLimitedClient") as mock_client:
        inst = AsyncMock()
        inst.get = handler
        mock_client.return_value.__aenter__ = AsyncMock(return_value=inst)
        mock_client.return_value.__aexit__ = AsyncMock(return_value=False)
        ep = DiscoveredEndpoint(
            url="https://example.com/search?q=test", method=EndpointMethod.GET,
            query_param_names=["q"],
        )
        return await XSSScanner().scan([ep])


@pytest.mark.asyncio
async def test_tag_stripping_server_with_quote_echo_is_not_confirmed() -> None:
    async def handler(url: str, **kwargs: object) -> httpx.Response:
        injected = parse_qs(urlparse(url).query).get("q", [""])[0]
        stripped = re.sub(r"<[^>]*>", "", injected)
        return _resp(f"<html><body><p>Results: {stripped}</p></body></html>", "text/html")

    findings = await _scan_get(handler)
    assert not any(f.severity == SeverityLevel.HIGH for f in findings)


@pytest.mark.asyncio
async def test_unescaped_angle_bracket_reflection_still_confirmed() -> None:
    async def handler(url: str, **kwargs: object) -> httpx.Response:
        injected = parse_qs(urlparse(url).query).get("q", [""])[0]
        return _resp(f"<html><body>Results: {injected}</body></html>", "text/html")

    findings = await _scan_get(handler)
    assert any(
        f.severity == SeverityLevel.HIGH
        and f.confidence == XSSConfig.CONFIDENCE_REFLECTED_CONFIRMED
        for f in findings
    )
