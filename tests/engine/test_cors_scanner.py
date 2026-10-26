"""Tests for CORSScanner verdict rules."""

from __future__ import annotations

import httpx
import pytest

from isitsecure.engine.enums import EndpointMethod, SeverityLevel
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.cors_scanner import CORSScanner

URL = "https://api.example.com/api/me"


def _ep() -> DiscoveredEndpoint:
    return DiscoveredEndpoint(url=URL, method=EndpointMethod.GET)


def _classify(origin, acao, creds, label="x"):
    return CORSScanner()._classify_cors_response(
        _ep(), origin, label, acao, creds, 200,
    )


class TestCorsClassification:
    def test_null_origin_rule_reachable(self):
        f = _classify("null", "null", False, "null_origin")
        assert f is not None
        assert f.title == "CORS allows null origin"

    def test_null_origin_with_credentials_is_high(self):
        f = _classify("null", "null", True, "null_origin")
        assert f.title == "CORS allows null origin"
        assert f.severity == SeverityLevel.HIGH

    def test_null_origin_without_credentials_is_medium(self):
        assert _classify("null", "null", False).severity == SeverityLevel.MEDIUM

    def test_reflected_origin_without_credentials_is_medium(self):
        f = _classify("https://evil.com", "https://evil.com", False)
        assert f is not None
        assert f.severity == SeverityLevel.MEDIUM

    def test_positive_control_reflected_with_credentials_is_high(self):
        f = _classify("https://evil.com", "https://evil.com", True)
        assert f.severity == SeverityLevel.HIGH
        assert f.title == "CORS reflects arbitrary Origin header"

    def test_positive_control_wildcard_credentials_is_critical(self):
        f = _classify("https://evil.com", "*", True)
        assert f.severity == SeverityLevel.CRITICAL

    def test_wildcard_without_credentials_is_medium(self):
        assert _classify("https://evil.com", "*", False).severity == SeverityLevel.MEDIUM


@pytest.mark.asyncio
async def test_null_only_server_end_to_end(monkeypatch):
    """A server that allows only Origin: null reports the null-origin title."""

    from datetime import timedelta

    from isitsecure.engine.shared.rate_limited_client import RateLimitedClient

    async def fake_get(self, url, **kwargs):
        headers = {}
        if kwargs.get("headers", {}).get("Origin") == "null":
            headers["Access-Control-Allow-Origin"] = "null"
        resp = httpx.Response(
            200, json={}, headers=headers,
            request=httpx.Request("GET", url, headers=kwargs.get("headers")),
        )
        resp.elapsed = timedelta(0)
        return resp

    monkeypatch.setattr(RateLimitedClient, "get", fake_get)
    findings = await CORSScanner().scan([_ep()])
    assert [f.title for f in findings] == ["CORS allows null origin"]
