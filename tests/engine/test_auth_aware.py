"""Tests for the auth-aware DAST scanner mixin (#115)."""

import datetime

import httpx
import pytest

from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.factory import create_deep_security_scan_agent
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.csrf_scanner import CSRFScanner
from isitsecure.engine.shared.auth_aware import AuthAwareScanner

# The HTTP-probing quick-depth DAST scanners that must carry the session (#115).
_HTTP_DAST = {
    "ActiveInjectionScanner", "CSRFScanner", "SSRFScanner", "MassAssignmentScanner",
    "OpenRedirectScanner", "HTTPProbeScanner", "FileUploadScanner", "GraphQLScanner",
    "CORSScanner", "SecurityHeadersScanner", "SourceMapScanner",
}


class TestMixin:
    def test_default_is_none(self):
        assert AuthAwareScanner().auth_headers is None

    def test_returns_set_headers(self):
        s = AuthAwareScanner()
        s._auth_headers = {"Cookie": "connect.sid=abc"}
        assert s.auth_headers == {"Cookie": "connect.sid=abc"}

    def test_empty_dict_is_none(self):
        s = AuthAwareScanner()
        s._auth_headers = {}
        assert s.auth_headers is None


def test_http_dast_scanners_are_auth_aware():
    """Every HTTP-probing quick-depth DAST scanner inherits the mixin, so the
    authenticated scan path can hand it the session."""
    agent = create_deep_security_scan_agent()
    aware = {type(s).__name__ for s in agent._dast_scanners if isinstance(s, AuthAwareScanner)}
    missing = _HTTP_DAST - aware
    assert not missing, f"HTTP DAST scanners missing auth support: {missing}"


@pytest.mark.asyncio
async def test_csrf_scanner_passes_auth_headers_to_client(monkeypatch):
    """A representative scanner threads its _auth_headers into the HTTP client."""
    captured: dict = {}

    class _FakeClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, *a, **k):
            r = httpx.Response(200, headers={"content-type": "text/html"}, text="",
                               request=httpx.Request("POST", "https://ex.com/x"))
            r.elapsed = datetime.timedelta(milliseconds=1)
            return r

        async def get(self, *a, **k):
            return await self.request("GET", *a, **k)

    monkeypatch.setattr(
        "isitsecure.engine.scanners.csrf_scanner.RateLimitedClient", _FakeClient
    )
    scanner = CSRFScanner()
    scanner._auth_headers = {"Cookie": "connect.sid=abc"}
    ep = DiscoveredEndpoint(url="https://ex.com/transfer", method=EndpointMethod.POST)
    await scanner.scan([ep], snapshot=None)
    assert captured.get("extra_headers") == {"Cookie": "connect.sid=abc"}


@pytest.mark.asyncio
async def test_unauthenticated_scanner_passes_none_to_client(monkeypatch):
    """With no auth injected, the scanner must pass extra_headers=None (not {})
    so an unauthenticated scan behaves exactly as before #115."""
    captured: dict = {}

    class _FakeClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, *a, **k):
            r = httpx.Response(200, headers={"content-type": "text/html"}, text="",
                               request=httpx.Request("POST", "https://ex.com/x"))
            r.elapsed = datetime.timedelta(milliseconds=1)
            return r

        async def get(self, *a, **k):
            return await self.request("GET", *a, **k)

    monkeypatch.setattr(
        "isitsecure.engine.scanners.csrf_scanner.RateLimitedClient", _FakeClient
    )
    scanner = CSRFScanner()  # _auth_headers left at the empty default
    ep = DiscoveredEndpoint(url="https://ex.com/transfer", method=EndpointMethod.POST)
    await scanner.scan([ep], snapshot=None)
    assert captured.get("extra_headers") is None


def test_propagation_gives_each_scanner_an_isolated_copy():
    """Mirror the orchestrator's propagation (agent.py): the guard hits every
    HTTP DAST scanner, and each gets its OWN copy of the crawl auth — mutating
    one scanner's headers must not leak into another or into the source dict."""
    agent = create_deep_security_scan_agent()
    crawl_auth = {"Cookie": "connect.sid=abc"}

    # This is exactly the loop in agent.py's authenticated path.
    for scanner in agent._dast_scanners:
        if hasattr(scanner, "_auth_headers"):
            scanner._auth_headers = dict(crawl_auth)

    aware = [s for s in agent._dast_scanners if isinstance(s, AuthAwareScanner)]
    assert aware, "expected some auth-aware scanners"
    for s in aware:
        assert s.auth_headers == {"Cookie": "connect.sid=abc"}
        assert s._auth_headers is not crawl_auth  # fresh per-instance copy

    # Mutating one scanner's copy leaks nowhere.
    aware[0]._auth_headers["Cookie"] = "tampered"
    assert crawl_auth == {"Cookie": "connect.sid=abc"}
    assert aware[1].auth_headers == {"Cookie": "connect.sid=abc"}
