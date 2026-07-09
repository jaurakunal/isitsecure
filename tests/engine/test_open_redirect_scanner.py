"""Tests for the open-redirect scanner, incl. the allowlist-bypass payload."""

from urllib.parse import parse_qs, urlparse

from isitsecure.engine.constants import OpenRedirectConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.open_redirect_scanner import OpenRedirectScanner


class _Resp:
    def __init__(self, status, headers=None, text=""):
        self.status_code = status
        self.headers = headers or {}
        self.text = text


class _AllowlistClient:
    """Simulates an app with a substring allowlist: only redirects when the
    payload contains the trusted value; plain payloads get 406."""

    def __init__(self, trusted: str):
        self._trusted = trusted

    async def get(self, url):
        to = parse_qs(urlparse(url).query).get("to", [""])[0]
        if self._trusted in to and "evil.com" in to:
            return _Resp(302, {"location": to})   # redirect goes to evil.com host
        return _Resp(406)


class TestAllowlistBypass:
    async def test_to_param_is_recognized(self):
        assert "to" in OpenRedirectConfig.REDIRECT_PARAM_NAMES

    async def test_bypass_payload_detects_allowlisted_redirect(self):
        ep = DiscoveredEndpoint(
            url="http://app/redirect?to=https://trusted.com/x",
            method=EndpointMethod.GET, query_param_names=["to"])
        client = _AllowlistClient(trusted="trusted.com")
        findings = await OpenRedirectScanner()._test_endpoint_param(
            client, ep, "to")
        assert findings, "allowlist-bypass payload should be detected"
        assert "trusted.com" in findings[0].request_payload  # embeds allowed value

    async def test_no_bypass_when_no_existing_value(self):
        # Same allowlist app, but the endpoint carries no existing value to
        # embed -> plain payloads stay blocked -> no finding.
        ep = DiscoveredEndpoint(
            url="http://app/redirect", method=EndpointMethod.GET,
            query_param_names=["to"])
        client = _AllowlistClient(trusted="trusted.com")
        findings = await OpenRedirectScanner()._test_endpoint_param(
            client, ep, "to")
        assert findings == []
