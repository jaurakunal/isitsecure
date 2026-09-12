"""Blind SSRF where the URL sink is a POST-body form field, not a query param.

Juice Shop's SSRF (and cross-site-imaging) lives in `imageUrl` on
`POST /profile/image/url` — an auth-gated, server-rendered form. The query-only
injector never reaches it. These tests pin the body injector and its targeting.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs

from isitsecure.engine.agent import DeepSecurityScanAgent
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import DiscoveredEndpoint


class TestIsUrlParam:
    def test_camelcase_compounds_match(self) -> None:
        for name in ("imageUrl", "avatarUrl", "callbackUri", "profileImage", "webhook"):
            assert DeepSecurityScanAgent._is_url_param(name), name

    def test_plain_names_match(self) -> None:
        for name in ("url", "uri", "src", "redirect"):
            assert DeepSecurityScanAgent._is_url_param(name)

    def test_non_url_params_do_not_match(self) -> None:
        for name in ("email", "username", "quantity", "comment", "password"):
            assert not DeepSecurityScanAgent._is_url_param(name)


def _oob() -> MagicMock:
    svc = MagicMock()
    svc.generate_url.return_value = "http://abc123.oob.example/cb"
    return svc


class TestOobSsrfPostBodies:
    async def test_posts_callback_into_url_body_param(self) -> None:
        ep = DiscoveredEndpoint(
            url="http://t/profile/image/url", method=EndpointMethod.POST,
            query_param_names=["imageUrl"],
        )
        sent = {}
        async def fake_request(method, url, **kw):
            sent["method"], sent["url"], sent["content"] = method, url, kw.get("content")
            sent["headers"] = kw.get("headers", {})
            return MagicMock(status_code=302)
        import isitsecure.engine.shared.rate_limited_client as rlc
        client = AsyncMock(); client.request = AsyncMock(side_effect=fake_request)
        client.__aenter__ = AsyncMock(return_value=client); client.__aexit__ = AsyncMock(return_value=False)
        orig = rlc.RateLimitedClient
        rlc.RateLimitedClient = MagicMock(return_value=client)
        try:
            n = await DeepSecurityScanAgent._oob_ssrf_post_bodies(
                _oob(), [ep], {"Authorization": "Bearer T", "Cookie": "token=T"}
            )
        finally:
            rlc.RateLimitedClient = orig
        assert n == 1
        assert sent["method"] == "POST"
        assert parse_qs(sent["content"])["imageUrl"] == ["http://abc123.oob.example/cb"]
        # auth (cookie included — server-rendered endpoints authenticate by cookie)
        assert sent["headers"].get("Cookie") == "token=T"

    async def test_skips_endpoints_without_url_params(self) -> None:
        ep = DiscoveredEndpoint(
            url="http://t/profile", method=EndpointMethod.POST,
            query_param_names=["email", "username"],
        )
        n = await DeepSecurityScanAgent._oob_ssrf_post_bodies(_oob(), [ep], None)
        assert n == 0

    async def test_skips_get_endpoints(self) -> None:
        ep = DiscoveredEndpoint(
            url="http://t/x?imageUrl=1", method=EndpointMethod.GET,
            query_param_names=["imageUrl"],
        )
        n = await DeepSecurityScanAgent._oob_ssrf_post_bodies(_oob(), [ep], None)
        assert n == 0


class TestDiscoverAuthedForms:
    async def test_extracts_form_endpoints_from_auth_pages(self, monkeypatch) -> None:
        from unittest.mock import AsyncMock, MagicMock
        import isitsecure.engine.shared.rate_limited_client as rlc

        profile_html = (
            '<form action="./profile/image/url" method="post">'
            '<input name="imageUrl"></form>'
        )
        async def fake_get(url):
            body = profile_html if url.endswith("/profile") else "<html></html>"
            return MagicMock(status_code=200,
                             headers={"content-type": "text/html"}, text=body)
        client = AsyncMock(); client.get = AsyncMock(side_effect=fake_get)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        monkeypatch.setattr(rlc, "RateLimitedClient", MagicMock(return_value=client))

        from isitsecure.engine.agent import DeepSecurityScanAgent
        eps = await DeepSecurityScanAgent._discover_authed_forms(
            "http://t", {"Cookie": "token=T"}
        )
        urls = [e.url for e in eps]
        assert any("profile/image/url" in u for u in urls), urls
