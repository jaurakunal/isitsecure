"""D1 review fixes: upload recall, canonical Host redirect, bad Location, JWT controls."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

import httpx
import pytest

from isitsecure.engine.constants import FileUploadConfig, HTTPProbeConfig, JWTAttackConfig
from isitsecure.engine.enums import EndpointMethod, SeverityLevel
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.file_upload_scanner import FileUploadScanner
from isitsecure.engine.scanners.http_probe_scanner import HTTPProbeScanner
from isitsecure.engine.scanners.jwt_scanner import JWTScanner
from isitsecure.engine.scanners.open_redirect_scanner import OpenRedirectScanner
from tests.engine.test_jwt_scanner import _make_auth_session, _make_endpoint, _make_jwt

UP = "https://example.com/upload"


def _r(body, status=200):
    return httpx.Response(status, text=body, headers={"content-type": "application/json"})


async def _upload_scan(post, get=None):
    with patch("isitsecure.engine.scanners.file_upload_scanner.RateLimitedClient") as mc:
        inst = AsyncMock()
        inst.post = post
        inst.get = get or AsyncMock(return_value=httpx.Response(404, text="nope"))
        mc.return_value.__aenter__ = AsyncMock(return_value=inst)
        mc.return_value.__aexit__ = AsyncMock(return_value=False)
        ep = DiscoveredEndpoint(url=UP, method=EndpointMethod.POST)
        return await FileUploadScanner().scan([ep])


def _typed(findings):
    return [f for f in findings if f.title == FileUploadConfig.TITLE_UNRESTRICTED_TYPE]


def _ext(kw):
    name = kw["files"]["file"][0]
    return "." + name.rsplit(".", 1)[-1]


class TestUploadRecall:
    @pytest.mark.asyncio
    async def test_url_with_extension_is_storage_evidence_even_if_get_differs(self) -> None:
        async def post(url, **kw):
            return _r(json.dumps({"id": "u1", "url": "/files/shell" + _ext(kw)}))

        # GET executes the script, so the payload is not served back verbatim.
        get = AsyncMock(return_value=httpx.Response(200, text="executed"))
        typed = _typed(await _upload_scan(post, get))
        assert typed
        assert all(f.severity == SeverityLevel.HIGH for f in typed)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("body", ["OK", '{"message":"File uploaded successfully"}'])
    async def test_unnamed_2xx_is_low_tier_not_silent(self, body) -> None:
        async def post(url, **kw):
            return _r(body)

        findings = await _upload_scan(post)
        typed = _typed(findings)
        assert typed
        for f in typed:
            assert f.severity == SeverityLevel.MEDIUM
            assert f.confidence <= 0.4
            assert "evidence of storage was not found" in f.evidence
            assert "evidence of storage was not found" in f.technical_detail
        assert FileUploadConfig.TITLE_PATH_TRAVERSAL not in {f.title for f in findings}

    @pytest.mark.asyncio
    async def test_failure_body_still_silent(self) -> None:
        async def post(url, **kw):
            return _r('{"success": false, "error": "invalid file"}')

        assert await _upload_scan(post) == []

    @pytest.mark.asyncio
    async def test_unsafe_followup_urls_are_not_fetched(self) -> None:
        async def post(url, **kw):
            return _r(json.dumps({"links": ["/logout", "/files/x?token=1", "/api/delete/9"]}))

        get = AsyncMock(return_value=httpx.Response(200, text="x"))
        await _upload_scan(post, get)
        get.assert_not_called()


def _mock(status=200, text="OK", headers=None):
    r = MagicMock()
    r.status_code, r.text = status, text
    r.headers = headers or {"content-type": "text/html"}
    return r


async def _probe(get_fn):
    async def request(method, url, **kw):
        return _mock(405, headers={})

    ep = DiscoveredEndpoint(url="https://example.com/api/v1/users", method=EndpointMethod.GET)
    with patch("isitsecure.engine.scanners.http_probe_scanner.RateLimitedClient") as M:
        client = AsyncMock()
        client.get = get_fn
        client.request = request
        M.return_value.__aenter__ = AsyncMock(return_value=client)
        M.return_value.__aexit__ = AsyncMock(return_value=False)
        return await HTTPProbeScanner().scan(endpoints=[ep])


def _host_findings(findings):
    return [f for f in findings if "Host header injection" in f.title]


def _forged_host(kw):
    headers = kw.get("headers") or {}
    return next((headers[h] for h in HTTPProbeConfig.HOST_HEADERS if h in headers), None)


class TestHostHeaderCanonical:
    @pytest.mark.asyncio
    async def test_same_path_redirect_is_low(self) -> None:
        async def get(url, **kw):
            host = _forged_host(kw)
            if host is None:
                return _mock(404, "nf")
            return _mock(301, "", {"location": f"https://{host}{urlparse(url).path or '/'}"})

        hf = _host_findings(await _probe(get))
        assert hf
        assert hf[0].severity == SeverityLevel.LOW and hf[0].confidence <= 0.4

    @pytest.mark.asyncio
    async def test_different_path_redirect_stays_high(self) -> None:
        async def get(url, **kw):
            host = _forged_host(kw)
            if host is None:
                return _mock(404, "nf")
            return _mock(302, "", {"location": f"https://{host}/account/reset?x=1"})

        hf = _host_findings(await _probe(get))
        assert hf and hf[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_body_reflection_stays_high(self) -> None:
        async def get(url, **kw):
            host = _forged_host(kw)
            if host is None:
                return _mock(404, "nf")
            return _mock(200, f'<a href="https://{host}/reset?t=abc">reset</a>')

        hf = _host_findings(await _probe(get))
        assert hf and hf[0].severity == SeverityLevel.HIGH


class TestOpenRedirectUnparsable:
    @pytest.mark.parametrize("loc", ["//[evil.com", "https://[evil.com/x"])
    def test_bad_ipv6_with_evil_is_external_and_does_not_raise(self, loc) -> None:
        assert OpenRedirectScanner()._is_external_redirect(loc) is True

    @pytest.mark.parametrize("loc", ["//[app.example.com", "https://[ok.example.com/x"])
    def test_bad_ipv6_without_evil_is_not_external(self, loc) -> None:
        assert OpenRedirectScanner()._is_external_redirect(loc) is False

    def test_valid_external_still_external(self) -> None:
        assert OpenRedirectScanner()._is_external_redirect("//evil.com/x") is True


class _Srv:
    def __init__(self, handler, fail_control=False):
        self.handler, self.fail_control = handler, fail_control
        self.control_calls = 0

    def client(self):
        async def get(url, headers=None, **kw):
            tok = (headers or {}).get("Authorization", "").removeprefix("Bearer ")
            if tok == JWTScanner.CONTROL_TOKEN:
                self.control_calls += 1
                if self.fail_control:
                    raise httpx.ReadTimeout("t")
            resp = MagicMock(spec=httpx.Response)
            resp.status_code, resp.text = self.handler(tok)
            return resp

        c = AsyncMock()
        c.get = AsyncMock(side_effect=get)
        c.__aenter__ = AsyncMock(return_value=c)
        c.__aexit__ = AsyncMock(return_value=None)
        return c


async def _jwt(srv):
    ep = _make_endpoint()
    sc = JWTScanner(auth_session=_make_auth_session(_make_jwt()), test_endpoint=ep.url)
    with patch("isitsecure.engine.scanners.jwt_scanner.RateLimitedClient") as M:
        M.return_value = srv.client()
        return await sc.scan(endpoints=[ep])


class TestJwtControlsDegrade:
    @pytest.mark.asyncio
    async def test_control_failure_does_not_abort_and_lowers_confidence(self) -> None:
        real = _make_jwt()

        def handler(tok):
            return (200, '{"d":1}') if (tok == real or tok.endswith(".")) else (401, "no")

        findings = await _jwt(_Srv(handler, fail_control=True))
        alg = [f for f in findings if f.title == JWTAttackConfig.TITLE_ALG_NONE]
        assert len(alg) == 1
        assert alg[0].confidence == pytest.approx(JWTAttackConfig.CONFIDENCE_ALG_NONE - 0.2)
        assert "No negative control" in alg[0].technical_detail

    @pytest.mark.asyncio
    async def test_control_failure_and_rejected_forgery_reports_nothing(self) -> None:
        real = _make_jwt()
        findings = await _jwt(
            _Srv(lambda t: (200, "{}") if t == real else (401, "no"), fail_control=True)
        )
        assert not [f for f in findings if f.severity == SeverityLevel.CRITICAL]

    @pytest.mark.asyncio
    async def test_controls_fetched_once_per_scan(self) -> None:
        srv = _Srv(lambda t: (401, "no"))
        await _jwt(srv)
        assert srv.control_calls == 1

    @pytest.mark.asyncio
    async def test_normal_control_keeps_full_confidence(self) -> None:
        real = _make_jwt()
        findings = await _jwt(
            _Srv(lambda t: (200, "{}") if (t == real or t.endswith(".")) else (401, "no"))
        )
        alg = [f for f in findings if f.title == JWTAttackConfig.TITLE_ALG_NONE]
        assert alg and alg[0].confidence == JWTAttackConfig.CONFIDENCE_ALG_NONE
