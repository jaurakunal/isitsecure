"""Regression + positive-control tests for batch D2 auth/access fixes.

Covers: shared cookie jar bleed (#2), cross-user IDOR content guard (#3),
cross-user write IDOR false positives (#4), privilege-escalation verdicts
(#7), PostgREST 204-for-zero-rows (#8) and the SessionScanner auth wiring
(#15).  All HTTP is mocked or served from 127.0.0.1.
"""

from __future__ import annotations

import base64
import http.server
import json
import socketserver
import threading
import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import CrossUserIDORConfig
from isitsecure.engine.enums import (
    AuthProvider,
    EndpointMethod,
    IDORRiskLevel,
    IDORTestType,
    SeverityLevel,
)
from isitsecure.engine.models import (
    DiscoveredEndpoint,
    IDORProbeResult,
    InterceptedRequest,
)
from isitsecure.engine.scanners.idor_scanner import IDORScanner
from isitsecure.engine.scanners.privilege_escalation_scanner import (
    PrivilegeEscalationScanner,
)
from isitsecure.engine.scanners.session_scanner import SessionScanner

SUPABASE_URL = "https://test-project.supabase.co"
ANON_KEY = "anon.key.sig"


def _sess(token: str) -> AuthSession:
    return AuthSession(
        user_id=token, access_token=token,
        headers={"Authorization": f"Bearer {token}"},
        provider=AuthProvider.TOKEN,
    )


# ---------------------------------------------------------------- local server


def _serve(handler):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _go(self, m):
            handler(self, m)

        def do_GET(self):
            self._go("GET")

        def do_PATCH(self):
            self._go("PATCH")

        def do_POST(self):
            self._go("POST")

    class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    srv = S(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _reply(h, code, body, headers=None, ctype="application/json"):
    b = body.encode()
    h.send_response(code)
    h.send_header("Content-Type", ctype)
    h.send_header("Content-Length", str(len(b)))
    for k, v in (headers or {}).items():
        h.send_header(k, v)
    h.end_headers()
    h.wfile.write(b)


@pytest.fixture(autouse=True)
def _no_delay(monkeypatch):
    monkeypatch.setattr(CrossUserIDORConfig, "PROBE_DELAY_SECONDS", 0)


def _get_ep(url, method=EndpointMethod.GET):
    return DiscoveredEndpoint(
        url=url, method=method, has_path_params=True, path_param_names=["id"])


# ------------------------------------------------------------ #2 cookie jar


def _bola_app(set_cookie: bool):
    def h(h_, m):
        auth = h_.headers.get("Authorization")
        ck = h_.headers.get("Cookie", "")
        hdr = {"Set-Cookie": "sid=abc; Path=/"} if (set_cookie and auth) else None
        if not auth and "sid=" not in ck:
            return _reply(h_, 401, "{}")
        if h_.path == "/items":
            return _reply(h_, 200, json.dumps([{"id": 5}]), hdr)
        if h_.path == "/items/5":  # BOLA: no ownership check
            return _reply(h_, 200, '{"id":5,"secret":"A-data"}', hdr)
        _reply(h_, 404, "{}")
    return _serve(h)


@pytest.mark.parametrize("set_cookie", [False, True])
async def test_bola_reported_even_when_app_sets_cookies(set_cookie):
    srv, url = _bola_app(set_cookie)
    try:
        res = await IDORScanner().scan_cross_user_api(
            _sess("A"), _sess("B"), [_get_ep(url + "/items/5")])
    finally:
        srv.shutdown()
    assert [r.risk_level for r in res] == [IDORRiskLevel.CONFIRMED]


# --------------------------------------------------- #3 volatile-body guard


async def test_bola_with_volatile_fields_still_reported():
    def h(h_, m):
        if not h_.headers.get("Authorization"):
            return _reply(h_, 401, "{}")
        if h_.path == "/docs":
            return _reply(h_, 200, json.dumps([{"id": 7}]))
        if h_.path == "/docs/7":
            return _reply(h_, 200, json.dumps(
                {"id": 7, "title": "A secret", "served_at": time.time(),
                 "requestId": h_.headers.get("Authorization")}))
        _reply(h_, 404, "{}")
    srv, url = _serve(h)
    try:
        res = await IDORScanner().scan_cross_user_api(
            _sess("A"), _sess("B"), [_get_ep(url + "/docs/7")])
    finally:
        srv.shutdown()
    assert [r.risk_level for r in res] == [IDORRiskLevel.CONFIRMED]


async def test_caller_scoped_endpoint_not_reported():
    # id ignored: each caller gets THEIR OWN data -> not cross-user access
    def h(h_, m):
        tok = h_.headers.get("Authorization")
        if not tok:
            return _reply(h_, 401, "{}")
        if h_.path == "/me":
            return _reply(h_, 200, json.dumps([{"id": 7}]))
        if h_.path == "/me/7":
            return _reply(h_, 200, json.dumps(
                {"id": 7, "owner": tok, "served_at": time.time()}))
        _reply(h_, 404, "{}")
    srv, url = _serve(h)
    try:
        res = await IDORScanner().scan_cross_user_api(
            _sess("A"), _sess("B"), [_get_ep(url + "/me/7")])
    finally:
        srv.shutdown()
    assert res == []


def test_same_resource_helper():
    same = IDORScanner._same_resource
    assert same('{"a":1,"updated_at":"x"}', '{"a":1,"updated_at":"y"}')
    assert same('{"a":1}', '{"a":1,"viewer":"B"}')
    assert not same('{"owner":"A"}', '{"owner":"B"}')
    assert not same("not json a", "not json b")
    assert same("plain", "plain")


# ------------------------------------------------------ #4 write IDOR FPs


class _Resp:
    def __init__(self, status, text=""):
        self.status_code = status
        self.text = text


class _Client:
    def __init__(self, fn):
        self.fn = fn

    async def request(self, method, url, headers=None, content=None):
        auth = (headers or {}).get("Authorization", "")
        who = "A" if "tokA" in auth else "B" if "tokB" in auth else "anon"
        return self.fn(who, url)


async def _write_probe(fn):
    a = _sess("tokA")
    b = _sess("tokB")
    ep = _get_ep("http://api/notes/7", EndpointMethod.PATCH)
    return await IDORScanner()._probe_cross_user_api(
        _Client(fn), ep, "http://api/notes/7", "7", a, b)


@pytest.mark.parametrize("status", [404, 405, 500, 410])
async def test_write_idor_not_reported_on_secure_answers(status):
    def fn(who, url):
        if who == "anon":
            return _Resp(401)
        return _Resp(200) if who == "A" else _Resp(status)
    assert await _write_probe(fn) is None


async def test_write_idor_2xx_still_confirmed():
    def fn(who, url):
        return _Resp(401) if who == "anon" else _Resp(200, "{}")
    r = await _write_probe(fn)
    assert r.risk_level == IDORRiskLevel.CONFIRMED and r.write_accessible


async def test_write_idor_400_vs_404_control_is_likely():
    # B passes authz on A's object (400 body validation) but a nonexistent id
    # is 404: status discriminates, so keep LIKELY at the higher confidence.
    def fn(who, url):
        if who == "anon":
            return _Resp(401)
        if who == "A" or url.endswith("/7"):
            return _Resp(400)
        return _Resp(404)
    r = await _write_probe(fn)
    assert r.risk_level == IDORRiskLevel.LIKELY
    assert r.confidence == CrossUserIDORConfig.CONFIDENCE_LIKELY_WRITE


async def test_write_idor_400_same_as_control_is_low_confidence_likely():
    def fn(who, url):
        return _Resp(401) if who == "anon" else _Resp(400)
    r = await _write_probe(fn)
    assert r.risk_level == IDORRiskLevel.LIKELY
    assert r.confidence == CrossUserIDORConfig.CONFIDENCE_LIKELY_WRITE_AMBIGUOUS


# ----------------------------------------------------- #8 PostgREST 204 / 0 rows


def _probe(status, body=""):
    return IDORProbeResult(
        original_url="u", probed_url="u", test_type=IDORTestType.CROSS_USER_WRITE,
        probed_status=status,
        probed_body_preview=body)


def test_idor_write_success_requires_returned_rows():
    ok = IDORScanner._is_write_success
    assert not ok(_probe(204))          # PostgREST: 0 rows affected looks like this
    assert not ok(_probe(200, "[]"))
    assert not ok(_probe(200, "[ ]"))
    assert ok(_probe(200, '[{"id":1}]'))
    assert ok(_probe(200, '{"id":1}'))


def test_idor_supabase_write_prefers_representation():
    assert CrossUserIDORConfig.SAFE_PATCH_PREFER_HEADER == "return=representation"


def _r(status=200, body="", ctype=None):
    return httpx.Response(
        status_code=status, text=body,
        headers={"content-type": ctype} if ctype else None,
        request=httpx.Request("GET", "https://t.com"))


def _mock_client(**resp):
    c = AsyncMock()
    c.get = AsyncMock(return_value=resp.get("get", _r(401)))
    c.patch = AsyncMock(return_value=resp.get("patch", _r(403)))
    c.post = AsyncMock(return_value=resp.get("post", _r(403)))
    c.request = AsyncMock(return_value=resp.get("request", _r(403)))
    c.__aenter__ = AsyncMock(return_value=c)
    c.__aexit__ = AsyncMock(return_value=False)
    return c


def _patched(client):
    return patch(
        "isitsecure.engine.scanners.privilege_escalation_scanner."
        "RateLimitedClient", return_value=client)


_SUPABASE_CASES = [
    (dict(tables=["user_roles"]), "modify their own role"),
    (dict(owned_resource_ids={"deals": ["u1"]}), "modify another user"),
]


@pytest.mark.parametrize("scan_kwargs,needle", _SUPABASE_CASES)
async def test_supabase_patch_204_zero_rows_not_reported(scan_kwargs, needle):
    client = _mock_client(patch=_r(204))
    with _patched(client):
        f = await PrivilegeEscalationScanner().scan(
            _sess("reg"), supabase_url=SUPABASE_URL, anon_key=ANON_KEY,
            **scan_kwargs)
    assert not [x for x in f if needle in x.title.lower()]
    prefer = client.patch.call_args.kwargs["headers"]["Prefer"]
    assert prefer == "return=representation"


@pytest.mark.parametrize("scan_kwargs,needle", _SUPABASE_CASES)
async def test_supabase_patch_empty_representation_not_reported(scan_kwargs, needle):
    client = _mock_client(patch=_r(200, "[]", "application/json"))
    with _patched(client):
        f = await PrivilegeEscalationScanner().scan(
            _sess("reg"), supabase_url=SUPABASE_URL, anon_key=ANON_KEY,
            **scan_kwargs)
    assert not [x for x in f if needle in x.title.lower()]


@pytest.mark.parametrize("scan_kwargs,needle", _SUPABASE_CASES)
async def test_supabase_patch_with_rows_still_critical(scan_kwargs, needle):
    client = _mock_client(patch=_r(200, '[{"id":"u1"}]', "application/json"))
    with _patched(client):
        f = await PrivilegeEscalationScanner().scan(
            _sess("reg"), supabase_url=SUPABASE_URL, anon_key=ANON_KEY,
            **scan_kwargs)
    hits = [x for x in f if needle in x.title.lower()]
    assert hits and all(x.severity == SeverityLevel.CRITICAL for x in hits)


# ----------------------------------------------------------- #7 priv-esc


SHELL = "<!doctype html><html><body><div id=root></div></body></html>"


def _ep(url, method=EndpointMethod.GET, requires_auth=None):
    return DiscoveredEndpoint(url=url, method=method, requires_auth=requires_auth)


async def test_spa_shell_not_reported_as_admin_route_or_auth_endpoint():
    # Catch-all shell: anonymous gets the same 200 HTML -> public, not escalation.
    client = _mock_client(get=_r(200, SHELL, "text/html; charset=utf-8"))
    eps = [_ep("https://x.com/admin/users"),
           _ep("https://x.com/api/profile", requires_auth=True)]
    with _patched(client):
        f = await PrivilegeEscalationScanner().scan(_sess("reg"), endpoints=eps)
    assert f == []


async def test_json_admin_route_still_reported():
    client = _mock_client(get=_r(200, '{"users":[{"id":1}]}', "application/json"))
    with _patched(client):
        f = await PrivilegeEscalationScanner().scan(
            _sess("reg"), endpoints=[_ep("https://x.com/api/admin/users")])
    assert len(f) == 1 and f[0].severity == SeverityLevel.HIGH


async def test_server_rendered_admin_page_reported_when_anon_denied():
    page = ("<html><body><h1>User admin</h1><table><tr><td>a@x.com</td>"
            "</tr></table></body></html>")

    async def get(url, headers=None, **kw):
        if headers and "Authorization" in headers:
            return _r(200, page, "text/html")
        return _r(302, "", "text/html")
    client = _mock_client()
    client.get = AsyncMock(side_effect=get)
    with _patched(client):
        f = await PrivilegeEscalationScanner().scan(
            _sess("reg"), endpoints=[_ep("https://x.com/admin/users")])
    assert len(f) == 1


def _mut(method="POST", url="https://x.com/api/notes", status=201):
    return InterceptedRequest(
        url=url, method=method, response_status=status, request_body='{"a":1}')


@pytest.mark.parametrize("admin", [None, "same"])
async def test_mutation_replay_needs_distinct_admin_identity(admin):
    client = _mock_client(request=_r(201, '{"id":1}'))
    with _patched(client):
        f = await PrivilegeEscalationScanner().scan(
            _sess("reg"), admin_session=_sess("reg") if admin else None,
            intercepted_requests=[_mut()])
    assert f == []
    client.request.assert_not_called()


async def test_mutation_replay_never_replays_delete():
    client = _mock_client(request=_r(200, "{}"))
    with _patched(client):
        f = await PrivilegeEscalationScanner().scan(
            _sess("reg"), admin_session=_sess("adm"),
            intercepted_requests=[
                _mut("DELETE", "https://x.com/api/admin/u/1", 200)])
    assert f == []
    client.request.assert_not_called()


async def test_mutation_replay_genuine_escalation_still_reported():
    client = _mock_client(request=_r(200, '{"ok":true}', "application/json"))
    with _patched(client):
        f = await PrivilegeEscalationScanner().scan(
            _sess("reg"), admin_session=_sess("adm"),
            intercepted_requests=[
                _mut("POST", "https://x.com/api/admin/users/promote", 200)])
    assert len(f) == 1 and f[0].severity == SeverityLevel.HIGH


async def test_mutation_replay_on_ordinary_path_is_medium_not_high():
    client = _mock_client(request=_r(201, '{"id":1}', "application/json"))
    with _patched(client):
        f = await PrivilegeEscalationScanner().scan(
            _sess("reg"), admin_session=_sess("adm"),
            intercepted_requests=[_mut()])
    assert len(f) == 1 and f[0].severity == SeverityLevel.MEDIUM


async def test_differential_not_polluted_by_cookie_jar():
    # The admin response sets a role cookie; a shared jar would replay it on the
    # regular user's request and erase the difference (false negative).
    big = json.dumps([{"id": i, "pad": "x" * 60} for i in range(20)])
    small = json.dumps([{"id": 1, "pad": "x" * 60}, {"id": 2, "pad": "y" * 60}])

    def h(h_, m):
        auth = h_.headers.get("Authorization", "")
        ck = h_.headers.get("Cookie", "")
        if "adm" in auth or "role=admin" in ck:
            return _reply(h_, 200, big, {"Set-Cookie": "role=admin; Path=/"})
        _reply(h_, 200, small)
    srv, url = _serve(h)
    try:
        f = await PrivilegeEscalationScanner().scan(
            _sess("reg"), admin_session=_sess("adm"),
            endpoints=[_ep(url + "/api/users", requires_auth=True)])
    finally:
        srv.shutdown()
    assert [x for x in f if "admin sees more data" in x.title], [x.title for x in f]


# ---------------------------------------------------------------- #15 session


def _jwt(exp):
    def enc(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'HS256'})}.{enc({'sub': 'u', 'exp': exp})}.sig"


async def test_session_scanner_reads_lazily_supplied_session():
    holder = {"s": None}
    sc = SessionScanner(auth_session_source=lambda: holder["s"])
    assert await sc.scan([]) == []
    holder["s"] = AuthSession(
        user_id="u", access_token=_jwt(int(time.time()) + 90 * 86400),
        provider=AuthProvider.TOKEN)
    assert len(await sc.scan([])) == 1


def test_factory_wires_auth_session_into_session_scanner():
    from isitsecure.engine.factory import create_deep_security_scan_agent
    agent = create_deep_security_scan_agent()
    sc = next(s for s in agent._dast_scanners if isinstance(s, SessionScanner))
    assert sc._resolve_auth_session() is None
    agent._jwt_scanner._auth_session = _sess("tok")
    assert sc._resolve_auth_session() is agent._jwt_scanner._auth_session
