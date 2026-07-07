"""Tests for REST cross-user IDOR (BOLA) and the generic REST login provider."""

from __future__ import annotations

import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.auth.rest_login_auth import RestLoginAuthProvider
from isitsecure.engine.enums import (
    AuthProvider,
    EndpointMethod,
    IDORRiskLevel,
)
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.idor_scanner import IDORScanner


class _Resp:
    def __init__(self, status: int, text: str = "") -> None:
        self.status_code = status
        self.text = text


class _FakeClient:
    """Returns canned responses keyed on the request's auth identity."""

    def __init__(self, responder) -> None:
        self._responder = responder

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def request(self, method, url, headers=None, content=None):
        auth = (headers or {}).get("Authorization", "")
        who = "anon"
        if "tokA" in auth:
            who = "A"
        elif "tokB" in auth:
            who = "B"
        return self._responder(method, who)


def _sessions():
    a = AuthSession(user_id="alice", access_token="tokA",
                    headers={"Authorization": "Bearer tokA"},
                    provider=AuthProvider.TOKEN)
    b = AuthSession(user_id="bob", access_token="tokB",
                    headers={"Authorization": "Bearer tokB"},
                    provider=AuthProvider.TOKEN)
    return a, b


def _write_ep():
    return DiscoveredEndpoint(
        url="http://api/users/v1/{username}/email", method=EndpointMethod.PUT,
        has_path_params=True, path_param_names=["username"])


def _read_ep():
    return DiscoveredEndpoint(
        url="http://api/users/v1/{username}", method=EndpointMethod.GET,
        has_path_params=True, path_param_names=["username"])


class TestProbeCrossUserApi:
    async def _probe(self, endpoint, responder):
        a, b = _sessions()
        client = _FakeClient(responder)
        return await IDORScanner()._probe_cross_user_api(
            client, endpoint, endpoint.url.replace("{username}", "alice"),
            "alice", a, b)

    async def test_write_bola_detected_even_on_body_error(self):
        # anon denied, owner 400 (past auth), attacker 400 (past auth) => LIKELY
        def r(method, who):
            return _Resp(401) if who == "anon" else _Resp(400)
        result = await self._probe(_write_ep(), r)
        assert result is not None
        assert result.write_accessible
        assert result.risk_level == IDORRiskLevel.LIKELY

    async def test_write_bola_confirmed_on_2xx(self):
        def r(method, who):
            return _Resp(401) if who == "anon" else _Resp(200)
        result = await self._probe(_write_ep(), r)
        assert result.write_accessible
        assert result.risk_level == IDORRiskLevel.CONFIRMED

    async def test_public_endpoint_is_not_flagged(self):
        # anonymous request succeeds => public, must NOT be reported (FP guard)
        def r(method, who):
            return _Resp(200)
        assert await self._probe(_read_ep(), r) is None

    async def test_properly_protected_is_not_flagged(self):
        # anon denied, owner ok, attacker denied => safe
        def r(method, who):
            if who == "anon":
                return _Resp(401)
            if who == "A":
                return _Resp(200)
            return _Resp(403)
        assert await self._probe(_read_ep(), r) is None

    async def test_read_idor_confirmed(self):
        def r(method, who):
            if who == "anon":
                return _Resp(401)
            return _Resp(200)
        result = await self._probe(_read_ep(), r)
        assert result.read_accessible
        assert result.risk_level == IDORRiskLevel.CONFIRMED

    async def test_owner_cannot_reach_returns_none(self):
        # owner gets 404 => not A's resource
        def r(method, who):
            return _Resp(404)
        assert await self._probe(_read_ep(), r) is None


class TestRestLoginProvider:
    def test_find_key_nested(self):
        data = {"data": {"session": {"auth_token": "xyz"}}}
        assert RestLoginAuthProvider._find_key(data, "auth_token") == "xyz"

    def test_extract_token_from_known_key(self):
        prov = RestLoginAuthProvider("http://api")
        resp = _Resp(200)
        resp.json = lambda: {"auth_token": "the-token"}
        assert prov._extract_token(resp) == "the-token"

    def test_extract_token_jwt_regex_fallback(self):
        prov = RestLoginAuthProvider("http://api")
        jwt = "eyJhbGc.eyJzdWIiOiJhIn0.sig"
        resp = _Resp(200, text=f'{{"weird_field": "{jwt}"}}')
        resp.json = lambda: {"weird_field": jwt}  # not a known token key
        assert prov._extract_token(resp) == jwt

    def test_jwt_subject_decoded(self):
        # {"sub": "alice"} base64url payload
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig"
        assert RestLoginAuthProvider._jwt_subject(token) == "alice"

    def test_jwt_subject_bad_token_none(self):
        assert RestLoginAuthProvider._jwt_subject("not-a-jwt") is None

    def test_build_session_uses_jwt_sub(self):
        prov = RestLoginAuthProvider("http://api")
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.sig"
        sess = prov._build_session(token, "alice@x.com")
        assert sess.user_id == "alice"
        assert sess.headers["Authorization"] == f"Bearer {token}"


@pytest.mark.parametrize("method,expected", [
    ("GET", True), ("PUT", True), ("PATCH", True),
    ("DELETE", False), ("POST", False),
])
async def test_scan_cross_user_api_method_filter(method, expected):
    """Only GET/PUT/PATCH are probed; DELETE/POST are skipped."""
    a, b = _sessions()
    ep = DiscoveredEndpoint(
        url="http://api/r/{id}", method=EndpointMethod(method),
        has_path_params=True, path_param_names=["id"])
    probed = {"called": False}

    async def fake_probe(*args, **kwargs):
        probed["called"] = True
        return None

    async def harvest(*a, **k):
        return ["1"]  # a real id so testable methods have a candidate

    scanner = IDORScanner()
    scanner._probe_cross_user_api = fake_probe
    scanner._harvest_ids = harvest
    await scanner.scan_cross_user_api(a, b, [ep])
    assert probed["called"] == expected


class TestHarvestingAndGuards:
    async def _probe(self, endpoint, responder):
        a, b = _sessions()
        client = _FakeClient(responder)
        return await IDORScanner()._probe_cross_user_api(
            client, endpoint, endpoint.url.replace("{username}", "alice"),
            "alice", a, b)

    async def test_read_content_mismatch_not_flagged(self):
        # attacker sees different (own) data -> id ignored/coerced, not IDOR
        def r(method, who):
            if who == "anon":
                return _Resp(401)
            if who == "A":
                return _Resp(200, "A-private-data")
            return _Resp(200, "B-own-data")
        assert await self._probe(_read_ep(), r) is None

    async def test_read_content_match_flagged(self):
        # attacker sees the SAME resource the owner sees -> real read IDOR
        def r(method, who):
            return _Resp(401) if who == "anon" else _Resp(200, "same-data")
        res = await self._probe(_read_ep(), r)
        assert res is not None and res.read_accessible

    async def test_read_attacker_non_2xx_not_flagged(self):
        # attacker gets 400 (not 401/403 but not success) -> no real access
        def r(method, who):
            if who == "anon":
                return _Resp(401)
            if who == "A":
                return _Resp(200, "data")
            return _Resp(400)
        assert await self._probe(_read_ep(), r) is None

    def test_extract_field_values(self):
        ev = IDORScanner._extract_field_values
        assert ev('{"data":[{"id":42},{"id":7}]}', "id") == ["42", "7"]
        assert ev('{"users":[{"username":"alice"}]}', "username") == ["alice"]
        assert ev('{"id":true}', "id") == []          # bool excluded
        assert ev("<html>", "id") == []               # non-json

    async def test_numeric_slot_does_not_substitute_string_identity(self):
        # A numeric id-variant (/items/1) must not get the email substituted.
        scanner = IDORScanner()
        probed: list[str] = []

        async def rec(client, method, url, session, body):
            probed.append(url)
            return _Resp(404)

        async def no_harvest(*a, **k):
            return []

        scanner._authed_request = rec
        scanner._harvest_ids = no_harvest
        a = AuthSession(user_id="alice@x.com", access_token="t",
                        provider=AuthProvider.TOKEN)
        b = AuthSession(user_id="bob@x.com", access_token="t2",
                        provider=AuthProvider.TOKEN)
        ep = DiscoveredEndpoint(url="http://api/items/1",
                                method=EndpointMethod.GET, has_path_params=True,
                                path_param_names=["id"])
        await scanner.scan_cross_user_api(a, b, [ep])
        assert not any("alice" in u for u in probed)


class TestIdShapeAndIdentityGating:
    async def _run(self, ep, harvest_return, id_a="alice@x.com"):
        scanner = IDORScanner()
        probed: list[str] = []

        async def rec(client, method, url, session, body):
            probed.append(url)
            return _Resp(404)

        async def harvest(*a, **k):
            return harvest_return

        scanner._authed_request = rec
        scanner._harvest_ids = harvest
        a = AuthSession(user_id=id_a, access_token="t", provider=AuthProvider.TOKEN)
        b = AuthSession(user_id="bob@x.com", access_token="t2",
                        provider=AuthProvider.TOKEN)
        await scanner.scan_cross_user_api(a, b, [ep])
        return probed

    async def test_uuid_ids_not_filtered_out(self):
        # /things/1 variant but real ids are UUIDs: the UUID must be probed
        # (fixes the false negative from keying off the synthetic "/1"), and
        # the string identity must NOT be injected into the opaque slot.
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        ep = DiscoveredEndpoint(url="http://api/things/1",
                                method=EndpointMethod.GET, has_path_params=True,
                                path_param_names=["id"])
        probed = await self._run(ep, [uuid])
        assert any(uuid in u for u in probed)
        assert not any("alice" in u for u in probed)

    async def test_identity_param_substitutes_identity(self):
        # An identity-named slot ({username}) does get A's identity probed,
        # even when the collection harvest is empty.
        ep = DiscoveredEndpoint(url="http://api/users/{username}",
                                method=EndpointMethod.GET, has_path_params=True,
                                path_param_names=["username"])
        probed = await self._run(ep, [], id_a="alice")
        assert any("alice" in u for u in probed)

    async def test_numeric_ids_drop_stray_identity(self):
        # Identity-named slot but the real ids are numeric -> the email is
        # dropped (kept only for genuinely identity-shaped ids).
        ep = DiscoveredEndpoint(url="http://api/users/{user_id}",
                                method=EndpointMethod.GET, has_path_params=True,
                                path_param_names=["user_id"])
        probed = await self._run(ep, ["1", "2"])
        assert any("/users/1" in u for u in probed)
        assert not any("alice" in u for u in probed)
