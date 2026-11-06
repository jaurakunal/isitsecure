"""Tests for robust browser-login capture: JWT-shape detection, nested-blob extraction, wire
sniffing, structural submit, login-page discovery, cookie-only sessions and storage_state.

Pure-logic tests use fakes; ``TestBrowserAuthLive`` drives real headless Chromium against a
localhost static fixture (skipped when Chromium is unavailable). No third-party network.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from isitsecure.engine.auth.browser_auth import BrowserAuthProvider
from isitsecure.engine.auth.browser_login_helper import (
    BrowserCaptureConfig,
    BrowserLoginHelper,
    find_jwt_deep,
)
from isitsecure.engine.auth.protocols import AuthCredentials
from isitsecure.engine.constants import BrowserLoginConfig
from isitsecure.engine.enums import AuthProvider
from isitsecure.engine.shared.jwt_utils import looks_like_jwt


def _b64(obj: object, pad: bool = False) -> str:
    raw = base64.urlsafe_b64encode(json.dumps(obj).encode()).decode()
    return raw if pad else raw.rstrip("=")


def make_jwt(payload: dict | None = None, pad: bool = False) -> str:
    return ".".join([
        _b64({"alg": "HS256", "typ": "JWT"}, pad),
        _b64(payload or {"sub": "user-1", "role": "user"}, pad),
        "c2lnbmF0dXJl",
    ])


JWT = make_jwt()


class TestLooksLikeJwt:
    def test_valid_jwt(self):
        assert looks_like_jwt(JWT)

    def test_padded_segments_accepted(self):
        assert looks_like_jwt(make_jwt(pad=True))

    def test_unpadded_payload_with_odd_length_accepted(self):
        assert looks_like_jwt(make_jwt({"sub": "a"}))

    @pytest.mark.parametrize("value", [
        "", "abc", "a.b", "a.b.c.d", "1.2.3", "example.com.au", "v1.2.3",
        "not.a.jwt", "eyJ.eyJ.sig",
    ])
    def test_non_jwt_dotted_strings_rejected(self, value):
        assert not looks_like_jwt(value)

    def test_non_string_rejected(self):
        assert not looks_like_jwt(None)
        assert not looks_like_jwt(123)
        assert not looks_like_jwt(["a", "b", "c"])

    def test_segments_that_decode_to_non_objects_rejected(self):
        bad = f"{_b64([1, 2])}.{_b64('str')}.sig"
        assert not looks_like_jwt(bad)

    def test_empty_json_objects_rejected(self):
        assert not looks_like_jwt(f"{_b64({})}.{_b64({})}.sig")


class TestFindJwtDeep:
    def test_bare_jwt(self):
        assert find_jwt_deep(JWT) == JWT

    def test_quoted_jwt(self):
        assert find_jwt_deep(f'"{JWT}"') == JWT

    def test_nested_dict_json(self):
        assert find_jwt_deep(json.dumps({"a": {"b": [{"c": JWT}]}})) == JWT

    def test_double_serialized_redux_persist(self):
        inner = json.dumps({"userReducer": json.dumps({"token": JWT, "name": "x"})})
        outer = json.dumps({"reducers": inner, "_persist": json.dumps({"version": -1})})
        assert find_jwt_deep(outer) == JWT

    def test_prefers_access_over_refresh_and_id(self):
        refresh, ident = make_jwt({"sub": "r"}), make_jwt({"sub": "i"})
        blob = json.dumps({
            "refresh_token": refresh, "id_token": ident, "access_token": JWT,
        })
        assert find_jwt_deep(blob) == JWT

    def test_none_for_non_jwt_values(self):
        assert find_jwt_deep(json.dumps({"theme": "dark", "v": "1.2.3"})) is None
        assert find_jwt_deep("plain") is None
        assert find_jwt_deep(None) is None

    def test_depth_bound_prevents_runaway(self):
        node: object = JWT
        for _ in range(BrowserCaptureConfig.MAX_JWT_SEARCH_DEPTH + 3):
            node = {"k": node}
        assert find_jwt_deep(node) is None


class TestExtractTokenShapeFallback:
    async def test_finds_jwt_under_arbitrary_key(self):
        page = MagicMock()

        async def evaluate(script):
            if "Object.keys" in script:
                return ["apptoken"]
            if "Object.values(localStorage)" in script:
                return [JWT]
            return None

        page.evaluate = evaluate
        assert await BrowserLoginHelper.extract_token(page) == JWT

    async def test_finds_nested_blob_in_session_storage(self):
        blob = json.dumps({"x": json.dumps({"accessToken": JWT})})
        page = MagicMock()

        async def evaluate(script):
            if "Object.values(sessionStorage)" in script:
                return [blob]
            if "Object.keys" in script:
                return []
            return None

        page.evaluate = evaluate
        assert await BrowserLoginHelper.extract_token(page) == JWT

    async def test_well_known_key_still_wins_and_skips_scan(self):
        """Regression: the original key-based path returns before any shape scan."""
        calls: list[str] = []
        page = MagicMock()

        async def evaluate(script):
            calls.append(script)
            if "localStorage.getItem('access_token')" in script:
                return "plain-opaque-token"
            return None

        page.evaluate = evaluate
        assert await BrowserLoginHelper.extract_token(page) == "plain-opaque-token"
        assert not any("Object.values" in c for c in calls)

    async def test_non_jwt_values_yield_none(self):
        page = MagicMock()

        async def evaluate(script):
            return [] if "Object" in script else None

        page.evaluate = evaluate
        assert await BrowserLoginHelper.extract_token(page) is None


class _Req:
    def __init__(self, headers):
        self.headers = headers


class TestTokenSniffer:
    def _attach(self):
        handlers = []
        page = MagicMock()
        page.on = lambda event, cb: handlers.append((event, cb))
        sniffed = BrowserLoginHelper.attach_token_sniffer(page)
        assert handlers and handlers[0][0] == "request"
        return sniffed, handlers[0][1]

    def test_captures_bearer_jwt_and_apikey(self):
        sniffed, cb = self._attach()
        cb(_Req({"authorization": f"Bearer {JWT}", "apikey": "pk_123"}))
        assert sniffed == {"authorization": f"Bearer {JWT}", "apikey": "pk_123"}

    def test_ignores_non_jwt_bearer(self):
        sniffed, cb = self._attach()
        cb(_Req({"authorization": "Bearer opaque-token"}))
        assert "authorization" not in sniffed

    def test_first_token_wins(self):
        sniffed, cb = self._attach()
        other = make_jwt({"sub": "other"})
        cb(_Req({"authorization": f"Bearer {JWT}"}))
        cb(_Req({"authorization": f"Bearer {other}"}))
        assert sniffed["authorization"] == f"Bearer {JWT}"

    def test_header_read_failure_never_raises(self):
        sniffed, cb = self._attach()

        class Boom:
            @property
            def headers(self):
                raise RuntimeError("x")

        cb(Boom())
        assert sniffed == {}

    def test_page_without_on_is_tolerated(self):
        assert BrowserLoginHelper.attach_token_sniffer(object()) == {}


class TestClickSubmitFallbacks:
    async def test_structural_fallback_used_when_no_selector_matches(self):
        page = AsyncMock()
        page.query_selector = AsyncMock(return_value=None)
        page.evaluate = AsyncMock(return_value=True)
        assert await BrowserLoginHelper.click_submit(page) is True
        page.keyboard.press.assert_not_called()

    async def test_enter_key_fallback(self):
        pw = AsyncMock()
        pw.is_visible = AsyncMock(return_value=True)

        async def qs(selector):
            return pw if selector == 'input[type="password"]' else None

        page = AsyncMock()
        page.query_selector = qs
        page.evaluate = AsyncMock(return_value=False)
        assert await BrowserLoginHelper.click_submit(page) is True
        pw.focus.assert_awaited_once()
        page.keyboard.press.assert_awaited_once_with("Enter")

    async def test_false_when_nothing_works(self):
        page = AsyncMock()
        page.query_selector = AsyncMock(return_value=None)
        page.evaluate = AsyncMock(side_effect=RuntimeError("boom"))
        assert await BrowserLoginHelper.click_submit(page) is False


class TestGotoLoginPage:
    async def test_noop_when_form_present(self):
        page = AsyncMock()
        page.evaluate = AsyncMock(return_value={"ok": True})
        assert await BrowserLoginHelper.goto_login_page(page, "http://x.test") is True
        page.goto.assert_not_called()

    async def test_follows_login_link(self):
        page = AsyncMock()
        state = {"on_login": False}

        async def evaluate(script, *args):
            if args:  # login-link finder
                return "/signin-here"
            return {"ok": state["on_login"]}

        async def goto(url, **kw):
            state["on_login"] = url.endswith("/signin-here")

        page.evaluate = evaluate
        page.goto = goto
        assert await BrowserLoginHelper.goto_login_page(page, "http://x.test/app") is True

    async def test_tries_common_routes_then_restores_start_url(self):
        visited: list[str] = []
        page = AsyncMock()

        async def evaluate(script, *args):
            return "" if args else {"ok": False}

        async def goto(url, **kw):
            visited.append(url)

        page.evaluate = evaluate
        page.goto = goto
        assert await BrowserLoginHelper.goto_login_page(page, "http://x.test/start") is False
        assert visited[0] == "http://x.test/#/login"
        assert visited[-1] == "http://x.test/start"  # returned to the given page


# ---------------------------------------------------------------------------
# Live Chromium against a localhost static fixture
# ---------------------------------------------------------------------------

_FORM = """<!doctype html><html><body>
<form onsubmit="return false">
  <input type="email" name="email"><input type="password" name="password">
  <div role="button" id="go">Anmelden</div>
</form>
<script>
document.getElementById('go').onclick = function () { ON_LOGIN };
</script></body></html>"""

_PAGES = {
    # token buried in a double-serialized redux-persist blob under an arbitrary key
    "redux.html": _FORM.replace("ON_LOGIN", (
        "localStorage.setItem('persist:root', JSON.stringify({user: JSON.stringify("
        "{session: {accessToken: '@JWT@'}})}));")),
    # token only ever appears on the wire
    "wire.html": _FORM.replace("ON_LOGIN", (
        "fetch('/api/me', {headers: {Authorization: 'Bearer @JWT@'}});")),
    # cookie-only session
    "cookie.html": _FORM.replace("ON_LOGIN", "document.cookie='sid=abc123; path=/';"),
    # legacy path: opaque (non-JWT) token under a well-known key must behave exactly as before
    "legacy.html": _FORM.replace(
        "ON_LOGIN", "localStorage.setItem('access_token', 'opaque-token-value-123');"),
    # nothing at all
    "none.html": _FORM.replace("ON_LOGIN", "document.title='x';"),
    # bare origin with a login link (the form lives on redux.html)
    "index.html": '<!doctype html><html><body><a href="/redux.html">Sign in</a></body></html>',
}


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    root: Path = tmp_path_factory.mktemp("site")
    for name, html in _PAGES.items():
        (root / name).write_text(html.replace("@JWT@", JWT))
    (root / "api").mkdir()
    (root / "api" / "me").write_text("{}")
    handler = partial(SimpleHTTPRequestHandler, directory=str(root))
    handler.log_message = lambda *a, **k: None  # type: ignore[attr-defined]
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture(autouse=True)
def _fast_polls(monkeypatch):
    monkeypatch.setattr(BrowserCaptureConfig, "POST_LOGIN_TOKEN_POLLS", 3)
    monkeypatch.setattr(BrowserCaptureConfig, "POST_LOGIN_TOKEN_POLL_MS", 100)
    monkeypatch.setattr(BrowserLoginConfig, "NETWORK_IDLE_TIMEOUT_MS", 2000)
    monkeypatch.setattr(BrowserLoginConfig, "LOGIN_WAIT_TIMEOUT_MS", 3000)


def _creds(url: str) -> AuthCredentials:
    return AuthCredentials(
        provider=AuthProvider.BROWSER, email="u@example.test",
        password="Sup3r-secret!", login_url=url,  # noqa: S106
    )


async def _login(url: str):
    try:
        return await BrowserAuthProvider().authenticate(_creds(url))
    except ImportError:
        pytest.skip("playwright not installed")
    except Exception as exc:  # noqa: BLE001
        if "Executable doesn't exist" in str(exc):
            pytest.skip("chromium not installed")
        raise


class TestBrowserAuthLive:
    async def test_nested_redux_blob_token_and_storage_state(self, site):
        session = await _login(f"{site}/redux.html")
        assert session.access_token == JWT
        assert session.headers["Authorization"] == f"Bearer {JWT}"
        state = session.user_metadata["storage_state"]
        names = [e["name"] for o in state["origins"] for e in o["localStorage"]]
        assert "persist:root" in names
        assert "cookies" in session.user_metadata

    async def test_legacy_well_known_key_unchanged(self, site):
        session = await _login(f"{site}/legacy.html")
        assert session.access_token == "opaque-token-value-123"  # noqa: S105
        assert session.headers == {"Authorization": "Bearer opaque-token-value-123"}

    async def test_wire_sniffed_token(self, site):
        session = await _login(f"{site}/wire.html")
        assert session.access_token == JWT

    async def test_cookie_only_session_accepted_with_warning(self, site, caplog):
        with caplog.at_level(logging.WARNING):
            session = await _login(f"{site}/cookie.html")
        assert session.access_token == ""
        assert "sid=abc123" in session.headers["Cookie"]
        assert "Authorization" not in session.headers
        assert session.user_metadata["cookies"] == {"sid": "abc123"}
        warning = " ".join(r.getMessage() for r in caplog.records)
        assert "NO bearer token" in warning
        assert "abc123" not in warning and "Sup3r-secret" not in warning

    async def test_no_token_no_cookies_raises(self, site):
        with pytest.raises(ValueError, match=BrowserLoginConfig.ERROR_NO_TOKEN_FOUND):
            await _login(f"{site}/none.html")

    async def test_bare_origin_discovers_login_page(self, site):
        session = await _login(f"{site}/index.html")
        assert session.access_token == JWT
