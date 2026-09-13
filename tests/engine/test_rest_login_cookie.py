"""The REST login session prefers the app's real cookie, falls back to mirroring.

Server-rendered endpoints (Juice Shop's /profile/image/url) authenticate by
cookie and 500 on a bearer-only request. When the app sets a session cookie on
login we reuse that real cookie (general); only when it sets none do we mirror
the JWT into common cookie names. #SSRF
"""
from isitsecure.engine.auth.rest_login_auth import RestLoginAuthProvider


def test_prefers_the_real_login_cookie() -> None:
    prov = RestLoginAuthProvider("http://t")
    sess = prov._build_session("JWT123", "u@x.test", real_cookie="sid=abc; csrf=xyz")
    assert sess.headers["Authorization"] == "Bearer JWT123"
    # the app's real cookie, not a synthesized guess
    assert sess.headers["Cookie"] == "sid=abc; csrf=xyz"
    assert "JWT123" not in sess.headers["Cookie"]


def test_falls_back_to_mirroring_when_login_sets_no_cookie() -> None:
    prov = RestLoginAuthProvider("http://t")
    sess = prov._build_session("JWT123", "u@x.test")  # no real cookie
    cookie = sess.headers.get("Cookie", "")
    assert "token=JWT123" in cookie
    assert "access_token=JWT123" in cookie
