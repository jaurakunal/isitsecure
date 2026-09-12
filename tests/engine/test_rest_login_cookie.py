"""The REST login session must carry a cookie, not only a bearer header.

Server-rendered endpoints (Juice Shop's /profile/image/url) authenticate by the
`token` cookie and 500 on a bearer-only request. #SSRF
"""
from isitsecure.engine.auth.rest_login_auth import RestLoginAuthProvider


def test_session_mirrors_token_into_cookie() -> None:
    prov = RestLoginAuthProvider("http://t")
    sess = prov._build_session("JWT123", "u@x.test")
    assert sess.headers["Authorization"] == "Bearer JWT123"
    cookie = sess.headers.get("Cookie", "")
    assert "token=JWT123" in cookie
    assert "access_token=JWT123" in cookie
