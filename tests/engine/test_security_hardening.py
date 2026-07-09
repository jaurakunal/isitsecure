"""Regression tests for the OSS-readiness security fixes."""

import os
import tempfile

import pytest

from isitsecure.engine.code_analysis import repo_ingestion
from isitsecure.engine.shared.safe_path import resolve_within

# The class carrying _validate_remote (avoids coupling to the exact class name).
_REPO_CLS = next(
    c for c in vars(repo_ingestion).values()
    if hasattr(c, "_validate_remote")
)


class TestSafePath:
    def test_legit_path_resolves_inside_repo(self):
        base = tempfile.mkdtemp()
        target = resolve_within(base, "src/app.py")
        assert target.startswith(os.path.realpath(base) + os.sep)

    @pytest.mark.parametrize("bad", [
        "/etc/passwd", "../../etc/passwd", "../outside.txt",
        "a/../../b", "/tmp/evil",
    ])
    def test_traversal_and_absolute_rejected(self, bad):
        base = tempfile.mkdtemp()
        with pytest.raises(ValueError):
            resolve_within(base, bad)


class TestValidateRemote:
    @pytest.mark.parametrize("url", [
        "ext::sh -c id",          # git transport helper -> RCE
        "fd::17",
        "file:///etc/passwd",     # local file read
        "--upload-pack=/x",       # arg injection
        "-oProxyCommand=x",
        "https://a::b/c",         # embedded transport helper
    ])
    def test_dangerous_urls_rejected(self, url):
        with pytest.raises(RuntimeError):
            _REPO_CLS._validate_remote(url, "main")

    def test_dangerous_branch_rejected(self):
        with pytest.raises(RuntimeError):
            _REPO_CLS._validate_remote("https://github.com/a/b", "--upload-pack=x")

    @pytest.mark.parametrize("url", [
        "https://github.com/a/b",
        "http://localhost/a/b",
        "git@github.com:a/b.git",
        "ssh://git@host/x",
        "git://host/x",
    ])
    def test_legitimate_urls_allowed(self, url):
        _REPO_CLS._validate_remote(url, "main")  # must not raise


def test_server_cors_is_not_wildcard():
    """The launch server must not allow any origin."""
    from isitsecure.server import app as server_app
    cors = [m for m in server_app.app.user_middleware
            if "CORS" in m.cls.__name__]
    assert cors, "CORS middleware missing"
    opts = cors[0].kwargs if hasattr(cors[0], "kwargs") else cors[0].options
    assert opts.get("allow_origins") != ["*"]
    assert opts.get("allow_origin_regex")  # loopback-only regex in place


class TestCredentialRedirect:
    """Credentialed clients must not auto-follow cross-origin redirects (M1)."""

    _kw = dict(max_concurrent=1, delay_seconds=0.0, timeout_seconds=5.0,
               user_agent="test")

    async def test_auth_header_disables_redirect_following(self):
        from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
        async with RateLimitedClient(**self._kw,
                                     extra_headers={"apikey": "secret"}) as c:
            assert c._client.follow_redirects is False
        async with RateLimitedClient(**self._kw,
                                     extra_headers={"Authorization": "Bearer x"}) as c:
            assert c._client.follow_redirects is False

    async def test_no_credentials_follows_redirects_by_default(self):
        from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
        async with RateLimitedClient(**self._kw) as c:
            assert c._client.follow_redirects is True
