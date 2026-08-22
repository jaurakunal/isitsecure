"""Tests for the contained-mode Chromium launch options.

The invariant that keeps ``scan`` byte-identical: OFF the contained lockdown the helper
contributes nothing, so the browser launch is untouched. Only inside the lockdown (the
``ISITSECURE_CONTAINED`` sentinel) does it route the browser through the egress proxy.
"""

from __future__ import annotations

from isitsecure.engine.shared.browser_launch import contained_browser_launch_kwargs


def test_no_kwargs_on_the_host(monkeypatch):
    monkeypatch.delenv("ISITSECURE_CONTAINED", raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy:8080")  # present, but not contained
    assert contained_browser_launch_kwargs() == {}


def test_contained_without_a_proxy_still_carries_survival_args(monkeypatch):
    # Even without a proxy, the container-survival Chromium args must be present (the
    # /dev/shm fix is about the container, not the proxy).
    monkeypatch.setenv("ISITSECURE_CONTAINED", "1")
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        monkeypatch.delenv(var, raising=False)
    kw = contained_browser_launch_kwargs()
    assert "proxy" not in kw
    assert "--disable-dev-shm-usage" in kw["args"] and "--disable-gpu" in kw["args"]


def test_contained_with_proxy_routes_the_browser_through_it(monkeypatch):
    monkeypatch.setenv("ISITSECURE_CONTAINED", "1")
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://isitsec_proxy:8080")
    kw = contained_browser_launch_kwargs()
    assert kw["proxy"] == {"server": "http://isitsec_proxy:8080"}
    assert "--disable-dev-shm-usage" in kw["args"]


def test_https_proxy_wins_over_http_proxy(monkeypatch):
    monkeypatch.setenv("ISITSECURE_CONTAINED", "1")
    monkeypatch.setenv("HTTP_PROXY", "http://http-only:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://https-first:8080")
    assert contained_browser_launch_kwargs()["proxy"]["server"] == "http://https-first:8080"
