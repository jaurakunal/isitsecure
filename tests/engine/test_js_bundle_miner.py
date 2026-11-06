"""Tests for the JS bundle miner and its wiring into endpoint discovery."""

from __future__ import annotations

import logging

import pytest

from isitsecure.engine.scanners.endpoint_discovery import EndpointDiscoveryScanner
from isitsecure.engine.shared.js_bundle_miner import (
    extract_script_srcs,
    is_catch_all,
    is_plausible_backend,
    is_third_party,
    mine_api_calls,
    mine_absolute_urls,
    mine_backend_origins,
    mine_spa_routes,
    prioritize_bundles,
)

SHELL = "https://app.example-spa.io"
BACKEND = "https://ab12cd34.execute-api.us-east-1.amazonaws.com"

# A minified-style bundle: cross-origin gateway host, base+property concatenation,
# a fetch with a method, and third-party noise that must not become a target.
BUNDLE = (
    'const cfg={apiBase:"' + BACKEND + '/prod"};'
    'class A{constructor(h){this.hostServer="' + BACKEND + '/prod";'
    'this.host=this.hostServer+"/accounts";}'
    'save(b){return this.http.post(this.host,b)}'
    'del(i){return this.http.delete(this.hostServer+"/accounts/"+i)}}'
    'fetch("' + BACKEND + '/prod/me",{method:"PUT",body:1});'
    'axios.get(`${cfg.apiBase}/orders/${id}`);'
    'var s="https://js.stripe.com/v3",g="https://www.google-analytics.com/a.js",'
    'c="https://d111.cloudfront.net/x.png",b="https://my-bucket.s3.amazonaws.com/img.png",'
    'h="https://api.hubspot.com/crm/v3",d="https://docs.vendor-site.org/guide";'
)


def test_third_party_exclusion():
    assert is_third_party("api.hubspot.com")
    assert is_third_party("js.stripe.com")
    assert not is_third_party("ab12cd34.execute-api.us-east-1.amazonaws.com")


@pytest.mark.parametrize("url", [
    "https://js.stripe.com/v3",
    "https://my-bucket.s3.amazonaws.com/img.png",
    "https://d111.cloudfront.net/x.png",
    "https://docs.vendor-site.org/guide",   # no API evidence
    "http://127.0.0.1:9000/api/x",
    "http://localhost:3000/api/x",
])
def test_not_plausible_backend(url):
    assert not is_plausible_backend(url)


@pytest.mark.parametrize("url", [
    "https://ab12cd34.execute-api.us-east-1.amazonaws.com/prod",
    "https://api.myapp.io",
    "https://backend-2.myapp.io",
    "https://services.myapp.io/api/v1",
])
def test_plausible_backend(url):
    assert is_plausible_backend(url)


def test_backend_origins_cross_origin_only():
    assert [m.origin for m in mine_backend_origins(BUNDLE, SHELL)] == [BACKEND]
    # The same host is not "cross-origin" when the page itself lives there.
    assert mine_backend_origins(BUNDLE, BACKEND + "/") == []


def test_backend_origin_carries_evidence():
    (m,) = mine_backend_origins(BUNDLE, SHELL)
    assert "execute-api" in m.evidence


def test_docs_host_with_api_in_path_is_not_ranked_over_real_backend():
    text = '"https://developers.vendor.io/docs/guide","' + BACKEND + '/prod"'
    assert [m.origin for m in mine_backend_origins(text, SHELL)] == [BACKEND]


def test_origin_cap_ranks_by_evidence_before_truncating(monkeypatch, caplog):
    import isitsecure.engine.shared.js_bundle_miner as jm
    monkeypatch.setattr(jm, "MAX_BACKEND_HOSTS", 2)
    # Three path-hint-only hosts seen first, then a strong api-labelled host seen last.
    text = ('"https://a.svc-one.io/v1/x","https://b.svc-two.io/v1/x","https://c.svc-three.io/v1/x",'
            '"https://api.realbackend.io"')
    with caplog.at_level(logging.INFO, logger=jm.logger.name):
        origins = [m.origin for m in jm.mine_backend_origins(text, SHELL)]
    assert origins[0] == "https://api.realbackend.io"
    assert len(origins) == 2
    assert "dropping backend origin" in caplog.text


def test_absolute_urls_deduped():
    assert mine_absolute_urls('"https://a.io/x","https://a.io/x"') == ["https://a.io/x"]


def test_calls_resolve_base_property_concatenation():
    calls = set(mine_api_calls(BUNDLE))
    assert ("POST", BACKEND + "/prod/accounts") in calls      # this.hostServer + this.host chain
    assert ("DELETE", BACKEND + "/prod/accounts/") in calls   # base + literal + id
    assert ("PUT", BACKEND + "/prod/me") in calls             # fetch with method
    assert ("GET", BACKEND + "/prod/orders/{id}") in calls    # template literal, id slot


def test_calls_skip_assets_and_unresolvable():
    assert mine_api_calls('x.get("/logo.png");y.post(unknownVar,1);') == []


def test_spa_routes_include_angular_slashless_and_drop_session_routes():
    text = (
        '{path:"/shop"},{path:"deluxe-membership"},{"path":\'/post/:id\'},'
        '{path:"login"},{path:"/logout"},{clipPath:"/nope"},{path:"M10 20"}'
    )
    assert mine_spa_routes(text) == ["/shop", "/deluxe-membership", "/post"]


def test_script_srcs_same_origin_only_and_prioritised():
    html = (
        '<script src="/chunk-1.js"></script><script src="/polyfills.js"></script>'
        '<script src="https://cdn.other.com/lib.js"></script><script src="main.abc.js"></script>'
    )
    srcs = extract_script_srcs(html, SHELL + "/")
    assert all(s.startswith(SHELL) for s in srcs)
    assert prioritize_bundles(srcs) == [
        SHELL + "/main.abc.js", SHELL + "/chunk-1.js", SHELL + "/polyfills.js",
    ]


def test_catch_all_static_shell_detection():
    shell = "<html><body>app</body></html>"
    assert is_catch_all(shell, shell, shell)
    assert not is_catch_all(shell, '{"error":"not found"}')
    assert not is_catch_all(shell)   # one sample proves nothing
    assert not is_catch_all("", "")


# --- Wiring into the DAST inventory ---


def _quiet_scanner(monkeypatch, probe_writes=False):
    scanner = EndpointDiscoveryScanner(probe_writes=probe_writes)
    probed: list[set[str]] = []

    async def _record(urls, endpoints):
        probed.append(set(urls))

    async def _noop(*a, **k):
        return None

    monkeypatch.setattr(scanner, "_probe_api_base_urls", _record)
    monkeypatch.setattr(scanner, "_probe_openapi_specs", _noop)
    monkeypatch.setattr(scanner, "_probe_supabase_urls", _noop)
    monkeypatch.setattr(scanner, "_discover_html_forms", _noop)
    return scanner, probed


@pytest.mark.asyncio
async def test_discovery_inventory_gains_cross_origin_backend(monkeypatch):
    scanner, probed = _quiet_scanner(monkeypatch, probe_writes=True)
    eps = await scanner.discover(BUNDLE, "<html></html>", SHELL)

    by_key = {(e.method.value, e.url) for e in eps}
    assert ("POST", BACKEND + "/prod/accounts") in by_key
    assert ("PUT", BACKEND + "/prod/me") in by_key
    assert BACKEND in probed[0]
    assert not any("stripe" in e.url for e in eps)


@pytest.mark.asyncio
async def test_unsafe_methods_gated_on_probe_writes(monkeypatch):
    scanner, _ = _quiet_scanner(monkeypatch, probe_writes=False)
    eps = await scanner.discover(BUNDLE, "<html></html>", SHELL)
    mined = [e for e in eps if e.source_pattern == "js_bundle_miner"]
    assert mined, "mined endpoints still inventoried"
    assert {e.method.value for e in mined} == {"GET"}


@pytest.mark.asyncio
async def test_third_party_api_host_not_probed(monkeypatch):
    scanner, probed = _quiet_scanner(monkeypatch)
    await scanner.discover('var h="https://api.hubspot.com/crm/v3";', "", SHELL)
    assert not any("hubspot" in u for u in probed[0])


@pytest.mark.asyncio
async def test_docs_link_not_probed(monkeypatch):
    scanner, probed = _quiet_scanner(monkeypatch)
    await scanner.discover('a="https://developers.vendor.io/api/";', "", SHELL)
    assert not any("vendor.io" in u for u in probed[0])


@pytest.mark.asyncio
async def test_relative_calls_not_retargeted_to_sole_vendor_origin(monkeypatch):
    scanner, _ = _quiet_scanner(monkeypatch)
    text = 'var v="https://api.foo.io/v1";http.get("/api/items");http.post("/api/orders",b);'
    eps = await scanner.discover(text, "", SHELL)
    own = [e for e in eps if e.url.startswith(SHELL)]
    assert any(e.url == SHELL + "/api/items" for e in own)
    assert not any(e.url.startswith("https://api.foo.io") and "/api/items" in e.url for e in eps)


@pytest.mark.asyncio
async def test_probe_switch_disables_mined_backends(monkeypatch):
    scanner, probed = _quiet_scanner(monkeypatch)
    monkeypatch.setattr(scanner, "PROBE_MINED_BACKENDS", False)
    await scanner.discover(BUNDLE, "", SHELL)
    assert BACKEND not in probed[0]
