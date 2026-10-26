"""D2: the vendor filter must not drop first-party code (B6 #7)."""

from __future__ import annotations

import pytest

from isitsecure.engine.ingestion.vendor_filter import VendorAssetFilter

# Split so the fixture is not itself a committed key-shaped literal.
FAKE_KEY = "sk_" + "live_abcdefghijklmnopqrstuvwx"
APP_CODE = f'const k="{FAKE_KEY}"; fetch("/api/x");'
WEBPACK_RUNTIME_APP = (
    "(()=>{var __webpack_modules__={1:()=>{" + APP_CODE + "}};"
    "function __webpack_require__(i){return __webpack_modules__[i]()}})();"
)
SITE = "https://app.example.com/"


def vendor(url: str, content: str = APP_CODE, site: str = SITE) -> bool:
    return VendorAssetFilter(site).is_vendor_asset(url, content)


# --- first-party code that was wrongly dropped --------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://app.example.com/_next/static/chunks/app/dashboard/page-1a2b3c.js",
        "https://app.example.com/_next/static/chunks/pages/index-1a2b3c.js",
        "https://app.example.com/_next/static/chunks/pages/_app-1a2b3c.js",
    ],
)
def test_next_page_chunks_are_first_party(url: str) -> None:
    assert vendor(url) is False


def test_webpack_app_bundle_is_first_party() -> None:
    assert vendor("https://app.example.com/static/js/main.abc123.js", WEBPACK_RUNTIME_APP) is False


def test_separate_first_party_cdn_domain_is_first_party() -> None:
    assert vendor("https://cdn.example-static.com/app.js") is False


@pytest.mark.parametrize(
    "site,asset",
    [
        ("https://shop.example.co.uk/", "https://cdn.example.co.uk/app.js"),
        ("https://myapp.vercel.app/", "https://myapp.vercel.app/app.js"),
    ],
)
def test_same_site_with_multi_label_suffix_is_first_party(site: str, asset: str) -> None:
    assert vendor(asset, site=site) is False


# --- vendor / third-party code that must still be dropped (positive controls) -


@pytest.mark.parametrize(
    "url",
    [
        "https://app.example.com/_next/static/chunks/framework-1a2b3c4d.js",
        "https://app.example.com/_next/static/chunks/main-1a2b3c4d.js",
        "https://app.example.com/_next/static/chunks/webpack-1a2b3c4d.js",
        "https://app.example.com/_next/static/chunks/polyfills-1a2b3c4d.js",
        "https://app.example.com/_next/static/chunks/main-app-1a2b3c4d.js",
        "https://app.example.com/_next/static/chunks/1234-1a2b3c4d.js",
        "https://app.example.com/_nuxt/entry.abc.js",
        "https://app.example.com/js/chunk-vendors.js",
    ],
)
def test_framework_and_vendor_bundles_stay_vendor(url: str) -> None:
    assert vendor(url) is True


def test_react_bundle_stays_vendor_by_content() -> None:
    content = "/* react-dom/cjs/react-dom.production.min.js */ " + APP_CODE
    assert vendor("https://app.example.com/static/js/main.abc.js", content) is True


@pytest.mark.parametrize(
    "site,asset",
    [
        (SITE, "https://cdn.evil.com/app.js"),
        (SITE, "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"),
        ("https://shop.example.co.uk/", "https://evil.other.co.uk/app.js"),
        ("https://myapp.vercel.app/", "https://other.vercel.app/app.js"),
    ],
)
def test_other_sites_stay_third_party(site: str, asset: str) -> None:
    assert vendor(asset, site=site) is True
