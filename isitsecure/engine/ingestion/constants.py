"""Constants for URL ingestion and vendor filtering.

Inlined subset from security_audit.constants needed for standalone operation.
"""


class ScanConfig:
    """Configuration constants for URL ingestion."""

    PAGE_LOAD_TIMEOUT_MS = 60000
    ASSET_FETCH_TIMEOUT_SECONDS = 15
    MAX_JS_BUNDLE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB
    MAX_ASSETS_TO_FETCH = 20
    MAX_PROBE_CONTENT_LENGTH = 5000
    MIN_INLINE_SCRIPT_LENGTH = 50

    DEFAULT_VIEWPORT_WIDTH = 1920
    DEFAULT_VIEWPORT_HEIGHT = 1080

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    PROBE_PATHS = [
        "/.env",
        "/config.js",
        "/.git/config",
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
    ]


class InjectionScannerConfig:
    """Vendor/framework detection configuration for asset filtering."""

    FRAMEWORK_PATH_PREFIXES = (
        "/_next/",
        "/_nuxt/",
        "/_astro/",
        "/__remix/",
    )

    FRAMEWORK_BUNDLE_PATH_PATTERNS = (
        r"""/static/js/(?:runtime|vendors|chunk)-""",
        r"""/(?:webpack-runtime|framework|commons)-[0-9a-f]+\.js""",
        r"""/(?:runtime|polyfills|vendor|scripts)\.[0-9a-f]+\.js""",
        r"""/assets/(?:vendor|polyfills|framework)-[0-9a-f]+\.js""",
        r"""/(?:vendors|vendor|runtime)~?[.-][0-9a-f]+\.js""",
        r"""/build/(?:_shared|entry)\.""",
    )

    VENDOR_CONTENT_MARKERS_STRONG = (
        "__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED",
        "react-dom/cjs/react-dom",
        "self.webpackChunk_N_E",
        "webpackJsonpCallback",
        "__turbopack_require__",
        "__turbopack_external_require__",
        "ɵɵdefineComponent",
        "ɵɵelementStart",
    )

    VENDOR_CONTENT_MARKERS = (
        "__webpack_require__",
        "__webpack_modules__",
        "__webpack_exports__",
        "webpackChunkName",
        "__vite_ssr_import__",
        "__NEXT_DATA__",
        "__next_f",
        "__next_app_webpack_require__",
        "__NUXT__",
        "__nuxt_component_",
        "__ng_entrypoint__",
        'Symbol.for("react.element")',
        "__svelte_meta",
    )

    VENDOR_CONTENT_MARKER_THRESHOLD = 2

    THIRD_PARTY_SCRIPT_DOMAINS = (
        "connect.facebook.net",
        "www.facebook.com",
        "www.googletagmanager.com",
        "www.google-analytics.com",
        "googleads.g.doubleclick.net",
        "www.googleadservices.com",
        "pagead2.googlesyndication.com",
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
        "unpkg.com",
        "ajax.googleapis.com",
        "maps.googleapis.com",
        "apis.google.com",
        "static.hotjar.com",
        "script.hotjar.com",
        "snap.licdn.com",
        "static.ads-twitter.com",
        "analytics.tiktok.com",
        "bat.bing.com",
        "js.hs-scripts.com",
        "js.hs-analytics.net",
        "js.hsforms.net",
        "widget.intercom.io",
        "js.intercomcdn.com",
        "cdn.segment.com",
        "cdn.amplitude.com",
        "cdn.mxpnl.com",
        "cdn.heapanalytics.com",
        "js.stripe.com",
        "js.braintreegateway.com",
        "challenges.cloudflare.com",
        "static.cloudflareinsights.com",
        "plausible.io",
        "cdn.sentry.io",
    )
