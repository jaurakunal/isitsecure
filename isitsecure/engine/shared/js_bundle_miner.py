"""Mine a SPA's HTML + JS bundles for its real backend.

A real-world SPA is often a static shell (CDN/S3) whose API lives on a *different*
host, referenced only inside the JS bundle (``https://xxxx.execute-api…/prod`` plus
path strings assembled at runtime). Same-origin page scraping never sees it. This
module:

- lists the ``<script src>`` bundles worth fetching (same-origin, so the fetch stays
  in scope);
- mines text for absolute API URLs and the cross-origin hosts they name, excluding
  third-party providers (analytics / CDNs / payment / SaaS integrations) and keeping
  only hosts that look like the app's OWN backend (``is_plausible_backend``);
- mines ``(METHOD, url-or-path)`` call sites from fetch/axios/HttpClient calls,
  resolving base+property concatenation (``this.http.post(this.server + this.host)``)
  against the bundle's own string bindings;
- mines client-side SPA routes (React/Vue ``path:"/shop"``, Angular slash-less);
- detects the catch-all-200 static-shell pattern.

Pure and network-free; the caller does any (scoped) fetching. Stdlib only.

Consumers: endpoint discovery uses ``mine_backend_origins`` / ``mine_api_calls``. The
bundle-listing, route-mining and static-shell helpers (``extract_script_srcs``,
``prioritize_bundles``, ``mine_spa_routes``, ``is_catch_all``) are not wired into a scan
path yet; they are kept for the authenticated-crawler follow-up (#274).
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# <script src="…"> (and module preloads) — the bundles worth fetching.
_SCRIPT_SRC_RE = re.compile(
    r"""<(?:script[^>]+src|link[^>]+href)\s*=\s*["']([^"']+\.js)["']""", re.IGNORECASE)
# Absolute http(s) URLs anywhere in text.
_ABS_URL_RE = re.compile(r"""https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9_\-./~%+]*)?""")

# Third-party hosts (suffix match) whose presence in a bundle is NOT the app's own backend —
# never surfaced as a scan target (probing them would hit someone else's system).
THIRD_PARTY_SUFFIXES = (
    "googleapis.com", "google.com", "gstatic.com", "google-analytics.com",
    "googletagmanager.com", "doubleclick.net", "gstatic.cn", "recaptcha.net",
    "facebook.com", "facebook.net", "fbcdn.net", "twitter.com", "x.com",
    "stripe.com", "stripe.network", "paypal.com", "braintreegateway.com",
    "cloudflare.com", "cloudflareinsights.com", "jsdelivr.net", "unpkg.com",
    "bootstrapcdn.com", "jquery.com",
    "sentry.io", "segment.com", "segment.io", "hotjar.com", "mixpanel.com",
    "amplitude.com", "intercom.io", "intercomcdn.com", "fullstory.com",
    "cloudfront.net", "gravatar.com", "w3.org", "schema.org",
    "youtube.com", "ytimg.com", "vimeo.com", "linkedin.com", "bing.com",
    "microsoft.com", "windows.net", "office.com", "apple.com", "github.com",
    "githubusercontent.com", "npmjs.org", "example.com", "example.org",
    # Third-party SaaS platforms an app INTEGRATES with (CRM / messaging / support): the app is
    # a tenant, not the owner, so their API is another company's system and other customers' data.
    "gohighlevel.com", "leadconnectorhq.com", "msgsndr.com", "twilio.com", "sendgrid.net",
    "hubspot.com", "hs-scripts.com", "zendesk.com", "salesforce.com", "force.com",
    "mailchimp.com", "algolia.net", "algolianet.com", "datadoghq.com", "datadoghq.eu",
    "launchdarkly.com", "auth0.com", "okta.com", "posthog.com", "logrocket.com",
    "bugsnag.com", "rollbar.com", "newrelic.com", "nr-data.net", "slack.com", "mapbox.com",
    "openai.com", "anthropic.com", "shopify.com", "myshopify.com", "firebaseio.com",
)
# Host labels / path shapes that mark a host as an API (as opposed to a page, CDN or bucket).
_API_HOST_LABEL_RE = re.compile(r"^(?:api|backend|server|gateway|graphql|rest|execute-api)(?:[-\d].*)?$")
_API_URL_PATH_RE = re.compile(r"/(?:api|rest|graphql|v\d+|prod|dev|staging)(?:/|$)", re.IGNORECASE)
# Documentation / marketing / status hosts: their URLs mention "/api/" but are pages, not an API.
_DOCS_HOST_RE = re.compile(
    r"^(?:docs?|developers?|dev-docs|help|support|status|blog|www|learn|wiki|community|kb)[.\-]")
# Object-storage / static-asset hosts: never an API even though they are cross-origin.
_STATIC_HOST_RE = re.compile(r"(?:^|[.-])(?:s3[.-]|cdn|static|assets|media|img|images|fonts)", re.IGNORECASE)

# Asset extensions a "path" string might be — not endpoints.
_ASSET_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
              ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4", ".webm", ".json.map")
MAX_URLS = 120
MAX_CALLS = 120
MAX_ROUTES = 60
MAX_BACKEND_HOSTS = 3
_MAX_BINDINGS = 8000

# Client-side ROUTE paths declared in an SPA router config (``path:"/shop"``,
# ``"path":'/shop'``). These are the app's navigable feature routes, not API endpoints.
# Word-boundary before ``path`` so ``clipPath``/``keypath`` don't match. The value may be
# ``/``-prefixed (React/Vue) or a bare segment (Angular: ``path:"deluxe-membership"``); the
# first char after an optional ``/`` must be lowercase/digit so an SVG ``path:"M10 20…"`` or
# a PascalCase value is not mistaken for a route.
_SPA_ROUTE_RE = re.compile(
    r"""(?<![A-Za-z0-9_$])path["']?\s*:\s*["'](/?[a-z0-9][A-Za-z0-9_\-./:*]{0,120})["']""")
# Routes that would end or waste an authenticated crawl (first path segment).
_SESSION_BREAKING_ROUTES = frozenset({
    "login", "logout", "signin", "sign-in", "signout", "sign-out", "signup", "sign-up",
    "register", "reset-password", "forgot-password",
})


def is_third_party(host: str) -> bool:
    """Whether ``host`` is a known third-party provider (not the app's own backend)."""
    host = host.lower()
    return any(host == s or host.endswith("." + s) for s in THIRD_PARTY_SUFFIXES)


def _is_ip_or_local(host: str) -> bool:
    if host == "localhost" or host.endswith((".localhost", ".local")):
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def backend_evidence(url: str) -> str:
    """Why ``url`` plausibly names the app's OWN API backend ('' if it does not).

    A mined host becomes a scan target, so the bar is deliberately higher than "not on the
    third-party list": the host must not be third-party/static/IP/localhost AND must carry
    API evidence -- an api-ish host label such as ``execute-api`` ("host label"), or an
    api/version/stage path segment ("api path"). Unrelated hosts that merely appear in a
    bundle (docs links, bucket URLs, vendor sites) therefore never widen the scan scope."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host or "." not in host or _is_ip_or_local(host):
        return ""
    if is_third_party(host) or _STATIC_HOST_RE.search(host) or _DOCS_HOST_RE.match(host):
        return ""
    for label in host.split("."):
        if _API_HOST_LABEL_RE.match(label):
            return f"api-like host label '{label}'"
    if _API_URL_PATH_RE.search(parsed.path or ""):
        return f"api path segment in {parsed.path}"
    return ""


def is_plausible_backend(url: str) -> bool:
    """Whether an absolute URL plausibly names the app's own API backend."""
    return bool(backend_evidence(url))


def extract_script_srcs(html: str, base_url: str) -> list[str]:
    """Same-origin ``.js`` bundle URLs to fetch (absolute; cross-origin scripts skipped so
    the fetch stays in scope). Order-preserving, de-duped."""
    base = urlparse(base_url)
    out: list[str] = []
    for raw in _SCRIPT_SRC_RE.findall(html or ""):
        full = urljoin(base_url, raw)
        parsed = urlparse(full)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.hostname and base.hostname and parsed.hostname != base.hostname:
            continue
        if full not in out:
            out.append(full)
    return out


# Entry/shared bundle name tokens hold the app's core HTTP-service code; lazy ``chunk-*``
# bundles hold per-feature UI and polyfills hold shims. Generic build conventions.
_ENTRY_BUNDLE_TOKENS = ("main", "index", "app", "vendor", "common", "runtime", "scripts", "bundle")


def prioritize_bundles(urls: list[str]) -> list[str]:
    """Stable-sort bundle URLs so entry/shared bundles come first and polyfills last, so a
    head-of-list fetch cap does not drop the entry bundle that carries the API call sites."""
    def rank(url: str) -> int:
        name = urlparse(url).path.rsplit("/", 1)[-1].lower()
        if "polyfill" in name:
            return 2
        if any(tok in name for tok in _ENTRY_BUNDLE_TOKENS):
            return 0
        return 1
    return sorted(urls, key=rank)


def _is_api_path(path: str) -> bool:
    lower = path.lower()
    if lower.endswith(_ASSET_EXT) or path in ("/", ""):
        return False
    return bool(re.search(r"[a-z]", lower))


# CLIENT API CALL SITES carrying an HTTP METHOD: ``.post("/api/x"``, ``.put(`${base}/y/${id}`)``
# (HttpClient / axios / jQuery) and ``fetch("/x", {method:"POST"})``.
_CALL_RE = re.compile(
    r"""\.(get|post|put|patch|delete)\s*\(\s*[`"']([^`"']{1,200})[`"']""", re.IGNORECASE)
_FETCH_RE = re.compile(
    r"""fetch\s*\(\s*[`"']([^`"']{1,200})[`"'][^)]{0,200}?method\s*:\s*[`"'](get|post|put|patch|delete)""",
    re.IGNORECASE | re.DOTALL)
# An optional absolute origin followed by a path fragment inside a call's URL argument.
_TARGET_IN_ARG_RE = re.compile(r"(?:https?://[A-Za-z0-9.\-]+(?::\d+)?)?/[A-Za-z0-9_\-./{}$:]{1,120}")


def _target_from_arg(arg: str) -> str:
    """The ``[origin]/path`` fragment inside a call's URL argument (a bare path or a template
    literal like ``${env.api}/rest/basket/${id}``) with ``${…}`` id slots normalised to
    ``{id}``. Keeps an absolute origin when the argument carries one. '' if none."""
    m = _TARGET_IN_ARG_RE.search(arg or "")
    if not m:
        return ""
    return re.sub(r"\$\{[^}]*\}", "{id}", m.group(0))


def _target_path(target: str) -> str:
    return urlparse(target).path if "://" in target else target


# Constant propagation: resolve a base+property CONCAT (``this.hostServer + this.host``), the
# dominant real-app idiom the quote-first regex misses. It resolves THIS app's identifiers to
# THIS app's string literals, so it needs no vocabulary and survives minification.
_METHOD_CALL_EXPR_RE = re.compile(
    r"""\.(get|post|put|patch|delete)\s*\(\s*([A-Za-z_$][^,)]{0,160})""", re.IGNORECASE)
# name bound to a string literal, optionally after a base-expression prefix so the PATH literal
# in a concat assignment is captured too: ``host = "/api/X"``, ``this.host = this.base + "/api/X"``.
_BINDING_RE = re.compile(
    r"""(\w+)\s*[:=]\s*(?:([\w$.\[\]]+)\s*\+\s*)?["'`]([^"'`\n]{1,200})["'`]""")
# A leading ``${expr}`` in a template-literal URL (``${this.api}/orders``).
_LEADING_TEMPLATE_RE = re.compile(r"^\$\{([^}]*)\}")
_MAX_RESOLVE_DEPTH = 3

# (position, name, literal, prefix-name) -- prefix-name is the base identifier a concat binding
# starts from ("" when the literal stands alone).
_Binding = tuple[int, str, str, str]


def _member_name(expr: str) -> str:
    """Last member segment of an identifier chain: ``this.host`` -> ``host``."""
    name = re.split(r"[.\[]", expr.strip())[-1].strip("] )")
    return re.sub(r"[^\w$]", "", name)


def _string_bindings(text: str) -> list[_Binding]:
    """Bindings of names to URL/path strings, in source order. Position lets a call resolve
    against the NEAREST PRECEDING binding of a name (each service's binding sits just before
    its own call sites), avoiding cross-contamination when a common name (``host``) is
    reused. Only values containing ``/`` are kept."""
    out: list[_Binding] = []
    for m in _BINDING_RE.finditer(text or ""):
        if "/" not in m.group(3):
            continue
        out.append((m.start(), m.group(1), m.group(3), _member_name(m.group(2) or "")))
        if len(out) >= _MAX_BINDINGS:
            break
    return out


def _resolve_name(bindings: list[_Binding], name: str, pos: int, depth: int = 0) -> str:
    """Value of ``name`` at ``pos``: the nearest BEFORE (else the first after) binding, with its
    concat prefix resolved recursively (bounded) so ``host = hostServer + "/accounts"`` yields
    the full ``<hostServer literal>/accounts``."""
    cands = [b for b in bindings if b[1] == name]
    if not cands:
        return ""
    before = [b for b in cands if b[0] < pos]
    bpos, _n, literal, prefix = max(before) if before else min(cands)
    if prefix and prefix != name and depth < _MAX_RESOLVE_DEPTH:
        return _resolve_name(bindings, prefix, bpos, depth + 1) + literal
    return literal


def _resolve_call_arg(expr: str, bindings: list[_Binding], pos: int) -> str:
    """Resolve a first-argument expression to a string by concatenating its ``+`` terms: a literal
    contributes itself, an identifier/member its resolved binding. '' if nothing resolves."""
    parts: list[str] = []
    for term in expr.split("+"):
        term = term.strip()
        if not term:
            continue
        if term[0] in "\"'`":
            parts.append(term.strip("\"'`"))
        elif name := _member_name(term):
            parts.append(_resolve_name(bindings, name, pos))
    return "".join(parts)


def _expand_leading_template(arg: str, bindings: list[_Binding], pos: int) -> str:
    """Resolve a leading ``${base}`` of a template-literal URL against the bindings."""
    m = _LEADING_TEMPLATE_RE.match(arg)
    if not m or not bindings:
        return arg
    base = _resolve_name(bindings, _member_name(m.group(1)), pos)
    return base + arg[m.end():] if base else arg


def mine_api_calls(text: str) -> list[tuple[str, str]]:
    """Mine ``(METHOD, target)`` API call sites from a JS bundle, where ``target`` is a path or,
    when the call's base resolves to an absolute origin, a full URL. Covers quoted-literal calls,
    ``fetch(url, {method})`` and base+property concatenation. De-duped, bounded, path-shaped only."""
    src = text or ""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    bindings = _string_bindings(src)

    def _add(method: str, arg: str, pos: int) -> None:
        target = _target_from_arg(_expand_leading_template(arg, bindings, pos))
        key = (method.upper(), target)
        if target and _is_api_path(_target_path(target)) and key not in seen and len(out) < MAX_CALLS:
            seen.add(key)
            out.append(key)

    for m in _CALL_RE.finditer(src):
        _add(m.group(1), m.group(2), m.start())
    for m in _FETCH_RE.finditer(src):
        _add(m.group(2), m.group(1), m.start())
    if bindings:
        for m in _METHOD_CALL_EXPR_RE.finditer(src):
            _add(m.group(1), _resolve_call_arg(m.group(2), bindings, m.start()), m.start())
    return out


def mine_absolute_urls(text: str) -> list[str]:
    """Absolute http(s) URLs in ``text`` (a JS bundle or HTML). De-duped, bounded."""
    urls: list[str] = []
    for match in _ABS_URL_RE.findall(text or ""):
        url = match.rstrip(".,;)")
        if urlparse(url).hostname and url not in urls and len(urls) < MAX_URLS:
            urls.append(url)
    return urls


@dataclass(frozen=True)
class MinedOrigin:
    """A cross-origin backend origin and the evidence that made it plausible."""

    origin: str
    evidence: str
    score: int


def mine_backend_origins(text: str, page_url: str) -> list[MinedOrigin]:
    """Distinct cross-origin backend origins mined from absolute URLs and call sites in ``text``.

    Same-origin hosts are excluded (already in scope) and implausible ones rejected. The
    strongest evidence wins (an api-like host label outranks a bare path hint, and each extra
    plausible reference to the origin adds weight); only then is the list capped at
    ``MAX_BACKEND_HOSTS`` and the dropped origins logged -- so the cap never silently discards
    a better candidate in favour of an earlier-seen one."""
    page_host = (urlparse(page_url).hostname or "").lower()
    urls = mine_absolute_urls(text) + [t for _m, t in mine_api_calls(text) if "://" in t]
    found: dict[str, list] = {}   # origin -> [evidence, score]
    for url in urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        evidence = backend_evidence(url)
        if not host or host == page_host or not evidence:
            continue
        origin = f"{parsed.scheme}://{parsed.netloc}"
        weight = 2 if evidence.startswith("api-like host") else 1
        entry = found.setdefault(origin, [evidence, 0])
        if weight > 1 and not entry[0].startswith("api-like host"):
            entry[0] = evidence
        entry[1] += weight
    ranked = sorted(found.items(), key=lambda kv: -kv[1][1])   # stable: ties keep discovery order
    for origin, (_ev, score) in ranked[MAX_BACKEND_HOSTS:]:
        logger.info("js_bundle_miner: dropping backend origin %s (score %d) over cap %d",
                    origin, score, MAX_BACKEND_HOSTS)
    return [MinedOrigin(o, ev, sc) for o, (ev, sc) in ranked[:MAX_BACKEND_HOSTS]]


def mine_spa_routes(text: str) -> list[str]:
    """Mine an SPA's client-side route paths from its router config. Returns navigable route
    paths (leading ``/``) with parameterised/wildcard segments trimmed to their static prefix
    (``/post/:id`` -> ``/post``), excluding session-breaking routes (login/logout/signup/…).
    Order-preserving, de-duped, bounded."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in _SPA_ROUTE_RE.findall(text or ""):
        static = raw
        for marker in (":", "*"):
            idx = static.find(marker)
            if idx != -1:
                static = static[:idx]
        static = "/" + static.strip("/")
        if static == "/" or static.lower().endswith(_ASSET_EXT):
            continue
        if static.strip("/").split("/", 1)[0].lower() in _SESSION_BREAKING_ROUTES:
            continue
        if static not in seen:
            seen.add(static)
            out.append(static)
        if len(out) >= MAX_ROUTES:
            break
    return out


def is_catch_all(*bodies: str) -> bool:
    """Whether responses to distinct nonsense paths are effectively identical — the static-shell
    signature (a server returning its index.html, 200, for ANY path). Needs at least two
    non-empty, byte-similar bodies."""
    present = [b for b in bodies if b and b.strip()]
    if len(present) < 2:
        return False
    first = present[0].strip()
    return all(_similar(first, other.strip()) for other in present[1:])


def _similar(a: str, b: str) -> bool:
    """Identical, or same length and a matching long prefix (tolerates a tiny dynamic nonce)."""
    if a == b:
        return True
    if abs(len(a) - len(b)) > max(32, len(a) // 100):
        return False
    head = min(len(a), len(b), 512)
    return a[:head] == b[:head]
