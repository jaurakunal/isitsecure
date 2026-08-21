"""Authenticated web crawler using Playwright.

Logs in via the browser UI, then BFS-crawls all internal links while
intercepting every network request.  Discovers:

- Pages only visible when logged in (dashboard, settings, admin)
- API calls made by those pages (XHR / fetch interception)
- Supabase REST queries with table names and filters
- Resources owned by the authenticated user (UUIDs, numeric IDs)
- Auth headers / tokens for downstream scanners
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from collections import deque
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    from playwright.async_api import async_playwright
except ImportError:  # pragma: no cover
    async_playwright = None  # type: ignore[assignment, misc]

from isitsecure.engine.auth.browser_login_helper import (
    BrowserLoginHelper,
    extract_token_from_json,
)
from isitsecure.engine.constants import (
    AuthenticatedCrawlerConfig,
    BrowserLoginConfig,
    BrowserSignupConfig,
    SharedPatterns,
)
from isitsecure.engine.enums import EndpointCategory, EndpointMethod
from isitsecure.engine.models import (
    AuthenticatedCrawlResult,
    BrowserSignupResult,
    DiscoveredEndpoint,
    FormField,
    FormFillPlan,
    FormPerception,
    InterceptedRequest,
)
from isitsecure.engine.shared.html_endpoint_extractor import (
    extract_html_endpoints,
)
from isitsecure.engine.shared.progress import emit
from isitsecure.engine.shared.supabase_utils import (
    extract_supabase_table_from_url,
)

logger = logging.getLogger(__name__)

# Bounded adaptive retries for the LLM form-comprehension signup (perceive → plan → execute
# → submit, re-perceiving on a still-invalid form). Module-level so tests can tighten it.
_MAX_FORM_ATTEMPTS = BrowserSignupConfig.MAX_FORM_ATTEMPTS

# --- Browser-signup DOM helpers (JS run in the page; see AuthenticatedCrawler.signup) ---
# Each carries a distinctive marker comment so tests can dispatch a mock ``page.evaluate``.

# Return the href of the first anchor whose text/href looks like a "go to register" link.
_FIND_REGISTER_LINK_JS = """
(keywords) => { /* find-register-link */
  const anchors = Array.from(document.querySelectorAll('a[href]'));
  for (const a of anchors) {
    const text = (a.textContent || '').toLowerCase();
    const href = (a.getAttribute('href') || '').toLowerCase();
    if (keywords.some((k) => text.includes(k) || href.includes(k))) {
      return a.href || a.getAttribute('href') || '';
    }
  }
  return '';
}
"""

# True when the current page renders a registration form (a visible password input).
_HAS_SIGNUP_FORM_JS = """
() => { /* has-signup-form */
  const vis = (el) => !!(el.offsetParent || el.getClientRects().length);
  return !!Array.from(document.querySelectorAll('input[type="password"]')).find(vis);
}
"""

# Enumerate the visible, fillable inputs/selects, stamping each with an index attribute
# so the Python side can target it for filling, and returning its identifying metadata.
_ENUM_SIGNUP_FIELDS_JS = """
(attr) => { /* enum-signup-fields */
  const skip = ["hidden", "file", "submit", "button", "reset", "image"];
  const vis = (el) => !!(el.offsetParent || el.getClientRects().length);
  const nodes = Array.from(document.querySelectorAll('input, select, textarea'));
  const out = [];
  let idx = 0;
  for (const el of nodes) {
    const type = (el.getAttribute('type') || el.tagName.toLowerCase()).toLowerCase();
    if (skip.includes(type) || el.disabled || !vis(el)) continue;
    let label = '';
    if (el.id) {
      const l = document.querySelector('label[for="' + el.id + '"]');
      if (l) label = l.textContent || '';
    }
    if (!label && el.closest) {
      const l = el.closest('label');
      if (l) label = l.textContent || '';
    }
    el.setAttribute(attr, String(idx));
    out.push({
      idx: idx,
      name: el.getAttribute('name') || '',
      id: el.getAttribute('id') || '',
      type: type,
      placeholder: el.getAttribute('placeholder') || '',
      aria: el.getAttribute('aria-label') || '',
      label: (label || '').trim(),
      required: el.hasAttribute('required'),
    });
    idx++;
  }
  return out;
}
"""

# True when a CAPTCHA widget is present on the page (the form is walled).
_DETECT_CAPTCHA_JS = """
(selector) => { /* detect-captcha */
  return !!document.querySelector(selector);
}
"""

# The page's visible text (for detecting an email/SMS-verification wall).
_SIGNUP_PAGE_TEXT_JS = """
() => { /* signup-page-text */
  return document.body ? (document.body.innerText || '') : '';
}
"""

# Rich PERCEPTION of the register form for the LLM form-comprehension path. For every visible
# fillable control it CLASSIFIES the control into a CANONICAL, framework-agnostic ``control_kind``
# (text / single_select / multi_select / radio_group / checkbox / toggle / other) detected across
# native HTML, Angular Material (mat-select / mat-radio-group / mat-checkbox / mat-slide-toggle)
# and React/ARIA ([role=combobox/listbox/radiogroup/checkbox/switch], react-select), stamps a
# unique locator attribute, and returns its identifying metadata. Native radios sharing a ``name``
# (and mat-radio-group / role=radiogroup) collapse to ONE radio_group field. For a choice control
# it enumerates the option texts INLINE (native <option>s / radio labels); an overlay widget
# (mat-select / combobox / listbox / react-select), whose options render lazily only when opened,
# is flagged ``overlay:true`` so the Python side can open→read→close it. Also stamps and returns
# the submit control's locator. (See AuthenticatedCrawler._perceive_form.)
_PERCEIVE_FORM_JS = """
(cfg) => { /* perceive-form */
  const fieldAttr = cfg.fieldAttr;
  const submitAttr = cfg.submitAttr;
  const maxOptions = cfg.maxOptions;
  const skip = ["hidden", "file", "submit", "button", "reset", "image"];
  const vis = (el) => !!(el.offsetParent || el.getClientRects().length);
  const labelFor = (el) => {
    let label = '';
    if (el.id) {
      const l = document.querySelector('label[for="' + el.id + '"]');
      if (l) label = l.textContent || '';
    }
    if (!label && el.closest) {
      const l = el.closest('label');
      if (l) label = l.textContent || '';
    }
    return (label || '').trim();
  };
  const cls = (el) => (el.getAttribute('class') || '').toLowerCase();
  const isReactSelect = (el) => {
    const c = cls(el);
    return c.indexOf('select__control') !== -1 || c.indexOf('react-select') !== -1
      || /select-\\w+__control/.test(c);
  };
  const multiSelectable = (el) =>
    (el.getAttribute('aria-multiselectable') || '') === 'true' || el.hasAttribute('multiple')
    || !!el.querySelector('[aria-multiselectable="true"], select[multiple]');
  const classify = (el, tag, type, role) => {
    if (tag === 'mat-slide-toggle' || role === 'switch') return {kind: 'toggle', overlay: false};
    if (tag === 'mat-checkbox' || role === 'checkbox' || type === 'checkbox')
      return {kind: 'checkbox', overlay: false};
    if (tag === 'mat-radio-group' || role === 'radiogroup')
      return {kind: 'radio_group', overlay: false};
    if (tag === 'select')
      return {kind: el.multiple ? 'multi_select' : 'single_select', overlay: false};
    if (tag === 'mat-select')
      return {kind: multiSelectable(el) ? 'multi_select' : 'single_select', overlay: true};
    if (role === 'combobox') return {kind: 'single_select', overlay: true};
    if (role === 'listbox')
      return {kind: multiSelectable(el) ? 'multi_select' : 'single_select', overlay: true};
    if (isReactSelect(el))
      return {kind: multiSelectable(el) ? 'multi_select' : 'single_select', overlay: true};
    const textish = ['text', 'email', 'password', 'number', 'tel', 'url', 'search'];
    if (tag === 'textarea' || textish.indexOf(type) !== -1) return {kind: 'text', overlay: false};
    return {kind: 'other', overlay: false};
  };
  const readInlineOptions = (el, tag, role) => {
    let nodes = [];
    if (tag === 'select') {
      nodes = Array.from(el.querySelectorAll('option'));
    } else if (tag === 'mat-radio-group' || role === 'radiogroup') {
      nodes = Array.from(el.querySelectorAll('mat-radio-button, [role="radio"]'));
    } else {
      nodes = Array.from(el.querySelectorAll('mat-option, [role="option"], option'));
    }
    const out = [];
    for (const n of nodes) {
      const text = (n.textContent || n.value || '').trim();
      if (text && out.indexOf(text) === -1) out.push(text);
      if (out.length >= maxOptions) break;
    }
    return out;
  };
  const selector = ['input', 'select', 'textarea', 'mat-select', 'mat-radio-group',
    'mat-checkbox', 'mat-slide-toggle', '[role="combobox"]', '[role="listbox"]',
    '[role="radiogroup"]', '[role="checkbox"]', '[role="switch"]'].join(', ');
  const nodes = Array.from(document.querySelectorAll(selector));
  const out = [];
  let idx = 0;
  const seenRadio = {};
  const push = (el, kind, tag, type, options, overlay) => {
    el.setAttribute(fieldAttr, String(idx));
    out.push({
      locator: '[' + fieldAttr + '="' + idx + '"]', control_kind: kind, tag: tag, type: type,
      name: el.getAttribute('name') || '', id: el.getAttribute('id') || '', label: labelFor(el),
      placeholder: el.getAttribute('placeholder') || '', aria: el.getAttribute('aria-label') || '',
      required: el.hasAttribute('required') || (el.getAttribute('aria-required') || '') === 'true',
      value: (el.value !== undefined && el.value !== null) ? String(el.value) : '',
      options: options, overlay: overlay,
    });
    idx++;
  };
  for (const el of nodes) {
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute('type') || tag).toLowerCase();
    const role = (el.getAttribute('role') || '').toLowerCase();
    if (skip.indexOf(type) !== -1 || el.disabled || !vis(el)) continue;
    // A native radio inside a mat-radio-group / role=radiogroup is spoken for by that group.
    if (type === 'radio' && el.closest('mat-radio-group, [role="radiogroup"]')) continue;
    // Group native radios sharing a name into ONE radio_group field (options = the choices).
    if (type === 'radio') {
      const name = el.getAttribute('name') || '';
      const key = 'r:' + (name || ('_' + idx));
      if (seenRadio[key]) continue;
      seenRadio[key] = true;
      const scoped = name
        ? Array.from(document.querySelectorAll('input[type="radio"][name="' + name + '"]'))
        : [el];
      const opts = [];
      for (const r of scoped) {
        const t = (labelFor(r) || r.value || '').trim();
        if (t && opts.indexOf(t) === -1) opts.push(t);
        if (opts.length >= maxOptions) break;
      }
      push(el, 'radio_group', tag, type, opts, false);
      continue;
    }
    const info = classify(el, tag, type, role);
    const isChoice = info.kind === 'single_select' || info.kind === 'multi_select'
      || info.kind === 'radio_group';
    push(el, info.kind, tag, type,
      isChoice ? readInlineOptions(el, tag, role) : [], info.overlay);
  }
  let submit = '';
  let btn = document.querySelector('button[type="submit"], input[type="submit"]');
  if (!btn) {
    btn = Array.from(document.querySelectorAll('button')).find(
      (b) => /register|sign ?up|create account|get started/i.test(b.textContent || ''));
  }
  if (btn) {
    btn.setAttribute(submitAttr, '1');
    submit = '[' + submitAttr + '="1"]';
  }
  return { fields: out, submit: submit };
}
"""

# Read the option texts of a JUST-OPENED overlay dropdown (mat-select / combobox / listbox /
# react-select) — its options render lazily in a CDK/portal overlay only while open. Called by
# the Python side after it clicks the widget's trigger; READ-ONLY (never selects). (See
# AuthenticatedCrawler._enumerate_overlay_options.)
_READ_OVERLAY_OPTIONS_JS = """
(cfg) => { /* read-overlay-options */
  const maxOptions = cfg.maxOptions;
  const nodes = Array.from(document.querySelectorAll(
    'mat-option, [role="option"], .select__option, [class*="option"]'));
  const out = [];
  for (const n of nodes) {
    const text = (n.textContent || '').trim();
    if (text && out.indexOf(text) === -1) out.push(text);
    if (out.length >= maxOptions) break;
  }
  return out;
}
"""

# Choose ONE option of a radio_group by visible text (case-insensitive, trimmed, exact-then-
# contains). Handles native ``input[type=radio]`` (grouped by ``name``), mat-radio-button, and
# ``[role=radio]``. Clicks the matching control; returns whether one matched. (See
# AuthenticatedCrawler._choose_option.)
_CHOOSE_OPTION_JS = """
(cfg) => { /* choose-option */
  const want = (cfg.value || '').trim().toLowerCase();
  const el = document.querySelector(cfg.locator);
  if (!el) return false;
  const type = (el.getAttribute('type') || '').toLowerCase();
  let group;
  if (type === 'radio') {
    const name = el.getAttribute('name') || '';
    group = name
      ? Array.from(document.querySelectorAll('input[type="radio"][name="' + name + '"]'))
      : [el];
  } else {
    group = Array.from(el.querySelectorAll('mat-radio-button, [role="radio"], input[type="radio"]'));
  }
  const textOf = (r) => {
    let t = (r.textContent || '').trim();
    if (!t && r.id) {
      const l = document.querySelector('label[for="' + r.id + '"]');
      if (l) t = (l.textContent || '').trim();
    }
    if (!t && r.closest) { const l = r.closest('label'); if (l) t = (l.textContent || '').trim(); }
    return (t || r.value || '').trim().toLowerCase();
  };
  const click = (r) => { (r.matches('input') ? r : (r.querySelector('input') || r)).click(); return true; };
  for (const r of group) { if (textOf(r) === want) return click(r); }
  for (const r of group) { if (want && textOf(r).indexOf(want) !== -1) return click(r); }
  return false;
}
"""

# Set a checkbox/toggle to a desired boolean, handling native ``input``, mat-checkbox /
# mat-slide-toggle, and ``[role=checkbox]``/``[role=switch]``. Reads the current state
# (``.checked`` of the inner input, else ``aria-checked``) and clicks only if it differs. (See
# AuthenticatedCrawler._set_checked, used for the mat/role variants.)
_SET_STATE_JS = """
(cfg) => { /* set-control-state */
  const desired = !!cfg.checked;
  const el = document.querySelector(cfg.locator);
  if (!el) return false;
  const inner = el.matches('input') ? el : el.querySelector('input');
  const current = (inner && inner.checked !== undefined)
    ? !!inner.checked : (el.getAttribute('aria-checked') || '') === 'true';
  if (current !== desired) {
    (el.matches('input') ? el : (el.querySelector('label, input, button') || el)).click();
  }
  return desired;
}
"""


class AuthenticatedCrawler:
    """Crawls a web app as an authenticated user using Playwright.

    Responsibilities are split across collaborators:
    - ``BrowserLoginHelper`` handles form-filling and token extraction (DRY)
    - This class handles BFS crawling, network interception, and result building
    """

    _UUID_RE = re.compile(AuthenticatedCrawlerConfig.UUID_PATTERN, re.IGNORECASE)

    def __init__(
        self,
        base_url: str,
        email: str,
        password: str,
        login_url: str | None = None,
        seed_routes: list[str] | None = None,
        safe_mode: bool = False,
        deep: bool = False,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._email = email
        self._password = password
        self._login_url = login_url or f"{self._base_url}/login"
        self._seed_routes = seed_routes or []
        # When True (the pentest crawl path), blind clicking of state-changing buttons is
        # disabled: only clearly-destructive text is filtered by the default heuristic, so
        # an icon-only / non-English / "Confirm" button still triggers an unaudited real
        # side effect that never routes through the destructive-op floor. safe_mode skips
        # button interaction entirely. Default False keeps scan behavior byte-identical.
        self._safe_mode = safe_mode
        # DEEP is a pentest-only opt-in (the pentest ``crawl`` tool sets it alongside
        # ``safe_mode``); scan builds the crawler WITHOUT it. It only widens two conservative,
        # read-only knobs to surface more of a heavy SPA's live API — a higher page budget
        # and a longer per-page network-idle settle (so more XHR/fetch is captured by the
        # existing interception). It does NOT change what is clicked (still safe/no blind
        # clicks), the origin bound, or the scheme guard. Because both knobs DEFAULT to the
        # existing scan constants when ``deep`` is False, scan's page budget and waits are
        # byte-identical.
        self._deep = deep
        self._max_pages = (
            AuthenticatedCrawlerConfig.DEEP_MAX_PAGES_TO_VISIT if deep
            else AuthenticatedCrawlerConfig.MAX_PAGES_TO_VISIT
        )
        self._bfs_network_idle_timeout_ms = (
            AuthenticatedCrawlerConfig.DEEP_BFS_NETWORK_IDLE_TIMEOUT_MS if deep
            else AuthenticatedCrawlerConfig.BFS_NETWORK_IDLE_TIMEOUT_MS
        )

        self._intercepted: list[InterceptedRequest] = []
        self._auth_headers: dict[str, str] = {}
        self._visited: set[str] = set()
        self._link_queue: deque[str] = deque()
        self._login_succeeded = False
        # Server-rendered form/link endpoints found on crawled pages, keyed
        # "METHOD:url" — complements the intercepted XHR/fetch endpoints.
        self._html_endpoints: dict[str, DiscoveredEndpoint] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def crawl(self) -> AuthenticatedCrawlResult:
        """Execute the full authenticated crawl."""
        if async_playwright is None:
            logger.error(AuthenticatedCrawlerConfig.ERROR_PLAYWRIGHT_UNAVAILABLE)
            return AuthenticatedCrawlResult(
                errors=[AuthenticatedCrawlerConfig.ERROR_PLAYWRIGHT_UNAVAILABLE],
            )

        result = AuthenticatedCrawlResult()

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    context = await browser.new_context(
                        viewport={"width": 1280, "height": 720},
                    )
                    page = await context.new_page()
                    self._setup_interception(page)
                    self._setup_websocket_capture(page)

                    self._login_succeeded = await self._login(page)
                    if not self._login_succeeded:
                        result.errors.append(
                            BrowserLoginConfig.ERROR_LOGIN_FAILED.format(
                                error="Could not complete login flow"
                            )
                        )

                    self._auth_headers = await self._extract_auth_headers(page)
                    result.auth_headers = self._auth_headers

                    self._seed_link_queue()
                    await self._discover_links_from_page(page)

                    pages_visited = await self._bfs_crawl(page, result)

                    await page.close()
                    await context.close()
                finally:
                    await browser.close()

            result.pages_visited = pages_visited
            result.pages_discovered = sorted(self._visited)
            result.intercepted_requests = self._intercepted[
                : AuthenticatedCrawlerConfig.MAX_INTERCEPTED_REQUESTS
            ]
            result.supabase_queries = self._filter_supabase_queries()
            result.discovered_endpoints = self._build_endpoints()
            result.owned_resource_ids = self._aggregate_resource_ids()
            result.tables_discovered = self._extract_supabase_tables()

        except Exception as exc:
            error_msg = AuthenticatedCrawlerConfig.ERROR_CRAWL_FAILED.format(
                error=str(exc)
            )
            logger.error(error_msg)
            result.errors.append(error_msg)

        logger.info(
            AuthenticatedCrawlerConfig.LOG_CRAWL_SUMMARY,
            self._login_succeeded,
            result.pages_visited,
            len(result.intercepted_requests),
            len(result.discovered_endpoints),
            len(result.owned_resource_ids),
            len(result.tables_discovered),
        )
        return result

    # ------------------------------------------------------------------
    # Browser self-registration (pentest-only; scan NEVER calls this)
    # ------------------------------------------------------------------

    async def signup(
        self,
        *,
        username: str,
        email: str | None = None,
        password: str | None = None,
        synthesize: Callable[[str], Any] | None = None,
        register_url: str | None = None,
        form_filler: Callable[..., Any] | None = None,
    ) -> BrowserSignupResult:
        """Drive a REAL browser to self-register the AGENT'S OWN account, capturing the
        real signup endpoint from the resulting XHR.

        This is the "read and UNDERSTAND the app, don't guess" fallback for a JavaScript SPA
        whose signup endpoint is not discoverable by path-probing (e.g. Juice Shop's
        ``POST /api/Users``): navigate to the register page, PERCEIVE the form (rich DOM
        extraction + a screenshot), let an LLM decide the fill (which value per field, WHICH
        dropdown option), EXECUTE the plan, submit, and read the intercepted API call the
        submit fired — which both reveals the real endpoint AND creates the account. On a
        still-invalid form it re-perceives and re-plans, bounded, then gives up honestly.

        When ``form_filler`` is None (tests / callers with no LLM), it falls back to the
        legacy HEURISTIC fill (:meth:`_fill_signup_form`) so nothing regresses. Either way it
        reuses the crawler's browser lifecycle and ``_setup_interception`` (so the signup XHR
        is captured exactly as ``crawl`` captures API calls) and ``BrowserLoginHelper`` for
        submission — a targeted, audited, single-form provisioning action, NOT the blind
        clicking ``safe_mode`` suppresses. It NEVER fills privilege fields (the executor
        strips any such plan action, and the heuristic path delegates to ``synthesize`` which
        returns ``None`` for them) and NEVER submits anything but the register form. A
        CAPTCHA / email- / SMS-verification wall is *detected and reported* via
        ``blocked_reason`` — never defeated (the honest boundary).

        ``email``/``password`` default to the crawler's constructor credentials.
        ``synthesize(name) -> value`` returns a safe value for an unrecognized field, or
        ``None`` to REFUSE it (privilege fields); it defaults to a benign string filler.
        Scan builds the crawler and only ever calls :meth:`crawl` — this method is on a
        separate path scan never invokes, so scan's behavior is byte-identical.
        """
        email = email or self._email
        password = password or self._password
        fill_value = synthesize or (lambda _name: "test")

        if async_playwright is None:
            logger.error(AuthenticatedCrawlerConfig.ERROR_PLAYWRIGHT_UNAVAILABLE)
            return BrowserSignupResult(
                success=False, email=email, password=password, username=username,
                error=AuthenticatedCrawlerConfig.ERROR_PLAYWRIGHT_UNAVAILABLE,
            )

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    context = await browser.new_context(
                        viewport={"width": 1280, "height": 720},
                    )
                    page = await context.new_page()
                    self._setup_interception(page)
                    result = await self._run_signup(
                        page, email, password, username, fill_value, register_url,
                        form_filler,
                    )
                    await page.close()
                    await context.close()
                finally:
                    await browser.close()
            return result
        except Exception as exc:  # noqa: BLE001 — a browser failure is a result, not a crash
            logger.error("Browser signup failed: %s", exc)
            return BrowserSignupResult(
                success=False, email=email, password=password, username=username,
                error=str(exc),
            )

    async def _run_signup(
        self,
        page: object,
        email: str,
        password: str,
        username: str,
        fill_value: Callable[[str], Any],
        register_url: str | None,
        form_filler: Callable[..., Any] | None = None,
    ) -> BrowserSignupResult:
        """The in-browser signup flow: find → wall-check → (LLM-perceive+plan+execute+adapt,
        or the heuristic fill) → submit → capture."""
        base = BrowserSignupResult(
            email=email, password=password, username=username,
        )
        if not await self._goto_register_page(page, register_url):
            base.error = BrowserSignupConfig.ERROR_NO_REGISTER_PAGE
            return base

        # Detect a real-world wall BEFORE filling/submitting — if walled we do not attempt
        # to defeat it and never submit the form.
        wall = await self._detect_signup_wall(page)
        if wall:
            base.blocked_reason = wall
            return base

        if form_filler is not None:
            return await self._llm_signup(
                page, email, password, username, fill_value, form_filler,
            )
        return await self._heuristic_signup(page, email, password, username, fill_value)

    async def _heuristic_signup(
        self,
        page: object,
        email: str,
        password: str,
        username: str,
        fill_value: Callable[[str], Any],
    ) -> BrowserSignupResult:
        """The legacy hardcoded-heuristic fill (no LLM): classify each field by role, fill,
        submit, capture. Kept so callers with no ``form_filler`` (tests / older code) still
        provision — nothing regresses."""
        if not await self._fill_signup_form(page, email, password, username, fill_value):
            return BrowserSignupResult(
                email=email, password=password, username=username,
                error=BrowserSignupConfig.ERROR_FIELDS_NOT_FOUND,
            )
        return await self._submit_and_capture(page, email, password, username)

    async def _llm_signup(
        self,
        page: object,
        email: str,
        password: str,
        username: str,
        fill_value: Callable[[str], Any],
        form_filler: Callable[..., Any],
    ) -> BrowserSignupResult:
        """PERCEIVE → UNDERSTAND → EXECUTE → ADAPT. Perceive the form (DOM + screenshot),
        ask the injected LLM form-filler for a plan (which value per field, WHICH dropdown
        option), execute it, submit, and read the intercepted signup XHR. On a still-invalid
        form (a disabled submit / a validation error keeping the register form on screen)
        re-perceive and re-plan, bounded by ``_MAX_FORM_ATTEMPTS``, then give up honestly."""
        identity = {"email": email, "password": password, "username": username}
        goal = BrowserSignupConfig.FORM_FILLER_GOAL
        last = BrowserSignupResult(
            email=email, password=password, username=username,
            error=BrowserSignupConfig.ERROR_FIELDS_NOT_FOUND,
        )
        for _attempt in range(_MAX_FORM_ATTEMPTS):
            perception = await self._perceive_form(page)
            if not perception.fields:
                last = BrowserSignupResult(
                    email=email, password=password, username=username,
                    error=BrowserSignupConfig.ERROR_FIELDS_NOT_FOUND,
                )
                break
            try:
                plan = await form_filler(perception, identity, goal)
            except Exception as exc:  # noqa: BLE001 — a filler failure is an empty plan, not a crash
                logger.debug("signup: form_filler raised: %s", exc)
                plan = FormFillPlan()
            await self._apply_fill_plan(page, plan, perception, fill_value)

            submitted = await BrowserLoginHelper.click_submit(
                page, BrowserSignupConfig.SUBMIT_BUTTON_SELECTORS,
            )
            if not submitted:
                # A disabled/absent submit means the form didn't validate — re-perceive
                # (now showing the disabled/error state) and re-plan on the next attempt.
                last = BrowserSignupResult(
                    email=email, password=password, username=username,
                    error=BrowserSignupConfig.ERROR_SUBMIT_FAILED,
                )
                await self._settle(page)
                continue

            await self._settle_after_submit(page)
            outcome = self._signup_outcome_from_intercepted(email, password, username)
            if outcome.success:
                return outcome
            last = outcome
            # Only adapt while the register form is still on screen (still invalid). If it is
            # gone, the submit navigated away and re-planning would fill nothing useful.
            if not await self._page_has_signup_form(page):
                break
        return last

    async def _submit_and_capture(
        self, page: object, email: str, password: str, username: str
    ) -> BrowserSignupResult:
        """Submit the register form and read the outcome from the intercepted signup XHR."""
        submitted = await BrowserLoginHelper.click_submit(
            page, BrowserSignupConfig.SUBMIT_BUTTON_SELECTORS,
        )
        if not submitted:
            return BrowserSignupResult(
                email=email, password=password, username=username,
                error=BrowserSignupConfig.ERROR_SUBMIT_FAILED,
            )
        await self._settle_after_submit(page)
        return self._signup_outcome_from_intercepted(email, password, username)

    async def _settle_after_submit(self, page: object) -> None:
        """Let the signup XHR fire and be captured by the interception handler."""
        try:
            await page.wait_for_load_state(  # type: ignore[union-attr]
                "networkidle",
                timeout=BrowserLoginConfig.NETWORK_IDLE_TIMEOUT_MS,
            )
        except Exception:
            await asyncio.sleep(BrowserSignupConfig.POST_SUBMIT_SETTLE_MS / 1000)

    # ------------------------------------------------------------------
    # Form perception + plan execution (LLM form-comprehension path)
    # ------------------------------------------------------------------

    async def _perceive_form(self, page: object) -> FormPerception:
        """PERCEIVE the visible register form: via ``page.evaluate`` extract a structured
        description of EVERY fillable control (a stable locator, tag/type, name/id, label,
        placeholder, aria-label, required, current value, and — for a native ``<select>`` or
        a custom dropdown — the enumerated option texts) and stamp the submit control's
        locator; then capture a bounded screenshot. Fully defensive — a failing evaluate /
        screenshot yields an empty perception rather than raising."""
        page_url = getattr(page, "url", "") or ""
        try:
            perceived = await page.evaluate(  # type: ignore[union-attr]
                _PERCEIVE_FORM_JS,
                {
                    "fieldAttr": BrowserSignupConfig.PERCEIVE_FIELD_ATTR,
                    "submitAttr": BrowserSignupConfig.PERCEIVE_SUBMIT_ATTR,
                    "maxOptions": BrowserSignupConfig.MAX_PERCEIVE_OPTIONS,
                },
            )
        except Exception as exc:
            logger.debug("signup: form perception failed: %s", exc)
            perceived = None
        perceived = perceived if isinstance(perceived, dict) else {}
        fields: list[FormField] = []
        enumerations = 0
        for f in (perceived.get("fields") or []):
            if not (isinstance(f, dict) and f.get("locator")):
                continue
            field = FormField(
                locator=str(f.get("locator") or ""),
                tag=str(f.get("tag") or ""),
                type=str(f.get("type") or ""),
                name=str(f.get("name") or ""),
                id=str(f.get("id") or ""),
                label=str(f.get("label") or ""),
                placeholder=str(f.get("placeholder") or ""),
                aria_label=str(f.get("aria") or ""),
                required=bool(f.get("required")),
                value=str(f.get("value") or ""),
                options=[str(o) for o in (f.get("options") or [])],
                control_kind=str(f.get("control_kind") or "other"),
            )
            # A lazy-rendered overlay dropdown (mat-select / combobox / listbox / react-select)
            # exposes its options only once opened, so perception returned none. Enumerate them
            # by OPENING the widget (read-only, never selecting), bounded by the per-form cap so
            # a hostile form can't make us open unboundedly.
            if (
                not field.options
                and field.control_kind in ("single_select", "multi_select")
                and f.get("overlay")
                and enumerations < BrowserSignupConfig.MAX_OVERLAY_ENUMERATIONS
            ):
                enumerations += 1
                field.options = await self._enumerate_overlay_options(page, field.locator)
            fields.append(field)
        return FormPerception(
            fields=fields,
            screenshot_b64=await self._capture_screenshot(page),
            page_url=page_url,
            submit_locator=str(perceived.get("submit") or ""),
        )

    async def _enumerate_overlay_options(self, page: object, locator: str) -> list[str]:
        """OPEN an overlay dropdown to read the options it renders lazily, then CLOSE it —
        READ-ONLY (it never selects an option and never submits). Clicks the widget's trigger,
        waits for the overlay to render, reads the ``mat-option``/``[role=option]``/react-select
        option nodes, and presses Escape to restore state. Fully best-effort and BOUNDED: a
        widget that won't open (or an evaluate that fails) yields ``[]`` rather than raising."""
        try:
            trigger = await page.query_selector(locator)  # type: ignore[union-attr]
            if not trigger:
                return []
            await trigger.click()
        except Exception as exc:
            logger.debug("signup: could not open dropdown %s to enumerate: %s", locator, exc)
            return []
        await self._settle(page)
        try:
            opts = await page.evaluate(  # type: ignore[union-attr]
                _READ_OVERLAY_OPTIONS_JS,
                {"maxOptions": BrowserSignupConfig.MAX_PERCEIVE_OPTIONS},
            )
        except Exception as exc:
            logger.debug("signup: overlay option read for %s failed: %s", locator, exc)
            opts = []
        await self._close_overlay(page)
        return [str(o) for o in (opts or [])]

    async def _close_overlay(self, page: object) -> None:
        """Dismiss an opened overlay dropdown by pressing Escape (best-effort — restores the
        page to its pre-enumeration state so the option-read never leaves a widget open)."""
        try:
            await page.keyboard.press("Escape")  # type: ignore[union-attr]
        except Exception as exc:
            logger.debug("signup: overlay close failed: %s", exc)

    async def _capture_screenshot(self, page: object) -> str:
        """A base64 PNG of the current page, bounded by ``SCREENSHOT_MAX_BYTES`` (an
        oversized or failing screenshot yields ``""`` — the structured fields still carry the
        form; the screenshot is a supplement, never a hard dependency)."""
        try:
            png = await page.screenshot()  # type: ignore[union-attr]
        except Exception as exc:
            logger.debug("signup: screenshot failed: %s", exc)
            return ""
        if not png or len(png) > BrowserSignupConfig.SCREENSHOT_MAX_BYTES:
            return ""
        return base64.b64encode(png).decode("ascii")

    # Canonical control kinds the executor drives, and the fallback verb→kind map used when a
    # field carries no ``control_kind`` (a hand-built field / a legacy plan) — this is what
    # keeps the old ``type``/``select``/``check`` plans working.
    _CONTROL_KINDS = frozenset(
        {"text", "single_select", "multi_select", "radio_group", "checkbox", "toggle"}
    )
    _ACTION_KIND = {
        "type": "text", "select": "single_select", "select_multi": "multi_select",
        "choose": "radio_group", "check": "checkbox", "uncheck": "checkbox", "toggle": "toggle",
    }

    async def _apply_fill_plan(
        self,
        page: object,
        plan: FormFillPlan,
        perception: FormPerception,
        fill_value: Callable[[str], Any],
    ) -> None:
        """EXECUTE a fill plan by DISPATCHING each action to the driver for the perceived
        field's canonical ``control_kind`` (one driver per kind, each handling the native /
        Angular Material / React-ARIA variant): text→fill, single_select→native ``select_option``
        or overlay open-then-click, multi_select→native multi-``select_option`` or overlay
        open-then-click-each, radio_group→click the matching radio, checkbox→set checked,
        toggle→set on/off. The privilege guard is ENFORCED here independently of the planner's
        strip: any action targeting a field whose synthesized value is ``None`` (an
        authorization/privilege field) is refused. Finally, any REQUIRED field the plan left
        untouched is back-filled via ``fill_value`` (``_synthesize_field``) so a form needing a
        field the LLM omitted still validates — never a privilege field."""
        by_locator = {f.locator: f for f in perception.fields}
        targeted: set[str] = set()
        for action in plan.actions:
            field = by_locator.get(action.locator)
            if field is not None and fill_value(self._perceived_field_key(field)) is None:
                continue  # privilege/authorization field — never filled (executor-enforced)
            targeted.add(action.locator)
            await self._drive_action(page, action, field)
        await self._backfill_required(page, perception, targeted, fill_value)

    async def _drive_action(
        self, page: object, action: Any, field: FormField | None
    ) -> None:
        """Route ONE fill action to the driver for its resolved ``control_kind``. An unknown/
        ``other`` kind is a no-op (a hallucinated control can't drive an unexpected widget)."""
        kind = self._effective_kind(field, action)
        locator = action.locator
        if kind == "text":
            await BrowserLoginHelper.fill_input(page, (locator,), str(action.value))
        elif kind == "single_select":
            await self._select_option(page, locator, str(action.value), field)
        elif kind == "multi_select":
            await self._select_multi(page, locator, self._action_values(action), field)
        elif kind == "radio_group":
            await self._choose_option(page, locator, str(action.value))
        elif kind in ("checkbox", "toggle"):
            await self._set_checked(page, locator, self._desired_bool(action), field)

    @classmethod
    def _effective_kind(cls, field: FormField | None, action: Any) -> str:
        """Resolve the control kind to drive: the perceived field's ``control_kind`` when it is
        a known canonical kind, else inferred from the action verb (backward-compat for legacy
        ``type``/``select``/``check`` plans), else from the field's tag/type."""
        if field is not None:
            kind = (field.control_kind or "").lower()
            if kind in cls._CONTROL_KINDS:
                return kind
        act = (action.action or "").lower()
        if act in cls._ACTION_KIND:
            return cls._ACTION_KIND[act]
        return cls._field_kind(field) if field is not None else "text"

    @classmethod
    def _field_kind(cls, field: FormField) -> str:
        """The canonical kind of a perceived field from its ``control_kind`` (when known) else
        inferred from tag/type/options — used for back-filling a field with no plan action."""
        kind = (field.control_kind or "").lower()
        if kind in cls._CONTROL_KINDS:
            return kind
        if (field.tag or "").lower() == "select":
            return "single_select"
        if (field.type or "").lower() == "checkbox":
            return "checkbox"
        if field.options:
            return "single_select"
        return "text"

    @staticmethod
    def _action_values(action: Any) -> list[str]:
        """The list of chosen options for a multi-select action: the action's ``values`` if
        present, else its single ``value`` wrapped (so a single-valued multi action still
        works). Empty strings are dropped."""
        vals = [str(v) for v in (getattr(action, "values", None) or []) if str(v)]
        if not vals and action.value:
            vals = [str(action.value)]
        return vals

    @staticmethod
    def _desired_bool(action: Any) -> bool:
        """The desired on/off state for a checkbox/toggle action: ``uncheck`` → off; an explicit
        falsey ``value``/``values[0]`` (false/0/off/no/unchecked) → off; otherwise on (a
        ``check``/``toggle`` with no explicit value means 'set it')."""
        if (action.action or "").lower() == "uncheck":
            return False
        raw = action.value
        if not raw and getattr(action, "values", None):
            raw = action.values[0]
        return str(raw or "").strip().lower() not in ("false", "0", "off", "no", "unchecked")

    async def _select_multi(
        self, page: object, locator: str, values: list[str], field: FormField | None
    ) -> None:
        """Drive a multi_select to ``values``. A native ``<select multiple>`` (``field.tag ==
        'select'``) uses ``select_option`` with the whole list (by label, then by value); an
        overlay multi-select (mat-select[multiple] / listbox / react-select) is OPENED once,
        each matching option clicked, then closed. Best-effort — logged, never raised."""
        if not values:
            return
        if field is not None and (field.tag or "").lower() == "select":
            for kwargs in ({"label": values}, {"value": values}):
                try:
                    await page.select_option(locator, **kwargs)  # type: ignore[union-attr]
                    return
                except Exception as exc:
                    logger.debug("signup: native multi select_option %s failed: %s", kwargs, exc)
            return
        try:
            trigger = await page.query_selector(locator)  # type: ignore[union-attr]
            if trigger:
                await trigger.click()
        except Exception as exc:
            logger.debug("signup: could not open multi dropdown %s: %s", locator, exc)
            return
        await self._settle(page)
        for value in values:
            await self._click_custom_option(page, value)
        await self._close_overlay(page)

    async def _choose_option(self, page: object, locator: str, value: str) -> bool:
        """Choose one option of a radio_group (native radios / mat-radio-button / [role=radio])
        by matching visible text, via ``_CHOOSE_OPTION_JS``. Best-effort; returns whether an
        option matched (never raises)."""
        try:
            matched = await page.evaluate(  # type: ignore[union-attr]
                _CHOOSE_OPTION_JS, {"locator": locator, "value": value},
            )
        except Exception as exc:
            logger.debug("signup: radio choose on %s failed: %s", locator, exc)
            return False
        return bool(matched)

    async def _set_checked(
        self, page: object, locator: str, desired: bool, field: FormField | None
    ) -> None:
        """Set a checkbox/toggle to ``desired``. A NATIVE ``input`` uses Playwright
        ``check``/``uncheck`` (idempotent); a mat-checkbox / mat-slide-toggle / [role=checkbox] /
        [role=switch] is driven by ``_SET_STATE_JS`` (read current state, click only if it
        differs). Best-effort — logged, never raised."""
        tag = (field.tag or "").lower() if field is not None else ""
        if tag in ("", "input"):
            try:
                element = await page.query_selector(locator)  # type: ignore[union-attr]
                if element:
                    if desired:
                        await element.check()
                    else:
                        await element.uncheck()
            except Exception as exc:
                logger.debug("signup: native checkbox set on %s failed: %s", locator, exc)
            return
        try:
            await page.evaluate(  # type: ignore[union-attr]
                _SET_STATE_JS, {"locator": locator, "checked": desired},
            )
        except Exception as exc:
            logger.debug("signup: control-state set on %s failed: %s", locator, exc)

    async def _backfill_required(
        self,
        page: object,
        perception: FormPerception,
        targeted: set[str],
        fill_value: Callable[[str], Any],
    ) -> None:
        """Fill any REQUIRED perceived field the plan did not target and that has no current
        value, using ``fill_value`` and the field's canonical kind. Password fields are left to
        the LLM (a guessed password would break a confirm-match); a privilege field
        (``fill_value`` → ``None``) is skipped. The ``_synthesize_field`` safety net for a field
        the LLM omitted."""
        for field in perception.fields:
            if field.locator in targeted or not field.required or field.value:
                continue
            ftype = (field.type or "").lower()
            if ftype == "password":
                continue
            value = fill_value(self._perceived_field_key(field))
            if value is None:  # privilege/authorization field — never filled
                continue
            kind = self._field_kind(field)
            if kind == "checkbox" or value is True:
                await self._set_checked(page, field.locator, True, field)
            elif kind == "toggle":
                await self._set_checked(page, field.locator, True, field)
            elif kind == "radio_group":
                await self._choose_option(page, field.locator, str(value))
            elif kind == "multi_select":
                await self._select_multi(page, field.locator, [str(value)], field)
            elif kind == "single_select":
                await self._select_option(page, field.locator, str(value), field)
            else:
                await BrowserLoginHelper.fill_input(page, (field.locator,), str(value))

    async def _select_option(
        self, page: object, locator: str, value: str, field: FormField | None
    ) -> None:
        """Set a dropdown to ``value``. A native ``<select>`` (``field.tag == 'select'``) is
        driven with ``page.select_option`` (by visible label, then by value); a CUSTOM
        dropdown (mat-select / role=listbox) is OPENED by clicking its trigger, then the
        option whose visible text matches ``value`` is clicked. Best-effort — a failure is
        logged, not raised."""
        if field is not None and (field.tag or "").lower() == "select":
            for kwargs in ({"label": value}, {"value": value}):
                try:
                    await page.select_option(locator, **kwargs)  # type: ignore[union-attr]
                    return
                except Exception as exc:
                    logger.debug("signup: native select_option %s failed: %s", kwargs, exc)
            return
        try:
            trigger = await page.query_selector(locator)  # type: ignore[union-attr]
            if trigger:
                await trigger.click()
        except Exception as exc:
            logger.debug("signup: could not open custom dropdown %s: %s", locator, exc)
            return
        await self._settle(page)
        await self._click_custom_option(page, value)

    async def _click_custom_option(self, page: object, value: str) -> bool:
        """Click the custom-dropdown option whose visible text matches ``value``, trying the
        configured ``:has-text`` selectors in order. Returns True once one is clicked."""
        escaped = value.replace('"', '\\"')
        for template in BrowserSignupConfig.CUSTOM_OPTION_SELECTORS:
            selector = template.format(text=escaped)
            try:
                element = await page.query_selector(selector)  # type: ignore[union-attr]
            except Exception as exc:
                logger.debug("signup: option lookup %s failed: %s", selector, exc)
                continue
            if element:
                try:
                    await element.click()
                    return True
                except Exception as exc:
                    logger.debug("signup: option click %s failed: %s", selector, exc)
        return False

    @staticmethod
    def _perceived_field_key(field: FormField) -> str:
        """The most descriptive identifier of a perceived field, for ``fill_value``/privilege
        matching (mirrors the heuristic ``_field_key`` for the perceived-model shape)."""
        for value in (field.name, field.id, field.aria_label, field.label, field.placeholder):
            if value and value.strip():
                return value.strip()
        return ""

    async def _goto_register_page(
        self, page: object, register_url: str | None
    ) -> bool:
        """Navigate to the registration form: an explicit ``register_url`` hint, then a
        register link on the app's landing page, then the common register routes. Returns
        True once a page renders a registration form (a visible password input)."""
        if register_url and await self._try_register_url(page, register_url):
            return True

        try:
            await page.goto(  # type: ignore[union-attr]
                self._base_url,
                timeout=BrowserLoginConfig.NAVIGATION_TIMEOUT_MS,
                wait_until="domcontentloaded",
            )
            await self._settle(page)
        except Exception as exc:
            logger.debug("signup: landing navigation failed: %s", exc)

        href = await self._find_register_link(page)
        if href and await self._try_register_url(page, urljoin(self._base_url, href)):
            return True

        for route in BrowserSignupConfig.REGISTER_ROUTES:
            if await self._try_register_url(page, f"{self._base_url}{route}"):
                return True
        return False

    async def _try_register_url(self, page: object, url: str) -> bool:
        """Navigate to ``url`` and report whether it renders a registration form."""
        try:
            await page.goto(  # type: ignore[union-attr]
                url,
                timeout=BrowserLoginConfig.NAVIGATION_TIMEOUT_MS,
                wait_until="domcontentloaded",
            )
            await self._settle(page)
        except Exception as exc:
            logger.debug("signup: navigation to %s failed: %s", url, exc)
            return False
        return await self._page_has_signup_form(page)

    async def _settle(self, page: object) -> None:
        """Best-effort wait for the network to go idle after a navigation."""
        try:
            await page.wait_for_load_state(  # type: ignore[union-attr]
                "networkidle",
                timeout=BrowserLoginConfig.NETWORK_IDLE_TIMEOUT_MS,
            )
        except Exception as exc:
            logger.debug("signup: network-idle settle timed out: %s", exc)

    async def _find_register_link(self, page: object) -> str:
        """The href of a register/sign-up link on the current page, or ``""``."""
        try:
            href = await page.evaluate(  # type: ignore[union-attr]
                _FIND_REGISTER_LINK_JS,
                list(BrowserSignupConfig.REGISTER_LINK_KEYWORDS),
            )
        except Exception as exc:
            logger.debug("signup: register-link discovery failed: %s", exc)
            return ""
        return href or ""

    async def _page_has_signup_form(self, page: object) -> bool:
        """True when the current page renders a registration form (a password input)."""
        try:
            return bool(await page.evaluate(_HAS_SIGNUP_FORM_JS))  # type: ignore[union-attr]
        except Exception as exc:
            logger.debug("signup: form detection failed: %s", exc)
            return False

    async def _detect_signup_wall(self, page: object) -> str | None:
        """A real-world signup wall (CAPTCHA / email- / SMS-verification) present on the
        page, or ``None``. Detected so it can be REPORTED, never defeated."""
        try:
            has_captcha = bool(await page.evaluate(  # type: ignore[union-attr]
                _DETECT_CAPTCHA_JS, BrowserSignupConfig.CAPTCHA_SELECTOR,
            ))
        except Exception:
            has_captcha = False
        if has_captcha:
            return BrowserSignupConfig.BLOCKED_CAPTCHA

        try:
            text = await page.evaluate(_SIGNUP_PAGE_TEXT_JS)  # type: ignore[union-attr]
        except Exception:
            text = ""
        low = (text or "").lower()
        if any(ind in low for ind in BrowserSignupConfig.EMAIL_VERIFY_INDICATORS):
            return BrowserSignupConfig.BLOCKED_EMAIL_VERIFY
        if any(ind in low for ind in BrowserSignupConfig.SMS_VERIFY_INDICATORS):
            return BrowserSignupConfig.BLOCKED_SMS_VERIFY
        return None

    async def _fill_signup_form(
        self,
        page: object,
        email: str,
        password: str,
        username: str,
        fill_value: Callable[[str], Any],
    ) -> bool:
        """Enumerate the register form's fields and fill each by role: email → the agent
        email; every password input → the password (so a password + confirm pair both get
        the same value); a username field → the derived username; any other field → a value
        from ``fill_value`` (which returns ``None`` for a privilege field, so it is SKIPPED
        — never self-escalating). File/hidden/CAPTCHA inputs are skipped. Returns True when
        a password and an identity (email or username) were filled — a real form."""
        try:
            fields = await page.evaluate(  # type: ignore[union-attr]
                _ENUM_SIGNUP_FIELDS_JS, BrowserSignupConfig.SIGNUP_FIELD_ATTR,
            )
        except Exception as exc:
            logger.debug("signup: field enumeration failed: %s", exc)
            return False

        filled_pw = filled_identity = False
        for field in (fields or []):
            ftype = str(field.get("type") or "").lower()
            selector = (
                f'[{BrowserSignupConfig.SIGNUP_FIELD_ATTR}="{field.get("idx")}"]'
            )
            if ftype == "password":
                if await BrowserLoginHelper.fill_input(page, (selector,), password):
                    filled_pw = True
                continue
            if self._is_captcha_field(field):
                continue
            if ftype == "email" or self._field_matches(
                field, BrowserSignupConfig.EMAIL_FIELD_KEYWORDS
            ):
                if await BrowserLoginHelper.fill_input(page, (selector,), email):
                    filled_identity = True
                continue
            if self._field_matches(field, BrowserSignupConfig.USERNAME_FIELD_KEYWORDS):
                if await BrowserLoginHelper.fill_input(page, (selector,), username):
                    filled_identity = True
                continue
            value = fill_value(self._field_key(field))
            if value is None:                 # privilege/refused field — never filled
                continue
            if ftype == "checkbox":
                await self._check_box(page, selector)
                continue
            await BrowserLoginHelper.fill_input(page, (selector,), str(value))

        return filled_pw and filled_identity

    @staticmethod
    async def _check_box(page: object, selector: str) -> None:
        """Tick a consent/agreement checkbox (a required ToS box) without failing hard."""
        try:
            element = await page.query_selector(selector)  # type: ignore[union-attr]
            if element:
                await element.check()
        except Exception as exc:
            logger.debug("signup: checkbox toggle failed: %s", exc)

    @staticmethod
    def _field_signals(field: dict) -> str:
        """The field's identifying text (name/id/placeholder/aria/label), lowercased."""
        return " ".join(
            str(field.get(key) or "")
            for key in ("name", "id", "placeholder", "aria", "label")
        ).lower()

    @classmethod
    def _field_matches(cls, field: dict, keywords: tuple[str, ...]) -> bool:
        signals = cls._field_signals(field)
        return any(keyword in signals for keyword in keywords)

    @classmethod
    def _is_captcha_field(cls, field: dict) -> bool:
        return "captcha" in cls._field_signals(field)

    @staticmethod
    def _field_key(field: dict) -> str:
        """The most descriptive identifier for a field, for ``fill_value`` matching."""
        for key in ("name", "id", "aria", "label", "placeholder"):
            value = str(field.get(key) or "").strip()
            if value:
                return value
        return ""

    def _signup_outcome_from_intercepted(
        self, email: str, password: str, username: str
    ) -> BrowserSignupResult:
        """Read the signup outcome from the intercepted XHRs: find the POST the submit
        fired (preferring a signup-shaped path), report its endpoint + status, and count a
        2xx as success. No captured POST → an honest failure (the form submitted but no API
        call was seen — likely a non-JS or blocked form)."""
        posts = [req for req in self._intercepted if req.method.upper() == "POST"]
        if not posts:
            return BrowserSignupResult(
                success=False, email=email, password=password, username=username,
                error=BrowserSignupConfig.ERROR_NO_SIGNUP_XHR,
            )
        signup_posts = [
            req for req in posts
            if any(ind in urlparse(req.url).path.lower()
                   for ind in BrowserSignupConfig.SIGNUP_PATH_INDICATORS)
        ]
        chosen = (signup_posts or posts)[-1]
        path = urlparse(chosen.url).path
        status = chosen.response_status
        success = 200 <= status < 300
        result = BrowserSignupResult(
            success=success, signup_endpoint=path, status_code=status,
            email=email, password=password, username=username,
        )
        if not success:
            result.error = f"signup endpoint {path} returned {status}"
        return result

    # ------------------------------------------------------------------
    # Phase 1: Browser Login (delegates to BrowserLoginHelper)
    # ------------------------------------------------------------------

    async def _login(self, page: object) -> bool:
        """Navigate to login page and fill credentials via shared helper."""
        emit(f"crawling {self._login_url}")
        try:
            await page.goto(  # type: ignore[union-attr]
                self._login_url,
                timeout=BrowserLoginConfig.NAVIGATION_TIMEOUT_MS,
                wait_until="domcontentloaded",
            )
            try:
                await page.wait_for_load_state(  # type: ignore[union-attr]
                    "networkidle",
                    timeout=BrowserLoginConfig.NETWORK_IDLE_TIMEOUT_MS,
                )
            except Exception:
                pass

            # Try the fixed identity/password selectors first (fast, reliable
            # for email logins), then fall back to form-scoped detection, which
            # adapts to non-standard identity field names (e.g. "userName").
            email_ok = await BrowserLoginHelper.fill_input(
                page, BrowserLoginConfig.EMAIL_INPUT_SELECTORS, self._email,
            )
            pw_ok = email_ok and await BrowserLoginHelper.fill_input(
                page, BrowserLoginConfig.PASSWORD_INPUT_SELECTORS, self._password,
            )
            if not (email_ok and pw_ok):
                if not await BrowserLoginHelper.detect_and_fill_login(
                    page, self._email, self._password,
                ):
                    logger.warning(
                        "Could not locate login fields on %s", self._login_url
                    )
                    return False

            submitted = await BrowserLoginHelper.click_submit(page)
            if not submitted:
                logger.warning("Could not find submit button on %s", self._login_url)
                return False

            # Wait for post-login navigation
            try:
                await page.wait_for_load_state(  # type: ignore[union-attr]
                    "networkidle",
                    timeout=BrowserLoginConfig.LOGIN_WAIT_TIMEOUT_MS,
                )
            except Exception:
                await asyncio.sleep(BrowserLoginConfig.POST_LOGIN_SETTLE_MS / 1000)

            current_url = page.url  # type: ignore[union-attr]
            still_on_login = any(
                indicator in current_url.lower()
                for indicator in BrowserLoginConfig.LOGIN_PAGE_INDICATORS
            )
            if still_on_login:
                logger.warning("Still on login page after submit: %s", current_url)
                return False

            logger.info("Login succeeded, now at: %s", current_url)
            return True

        except Exception as exc:
            logger.error("Login failed: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Phase 2: Auth Token Extraction (delegates to BrowserLoginHelper)
    # ------------------------------------------------------------------

    async def _extract_auth_headers(self, page: object) -> dict[str, str]:
        """Build auth headers from browser storage + intercepted requests."""
        headers: dict[str, str] = {}

        token = await BrowserLoginHelper.extract_token(page)
        if token:
            headers[SharedPatterns.HEADER_AUTHORIZATION] = (
                f"{SharedPatterns.BEARER_PREFIX}{token}"
            )

        # Fallback: capture auth headers from intercepted API calls
        for req in self._intercepted:
            auth_val = req.request_headers.get(
                SharedPatterns.HEADER_AUTHORIZATION.lower()
            )
            if (
                auth_val
                and auth_val.startswith(SharedPatterns.BEARER_PREFIX)
                and len(auth_val) > BrowserLoginConfig.MIN_TOKEN_LENGTH
            ):
                headers[SharedPatterns.HEADER_AUTHORIZATION] = auth_val
                break
            apikey = req.request_headers.get(SharedPatterns.HEADER_APIKEY)
            if apikey:
                headers[SharedPatterns.HEADER_APIKEY] = apikey

        # Session cookies: many traditional / server-rendered apps authenticate
        # with a session cookie, not a bearer token. Capture the browser's
        # cookies so downstream HTTP DAST scanners can probe protected endpoints
        # authenticated (the crawl runs in an authed browser, but the follow-up
        # httpx probes don't inherit its context). #111
        try:
            cookies = await page.context.cookies()  # type: ignore[union-attr]
            cookie_header = "; ".join(
                f"{c['name']}={c['value']}" for c in cookies if c.get("name")
            )
            if cookie_header:
                headers[SharedPatterns.HEADER_COOKIE] = cookie_header
        except Exception as exc:  # noqa: BLE001 - cookies are best-effort
            logger.debug("Cookie capture failed: %s", exc)

        return headers

    # ------------------------------------------------------------------
    # Phase 3 + 4: Link Discovery + BFS Crawl
    # ------------------------------------------------------------------

    def _seed_link_queue(self) -> None:
        """Add seed routes and common authenticated paths to the queue."""
        for route in list(self._seed_routes) + list(
            AuthenticatedCrawlerConfig.COMMON_AUTH_PATHS
        ):
            url = f"{self._base_url}{route}" if route.startswith("/") else route
            normalized = self._normalize_url(url)
            if normalized and normalized not in self._visited:
                self._link_queue.append(normalized)

    async def _extract_html_endpoints(self, page: object, page_url: str) -> None:
        """Capture server-rendered <form>/<a?param> endpoints on this page.

        The interception handler only sees XHR/fetch; server-rendered forms
        (login, upload, profile-edit, admin actions that POST directly) leave
        no network call to intercept, so their surface must be read from HTML.
        """
        try:
            html = await page.content()  # type: ignore[union-attr]
        except Exception:
            return
        for ep in extract_html_endpoints(html, page_url):
            self._html_endpoints.setdefault(f"{ep.method.value}:{ep.url}", ep)

    async def _discover_links_from_page(self, page: object) -> None:
        """Extract all internal links from the current page DOM."""
        try:
            links = await page.evaluate(  # type: ignore[union-attr]
                """() => {
                    const anchors = document.querySelectorAll('a[href]');
                    return Array.from(anchors)
                        .map(a => a.href)
                        .filter(href => href && !href.startsWith('javascript:') && !href.startsWith('#'));
                }"""
            )

            count = 0
            for link in (links or []):
                if count >= AuthenticatedCrawlerConfig.MAX_LINKS_PER_PAGE:
                    break
                normalized = self._normalize_url(link)
                if normalized and normalized not in self._visited:
                    if self._is_same_origin(normalized):
                        self._link_queue.append(normalized)
                        count += 1
        except Exception as exc:
            logger.debug("Link discovery failed: %s", exc)

    async def _bfs_crawl(
        self, page: object, result: AuthenticatedCrawlResult
    ) -> int:
        """BFS-visit pages in the queue, discovering new links on each."""
        visited_count = 0

        while (
            self._link_queue
            and visited_count < self._max_pages
        ):
            url = self._link_queue.popleft()
            normalized = self._normalize_url(url)

            if not normalized or normalized in self._visited:
                continue

            self._visited.add(normalized)

            emit(f"crawling {normalized}")

            try:
                await page.goto(  # type: ignore[union-attr]
                    normalized,
                    timeout=AuthenticatedCrawlerConfig.NAVIGATION_TIMEOUT_MS,
                    wait_until="domcontentloaded",
                )
                try:
                    await page.wait_for_load_state(  # type: ignore[union-attr]
                        "networkidle",
                        timeout=self._bfs_network_idle_timeout_ms,
                    )
                except Exception:
                    await asyncio.sleep(
                        AuthenticatedCrawlerConfig.PAGE_LOAD_WAIT_MS / 1000
                    )

                visited_count += 1
                logger.debug("Crawled [%d]: %s", visited_count, normalized)

                await self._discover_links_from_page(page)
                await self._extract_html_endpoints(page, normalized)
                await self._interact_with_forms(page, normalized)

            except Exception as exc:
                error_msg = AuthenticatedCrawlerConfig.ERROR_PAGE_TIMEOUT.format(
                    url=normalized
                )
                logger.warning("%s — %s", error_msg, exc)
                result.errors.append(error_msg)

        return visited_count

    # ------------------------------------------------------------------
    # Network Interception
    # ------------------------------------------------------------------

    def _setup_interception(self, page: object) -> None:
        """Register network response handler to capture API calls."""

        async def on_response(response: object) -> None:
            try:
                url: str = response.url  # type: ignore[union-attr]
                if not self._is_api_call(url):
                    return
                if len(self._intercepted) >= AuthenticatedCrawlerConfig.MAX_INTERCEPTED_REQUESTS:
                    return

                request = response.request  # type: ignore[union-attr]

                req_headers = await self._capture_request_headers(request)
                req_body = await self._capture_request_body(request)

                body = ""
                content_type = ""
                try:
                    headers = response.headers  # type: ignore[union-attr]
                    content_type = (
                        headers.get("content-type", "") if headers else ""
                    )
                    body = await response.text()  # type: ignore[union-attr]
                except Exception:
                    pass

                ids = self._extract_ids(body)

                self._intercepted.append(
                    InterceptedRequest(
                        url=url,
                        method=request.method,
                        response_status=response.status,  # type: ignore[union-attr]
                        request_headers=req_headers,
                        request_body=req_body,
                        response_body_preview=body[
                            : AuthenticatedCrawlerConfig.MAX_BODY_PREVIEW_LENGTH
                        ],
                        response_content_type=content_type,
                        resource_ids_found=ids,
                    )
                )
            except Exception:
                pass

        page.on("response", on_response)  # type: ignore[union-attr]

    @staticmethod
    async def _capture_request_headers(request: object) -> dict[str, str]:
        """Capture security-relevant headers from a request."""
        req_headers: dict[str, str] = {}
        try:
            raw_headers = await request.all_headers()  # type: ignore[union-attr]
            for k, v in raw_headers.items():
                if k.lower() in AuthenticatedCrawlerConfig.CAPTURED_HEADER_NAMES:
                    req_headers[k.lower()] = v
        except Exception:
            pass
        return req_headers

    @staticmethod
    async def _capture_request_body(request: object) -> str:
        """Capture request body for state-changing methods."""
        try:
            method = request.method.upper()  # type: ignore[union-attr]
            if method in AuthenticatedCrawlerConfig.BODY_CAPTURE_METHODS:
                raw_body = request.post_data  # type: ignore[union-attr]
                if raw_body:
                    return raw_body[
                        : AuthenticatedCrawlerConfig.MAX_REQUEST_BODY_LENGTH
                    ]
        except Exception:
            pass
        return ""

    # ------------------------------------------------------------------
    # Form Interaction (discovers API calls triggered by form submissions)
    # ------------------------------------------------------------------

    async def _interact_with_forms(self, page: object, page_url: str = "") -> None:
        """Find forms and buttons on the page, click/submit them to trigger API calls.

        This catches endpoints that are only reachable by clicking buttons
        (e.g., "Create Deal", "Submit Review", "Update Profile").
        Network interception captures the resulting requests.

        In ``safe_mode`` (the pentest crawl path) blind-clicking is suppressed —
        clicking arbitrary buttons causes real, unaudited side effects that never pass
        through the destructive-op floor (the text-only "delete/remove/logout" filter
        misses icon-only / non-English / "Confirm" controls). Instead of throwing the
        write-flow away, ``safe_mode`` *records each form's action target* (method +
        action URL + field names) as a discovered endpoint via
        :meth:`_record_form_targets`, so the pentest planner learns the write-flow exists
        and can drive it through the floored ``http_request`` — gate-through, not
        blanket-suppress. Read-only: nothing is clicked or submitted. Default (scan)
        behavior below is unchanged.
        """
        if self._safe_mode:
            await self._record_form_targets(page, page_url)
            return
        try:
            # Find clickable buttons (excluding navigation and external links)
            buttons = await page.evaluate(  # type: ignore[union-attr]
                """() => {
                    const btns = document.querySelectorAll(
                        'button:not([type="submit"]), [role="button"], a.btn, a.button'
                    );
                    return Array.from(btns)
                        .filter(b => {
                            const text = (b.textContent || '').toLowerCase();
                            // Skip destructive or navigation actions
                            if (text.includes('delete') || text.includes('remove')
                                || text.includes('logout') || text.includes('sign out'))
                                return false;
                            return true;
                        })
                        .slice(0, 5)
                        .map((b, i) => ({
                            index: i,
                            text: (b.textContent || '').trim().substring(0, 50),
                            tag: b.tagName,
                        }));
                }"""
            )

            if not buttons:
                return

            for btn_info in (buttons or []):
                try:
                    # Re-query the button (DOM may have changed)
                    btn_elements = await page.query_selector_all(  # type: ignore[union-attr]
                        'button:not([type="submit"]), [role="button"]'
                    )
                    idx = btn_info.get("index", 0)
                    if idx < len(btn_elements):
                        await btn_elements[idx].click()
                        await asyncio.sleep(1)  # Wait for any API calls
                except Exception:
                    pass

        except Exception as exc:
            logger.debug("Form interaction failed: %s", exc)

    async def _record_form_targets(self, page: object, page_url: str) -> None:
        """``safe_mode`` replacement for blind button-clicking: read (never submit) each
        ``<form>``'s method + action + named fields from the live DOM and record it as a
        :class:`DiscoveredEndpoint`, so the pentest planner learns the write-flow exists
        and can drive it through the floored ``http_request`` instead of the crawler
        making an unaudited state change. Purely read-only — no element is clicked or
        submitted. Only ever called on the ``safe_mode`` path, so scan is unaffected.
        """
        try:
            forms = await page.evaluate(  # type: ignore[union-attr]
                """() => {
                    const skip = ['submit', 'button', 'reset', 'image', 'hidden'];
                    const forms = document.querySelectorAll('form');
                    return Array.from(forms).slice(0, 20).map(f => ({
                        action: f.getAttribute('action') || '',
                        method: (f.getAttribute('method') || 'get').toUpperCase(),
                        fields: Array.from(
                            f.querySelectorAll('input[name], select[name], textarea[name]')
                        )
                            .filter(i => !skip.includes(
                                (i.getAttribute('type') || '').toLowerCase()))
                            .map(i => i.getAttribute('name'))
                            .filter(n => n),
                    }));
                }"""
            )
        except Exception as exc:
            logger.debug("safe_mode form-target extraction failed: %s", exc)
            return

        for form in (forms or [])[: AuthenticatedCrawlerConfig.MAX_FORMS_PER_PAGE]:
            action = (form.get("action") or "").strip()
            url = (urljoin(page_url, action) if action else page_url).split("#")[0]
            if not url or not self._is_same_origin(url):
                continue
            method = self._parse_method(form.get("method") or "GET")
            fields = list(dict.fromkeys(f for f in (form.get("fields") or []) if f))
            key = f"{method.value}:{url}"
            self._html_endpoints.setdefault(
                key,
                DiscoveredEndpoint(
                    url=url,
                    method=method,
                    source_pattern=(
                        AuthenticatedCrawlerConfig.SAFE_MODE_FORM_SOURCE_PATTERN
                    ),
                    query_param_names=fields,
                    category=self._categorize_url(url),
                    requires_auth=True,
                ),
            )

    # ------------------------------------------------------------------
    # WebSocket Capture
    # ------------------------------------------------------------------

    def _setup_websocket_capture(self, page: object) -> None:
        """Register WebSocket handlers to capture WS messages.

        Captures WebSocket URLs and message patterns for downstream analysis.
        """

        def on_ws(ws: object) -> None:
            try:
                ws_url = ws.url  # type: ignore[union-attr]
                logger.debug("WebSocket opened: %s", ws_url)

                # Capture the WS connection as an intercepted request
                self._intercepted.append(
                    InterceptedRequest(
                        url=ws_url,
                        method="WS",
                        response_status=101,
                        response_content_type="websocket",
                    )
                )

                def on_message(msg: object) -> None:
                    try:
                        payload = msg.text if hasattr(msg, "text") else str(msg)  # type: ignore
                        if len(self._intercepted) < AuthenticatedCrawlerConfig.MAX_INTERCEPTED_REQUESTS:
                            ids = self._extract_ids(payload)
                            self._intercepted.append(
                                InterceptedRequest(
                                    url=ws_url,
                                    method="WS_MSG",
                                    response_status=200,
                                    response_body_preview=payload[
                                        : AuthenticatedCrawlerConfig.MAX_BODY_PREVIEW_LENGTH
                                    ],
                                    response_content_type="websocket/message",
                                    resource_ids_found=ids,
                                )
                            )
                    except Exception:
                        pass

                ws.on("framereceived", on_message)  # type: ignore[union-attr]
            except Exception:
                pass

        page.on("websocket", on_ws)  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # URL Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_static_asset(path: str) -> bool:
        """Check if a URL path refers to a static asset."""
        path_lower = path.lower()
        return any(
            path_lower.endswith(ext)
            for ext in AuthenticatedCrawlerConfig.SKIP_EXTENSIONS
        )

    def _normalize_url(self, url: str) -> str | None:
        """Normalize a URL: strip fragments and query params for dedup."""
        try:
            parsed = urlparse(url)
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            return normalized.rstrip("/") or None
        except Exception:
            return None

    def _is_same_origin(self, url: str) -> bool:
        """Check if a URL belongs to the same origin as the target."""
        try:
            parsed = urlparse(url)
            base_parsed = urlparse(self._base_url)

            # Origin is scheme + host: only real HTTP(S) URLs are in scope. Reject
            # everything else up front — this is the entry gate for the safe_mode
            # ``_record_form_targets`` path, so a crafted ``action="javascript://host/..."``
            # (whose netloc matches the base) must never be recorded as an endpoint.
            # Also fences ``data:``, ``file:`` and empty-scheme-with-authority tricks.
            if parsed.scheme not in ("http", "https"):
                return False

            if parsed.netloc != base_parsed.netloc:
                return False

            for domain in AuthenticatedCrawlerConfig.SKIP_LINK_DOMAINS:
                if domain in (parsed.netloc or ""):
                    return False

            return not self._is_static_asset(parsed.path)
        except Exception:
            return False

    @classmethod
    def _is_api_call(cls, url: str) -> bool:
        """Determine whether a URL is an API call (not a static asset)."""
        parsed = urlparse(url)
        if cls._is_static_asset(parsed.path):
            return False

        for indicator in AuthenticatedCrawlerConfig.API_INDICATORS:
            if indicator in url:
                return True

        return False

    # ------------------------------------------------------------------
    # ID Extraction
    # ------------------------------------------------------------------

    def _extract_ids(self, body: str) -> list[str]:
        """Extract UUIDs and numeric IDs from a response body."""
        if not body:
            return []

        ids: list[str] = list(self._UUID_RE.findall(body))

        try:
            data = json.loads(body)
            self._extract_ids_from_json(data, ids)
        except (json.JSONDecodeError, TypeError):
            pass

        seen: set[str] = set()
        unique: list[str] = []
        for id_val in ids:
            if id_val not in seen:
                seen.add(id_val)
                unique.append(id_val)
        return unique

    def _extract_ids_from_json(
        self, data: object, ids: list[str], depth: int = 0
    ) -> None:
        """Recursively extract IDs from JSON structures."""
        if depth > AuthenticatedCrawlerConfig.MAX_JSON_DEPTH:
            return

        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, (int, str)) and self._is_id_key(key):
                    str_val = str(value)
                    if str_val:
                        ids.append(str_val)
                elif isinstance(value, (dict, list)):
                    self._extract_ids_from_json(value, ids, depth + 1)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, (dict, list)):
                    self._extract_ids_from_json(item, ids, depth + 1)

    @staticmethod
    def _is_id_key(key: str) -> bool:
        key_lower = key.lower()
        return key_lower == "id" or key_lower.endswith("_id") or key_lower.endswith("id")

    # ------------------------------------------------------------------
    # Result Building
    # ------------------------------------------------------------------

    def _filter_supabase_queries(self) -> list[InterceptedRequest]:
        return [
            req for req in self._intercepted
            if AuthenticatedCrawlerConfig.SUPABASE_REST_INDICATOR in req.url
        ]

    def _extract_supabase_tables(self) -> list[str]:
        """Extract table names from intercepted Supabase REST queries."""
        tables: list[str] = []
        for req in self._intercepted:
            table = extract_supabase_table_from_url(req.url)
            if table and table not in tables:
                tables.append(table)
        return tables

    def _build_endpoints(self) -> list[DiscoveredEndpoint]:
        """Convert intercepted API calls into DiscoveredEndpoint models."""
        seen_keys: set[str] = set()
        endpoints: list[DiscoveredEndpoint] = []

        for req in self._intercepted:
            parsed = urlparse(req.url)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            dedup_key = f"{req.method.upper()}:{base}"

            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            method = self._parse_method(req.method)
            category = self._categorize_url(req.url)
            query_params = [
                k
                for k in (parsed.query.split("&") if parsed.query else [])
                if "=" in k
            ]
            query_param_names = [p.split("=")[0] for p in query_params]

            endpoints.append(
                DiscoveredEndpoint(
                    url=req.url,
                    method=method,
                    source_pattern=AuthenticatedCrawlerConfig.SOURCE_PATTERN,
                    has_path_params=self._has_path_ids(parsed.path),
                    query_param_names=query_param_names,
                    category=category,
                    requires_auth=True,
                )
            )

        # Add server-rendered form/link endpoints not already seen via XHR.
        for key, ep in self._html_endpoints.items():
            if key not in seen_keys:
                seen_keys.add(key)
                endpoints.append(ep)

        return endpoints

    def _aggregate_resource_ids(self) -> dict[str, list[str]]:
        """Group discovered resource IDs by their table/path."""
        result: dict[str, list[str]] = {}

        for req in self._intercepted:
            if not req.resource_ids_found:
                continue

            parsed = urlparse(req.url)
            key = extract_supabase_table_from_url(req.url) or parsed.path

            if key not in result:
                result[key] = []

            for rid in req.resource_ids_found:
                if rid not in result[key]:
                    result[key].append(rid)

        return result

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_method(method_str: str) -> EndpointMethod:
        try:
            return EndpointMethod(method_str.upper())
        except ValueError:
            return EndpointMethod.GET

    @staticmethod
    def _categorize_url(url: str) -> EndpointCategory:
        """Assign endpoint category using configurable rules (OCP)."""
        path_lower = urlparse(url).path.lower()
        for segments, category_value in AuthenticatedCrawlerConfig.CATEGORY_RULES:
            if any(seg in path_lower for seg in segments):
                return EndpointCategory(category_value)
        return EndpointCategory.RESOURCE_CRUD

    def _has_path_ids(self, path: str) -> bool:
        for segment in path.split("/"):
            if not segment:
                continue
            if self._UUID_RE.fullmatch(segment):
                return True
            if re.fullmatch(
                AuthenticatedCrawlerConfig.NUMERIC_ID_PATH_PATTERN, segment
            ):
                return True
        return False
