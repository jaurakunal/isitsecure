"""Browser-based DOM XSS scanner using Playwright.

Closes the gap between static regex sink detection (existing XSSScanner)
and Burp Suite's active DOM XSS scanner.  Uses a real Chromium browser to:

1. Hook dangerous DOM sinks via ``page.addInitScript()``
2. Navigate to pages with canary payloads in URL params, hash fragments,
   and ``postMessage``
3. Detect when a canary reaches a sink (confirmed DOM XSS)

Requires Playwright — degrades gracefully if unavailable.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
try:
    from playwright.async_api import Page, async_playwright
except ImportError:  # pragma: no cover
    Page = None  # type: ignore[assignment, misc]
    async_playwright = None  # type: ignore[assignment, misc]

from isitsecure.engine.constants import DOMXSSConfig
from isitsecure.engine.models import (
    DeepFinding,
    FindingSource,
)
from isitsecure.engine.shared.progress import emit
from isitsecure.engine.shared.url_utils import inject_query_param
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# JavaScript injected into every page BEFORE any app JS runs.
# Overrides dangerous sinks and records when a canary string flows
# into them.  Results are collected via ``window.__domxss_findings``.
# ------------------------------------------------------------------

_SINK_HOOK_SCRIPT = """
() => {
    window.__domxss_findings = [];

    const CANARY_RE = /DOMXSS_CANARY_[a-f0-9]{8}/;

    function _record(sink, value) {
        const match = typeof value === 'string' && CANARY_RE.exec(value);
        if (!match) return;
        window.__domxss_findings.push({
            sink: sink,
            canary: match[0],
            value: String(value).substring(0, 500),
            url: location.href,
            timestamp: Date.now(),
        });
    }

    // --- innerHTML / outerHTML ---
    const origInnerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (origInnerHTMLDesc && origInnerHTMLDesc.set) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(v) {
                _record('innerHTML', v);
                return origInnerHTMLDesc.set.call(this, v);
            },
            get: origInnerHTMLDesc.get,
            configurable: true,
        });
    }

    const origOuterHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (origOuterHTMLDesc && origOuterHTMLDesc.set) {
        Object.defineProperty(Element.prototype, 'outerHTML', {
            set: function(v) {
                _record('outerHTML', v);
                return origOuterHTMLDesc.set.call(this, v);
            },
            get: origOuterHTMLDesc.get,
            configurable: true,
        });
    }

    // --- document.write / writeln ---
    const origWrite = document.write.bind(document);
    document.write = function(...args) {
        args.forEach(a => _record('document.write', a));
        return origWrite(...args);
    };

    const origWriteln = document.writeln.bind(document);
    document.writeln = function(...args) {
        args.forEach(a => _record('document.writeln', a));
        return origWriteln(...args);
    };

    // --- eval ---
    const origEval = window.eval;
    window.eval = function(code) {
        _record('eval', code);
        return origEval.call(this, code);
    };

    // --- Function constructor ---
    const OrigFunction = window.Function;
    window.Function = function(...args) {
        args.forEach(a => _record('Function', a));
        return new OrigFunction(...args);
    };
    window.Function.prototype = OrigFunction.prototype;

    // --- insertAdjacentHTML ---
    const origInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(position, text) {
        _record('insertAdjacentHTML', text);
        return origInsertAdjacentHTML.call(this, position, text);
    };

    // --- location.href setter ---
    try {
        const locDesc = Object.getOwnPropertyDescriptor(window, 'location');
        // location is usually non-configurable, so we wrap assign/replace instead
    } catch(e) {}

    // --- location.assign / location.replace ---
    const origAssign = location.assign.bind(location);
    location.assign = function(url) {
        _record('location.assign', url);
        return origAssign(url);
    };

    const origReplace = location.replace.bind(location);
    location.replace = function(url) {
        _record('location.replace', url);
        return origReplace(url);
    };

    // --- window.open ---
    const origOpen = window.open.bind(window);
    window.open = function(url, ...rest) {
        _record('window.open', url);
        return origOpen(url, ...rest);
    };

    // --- setTimeout / setInterval with string args ---
    const origSetTimeout = window.setTimeout.bind(window);
    window.setTimeout = function(fn, ...rest) {
        if (typeof fn === 'string') _record('setTimeout', fn);
        return origSetTimeout(fn, ...rest);
    };

    const origSetInterval = window.setInterval.bind(window);
    window.setInterval = function(fn, ...rest) {
        if (typeof fn === 'string') _record('setInterval', fn);
        return origSetInterval(fn, ...rest);
    };
}
"""


# Text-bearing inputs an attacker could type into, selected by TYPE — not by any
# app-specific id/class/route — so input discovery stays generic. Non-text and
# password fields are excluded (typing markup there is noise, not signal).
_INTERACTIVE_INPUT_SELECTOR = (
    "input:not([type=hidden]):not([type=submit]):not([type=button])"
    ":not([type=reset]):not([type=checkbox]):not([type=radio])"
    ":not([type=file]):not([type=image]):not([type=range])"
    ":not([type=color]):not([type=password]), "
    "textarea, [contenteditable='true'], [contenteditable='']"
)


class DOMXSSScanner:
    """Browser-based DOM XSS scanner.

    Runs inside a Playwright Chromium instance.  Hooks dangerous sinks
    before page JS executes, then injects canary strings via multiple
    sources (URL params, hash, postMessage) to detect source-to-sink
    data flow confirming DOM XSS.

    This scanner is NOT a DASTScannerProtocol (it doesn't take
    endpoints + snapshot).  Instead it is invoked by the agent
    during the authenticated crawl phase, reusing the existing
    Playwright browser context.
    """

    SCANNER_NAME = DOMXSSConfig.SCANNER_NAME

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(
        self,
        pages_to_test: list[str],
        auth_headers: dict[str, str] | None = None,
    ) -> list[DeepFinding]:
        """Scan a list of page URLs for DOM XSS using a headless browser.

        Args:
            pages_to_test: Fully-qualified URLs to visit.
            auth_headers: Optional auth headers (cookies/bearer) to set.

        Returns:
            List of confirmed DOM XSS findings.
        """
        if async_playwright is None:
            logger.warning(DOMXSSConfig.ERROR_PLAYWRIGHT_UNAVAILABLE)
            return []

        if not pages_to_test:
            return []

        findings: list[DeepFinding] = []

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    context = await browser.new_context(
                        viewport={
                            "width": DOMXSSConfig.VIEWPORT_WIDTH,
                            "height": DOMXSSConfig.VIEWPORT_HEIGHT,
                        },
                    )

                    if auth_headers:
                        await self._set_auth_headers(context, auth_headers)

                    page = await context.new_page()
                    await page.add_init_script(_SINK_HOOK_SCRIPT)

                    tested = 0
                    for url in pages_to_test[:DOMXSSConfig.MAX_PAGES_TO_TEST]:
                        emit(f"DOM-XSS: {url}")
                        page_findings = await self._test_page(page, url)
                        findings.extend(page_findings)
                        tested += 1

                    await page.close()
                    await context.close()
                finally:
                    await browser.close()

        except Exception as exc:
            logger.error(
                DOMXSSConfig.ERROR_SCAN_FAILED.format(error=str(exc))
            )

        logger.info(
            DOMXSSConfig.LOG_SCAN_COMPLETE,
            len(findings),
            len(pages_to_test),
        )
        return findings

    async def scan_with_page(
        self,
        page: Page,
        pages_to_test: list[str],
    ) -> list[DeepFinding]:
        """Scan using an existing Playwright page (reuses browser session).

        Called from the authenticated crawler to avoid launching a
        second browser.  The init script must already be installed
        on the browser context.

        Args:
            page: Existing Playwright page with sink hooks installed.
            pages_to_test: URLs to test.

        Returns:
            List of confirmed DOM XSS findings.
        """
        findings: list[DeepFinding] = []

        for url in pages_to_test[:DOMXSSConfig.MAX_PAGES_TO_TEST]:
            emit(f"DOM-XSS: {url}")
            page_findings = await self._test_page(page, url)
            findings.extend(page_findings)

        logger.info(
            DOMXSSConfig.LOG_SCAN_COMPLETE,
            len(findings),
            len(pages_to_test),
        )
        return findings

    # ------------------------------------------------------------------
    # Per-page testing
    # ------------------------------------------------------------------

    async def _test_page(
        self,
        page: Page,
        url: str,
    ) -> list[DeepFinding]:
        """Test a single page URL for DOM XSS via multiple injection vectors.

        For each page:
        1. Inject canary via URL query params (one per common param name)
        2. Inject canary via URL hash fragment
        3. Inject canary via postMessage
        4. Collect any sink hits from ``window.__domxss_findings``
        """
        findings: list[DeepFinding] = []
        canary = self._generate_canary()

        # --- Vector 1: URL query parameters ---
        for param in DOMXSSConfig.INJECTION_PARAMS:
            hits = await self._inject_via_query_param(
                page, url, param, canary,
            )
            for hit in hits:
                findings.append(
                    self._build_finding(url, hit, "query_param", param, canary)
                )
            if findings:
                break  # One confirmed hit per page is sufficient

        # --- Vector 2: Hash fragment ---
        if not findings:
            hits = await self._inject_via_hash(page, url, canary)
            for hit in hits:
                findings.append(
                    self._build_finding(url, hit, "hash_fragment", "#", canary)
                )

        # --- Vector 3: postMessage ---
        if not findings:
            hits = await self._inject_via_postmessage(page, url, canary)
            for hit in hits:
                findings.append(
                    self._build_finding(url, hit, "postMessage", "message", canary)
                )

        # --- Vector 4: interactive form inputs (type -> submit -> observe) ---
        # Covers the flows URL navigation alone can't reach: reflected/DOM XSS
        # that requires TYPING into a field (e.g. an SPA search box that renders
        # the term client-side). Inputs are discovered from the live DOM, so it
        # is app-agnostic.
        if not findings:
            hits = await self._inject_via_inputs(page, url, canary)
            for hit in hits:
                findings.append(
                    self._build_finding(url, hit, "form_input", "input", canary)
                )

        return findings

    # ------------------------------------------------------------------
    # Injection vectors
    # ------------------------------------------------------------------

    async def _inject_via_query_param(
        self,
        page: Page,
        url: str,
        param_name: str,
        canary: str,
    ) -> list[dict]:
        """Navigate to the URL with a canary in a query parameter."""
        injected_url = inject_query_param(url, param_name, canary)
        return await self._navigate_and_collect(page, injected_url)

    async def _inject_via_hash(
        self,
        page: Page,
        url: str,
        canary: str,
    ) -> list[dict]:
        """Navigate to the URL with a canary in the hash fragment."""
        injected_url = f"{url}#{canary}"
        return await self._navigate_and_collect(page, injected_url)

    async def _inject_via_postmessage(
        self,
        page: Page,
        url: str,
        canary: str,
    ) -> list[dict]:
        """Navigate to the URL, then send a postMessage with the canary."""
        await self._safe_navigate(page, url)

        # Send canary via postMessage in multiple formats
        for payload in DOMXSSConfig.POSTMESSAGE_PAYLOADS:
            formatted = payload.replace("{canary}", canary)
            try:
                await page.evaluate(
                    f"window.postMessage({formatted}, '*')"
                )
            except Exception:
                pass

        await asyncio.sleep(DOMXSSConfig.POST_INJECT_WAIT_SECONDS)
        return await self._collect_findings(page)

    async def _inject_via_inputs(
        self,
        page: Page,
        url: str,
        canary: str,
    ) -> list[dict]:
        """Interactive vector: type a payload into each discoverable input,
        trigger its handlers + submit, and observe both the sink hooks and the
        rendered DOM.

        The payload embeds the canary token in an element id, so it confirms two
        ways — either is execution-equivalent and false-positive-free:
          * the string reaches a hooked DOM sink (innerHTML/write/eval/...), or
          * it is parsed into the DOM as a real element (the id materialises).

        Generic by construction: inputs are found by TYPE from the live DOM, with
        no app-specific selectors, ids, or routes.
        """
        await self._safe_navigate(page, url)

        # `<img>` with a broken src (no onerror) — harmless, but if this parses
        # into the DOM so would `<img onerror=...>`. The id IS the canary token,
        # so the sink-hook regex also matches if the string flows to a sink.
        payload = f'<img src=x id="{canary}">'

        try:
            handles = await page.query_selector_all(_INTERACTIVE_INPUT_SELECTOR)
        except Exception:
            return []

        for handle in handles[:DOMXSSConfig.MAX_INPUTS_PER_PAGE]:
            if not await self._fill_input(handle, payload):
                continue
            # First observe reflection on input/change handlers...
            await asyncio.sleep(DOMXSSConfig.POST_INJECT_WAIT_SECONDS)
            hits = await self._observe(page, canary, payload, url)
            if not hits:
                # ...then try submitting (many search boxes reflect on Enter).
                try:
                    await handle.press("Enter")
                except Exception:
                    pass
                await asyncio.sleep(DOMXSSConfig.POST_INJECT_WAIT_SECONDS)
                hits = await self._observe(page, canary, payload, url)
            if hits:
                return hits
        return []

    @staticmethod
    async def _fill_input(handle: object, payload: str) -> bool:
        """Type ``payload`` into one field. Returns False if it isn't typeable
        (detached, disabled, or a non-fillable custom widget)."""
        try:
            await handle.fill(payload)  # type: ignore[union-attr]
            return True
        except Exception:
            try:  # contenteditable / rich fields aren't fillable — type instead
                await handle.click()      # type: ignore[union-attr]
                await handle.type(payload)  # type: ignore[union-attr]
                return True
            except Exception:
                return False

    async def _observe(
        self,
        page: Page,
        canary: str,
        payload: str,
        url: str,
    ) -> list[dict]:
        """Collect sink-hook hits, falling back to a DOM-materialisation check."""
        hits = await self._collect_findings(page)
        if not hits and await self._canary_materialized(page, canary):
            hits = [{
                "sink": "rendered DOM (HTML injection)",
                "value": payload,
                "url": url,
            }]
        return hits

    @staticmethod
    async def _canary_materialized(page: Page, canary: str) -> bool:
        """True if an element carrying the canary id exists in the DOM — i.e. the
        typed payload was parsed as HTML rather than escaped to text."""
        try:
            return bool(await page.evaluate(
                "(id) => !!document.getElementById(id)", canary
            ))
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Navigation + collection
    # ------------------------------------------------------------------

    async def _navigate_and_collect(
        self,
        page: Page,
        url: str,
    ) -> list[dict]:
        """Navigate to a URL and collect any DOM XSS sink hits."""
        await self._safe_navigate(page, url)
        await asyncio.sleep(DOMXSSConfig.POST_INJECT_WAIT_SECONDS)
        return await self._collect_findings(page)

    async def _safe_navigate(self, page: Page, url: str) -> None:
        """Navigate with timeout and error handling."""
        try:
            await page.goto(
                url,
                timeout=DOMXSSConfig.NAVIGATION_TIMEOUT_MS,
                wait_until="domcontentloaded",
            )
            try:
                await page.wait_for_load_state(
                    "networkidle",
                    timeout=DOMXSSConfig.NETWORK_IDLE_TIMEOUT_MS,
                )
            except Exception:
                pass
        except Exception as exc:
            logger.debug("DOM XSS navigate failed for %s: %s", url, exc)

    async def _collect_findings(self, page: Page) -> list[dict]:
        """Read back any canary hits from the injected sink hooks."""
        try:
            results = await page.evaluate(
                """() => {
                    const findings = window.__domxss_findings || [];
                    window.__domxss_findings = [];
                    return findings;
                }"""
            )
            return results or []
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _set_auth_headers(
        context: object,
        headers: dict[str, str],
    ) -> None:
        """Set extra HTTP headers on the browser context for auth."""
        try:
            await context.set_extra_http_headers(headers)  # type: ignore[union-attr]
        except Exception as exc:
            logger.debug("Could not set auth headers: %s", exc)

    # ------------------------------------------------------------------
    # Finding builder
    # ------------------------------------------------------------------

    def _build_finding(
        self,
        page_url: str,
        hit: dict,
        vector: str,
        param: str,
        canary: str,
    ) -> DeepFinding:
        """Build a DeepFinding from a confirmed DOM XSS sink hit."""
        sink = hit.get("sink", "unknown")
        value_preview = hit.get("value", "")[:200]

        vector_label = {
            "query_param": f"URL query parameter '{param}'",
            "hash_fragment": "URL hash fragment (#)",
            "postMessage": "window.postMessage()",
            "form_input": "an interactive form input (typed + submitted)",
        }.get(vector, vector)

        return DeepFinding(
            source=FindingSource.DAST_AUTHENTICATED,
            category=FindingCategory.INJECTION_RISK,
            severity=SeverityLevel.HIGH,
            title=DOMXSSConfig.TITLE_CONFIRMED.format(sink=sink),
            description=DOMXSSConfig.DESC_CONFIRMED.format(
                url=page_url,
                sink=sink,
                vector=vector_label,
            ),
            technical_detail=(
                f"**Confirmed DOM XSS via browser execution**\n\n"
                f"**Page:** {page_url}\n"
                f"**Sink:** `{sink}`\n"
                f"**Source:** {vector_label}\n"
                f"**Canary:** `{canary}`\n"
                f"**Value reaching sink:** `{value_preview}`\n\n"
                f"The scanner injected a canary string via {vector_label} "
                f"and confirmed it reached the `{sink}` DOM sink during "
                f"live browser execution. This proves user-controlled input "
                f"flows to a dangerous DOM API without sanitization."
            ),
            evidence=(
                f"Canary '{canary}' injected via {vector_label} "
                f"reached {sink} sink on {page_url}"
            ),
            confidence=DOMXSSConfig.CONFIDENCE_CONFIRMED,
            scanner_name=self.SCANNER_NAME,
            endpoint_url=page_url,
            http_method="GET",
            request_payload=canary,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_canary() -> str:
        """Generate a unique canary string for DOM XSS detection."""
        return f"DOMXSS_CANARY_{uuid.uuid4().hex[:8]}"
