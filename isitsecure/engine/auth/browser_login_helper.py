"""Shared browser login utilities for Playwright-based authentication.

Extracted from BrowserAuthProvider and AuthenticatedCrawler to satisfy DRY.
Both classes delegate to this helper for form-filling, submission, and
token extraction from browser storage.
"""

from __future__ import annotations

import json
import logging

from isitsecure.engine.constants import BrowserLoginConfig, SharedPatterns
from isitsecure.engine.shared.jwt_utils import looks_like_jwt

logger = logging.getLogger(__name__)

# Form-scoped login-field detection. Finds the visible password input, scopes
# to its enclosing <form>, and marks the identity field as the visible
# text/email/tel input in that same form. Confined to the login form, so it
# adapts to any identity field name (userName, login, acct, ...) without ever
# grabbing an unrelated search box elsewhere on the page.
_ID_MARK = "data-isitsecure-idfield"
_PW_MARK = "data-isitsecure-pwfield"
_DETECT_LOGIN_FIELDS_JS = """
() => {
  const vis = (el) => !!(el.offsetParent || el.getClientRects().length);
  const pw = Array.from(document.querySelectorAll('input[type="password"]')).find(vis);
  if (!pw) return { ok: false };
  const scope = pw.closest('form') || document.body;
  const id = Array.from(scope.querySelectorAll('input')).find(
    (el) => el !== pw
      && ['text', 'email', 'tel'].includes(el.type)
      && !el.disabled
      && vis(el)
  );
  if (!id) return { ok: false };
  id.setAttribute('data-isitsecure-idfield', '1');
  pw.setAttribute('data-isitsecure-pwfield', '1');
  return { ok: true };
}
"""

# Structural, language-agnostic submit: click the submit control of the FORM holding the password
# field (a semantic submit if present, else the last enabled visible button in it). Needs no CTA
# text, so it works on SPAs whose button label is unlisted, non-English or icon-only.
_STRUCTURAL_SUBMIT_JS = """
() => {
  const vis = (el) => !!(el.offsetParent || el.getClientRects().length);
  const pw = Array.from(document.querySelectorAll('input[type="password"]')).find(vis);
  if (!pw) return false;
  const form = pw.closest('form') || document;
  let btn = form.querySelector('button[type="submit"], input[type="submit"]');
  if (!btn || btn.disabled || !vis(btn)) {
    const cands = Array.from(
      form.querySelectorAll('button, [role="button"], input[type="button"]'))
      .filter((b) => vis(b) && !b.disabled);
    btn = cands[cands.length - 1] || null;
  }
  if (!btn) return false;
  btn.click();
  return true;
}
"""

# Find a 'log in / sign in' link on the current page by visible text or href token (web-standard,
# no app-specific selector). Used for login-page discovery when a bare origin was given.
_FIND_LOGIN_LINK_JS = """
(keywords) => {
  const els = Array.from(document.querySelectorAll('a[href], button'));
  for (const el of els) {
    const text = (el.textContent || '').toLowerCase();
    const href = (el.getAttribute('href') || '').toLowerCase();
    if (keywords.some((k) => text.includes(k) || href.includes(k))) {
      return el.href || el.getAttribute('href') || '';
    }
  }
  return '';
}
"""


class BrowserCaptureConfig:
    """Constants for the robust-capture additions (wire sniff, discovery, nested-JWT search).

    Module-local so the shared ``BrowserLoginConfig`` stays untouched; units mirror its.
    """

    # Poll storage + wire after login: POLLS * POLL_MS bounds the extra wait (~8s). A token written
    # a beat after the login response is missed by a single read.
    POST_LOGIN_TOKEN_POLLS = 16
    POST_LOGIN_TOKEN_POLL_MS = 500
    # Login-page discovery routes tried off the origin when the landing page shows no login form.
    LOGIN_ROUTES = (
        "/#/login", "/login", "/signin", "/#/signin", "/sign-in", "/#/sign-in",
        "/account/login", "/users/login", "/auth/login",
    )
    LOGIN_LINK_KEYWORDS = (
        "log in", "login", "log-in", "sign in", "sign-in", "signin", "log on",
    )
    CREDENTIAL_INPUT_SELECTOR = "input[type='password']"
    # Bound on recursion when hunting a JWT in a serialized blob (a hostile value can't spin).
    MAX_JWT_SEARCH_DEPTH = 8
    # Generic key-name fragments so a blob holding access + refresh + id tokens yields access first.
    ACCESS_KEY_HINTS = ("access",)
    NON_ACCESS_HINTS = ("refresh", "id_token", "idtoken")


class BrowserLoginHelper:
    """Reusable Playwright login + token extraction logic.

    Used by both BrowserAuthProvider (standalone auth) and
    AuthenticatedCrawler (login-then-crawl).
    """

    # ------------------------------------------------------------------
    # Form Interaction
    # ------------------------------------------------------------------

    @staticmethod
    async def fill_input(
        page: object,
        selectors: tuple[str, ...],
        value: str,
    ) -> bool:
        """Try multiple selectors to find and fill an input field.

        Returns:
            True if an input was found and filled, False otherwise.
        """
        for selector in selectors:
            try:
                element = await page.query_selector(selector)  # type: ignore[union-attr]
                if element:
                    await element.fill(value)
                    return True
            except Exception:
                continue
        return False

    @staticmethod
    async def detect_and_fill_login(
        page: object,
        identity_value: str,
        password_value: str,
    ) -> bool:
        """Fill a login form by structure rather than a fixed selector list.

        Locates the password field, scopes to its form, picks the identity
        field in that form, and fills both via Playwright (real input events,
        so framework-controlled inputs register). Returns True if both fields
        were found and filled.
        """
        try:
            detected = await page.evaluate(_DETECT_LOGIN_FIELDS_JS)  # type: ignore[union-attr]
        except Exception as exc:
            logger.debug("Form-scoped login detection failed: %s", exc)
            return False
        if not isinstance(detected, dict) or not detected.get("ok"):
            return False
        id_ok = await BrowserLoginHelper.fill_input(
            page, (f'[{_ID_MARK}="1"]',), identity_value,
        )
        pw_ok = await BrowserLoginHelper.fill_input(
            page, (f'[{_PW_MARK}="1"]',), password_value,
        )
        return id_ok and pw_ok

    @staticmethod
    async def click_submit(page: object) -> bool:
        """Try multiple selectors to find and click the submit button.

        Returns:
            True if a submit button was found and clicked, False otherwise.
        """
        for selector in BrowserLoginConfig.SUBMIT_BUTTON_SELECTORS:
            try:
                element = await page.query_selector(selector)  # type: ignore[union-attr]
                if element:
                    await element.click()
                    return True
            except Exception:
                continue
        # Structural fallback: submit control of the form holding the password field.
        try:
            if await page.evaluate(_STRUCTURAL_SUBMIT_JS):  # type: ignore[union-attr]
                return True
        except Exception:  # noqa: BLE001,S110 — a fallback must never break the login flow
            pass
        # Enter-key fallback: focus the visible password field and press Enter, which submits
        # virtually any real login form without needing a button.
        try:
            pw = await page.query_selector('input[type="password"]')  # type: ignore[union-attr]
            if pw and await pw.is_visible():
                await pw.focus()
                await page.keyboard.press("Enter")  # type: ignore[union-attr]
                return True
        except Exception:  # noqa: BLE001,S110 — a fallback must never break the login flow
            pass
        return False

    # ------------------------------------------------------------------
    # Login-page discovery
    # ------------------------------------------------------------------

    @staticmethod
    async def has_login_fields(page: object) -> bool:
        """True when the current page renders a visible password input plus an identity input."""
        try:
            detected = await page.evaluate(_DETECT_LOGIN_FIELDS_JS)  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001 — a failed probe just means "not confirmed"
            logger.debug("login-field presence probe failed: %s", exc)
            return False
        return isinstance(detected, dict) and bool(detected.get("ok"))

    @staticmethod
    async def _find_login_link(page: object) -> str:
        """Href of a visible 'log in / sign in' link on the current page, or ''."""
        try:
            return await page.evaluate(  # type: ignore[union-attr]
                _FIND_LOGIN_LINK_JS, list(BrowserCaptureConfig.LOGIN_LINK_KEYWORDS)) or ""
        except Exception as exc:  # noqa: BLE001
            logger.debug("login-link discovery failed: %s", exc)
            return ""

    @staticmethod
    async def goto_login_page(page: object, start_url: str) -> bool:
        """Ensure the browser is on a page that renders a login form, discovering it when
        ``start_url`` (often a bare origin) shows none: a 'log in' link first, then common login
        routes off the origin. A no-op when the form is already present. Never raises.
        """
        if await BrowserLoginHelper.has_login_fields(page):
            return True
        from urllib.parse import urljoin, urlparse
        parsed = urlparse(start_url)
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else start_url

        async def _nav(url: str) -> bool:
            try:
                await page.goto(  # type: ignore[union-attr]
                    url, timeout=BrowserLoginConfig.NAVIGATION_TIMEOUT_MS,
                    wait_until="domcontentloaded")
                await page.wait_for_load_state(  # type: ignore[union-attr]
                    "networkidle", timeout=BrowserLoginConfig.NETWORK_IDLE_TIMEOUT_MS)
            except Exception as exc:  # noqa: BLE001
                logger.debug("login discovery nav to %s failed: %s", url, exc)
            try:
                await page.wait_for_selector(  # type: ignore[union-attr]
                    BrowserCaptureConfig.CREDENTIAL_INPUT_SELECTOR,
                    timeout=BrowserLoginConfig.LOGIN_WAIT_TIMEOUT_MS)
            except Exception:  # noqa: BLE001,S110 — absence is the expected non-match path
                pass
            return await BrowserLoginHelper.has_login_fields(page)

        href = await BrowserLoginHelper._find_login_link(page)
        if href and await _nav(urljoin(origin, href)):
            return True
        for route in BrowserCaptureConfig.LOGIN_ROUTES:
            if await _nav(f"{origin}{route}"):
                return True
        # Nothing matched: return to the page we were given so the caller's own fill/detect logic
        # (e.g. a multi-step login) runs where it always did, not on the last probed route.
        try:
            await page.goto(  # type: ignore[union-attr]
                start_url, timeout=BrowserLoginConfig.NAVIGATION_TIMEOUT_MS,
                wait_until="domcontentloaded")
        except Exception as exc:  # noqa: BLE001
            logger.debug("login discovery: restoring %s failed: %s", start_url, exc)
        return False

    # ------------------------------------------------------------------
    # Token Extraction
    # ------------------------------------------------------------------

    @staticmethod
    async def extract_token(page: object) -> str | None:
        """Extract auth token from localStorage or sessionStorage.

        Checks well-known key names first, then scans all keys for
        Supabase-style composite storage entries.

        Returns:
            The extracted token string, or None if no token was found.
        """
        try:
            # Check well-known localStorage keys
            for key in BrowserLoginConfig.LOCAL_STORAGE_TOKEN_KEYS:
                token = await page.evaluate(  # type: ignore[union-attr]
                    f"() => localStorage.getItem('{key}')"
                )
                if token:
                    return _clean_token(token)

            # Check well-known sessionStorage keys
            for key in BrowserLoginConfig.SESSION_STORAGE_TOKEN_KEYS:
                token = await page.evaluate(  # type: ignore[union-attr]
                    f"() => sessionStorage.getItem('{key}')"
                )
                if token:
                    return _clean_token(token)

            # Scan all localStorage keys for composite entries
            all_keys = await page.evaluate(  # type: ignore[union-attr]
                "() => Object.keys(localStorage)"
            )
            for key in (all_keys or []):
                if any(
                    ind in key.lower()
                    for ind in BrowserLoginConfig.LOCAL_STORAGE_KEY_INDICATORS
                ):
                    raw = await page.evaluate(  # type: ignore[union-attr]
                        f"() => localStorage.getItem('{key}')"
                    )
                    if raw:
                        token = extract_token_from_json(raw)
                        if token:
                            return token

            # Shape-based fallback: the token may sit under a non-standard key. Scan every
            # localStorage/sessionStorage value for a JWT-shaped string, or one nested in a
            # (possibly double-serialized) JSON blob such as Redux-persist.
            for store in ("localStorage", "sessionStorage"):
                values = await page.evaluate(  # type: ignore[union-attr]
                    f"() => Object.values({store})"
                )
                for raw in (values or []):
                    found = find_jwt_deep(str(raw))
                    if found:
                        return found

        except Exception as exc:
            logger.debug("Token extraction failed: %s", exc)

        return None

    @staticmethod
    def attach_token_sniffer(page: object) -> dict[str, str]:
        """Capture the auth token off the wire: the Bearer JWT (or ``apikey``) the app itself sends.

        Storage extraction guesses which key holds the token and races the SPA's async write; the
        token the app transmits IS the token. Returns a holder dict populated as requests fire:
        ``{"authorization": "Bearer <jwt>", "apikey": "<key>"}``. Best-effort; never raises.
        """
        captured: dict[str, str] = {}

        def _on_request(request: object) -> None:
            try:
                headers = request.headers or {}          # Playwright lowercases header names
            except Exception:  # noqa: BLE001 — a header read must never break the login flow
                return
            if "authorization" not in captured:
                auth = str(headers.get(SharedPatterns.HEADER_AUTHORIZATION.lower(), ""))
                if auth.startswith(SharedPatterns.BEARER_PREFIX) and looks_like_jwt(
                    auth[len(SharedPatterns.BEARER_PREFIX):]
                ):
                    captured["authorization"] = auth
            if "apikey" not in captured:
                apikey = str(headers.get(SharedPatterns.HEADER_APIKEY, ""))
                if apikey:
                    captured["apikey"] = apikey

        try:
            page.on("request", _on_request)  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001,S110 — sniffing is best-effort
            pass
        return captured


# ------------------------------------------------------------------
# Module-level helpers (stateless, easy to test)
# ------------------------------------------------------------------


def _clean_token(token: str) -> str:
    """Remove surrounding quotes from a token string."""
    return token.strip('"').strip("'")


def extract_token_from_json(raw: str) -> str | None:
    """Parse a JSON string and extract an access_token.

    Handles:
    - Top-level ``{"access_token": "..."}``
    - Supabase v2 nested ``{"currentSession": {"access_token": "..."}}``
    """
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            return None

        # Direct key
        for key in BrowserLoginConfig.JSON_TOKEN_KEYS:
            if data.get(key):
                return data[key]

        # Nested under session (Supabase v2)
        for wrapper_key in BrowserLoginConfig.JSON_SESSION_WRAPPER_KEYS:
            session = data.get(wrapper_key)
            if isinstance(session, dict):
                for key in BrowserLoginConfig.JSON_TOKEN_KEYS:
                    if session.get(key):
                        return session[key]

    except (json.JSONDecodeError, TypeError):
        pass
    return None


def find_jwt_deep(node: object, _depth: int = 0) -> str | None:
    """Recursively find the first JWT-shaped string in a (possibly nested) JSON blob.

    Handles double-serialized values (a JSON string stored inside JSON, as Redux-persist does),
    so a single ``json.loads`` never reaches the token. When a dict holds several JWTs it prefers
    an access-named key over refresh/id by generic name fragments. Depth-bounded.
    """
    if _depth > BrowserCaptureConfig.MAX_JWT_SEARCH_DEPTH or node is None:
        return None
    if isinstance(node, str):
        cleaned = _clean_token(node)
        if looks_like_jwt(cleaned):
            return cleaned
        try:
            parsed = json.loads(node)
        except (json.JSONDecodeError, ValueError):
            return None
        if parsed == node:                    # a bare JSON string that re-parses to itself
            return None
        return find_jwt_deep(parsed, _depth + 1)
    if isinstance(node, dict):
        def _rank(item: tuple[object, object]) -> int:
            key = str(item[0]).lower()
            if any(h in key for h in BrowserCaptureConfig.NON_ACCESS_HINTS):
                return 2
            if any(h in key for h in BrowserCaptureConfig.ACCESS_KEY_HINTS):
                return 0
            return 1
        for _key, value in sorted(node.items(), key=_rank):
            found = find_jwt_deep(value, _depth + 1)
            if found:
                return found
        return None
    if isinstance(node, list):
        for item in node:
            found = find_jwt_deep(item, _depth + 1)
            if found:
                return found
    return None
