"""Shared browser login utilities for Playwright-based authentication.

Extracted from BrowserAuthProvider and AuthenticatedCrawler to satisfy DRY.
Both classes delegate to this helper for form-filling, submission, and
token extraction from browser storage.
"""

from __future__ import annotations

import json
import logging
import time

from isitsecure.engine.constants import BrowserLoginConfig, SharedPatterns
from isitsecure.engine.shared.jwt_utils import decode_jwt_payload, looks_like_jwt

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
    # Storage values larger than this are not parsed as JSON (hostile/huge blob guard).
    MAX_BLOB_CHARS = 1_000_000
    # Overall wall-clock budget (seconds) for login-page discovery across all its navigations.
    LOGIN_DISCOVERY_BUDGET_S = 20.0
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

        deadline = time.monotonic() + BrowserCaptureConfig.LOGIN_DISCOVERY_BUDGET_S

        def _remaining_ms() -> int:
            return max(int((deadline - time.monotonic()) * 1000), 0)

        async def _nav(url: str) -> bool:
            # Every wait is capped by what is left of the overall budget.
            try:
                await page.goto(  # type: ignore[union-attr]
                    url, timeout=min(BrowserLoginConfig.NAVIGATION_TIMEOUT_MS, _remaining_ms()),
                    wait_until="domcontentloaded")
                await page.wait_for_load_state(  # type: ignore[union-attr]
                    "networkidle",
                    timeout=min(BrowserLoginConfig.NETWORK_IDLE_TIMEOUT_MS, _remaining_ms()))
            except Exception as exc:  # noqa: BLE001
                logger.debug("login discovery nav to %s failed: %s", url, exc)
            try:
                await page.wait_for_selector(  # type: ignore[union-attr]
                    BrowserCaptureConfig.CREDENTIAL_INPUT_SELECTOR,
                    timeout=min(BrowserLoginConfig.LOGIN_WAIT_TIMEOUT_MS, _remaining_ms()))
            except Exception:  # noqa: BLE001,S110 — absence is the expected non-match path
                pass
            return await BrowserLoginHelper.has_login_fields(page)

        href = await BrowserLoginHelper._find_login_link(page)
        if href and _remaining_ms() > 0 and await _nav(urljoin(origin, href)):
            return True
        for route in BrowserCaptureConfig.LOGIN_ROUTES:
            if _remaining_ms() <= 0:
                logger.debug("login discovery: time budget exhausted")
                break
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
    async def extract_token(page: object, shape_scan: bool = True) -> str | None:
        """Extract auth token from localStorage or sessionStorage.

        Checks well-known key names first, then scans all keys for
        Supabase-style composite storage entries, then (``shape_scan``) any storage
        value by JWT shape. ``shape_scan=False`` is the original key-based behaviour only.

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
            # Only identity-bearing JWTs are accepted (an anon/analytics key is not a session),
            # id/refresh-named keys are skipped, and the best-ranked candidate wins.
            if shape_scan:
                best: tuple[int, str] | None = None
                for store in ("localStorage", "sessionStorage"):
                    entries = await page.evaluate(  # type: ignore[union-attr]
                        f"() => Object.entries({store})"
                    )
                    for entry in (entries or []):
                        try:
                            key, raw = entry
                        except (TypeError, ValueError):
                            continue
                        if any(h in str(key).lower()
                               for h in BrowserCaptureConfig.NON_ACCESS_HINTS):
                            continue
                        found = find_jwt_deep(str(raw))
                        rank = jwt_identity_rank(found) if found else -1
                        if rank >= 1 and (best is None or rank > best[0]):
                            best = (rank, found)
                if best:
                    return best[1]

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
        best_rank = [-1]

        def _on_request(request: object) -> None:
            try:
                headers = request.headers or {}          # Playwright lowercases header names
            except Exception:  # noqa: BLE001 — a header read must never break the login flow
                return
            apikey = str(headers.get(SharedPatterns.HEADER_APIKEY, ""))
            if apikey and "apikey" not in captured:
                captured["apikey"] = apikey
            auth = str(headers.get(SharedPatterns.HEADER_AUTHORIZATION.lower(), ""))
            if not auth.startswith(SharedPatterns.BEARER_PREFIX):
                return
            tok = auth[len(SharedPatterns.BEARER_PREFIX):]
            # Pre-login requests (e.g. Supabase) carry the anon key as Bearer: skip a Bearer equal
            # to the apikey or an anon-role JWT, and let the LATEST best-ranked identity JWT win.
            if not looks_like_jwt(tok) or tok == apikey or tok == captured.get("apikey"):
                return
            rank = jwt_identity_rank(tok)
            if rank >= 0 and rank >= best_rank[0]:
                best_rank[0] = rank
                captured["authorization"] = auth

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


def jwt_identity_rank(token: str) -> int:
    """How strongly a JWT looks like a USER session: 2 = has ``sub``, 1 = has ``exp`` only,
    0 = neither, -1 = not decodable or an ``anon``-role key (a public client key, not a session).
    """
    payload = decode_jwt_payload(token)
    if not isinstance(payload, dict):
        return -1
    if str(payload.get("role", "")).lower() == "anon":
        return -1
    if payload.get("sub"):
        return 2
    return 1 if "exp" in payload else 0


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
        if len(node) > BrowserCaptureConfig.MAX_BLOB_CHARS:
            return None
        try:
            parsed = json.loads(node)
        except (json.JSONDecodeError, ValueError, RecursionError):
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
