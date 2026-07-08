"""Shared browser login utilities for Playwright-based authentication.

Extracted from BrowserAuthProvider and AuthenticatedCrawler to satisfy DRY.
Both classes delegate to this helper for form-filling, submission, and
token extraction from browser storage.
"""

from __future__ import annotations

import json
import logging

from isitsecure.engine.constants import BrowserLoginConfig

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

        except Exception as exc:
            logger.debug("Token extraction failed: %s", exc)

        return None


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
