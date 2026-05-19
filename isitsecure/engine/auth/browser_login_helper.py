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
