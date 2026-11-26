"""Browser-based authentication provider for the Deep Security Scan Agent.

Delegates form-filling and token extraction to ``BrowserLoginHelper``
to share logic with ``AuthenticatedCrawler`` (DRY).

Capture is layered so heavy SPAs do not silently degrade the scan to anonymous: the token is
read from browser storage (any key, incl. nested/double-serialized blobs) AND sniffed off the
wire, a cookie-only session is accepted, and the full Playwright ``storage_state`` is exposed in
``AuthSession.user_metadata`` for a later authenticated crawl to replay.
"""

from __future__ import annotations

import asyncio
import logging

from isitsecure.engine.constants import (
    BrowserAuthConfig,
    BrowserLoginConfig,
    SharedPatterns,
)
from isitsecure.engine.enums import AuthProvider

from .browser_login_helper import BrowserCaptureConfig, BrowserLoginHelper
from .protocols import AuthCredentials, AuthSession

logger = logging.getLogger(__name__)


def _wire_bearer(sniffed: dict[str, str]) -> str:
    """The Bearer token the app sent on the wire, or '' when none was seen."""
    auth = sniffed.get("authorization", "")
    prefix = SharedPatterns.BEARER_PREFIX
    tok = auth[len(prefix):] if auth.startswith(prefix) else ""
    # A Bearer equal to the apikey is the public client key, not a session.
    return "" if tok and tok == sniffed.get("apikey") else tok


async def _read_token(page: object, sniffed: dict[str, str]) -> tuple[str, str]:
    """One capture pass, most-trusted source first: original key-based storage read, then the
    wire (the token the app really sends, preferred over any guessed storage value), then the
    JWT-shape storage scan. Returns ``(token, source)`` or ``("", "")``."""
    token = await BrowserLoginHelper.extract_token(page, shape_scan=False)
    if token:
        return token, "storage"
    wire = _wire_bearer(sniffed)
    if wire:
        return wire, "wire"
    token = await BrowserLoginHelper.extract_token(page)
    return (token, "storage-scan") if token else ("", "")


class BrowserAuthProvider:
    """Authenticates via Playwright browser automation for custom auth flows.

    Launches a headless Chromium browser, navigates to the login page,
    fills credentials via ``BrowserLoginHelper``, and extracts auth tokens.

    NOTE: nothing outside ``auth/__init__`` constructs this provider yet, so the capture
    capabilities below (wire sniff, cookie-only, ``storage_state``) are not reachable from the
    CLI or server until a caller is wired in.
    """

    @property
    def provider_type(self) -> AuthProvider:
        return AuthProvider.BROWSER

    async def authenticate(self, credentials: AuthCredentials) -> AuthSession:
        """Authenticate by automating browser login flow."""
        if not credentials.login_url:
            raise ValueError(BrowserAuthConfig.ERROR_MISSING_LOGIN_URL)
        if not credentials.email or not credentials.password:
            raise ValueError(BrowserAuthConfig.ERROR_MISSING_CREDENTIALS)

        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise ImportError(BrowserAuthConfig.ERROR_PLAYWRIGHT_MISSING) from exc

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await browser.new_context()
                page = await context.new_page()
                # Sniff the token off the wire; attached BEFORE navigation so no early
                # authenticated request is missed.
                sniffed = BrowserLoginHelper.attach_token_sniffer(page)

                try:
                    await page.goto(
                        credentials.login_url,
                        timeout=BrowserLoginConfig.NAVIGATION_TIMEOUT_MS,
                    )
                except Exception as exc:
                    raise ValueError(
                        BrowserAuthConfig.ERROR_NAVIGATION_FAILED.format(
                            error=str(exc)
                        )
                    ) from exc

                # A heavy SPA paints the login form after ``load`` fires; filling straight after
                # goto runs on an empty shell. Settle the network, then wait for a password input.
                try:
                    await page.wait_for_load_state(
                        "networkidle", timeout=BrowserLoginConfig.NETWORK_IDLE_TIMEOUT_MS)
                except Exception:  # noqa: BLE001,S110 — settling is best-effort
                    pass
                try:
                    await page.wait_for_selector(
                        BrowserCaptureConfig.CREDENTIAL_INPUT_SELECTOR,
                        timeout=BrowserLoginConfig.LOGIN_WAIT_TIMEOUT_MS)
                except Exception:  # noqa: BLE001,S110 — absence handled by discovery below
                    pass

                # login_url may be a bare origin whose SPA serves login off a route/hash (e.g.
                # /#/login). Discover the login page; a no-op when the form is already present.
                await BrowserLoginHelper.goto_login_page(page, credentials.login_url)

                # Fill form via shared helper: fixed selectors first, then
                # form-scoped detection for non-standard identity field names.
                email_ok = await BrowserLoginHelper.fill_input(
                    page,
                    BrowserLoginConfig.EMAIL_INPUT_SELECTORS,
                    credentials.email,
                )
                pw_ok = email_ok and await BrowserLoginHelper.fill_input(
                    page,
                    BrowserLoginConfig.PASSWORD_INPUT_SELECTORS,
                    credentials.password,
                )
                if not (email_ok and pw_ok):
                    if not await BrowserLoginHelper.detect_and_fill_login(
                        page, credentials.email, credentials.password,
                    ):
                        raise ValueError(
                            BrowserLoginConfig.ERROR_LOGIN_FAILED.format(
                                error="Could not locate login fields"
                            )
                        )

                submitted = await BrowserLoginHelper.click_submit(page)
                if not submitted:
                    raise ValueError(
                        BrowserLoginConfig.ERROR_LOGIN_FAILED.format(
                            error="Could not find submit button"
                        )
                    )

                try:
                    await page.wait_for_load_state(
                        "networkidle",
                        timeout=BrowserLoginConfig.LOGIN_WAIT_TIMEOUT_MS,
                    )
                except Exception:  # noqa: BLE001,S110 — long-polling SPAs never go idle
                    pass

                token, cred_source = await self._capture_token(page, sniffed)

                cookies = await context.cookies()
                cookie_dict = {c["name"]: c["value"] for c in cookies}

                # Full storage_state (cookies + per-origin localStorage) so a later crawl can
                # replay it via ``new_context(storage_state=...)``. Best-effort; failure is {}.
                try:
                    storage_state = await context.storage_state()
                except Exception:  # noqa: BLE001 — a bonus artifact, never fatal
                    storage_state = {}

                # A session needs SOME credential: a bearer token and/or session cookies.
                if not token and not cookie_dict:
                    raise ValueError(BrowserLoginConfig.ERROR_NO_TOKEN_FOUND)

                headers: dict[str, str] = {}
                if token:
                    headers[SharedPatterns.HEADER_AUTHORIZATION] = (
                        f"{SharedPatterns.BEARER_PREFIX}{token}"
                    )
                    logger.info(
                        "browser login: session acquired (token=yes via %s, cookies=%d)",
                        cred_source, len(cookie_dict),
                    )
                else:
                    self._accept_cookie_only(
                        headers, sniffed, cookie_dict, storage_state,
                    )

                return AuthSession(
                    user_id=BrowserAuthConfig.DEFAULT_USER_ID,
                    access_token=token,
                    headers=headers,
                    user_metadata={"cookies": cookie_dict, "storage_state": storage_state},
                    provider=AuthProvider.BROWSER,
                )
            finally:
                await browser.close()

    @staticmethod
    async def _capture_token(page: object, sniffed: dict[str, str]) -> tuple[str, str]:
        """Poll storage AND the wire for the token; nudge with a reload as a last resort.

        The SPA writes its token to storage a beat after login and sends it on its first
        authenticated request; watching both removes the storage-guess race. Returns
        ``(token, source)`` where source is "storage"/"wire", or ``("", "")`` when none.
        """
        for _ in range(BrowserCaptureConfig.POST_LOGIN_TOKEN_POLLS):
            token, source = await _read_token(page, sniffed)
            if token:
                return token, source
            await asyncio.sleep(BrowserCaptureConfig.POST_LOGIN_TOKEN_POLL_MS / 1000)

        # Neither path yielded a token; the app may not have fired an authenticated request yet.
        # Reload to trigger one, then re-check the wire and storage once (bounded, best-effort).
        try:
            await page.reload(  # type: ignore[union-attr]
                timeout=BrowserLoginConfig.LOGIN_WAIT_TIMEOUT_MS)
            await page.wait_for_load_state(  # type: ignore[union-attr]
                "networkidle", timeout=BrowserLoginConfig.NETWORK_IDLE_TIMEOUT_MS)
        except Exception:  # noqa: BLE001,S110 — the nudge is best-effort
            pass
        return await _read_token(page, sniffed)

    @staticmethod
    def _accept_cookie_only(
        headers: dict[str, str],
        sniffed: dict[str, str],
        cookie_dict: dict[str, str],
        storage_state: dict,
    ) -> None:
        """Build headers for a token-less (cookie-only) session and warn loudly.

        A token-less session means JWT-forge / token-swap attacks cannot run; surface it now
        with what WAS seen (counts only, never names or values) instead of a mystery anonymous scan.
        """
        apikey = sniffed.get("apikey", "")
        if apikey:
            headers[SharedPatterns.HEADER_APIKEY] = apikey
        headers[SharedPatterns.HEADER_COOKIE] = "; ".join(
            f"{k}={v}" for k, v in cookie_dict.items()
        )
        # Counts only: storage key names can embed emails / user ids.
        ls_count = sum(
            len(o.get("localStorage") or []) for o in (storage_state.get("origins") or [])
        )
        logger.warning(
            "browser login: NO bearer token captured (storage or wire); accepting a "
            "cookie-only session (cookies=%d, apikey=%s, localStorage entries=%d). JWT-based "
            "attacks cannot run against this session. If the target is bearer-auth, capture "
            "failed (async write raced, token in IndexedDB, or incomplete login).",
            len(cookie_dict), "yes" if apikey else "no", ls_count,
        )

    async def refresh(self, session: AuthSession) -> AuthSession:
        """Browser auth does not support token refresh."""
        raise NotImplementedError(BrowserAuthConfig.ERROR_REFRESH_NOT_SUPPORTED)
