"""Browser-based authentication provider for the Deep Security Scan Agent.

Delegates form-filling and token extraction to ``BrowserLoginHelper``
to share logic with ``AuthenticatedCrawler`` (DRY).
"""

from __future__ import annotations

from isitsecure.engine.constants import (
    BrowserAuthConfig,
    BrowserLoginConfig,
    SharedPatterns,
)
from isitsecure.engine.enums import AuthProvider

from .browser_login_helper import BrowserLoginHelper
from .protocols import AuthCredentials, AuthSession


class BrowserAuthProvider:
    """Authenticates via Playwright browser automation for custom auth flows.

    Launches a headless Chromium browser, navigates to the login page,
    fills credentials via ``BrowserLoginHelper``, and extracts auth tokens.
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

                await page.wait_for_load_state(
                    "networkidle",
                    timeout=BrowserLoginConfig.LOGIN_WAIT_TIMEOUT_MS,
                )

                # Extract token via shared helper
                token = await BrowserLoginHelper.extract_token(page)
                if not token:
                    raise ValueError(BrowserLoginConfig.ERROR_NO_TOKEN_FOUND)

                cookies = await context.cookies()
                cookie_dict = {c["name"]: c["value"] for c in cookies}

                return AuthSession(
                    user_id=BrowserAuthConfig.DEFAULT_USER_ID,
                    access_token=token,
                    headers={
                        SharedPatterns.HEADER_AUTHORIZATION: (
                            f"{SharedPatterns.BEARER_PREFIX}{token}"
                        ),
                    },
                    user_metadata={"cookies": cookie_dict},
                    provider=AuthProvider.BROWSER,
                )
            finally:
                await browser.close()

    async def refresh(self, session: AuthSession) -> AuthSession:
        """Browser auth does not support token refresh."""
        raise NotImplementedError(BrowserAuthConfig.ERROR_REFRESH_NOT_SUPPORTED)
