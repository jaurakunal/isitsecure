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
import json
import logging
import re
from collections import deque
from urllib.parse import urlparse

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
    SharedPatterns,
)
from isitsecure.engine.enums import EndpointCategory, EndpointMethod
from isitsecure.engine.models import (
    AuthenticatedCrawlResult,
    DiscoveredEndpoint,
    InterceptedRequest,
)
from isitsecure.engine.shared.html_endpoint_extractor import (
    extract_html_endpoints,
)
from isitsecure.engine.shared.supabase_utils import (
    extract_supabase_table_from_url,
)

logger = logging.getLogger(__name__)


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
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._email = email
        self._password = password
        self._login_url = login_url or f"{self._base_url}/login"
        self._seed_routes = seed_routes or []

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
    # Phase 1: Browser Login (delegates to BrowserLoginHelper)
    # ------------------------------------------------------------------

    async def _login(self, page: object) -> bool:
        """Navigate to login page and fill credentials via shared helper."""
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
            and visited_count < AuthenticatedCrawlerConfig.MAX_PAGES_TO_VISIT
        ):
            url = self._link_queue.popleft()
            normalized = self._normalize_url(url)

            if not normalized or normalized in self._visited:
                continue

            self._visited.add(normalized)

            try:
                await page.goto(  # type: ignore[union-attr]
                    normalized,
                    timeout=AuthenticatedCrawlerConfig.NAVIGATION_TIMEOUT_MS,
                    wait_until="domcontentloaded",
                )
                try:
                    await page.wait_for_load_state(  # type: ignore[union-attr]
                        "networkidle",
                        timeout=AuthenticatedCrawlerConfig.BFS_NETWORK_IDLE_TIMEOUT_MS,
                    )
                except Exception:
                    await asyncio.sleep(
                        AuthenticatedCrawlerConfig.PAGE_LOAD_WAIT_MS / 1000
                    )

                visited_count += 1
                logger.debug("Crawled [%d]: %s", visited_count, normalized)

                await self._discover_links_from_page(page)
                await self._extract_html_endpoints(page, normalized)
                await self._interact_with_forms(page)

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

    async def _interact_with_forms(self, page: object) -> None:
        """Find forms and buttons on the page, click/submit them to trigger API calls.

        This catches endpoints that are only reachable by clicking buttons
        (e.g., "Create Deal", "Submit Review", "Update Profile").
        Network interception captures the resulting requests.
        """
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
