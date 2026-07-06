"""Enhanced endpoint discovery scanner.

Extracts API endpoints from client-side JavaScript bundles with method
detection (GET/POST/PUT/DELETE) and parameter identification. Goes beyond
the existing APIEndpointScanner by tracking HTTP methods, detecting path
parameters, and categorizing endpoints for IDOR testing.

For modern minified SPAs (Next.js, React, etc.) where fetch() calls use
variables instead of string literals, this scanner also:
- Discovers external API base URLs (api.*, backend.*, etc.)
- Probes those URLs with common API paths (/users, /me, /openapi.json)
- Discovers Supabase project URLs and probes the REST OpenAPI spec
- Extracts route paths that may correspond to API routes
"""

import logging
import re
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from isitsecure.engine.constants import (
    DeepScanConfig,
    EndpointDiscoveryConfig,
    IDORConfig,
    SharedPatterns,
)
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.enums import EndpointCategory, EndpointMethod
from isitsecure.engine.models import DiscoveredEndpoint

logger = logging.getLogger(__name__)


class EndpointDiscoveryScanner:
    """Discovers API endpoints and their HTTP methods from JS bundles.

    Two-phase discovery:
    Phase 1 (static): Extract endpoints from JS content using regex patterns
    Phase 2 (active): Probe discovered API base URLs with common paths
    """

    _METHOD_MAP = {
        "get": EndpointMethod.GET,
        "post": EndpointMethod.POST,
        "put": EndpointMethod.PUT,
        "patch": EndpointMethod.PATCH,
        "delete": EndpointMethod.DELETE,
    }

    # Routes that are purely frontend pages, not API endpoints
    _SKIP_FRONTEND_ROUTES = {
        "/login", "/register", "/signup", "/signin",
        "/pricing", "/privacy", "/terms", "/about",
        "/contact", "/faq", "/help", "/blog",
    }

    async def discover(
        self, js_content: str, html_content: str, base_url: str
    ) -> list[DiscoveredEndpoint]:
        """Discover all API endpoints from page content.

        Args:
            js_content: Concatenated JavaScript bundle content.
            html_content: Raw HTML of the target page.
            base_url: The target URL for resolving relative paths.

        Returns:
            Deduplicated list of discovered endpoints.
        """
        all_content = f"{html_content}\n{js_content}"
        raw_endpoints: dict[str, DiscoveredEndpoint] = {}

        # Phase 1: Static extraction from JS
        self._extract_fetch_endpoints(all_content, base_url, raw_endpoints)
        self._extract_fetch_with_method(all_content, base_url, raw_endpoints)
        self._extract_axios_endpoints(all_content, base_url, raw_endpoints)
        self._extract_xhr_endpoints(all_content, base_url, raw_endpoints)
        self._extract_api_paths(all_content, base_url, raw_endpoints)
        self._extract_supabase_endpoints(all_content, base_url, raw_endpoints)
        self._extract_parameterized_paths(all_content, base_url, raw_endpoints)

        # Phase 2: Discover API base URLs and probe them
        api_base_urls = self._discover_api_base_urls(all_content, base_url)
        supabase_urls = self._discover_supabase_urls(all_content)

        logger.info(
            "EndpointDiscovery phase 1: %d static endpoints, "
            "%d API base URLs, %d Supabase URLs",
            len(raw_endpoints),
            len(api_base_urls),
            len(supabase_urls),
        )

        await self._probe_api_base_urls(api_base_urls, raw_endpoints)
        anon_key = self._discover_supabase_anon_key(all_content)
        await self._probe_supabase_urls(
            supabase_urls, raw_endpoints, anon_key
        )

        # Phase 3: Extract app routes that might be API routes
        self._extract_app_routes(all_content, base_url, raw_endpoints)

        # Post-process: detect params, categorize
        endpoints = list(raw_endpoints.values())
        for endpoint in endpoints:
            self._detect_parameters(endpoint)
            self._categorize_endpoint(endpoint)

        # Generate /{id} variants for REST collection endpoints so IDOR and
        # per-param injection have object-level targets to test (e.g.
        # /api/Products -> /api/Products/1).
        for variant in self._build_id_variants(endpoints, raw_endpoints):
            self._categorize_endpoint(variant)
            endpoints.append(variant)

        logger.info(
            "EndpointDiscovery complete: %d unique endpoints from %d bytes of content",
            len(endpoints),
            len(all_content),
        )
        return endpoints[: EndpointDiscoveryConfig.MAX_ENDPOINTS_TO_DISCOVER]

    # --- Phase 1: Static extraction methods ---

    def _extract_fetch_endpoints(
        self,
        content: str,
        base_url: str,
        endpoints: dict[str, DiscoveredEndpoint],
    ) -> None:
        """Extract fetch("url") calls (default GET)."""
        for match in re.finditer(EndpointDiscoveryConfig.FETCH_PATTERN, content):
            url = match.group(1)
            self._add_endpoint(
                endpoints, url, base_url, EndpointMethod.GET, "fetch"
            )

    def _extract_fetch_with_method(
        self,
        content: str,
        base_url: str,
        endpoints: dict[str, DiscoveredEndpoint],
    ) -> None:
        """Extract fetch("url", {method: "POST"}) calls."""
        for match in re.finditer(
            EndpointDiscoveryConfig.FETCH_WITH_METHOD_PATTERN, content
        ):
            url = match.group(1)
            method_str = match.group(2).lower()
            method = self._METHOD_MAP.get(method_str, EndpointMethod.GET)
            self._add_endpoint(
                endpoints, url, base_url, method, "fetch_with_method"
            )

    def _extract_axios_endpoints(
        self,
        content: str,
        base_url: str,
        endpoints: dict[str, DiscoveredEndpoint],
    ) -> None:
        """Extract axios.get/post/put/delete("url") calls."""
        for match in re.finditer(
            EndpointDiscoveryConfig.AXIOS_PATTERN, content
        ):
            method_str = match.group(1).lower()
            url = match.group(2)
            method = self._METHOD_MAP.get(method_str, EndpointMethod.GET)
            self._add_endpoint(
                endpoints, url, base_url, method, "axios"
            )

    def _extract_xhr_endpoints(
        self,
        content: str,
        base_url: str,
        endpoints: dict[str, DiscoveredEndpoint],
    ) -> None:
        """Extract XMLHttpRequest .open("METHOD", "url") calls."""
        for match in re.finditer(EndpointDiscoveryConfig.XHR_PATTERN, content):
            method_str = match.group(1).lower()
            url = match.group(2)
            method = self._METHOD_MAP.get(method_str, EndpointMethod.GET)
            self._add_endpoint(
                endpoints, url, base_url, method, "xhr"
            )

    def _extract_api_paths(
        self,
        content: str,
        base_url: str,
        endpoints: dict[str, DiscoveredEndpoint],
    ) -> None:
        """Extract generic /api/..., /rest/..., /v1/... path literals, including
        interpolated template-literal URLs like `${server}/rest/products/search`."""
        for match in re.finditer(
            EndpointDiscoveryConfig.API_PATH_PATTERN, content
        ):
            url = match.group(1)
            self._add_endpoint(
                endpoints, url, base_url, EndpointMethod.GET, "api_path"
            )
        for match in re.finditer(
            EndpointDiscoveryConfig.TEMPLATE_API_PATH_PATTERN, content
        ):
            url = match.group(1)
            self._add_endpoint(
                endpoints, url, base_url, EndpointMethod.GET, "template_api_path"
            )

    def _extract_supabase_endpoints(
        self,
        content: str,
        base_url: str,
        endpoints: dict[str, DiscoveredEndpoint],
    ) -> None:
        """Extract Supabase .from("table") and .rpc("function") calls."""
        for match in re.finditer(
            EndpointDiscoveryConfig.SUPABASE_FROM_PATTERN, content
        ):
            table = match.group(1)
            rest_url = f"/rest/v1/{table}"
            self._add_endpoint(
                endpoints, rest_url, base_url, EndpointMethod.GET, "supabase_from"
            )

        for match in re.finditer(
            EndpointDiscoveryConfig.SUPABASE_RPC_PATTERN, content
        ):
            func = match.group(1)
            rpc_url = f"/rest/v1/rpc/{func}"
            self._add_endpoint(
                endpoints, rpc_url, base_url, EndpointMethod.POST, "supabase_rpc"
            )

    def _extract_parameterized_paths(
        self,
        content: str,
        base_url: str,
        endpoints: dict[str, DiscoveredEndpoint],
    ) -> None:
        """Extract paths with explicit params like /users/:id or /items/{id}."""
        for pattern in (
            EndpointDiscoveryConfig.PATH_PARAM_COLON_PATTERN,
            EndpointDiscoveryConfig.PATH_PARAM_BRACE_PATTERN,
        ):
            for match in re.finditer(pattern, content):
                url = match.group(1)
                self._add_endpoint(
                    endpoints,
                    url,
                    base_url,
                    EndpointMethod.GET,
                    "parameterized_path",
                )

    # --- Phase 2: Active probing of discovered API servers ---

    def _discover_api_base_urls(
        self, content: str, base_url: str
    ) -> set[str]:
        """Find external API base URLs in JS content."""
        urls: set[str] = set()

        # Pattern: https://api.example.com
        for match in re.finditer(
            EndpointDiscoveryConfig.EXTERNAL_API_URL_PATTERN, content
        ):
            url = match.group(1).rstrip("/")
            if not any(
                domain in url
                for domain in EndpointDiscoveryConfig.SKIP_DOMAINS
            ):
                urls.add(url)

        # Also add the target's own /api/ base
        parsed = urlparse(base_url)
        urls.add(f"{parsed.scheme}://{parsed.netloc}")

        return urls

    def _discover_supabase_urls(self, content: str) -> set[str]:
        """Find Supabase project URLs in JS content."""
        urls: set[str] = set()
        for match in re.finditer(
            EndpointDiscoveryConfig.SUPABASE_URL_PATTERN, content
        ):
            urls.add(match.group(1))

        # Also check for edge functions
        for match in re.finditer(
            EndpointDiscoveryConfig.SUPABASE_EDGE_FUNCTION_PATTERN, content
        ):
            func_name = match.group(1)
            logger.info("Discovered Supabase edge function: %s", func_name)

        return urls

    def _discover_supabase_anon_key(self, content: str) -> str | None:
        """Find the Supabase anon key (JWT) in JS content."""
        match = re.search(
            EndpointDiscoveryConfig.SUPABASE_ANON_KEY_PATTERN, content
        )
        if match:
            key = match.group(1)
            logger.info("Discovered Supabase anon key: %s...", key[:20])
            return key
        return None

    async def _probe_api_base_urls(
        self,
        api_base_urls: set[str],
        endpoints: dict[str, DiscoveredEndpoint],
    ) -> None:
        """Probe discovered API base URLs with common API paths."""
        async with RateLimitedClient(
            max_concurrent=SharedPatterns.DEFAULT_MAX_CONCURRENT,
            delay_seconds=SharedPatterns.DEFAULT_PROBE_DELAY,
            timeout_seconds=DeepScanConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            for base_url in api_base_urls:
                for path in EndpointDiscoveryConfig.COMMON_API_PROBE_PATHS:
                    probe_url = f"{base_url}{path}"
                    try:
                        resp = await client.get(probe_url)
                        if self._is_api_response(resp):
                            key = f"GET:{probe_url}"
                            if key not in endpoints:
                                endpoints[key] = DiscoveredEndpoint(
                                    url=probe_url,
                                    method=EndpointMethod.GET,
                                    source_pattern="api_probe",
                                )
                                logger.info(
                                    "Probed API endpoint: %s → %d",
                                    probe_url,
                                    resp.status_code,
                                )
                    except httpx.HTTPError:
                        continue

    async def _probe_supabase_urls(
        self,
        supabase_urls: set[str],
        endpoints: dict[str, DiscoveredEndpoint],
        anon_key: str | None = None,
    ) -> None:
        """Probe Supabase project URLs for exposed REST API and tables.

        If an anon key is found in the JS bundles, uses it to authenticate
        and retrieve the OpenAPI spec listing all public tables.
        """
        extra_headers: dict[str, str] = {"Accept": "application/json"}
        if anon_key:
            extra_headers["apikey"] = anon_key
            extra_headers["Authorization"] = f"Bearer {anon_key}"

        async with RateLimitedClient(
            max_concurrent=SharedPatterns.DEFAULT_MAX_CONCURRENT,
            delay_seconds=SharedPatterns.DEFAULT_PROBE_DELAY,
            timeout_seconds=DeepScanConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
            extra_headers=extra_headers,
        ) as client:
            for sb_url in supabase_urls:
                for path in EndpointDiscoveryConfig.SUPABASE_PROBE_PATHS:
                    probe_url = f"{sb_url}{path}"
                    try:
                        resp = await client.get(probe_url)
                        if resp.status_code == 200:
                            self._extract_tables_from_openapi(
                                resp.text, sb_url, endpoints
                            )
                    except httpx.HTTPError:
                        continue

    def _extract_tables_from_openapi(
        self,
        openapi_text: str,
        sb_url: str,
        endpoints: dict[str, DiscoveredEndpoint],
    ) -> None:
        """Extract table endpoints from Supabase OpenAPI spec."""
        try:
            import json
            spec = json.loads(openapi_text)
            paths = spec.get("paths", {})

            for path, methods in paths.items():
                full_url = f"{sb_url}/rest/v1{path}"

                for method_str in methods:
                    method = self._METHOD_MAP.get(
                        method_str.lower(), EndpointMethod.GET
                    )
                    key = f"{method.value}:{full_url}"
                    if key not in endpoints:
                        endpoints[key] = DiscoveredEndpoint(
                            url=full_url,
                            method=method,
                            source_pattern="supabase_openapi",
                        )

            logger.info(
                "Extracted %d paths from Supabase OpenAPI spec at %s",
                len(paths),
                sb_url,
            )
        except Exception as e:
            logger.debug("Failed to parse Supabase OpenAPI spec: %s", e)

    # --- Phase 3: App route extraction ---

    def _extract_app_routes(
        self,
        content: str,
        base_url: str,
        endpoints: dict[str, DiscoveredEndpoint],
    ) -> None:
        """Extract app routes that might be API-backed pages.

        Routes like /dashboard/home, /marketplace/deals may have
        corresponding API calls. We add them as potential endpoints
        to probe.
        """
        for match in re.finditer(
            EndpointDiscoveryConfig.ROUTE_PATH_PATTERN, content
        ):
            route = match.group(1)

            # Skip known pure-frontend routes
            if route.lower() in self._SKIP_FRONTEND_ROUTES:
                continue

            # Skip internal framework paths
            if route.startswith(("/_next", "/ROOT", "/node_modules")):
                continue

            # Routes with /dashboard, /api, or resource-like segments are interesting
            if any(
                seg in route.lower()
                for seg in (
                    "/dashboard", "/api", "/marketplace",
                    "/apps", "/deals", "/vector", "/iceberg",
                )
            ):
                self._add_endpoint(
                    endpoints, route, base_url,
                    EndpointMethod.GET, "app_route",
                )

    # --- Helpers ---

    def _add_endpoint(
        self,
        endpoints: dict[str, DiscoveredEndpoint],
        raw_url: str,
        base_url: str,
        method: EndpointMethod,
        source: str,
    ) -> None:
        """Resolve, validate, and add an endpoint to the collection."""
        resolved = self._resolve_url(raw_url, base_url)
        if not resolved:
            return

        if not self._should_include(resolved, base_url):
            return

        key = f"{method.value}:{resolved}"
        if key not in endpoints:
            endpoints[key] = DiscoveredEndpoint(
                url=resolved,
                method=method,
                source_pattern=source,
            )

    def _resolve_url(self, url: str, base_url: str) -> str | None:
        """Resolve a URL relative to the base URL.

        Returns None for template literals or unresolvable paths.
        """
        if "${" in url or "{{" in url or "#{" in url:
            return None

        if url.startswith(("http://", "https://")):
            return url

        if url.startswith("/"):
            return urljoin(base_url, url)

        # Relative API-ish paths (e.g. Angular's "rest/products/search")
        if re.match(r"^(?:api|rest|graphql|v[0-9]+)/", url):
            return urljoin(base_url.rstrip("/") + "/", url)

        return None

    def _should_include(self, url: str, base_url: str) -> bool:
        """Filter out static assets, analytics, and third-party domains."""
        parsed = urlparse(url)
        base_parsed = urlparse(base_url)

        # Skip known third-party domains
        if parsed.hostname and parsed.hostname != base_parsed.hostname:
            if any(
                domain in parsed.hostname
                for domain in EndpointDiscoveryConfig.SKIP_DOMAINS
            ):
                return False

        path = parsed.path.lower()
        if any(
            path.startswith(prefix)
            for prefix in EndpointDiscoveryConfig.SKIP_PATH_PREFIXES
        ):
            return False

        # Skip file extensions that are clearly not API endpoints
        if path.rsplit(".", 1)[-1] in (
            "js", "css", "png", "jpg", "jpeg", "gif", "svg",
            "ico", "woff", "woff2", "ttf", "eot", "map",
        ):
            return False

        return True

    def _is_api_response(self, response: httpx.Response) -> bool:
        """Check if a response looks like an API (not an HTML error page)."""
        if response.status_code >= 400:
            return False

        ct = response.headers.get("content-type", "").lower()
        body = response.text.strip()

        # JSON response = definitely an API
        if "application/json" in ct:
            return True

        # Starts with JSON but content-type is wrong
        if body and body[0] in ("{", "["):
            return True

        return False

    def _build_id_variants(
        self,
        endpoints: list[DiscoveredEndpoint],
        seen: dict[str, DiscoveredEndpoint],
    ) -> list[DiscoveredEndpoint]:
        """Create `/collection/1` object-level endpoints for REST collections.

        A GET endpoint whose last path segment is an alphabetic resource name
        (e.g. `/api/Products`, `/rest/basket`) and that has no path params is a
        collection; probing `/<collection>/1` gives IDOR and injection scanners
        an object-level target with a real ID parameter.
        """
        variants: list[DiscoveredEndpoint] = []
        for ep in endpoints:
            if ep.method != EndpointMethod.GET or ep.has_path_params:
                continue
            parsed = urlparse(ep.url)
            if parsed.query:
                continue
            segments = [s for s in parsed.path.split("/") if s]
            if not segments:
                continue
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", segments[-1]):
                continue
            variant_url = ep.url.rstrip("/") + "/1"
            key = f"GET:{variant_url}"
            if key in seen:
                continue
            seen[key] = None  # reserve so we don't duplicate across variants
            variants.append(
                DiscoveredEndpoint(
                    url=variant_url,
                    method=EndpointMethod.GET,
                    source_pattern="id_variant",
                    has_path_params=True,
                    path_param_names=["id"],
                )
            )
        return variants

    def _detect_parameters(self, endpoint: DiscoveredEndpoint) -> None:
        """Detect path and query parameters in the endpoint URL."""
        parsed = urlparse(endpoint.url)

        # Path params: segments that look like IDs
        segments = [s for s in parsed.path.split("/") if s]
        path_params: list[str] = []
        for i, segment in enumerate(segments):
            # :param or {param} style
            if segment.startswith(":") or (
                segment.startswith("{") and segment.endswith("}")
            ):
                param_name = segment.lstrip(":").strip("{}")
                path_params.append(param_name)
                continue

            # UUID in any path position is almost always an object reference
            if re.fullmatch(IDORConfig.UUID_PATTERN, segment):
                label = segments[i - 1].lower() if i > 0 else "object"
                path_params.append(f"{label}_id")
                continue

            # Segment after a known resource name that looks like an ID
            if i > 0:
                prev = segments[i - 1].lower()
                if prev in IDORConfig.ID_PATH_INDICATORS:
                    if (
                        re.fullmatch(IDORConfig.NUMERIC_ID_PATTERN, segment)
                        or re.fullmatch(IDORConfig.SHORT_HASH_PATTERN, segment)
                    ):
                        path_params.append(f"{prev}_id")

        endpoint.has_path_params = len(path_params) > 0
        endpoint.path_param_names = path_params

        # Query params
        query_params = parse_qs(parsed.query)
        id_query_params = [
            p for p in query_params if p.lower() in IDORConfig.ID_QUERY_PARAMS
        ]
        endpoint.query_param_names = id_query_params

    def _categorize_endpoint(self, endpoint: DiscoveredEndpoint) -> None:
        """Assign a semantic category based on URL patterns."""
        path = urlparse(endpoint.url).path.lower()

        if any(seg in path for seg in ("/auth", "/login", "/signup", "/oauth")):
            endpoint.category = EndpointCategory.AUTH
        elif any(seg in path for seg in ("/admin", "/dashboard/admin")):
            endpoint.category = EndpointCategory.ADMIN
        elif any(seg in path for seg in ("/user", "/profile", "/account", "/me")):
            endpoint.category = EndpointCategory.USER_DATA
        elif any(seg in path for seg in ("/file", "/upload", "/download", "/media")):
            endpoint.category = EndpointCategory.FILE_ACCESS
        elif any(seg in path for seg in ("/payment", "/invoice", "/billing", "/charge")):
            endpoint.category = EndpointCategory.PAYMENT
        elif endpoint.has_id_params:
            endpoint.category = EndpointCategory.RESOURCE_CRUD
        elif any(
            seg in path
            for seg in ("/public", "/health", "/status", "/version", "/ping")
        ):
            endpoint.category = EndpointCategory.PUBLIC
        else:
            endpoint.category = EndpointCategory.UNKNOWN
