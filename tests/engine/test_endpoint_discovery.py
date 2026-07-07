"""Tests for EndpointDiscoveryScanner."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.constants import EndpointDiscoveryConfig
from isitsecure.engine.enums import EndpointCategory, EndpointMethod
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.endpoint_discovery import (
    EndpointDiscoveryScanner,
)

BASE_URL = "https://example.com"


# --- Fixtures ---


@pytest.fixture
def scanner() -> EndpointDiscoveryScanner:
    return EndpointDiscoveryScanner()


# --- Helpers ---


def _run_static_extraction(
    scanner: EndpointDiscoveryScanner,
    content: str,
    base_url: str = BASE_URL,
) -> dict[str, DiscoveredEndpoint]:
    """Run all static extraction methods and return the endpoints dict."""
    endpoints: dict[str, DiscoveredEndpoint] = {}
    scanner._extract_fetch_endpoints(content, base_url, endpoints)
    scanner._extract_fetch_with_method(content, base_url, endpoints)
    scanner._extract_axios_endpoints(content, base_url, endpoints)
    scanner._extract_xhr_endpoints(content, base_url, endpoints)
    scanner._extract_api_paths(content, base_url, endpoints)
    scanner._extract_supabase_endpoints(content, base_url, endpoints)
    scanner._extract_parameterized_paths(content, base_url, endpoints)
    return endpoints


class TestEndpointDiscoveryScanner:
    """Tests for EndpointDiscoveryScanner."""

    # --- Fetch extraction ---

    @pytest.mark.asyncio
    async def test_extract_fetch_endpoints(self, scanner: EndpointDiscoveryScanner):
        """fetch('url') calls should be extracted as GET endpoints."""
        content = '''fetch("/api/users")'''
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_fetch_endpoints(content, BASE_URL, endpoints)

        assert len(endpoints) == 1
        ep = list(endpoints.values())[0]
        assert ep.url == f"{BASE_URL}/api/users"
        assert ep.method == EndpointMethod.GET
        assert ep.source_pattern == "fetch"

    @pytest.mark.asyncio
    async def test_extract_fetch_with_method(self, scanner: EndpointDiscoveryScanner):
        """fetch('url', {method: 'POST'}) should extract url and method."""
        content = '''fetch("/api/orders", {method: "POST"})'''
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_fetch_with_method(content, BASE_URL, endpoints)

        assert len(endpoints) == 1
        ep = list(endpoints.values())[0]
        assert ep.url == f"{BASE_URL}/api/orders"
        assert ep.method == EndpointMethod.POST
        assert ep.source_pattern == "fetch_with_method"

    # --- Axios extraction ---

    @pytest.mark.asyncio
    async def test_extract_axios_get(self, scanner: EndpointDiscoveryScanner):
        """axios.get('url') should be extracted as GET."""
        content = '''axios.get("/api/items")'''
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_axios_endpoints(content, BASE_URL, endpoints)

        assert len(endpoints) == 1
        ep = list(endpoints.values())[0]
        assert ep.url == f"{BASE_URL}/api/items"
        assert ep.method == EndpointMethod.GET

    @pytest.mark.asyncio
    async def test_extract_axios_post(self, scanner: EndpointDiscoveryScanner):
        """axios.post('url') should be extracted as POST."""
        content = '''axios.post("/api/items")'''
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_axios_endpoints(content, BASE_URL, endpoints)

        assert len(endpoints) == 1
        ep = list(endpoints.values())[0]
        assert ep.method == EndpointMethod.POST

    @pytest.mark.asyncio
    async def test_extract_axios_put(self, scanner: EndpointDiscoveryScanner):
        """axios.put('url') should be extracted as PUT."""
        content = '''axios.put("/api/items/1")'''
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_axios_endpoints(content, BASE_URL, endpoints)

        assert len(endpoints) == 1
        ep = list(endpoints.values())[0]
        assert ep.method == EndpointMethod.PUT

    @pytest.mark.asyncio
    async def test_extract_axios_delete(self, scanner: EndpointDiscoveryScanner):
        """axios.delete('url') should be extracted as DELETE."""
        content = '''axios.delete("/api/items/1")'''
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_axios_endpoints(content, BASE_URL, endpoints)

        assert len(endpoints) == 1
        ep = list(endpoints.values())[0]
        assert ep.method == EndpointMethod.DELETE

    # --- XHR extraction ---

    @pytest.mark.asyncio
    async def test_extract_xhr_endpoints(self, scanner: EndpointDiscoveryScanner):
        """XMLHttpRequest .open('METHOD', 'url') should be extracted."""
        content = '''.open("POST", "/api/submit")'''
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_xhr_endpoints(content, BASE_URL, endpoints)

        assert len(endpoints) == 1
        ep = list(endpoints.values())[0]
        assert ep.url == f"{BASE_URL}/api/submit"
        assert ep.method == EndpointMethod.POST

    # --- API path extraction ---

    @pytest.mark.asyncio
    async def test_extract_api_paths(self, scanner: EndpointDiscoveryScanner):
        """Generic /api/... and /v1/... path literals should be found."""
        content = '''const url = "/api/products/list"'''
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_api_paths(content, BASE_URL, endpoints)

        assert len(endpoints) == 1
        ep = list(endpoints.values())[0]
        assert "/api/products/list" in ep.url
        assert ep.method == EndpointMethod.GET

    @pytest.mark.asyncio
    async def test_extract_api_paths_v1(self, scanner: EndpointDiscoveryScanner):
        """/v1/... paths should also be extracted."""
        content = '''const url = "/v1/organizations"'''
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_api_paths(content, BASE_URL, endpoints)

        assert len(endpoints) == 1
        assert "/v1/organizations" in list(endpoints.values())[0].url

    # --- Supabase extraction ---

    @pytest.mark.asyncio
    async def test_extract_supabase_from(self, scanner: EndpointDiscoveryScanner):
        """.from('table') should produce /rest/v1/table endpoints."""
        content = '''.from("profiles")'''
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_supabase_endpoints(content, BASE_URL, endpoints)

        assert len(endpoints) == 1
        ep = list(endpoints.values())[0]
        assert "/rest/v1/profiles" in ep.url
        assert ep.method == EndpointMethod.GET
        assert ep.source_pattern == "supabase_from"

    @pytest.mark.asyncio
    async def test_extract_supabase_rpc(self, scanner: EndpointDiscoveryScanner):
        """.rpc('function') should produce /rest/v1/rpc/function POST endpoints."""
        content = '''.rpc("get_user_stats")'''
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_supabase_endpoints(content, BASE_URL, endpoints)

        assert len(endpoints) == 1
        ep = list(endpoints.values())[0]
        assert "/rest/v1/rpc/get_user_stats" in ep.url
        assert ep.method == EndpointMethod.POST
        assert ep.source_pattern == "supabase_rpc"

    # --- URL resolution ---

    def test_resolve_absolute_url(self, scanner: EndpointDiscoveryScanner):
        """Absolute URLs should be returned as-is."""
        result = scanner._resolve_url("https://api.example.com/data", BASE_URL)
        assert result == "https://api.example.com/data"

    def test_resolve_relative_url(self, scanner: EndpointDiscoveryScanner):
        """Relative URLs starting with / should be resolved against base."""
        result = scanner._resolve_url("/api/users", BASE_URL)
        assert result == f"{BASE_URL}/api/users"

    def test_resolve_template_literal_returns_none(
        self, scanner: EndpointDiscoveryScanner
    ):
        """Template literals with ${...} should return None."""
        assert scanner._resolve_url("/api/users/${userId}", BASE_URL) is None
        assert scanner._resolve_url("/api/users/{{id}}", BASE_URL) is None
        assert scanner._resolve_url("/api/users/#{id}", BASE_URL) is None

    def test_resolve_bare_path_returns_none(
        self, scanner: EndpointDiscoveryScanner
    ):
        """Bare non-API relative paths should return None; API-ish relative
        paths (Angular-style, e.g. "rest/..." / "api/...") are now resolved."""
        assert scanner._resolve_url("something/else", BASE_URL) is None
        resolved = scanner._resolve_url("api/users", BASE_URL)
        assert resolved is not None and resolved.endswith("/api/users")

    # --- Filtering ---

    def test_should_include_same_domain(self, scanner: EndpointDiscoveryScanner):
        """Same-domain API URLs should be included."""
        assert scanner._should_include(f"{BASE_URL}/api/users", BASE_URL) is True

    def test_should_exclude_static_assets(self, scanner: EndpointDiscoveryScanner):
        """URLs with static-asset extensions should be excluded."""
        assert scanner._should_include(f"{BASE_URL}/bundle.js", BASE_URL) is False
        assert scanner._should_include(f"{BASE_URL}/style.css", BASE_URL) is False
        assert scanner._should_include(f"{BASE_URL}/logo.png", BASE_URL) is False
        assert scanner._should_include(f"{BASE_URL}/icon.svg", BASE_URL) is False

    def test_should_exclude_skip_domains(self, scanner: EndpointDiscoveryScanner):
        """Known third-party domains should be excluded."""
        assert (
            scanner._should_include(
                "https://googleapis.com/api/data", BASE_URL
            )
            is False
        )
        assert (
            scanner._should_include(
                "https://sentry.io/api/report", BASE_URL
            )
            is False
        )

    def test_should_exclude_file_extensions(self, scanner: EndpointDiscoveryScanner):
        """Font and image file extensions should be excluded."""
        assert scanner._should_include(f"{BASE_URL}/font.woff2", BASE_URL) is False
        assert scanner._should_include(f"{BASE_URL}/image.jpg", BASE_URL) is False

    def test_should_exclude_skip_path_prefixes(
        self, scanner: EndpointDiscoveryScanner
    ):
        """Paths starting with known skip prefixes should be excluded."""
        assert scanner._should_include(f"{BASE_URL}/assets/logo.svg", BASE_URL) is False
        assert scanner._should_include(f"{BASE_URL}/_next/data/abc", BASE_URL) is False
        assert (
            scanner._should_include(f"{BASE_URL}/static/js/main.js", BASE_URL) is False
        )

    def test_should_include_api_path(self, scanner: EndpointDiscoveryScanner):
        """API paths should be included even on different subdomains."""
        assert (
            scanner._should_include("https://other.example.com/api/data", BASE_URL)
            is True
        )

    # --- Parameter detection ---

    def test_detect_uuid_in_path(self, scanner: EndpointDiscoveryScanner):
        """UUID segments in paths should be detected as path params."""
        ep = DiscoveredEndpoint(
            url=f"{BASE_URL}/users/550e8400-e29b-41d4-a716-446655440000",
            method=EndpointMethod.GET,
        )
        scanner._detect_parameters(ep)

        assert ep.has_path_params is True
        assert any("users_id" in p for p in ep.path_param_names)

    def test_detect_numeric_id_after_resource(
        self, scanner: EndpointDiscoveryScanner
    ):
        """Numeric IDs after known resource names should be detected."""
        ep = DiscoveredEndpoint(
            url=f"{BASE_URL}/users/12345",
            method=EndpointMethod.GET,
        )
        scanner._detect_parameters(ep)

        assert ep.has_path_params is True
        assert "users_id" in ep.path_param_names

    def test_detect_colon_param(self, scanner: EndpointDiscoveryScanner):
        """:param style path params should be detected."""
        ep = DiscoveredEndpoint(
            url=f"{BASE_URL}/users/:userId/posts/:postId",
            method=EndpointMethod.GET,
        )
        scanner._detect_parameters(ep)

        assert ep.has_path_params is True
        assert "userId" in ep.path_param_names
        assert "postId" in ep.path_param_names

    def test_detect_brace_param(self, scanner: EndpointDiscoveryScanner):
        """{param} style path params should be detected."""
        ep = DiscoveredEndpoint(
            url=f"{BASE_URL}/items/{'{item_id}'}",
            method=EndpointMethod.GET,
        )
        scanner._detect_parameters(ep)

        assert ep.has_path_params is True
        assert "item_id" in ep.path_param_names

    def test_detect_query_params(self, scanner: EndpointDiscoveryScanner):
        """ID-like query parameters should be detected."""
        ep = DiscoveredEndpoint(
            url=f"{BASE_URL}/api/data?user_id=123&org_id=456",
            method=EndpointMethod.GET,
        )
        scanner._detect_parameters(ep)

        assert "user_id" in ep.query_param_names
        assert "org_id" in ep.query_param_names

    def test_no_params_detected_for_clean_path(
        self, scanner: EndpointDiscoveryScanner
    ):
        """Paths without ID-like segments should have no params."""
        ep = DiscoveredEndpoint(
            url=f"{BASE_URL}/api/health",
            method=EndpointMethod.GET,
        )
        scanner._detect_parameters(ep)

        assert ep.has_path_params is False
        assert len(ep.path_param_names) == 0
        assert len(ep.query_param_names) == 0

    # --- Categorization ---

    def test_categorize_auth_endpoint(self, scanner: EndpointDiscoveryScanner):
        """Auth endpoints should be categorized as AUTH."""
        ep = DiscoveredEndpoint(url=f"{BASE_URL}/auth/login", method=EndpointMethod.POST)
        scanner._categorize_endpoint(ep)
        assert ep.category == EndpointCategory.AUTH

    def test_categorize_admin_endpoint(self, scanner: EndpointDiscoveryScanner):
        """Admin endpoints should be categorized as ADMIN."""
        ep = DiscoveredEndpoint(url=f"{BASE_URL}/admin/settings", method=EndpointMethod.GET)
        scanner._categorize_endpoint(ep)
        assert ep.category == EndpointCategory.ADMIN

    def test_categorize_user_data(self, scanner: EndpointDiscoveryScanner):
        """User data endpoints should be categorized as USER_DATA."""
        ep = DiscoveredEndpoint(url=f"{BASE_URL}/api/profile", method=EndpointMethod.GET)
        scanner._categorize_endpoint(ep)
        assert ep.category == EndpointCategory.USER_DATA

    def test_categorize_resource_crud(self, scanner: EndpointDiscoveryScanner):
        """Endpoints with ID params should be categorized as RESOURCE_CRUD."""
        ep = DiscoveredEndpoint(
            url=f"{BASE_URL}/api/items/123",
            method=EndpointMethod.GET,
            has_path_params=True,
            path_param_names=["items_id"],
        )
        scanner._categorize_endpoint(ep)
        assert ep.category == EndpointCategory.RESOURCE_CRUD

    def test_categorize_public(self, scanner: EndpointDiscoveryScanner):
        """Health/status endpoints should be categorized as PUBLIC."""
        ep = DiscoveredEndpoint(url=f"{BASE_URL}/health", method=EndpointMethod.GET)
        scanner._categorize_endpoint(ep)
        assert ep.category == EndpointCategory.PUBLIC

    def test_categorize_unknown(self, scanner: EndpointDiscoveryScanner):
        """Unmatched endpoints should be categorized as UNKNOWN."""
        ep = DiscoveredEndpoint(
            url=f"{BASE_URL}/api/widgets", method=EndpointMethod.GET
        )
        scanner._categorize_endpoint(ep)
        assert ep.category == EndpointCategory.UNKNOWN

    def test_categorize_file_access(self, scanner: EndpointDiscoveryScanner):
        """File-related endpoints should be categorized as FILE_ACCESS."""
        ep = DiscoveredEndpoint(url=f"{BASE_URL}/api/upload", method=EndpointMethod.POST)
        scanner._categorize_endpoint(ep)
        assert ep.category == EndpointCategory.FILE_ACCESS

    def test_categorize_payment(self, scanner: EndpointDiscoveryScanner):
        """Payment endpoints should be categorized as PAYMENT."""
        ep = DiscoveredEndpoint(
            url=f"{BASE_URL}/api/billing/charge", method=EndpointMethod.POST
        )
        scanner._categorize_endpoint(ep)
        assert ep.category == EndpointCategory.PAYMENT

    # --- Phase 2: Active probing ---

    @pytest.mark.asyncio
    async def test_discover_api_base_urls(self, scanner: EndpointDiscoveryScanner):
        """Should find external API base URLs in JS content."""
        content = 'const API = "https://api.myservice.com/v1"'
        urls = scanner._discover_api_base_urls(content, BASE_URL)

        assert "https://api.myservice.com" in urls
        # Should also include the target's own base
        assert "https://example.com" in urls

    @pytest.mark.asyncio
    async def test_discover_api_base_urls_skips_analytics(
        self, scanner: EndpointDiscoveryScanner
    ):
        """Analytics domains should not be included."""
        content = 'const url = "https://api.google-analytics.com/track"'
        urls = scanner._discover_api_base_urls(content, BASE_URL)

        assert not any("google-analytics" in u for u in urls)

    @pytest.mark.asyncio
    async def test_discover_supabase_urls(self, scanner: EndpointDiscoveryScanner):
        """Should find Supabase project URLs."""
        content = 'const SUPABASE_URL = "https://abcdef123.supabase.co"'
        urls = scanner._discover_supabase_urls(content)

        assert "https://abcdef123.supabase.co" in urls

    @pytest.mark.asyncio
    async def test_discover_supabase_anon_key(
        self, scanner: EndpointDiscoveryScanner
    ):
        """Should find Supabase anon key (JWT) in JS content."""
        fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSJ9.abcdef1234567890"
        content = f'const ANON_KEY = "{fake_jwt}"'
        key = scanner._discover_supabase_anon_key(content)

        assert key == fake_jwt

    @pytest.mark.asyncio
    async def test_discover_supabase_anon_key_none(
        self, scanner: EndpointDiscoveryScanner
    ):
        """Should return None when no key is found."""
        content = "const x = 42;"
        key = scanner._discover_supabase_anon_key(content)
        assert key is None

    @pytest.mark.asyncio
    async def test_probe_api_base_urls(self, scanner: EndpointDiscoveryScanner):
        """Should probe API base URLs and add endpoints for API-like responses."""
        mock_response = httpx.Response(
            status_code=200,
            headers={"content-type": "application/json"},
            text='{"users": []}',
            request=httpx.Request("GET", "https://example.com/api"),
        )

        with patch("isitsecure.engine.scanners.endpoint_discovery.RateLimitedClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            endpoints: dict[str, DiscoveredEndpoint] = {}
            await scanner._probe_api_base_urls({"https://example.com"}, endpoints)

            assert len(endpoints) > 0
            # At least one probed endpoint should exist
            assert any(ep.source_pattern == "api_probe" for ep in endpoints.values())

    @pytest.mark.asyncio
    async def test_probe_api_base_urls_skips_html(
        self, scanner: EndpointDiscoveryScanner
    ):
        """HTML responses should not be added as API endpoints."""
        mock_response = httpx.Response(
            status_code=200,
            headers={"content-type": "text/html"},
            text="<html><body>Not an API</body></html>",
            request=httpx.Request("GET", "https://example.com/api"),
        )

        with patch("isitsecure.engine.scanners.endpoint_discovery.RateLimitedClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            endpoints: dict[str, DiscoveredEndpoint] = {}
            await scanner._probe_api_base_urls({"https://example.com"}, endpoints)

            assert len(endpoints) == 0

    @pytest.mark.asyncio
    async def test_extract_tables_from_openapi(
        self, scanner: EndpointDiscoveryScanner
    ):
        """Should extract table endpoints from OpenAPI spec JSON."""
        openapi_spec = json.dumps(
            {
                "paths": {
                    "/users": {"get": {}, "post": {}},
                    "/orders": {"get": {}},
                }
            }
        )
        endpoints: dict[str, DiscoveredEndpoint] = {}
        sb_url = "https://abc.supabase.co"

        scanner._extract_tables_from_openapi(openapi_spec, sb_url, endpoints)

        assert len(endpoints) == 3
        urls = [ep.url for ep in endpoints.values()]
        assert f"{sb_url}/rest/v1/users" in urls
        assert f"{sb_url}/rest/v1/orders" in urls

    @pytest.mark.asyncio
    async def test_extract_tables_from_invalid_json(
        self, scanner: EndpointDiscoveryScanner
    ):
        """Invalid JSON should not raise, just log and return."""
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_tables_from_openapi("not json", "https://x.supabase.co", endpoints)
        assert len(endpoints) == 0

    # --- App routes ---

    @pytest.mark.asyncio
    async def test_extract_app_routes(self, scanner: EndpointDiscoveryScanner):
        """Should extract routes with interesting segments like /dashboard."""
        content = '"/dashboard/home"'
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_app_routes(content, BASE_URL, endpoints)

        assert len(endpoints) == 1
        ep = list(endpoints.values())[0]
        assert "/dashboard/home" in ep.url
        assert ep.source_pattern == "app_route"

    @pytest.mark.asyncio
    async def test_skip_frontend_routes(self, scanner: EndpointDiscoveryScanner):
        """Known frontend-only routes should be skipped."""
        content = '"/login"'
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_app_routes(content, BASE_URL, endpoints)

        assert len(endpoints) == 0

    @pytest.mark.asyncio
    async def test_skip_internal_framework_routes(
        self, scanner: EndpointDiscoveryScanner
    ):
        """Internal framework paths like /_next should be skipped."""
        content = '"/_next/data/abc123"'
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_app_routes(content, BASE_URL, endpoints)

        assert len(endpoints) == 0

    # --- Integration ---

    @pytest.mark.asyncio
    async def test_full_discover(self, scanner: EndpointDiscoveryScanner):
        """Full discover should return deduplicated, categorized endpoints."""
        js_content = '''
            fetch("/api/users");
            axios.post("/api/orders");
            .from("profiles");
        '''
        html_content = ""

        # Mock httpx to avoid real network calls
        with patch("isitsecure.engine.scanners.endpoint_discovery.RateLimitedClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(
                side_effect=httpx.HTTPError("mocked")
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            endpoints = await scanner.discover(js_content, html_content, BASE_URL)

        assert len(endpoints) > 0
        # All returned endpoints should have a category assigned
        for ep in endpoints:
            assert ep.category is not None

    @pytest.mark.asyncio
    async def test_empty_content(self, scanner: EndpointDiscoveryScanner):
        """Empty content should return zero endpoints."""
        with patch("isitsecure.engine.scanners.endpoint_discovery.RateLimitedClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.HTTPError("mocked"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            endpoints = await scanner.discover("", "", BASE_URL)

        assert len(endpoints) == 0

    @pytest.mark.asyncio
    async def test_respects_max_endpoints(self, scanner: EndpointDiscoveryScanner):
        """Discover should truncate to MAX_ENDPOINTS_TO_DISCOVER."""
        # Generate a lot of unique fetch calls
        lines = [f'fetch("/api/resource{i}")' for i in range(200)]
        js_content = "\n".join(lines)

        with patch("isitsecure.engine.scanners.endpoint_discovery.RateLimitedClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.HTTPError("mocked"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            endpoints = await scanner.discover(js_content, "", BASE_URL)

        assert len(endpoints) <= EndpointDiscoveryConfig.MAX_ENDPOINTS_TO_DISCOVER

    # --- Deduplication ---

    @pytest.mark.asyncio
    async def test_deduplication(self, scanner: EndpointDiscoveryScanner):
        """Duplicate endpoints (same method + url) should be deduplicated."""
        content = '''
            fetch("/api/users");
            fetch("/api/users");
            fetch("/api/users");
        '''
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_fetch_endpoints(content, BASE_URL, endpoints)

        assert len(endpoints) == 1

    # --- is_api_response helper ---

    def test_is_api_response_json(self, scanner: EndpointDiscoveryScanner):
        """JSON content-type should be recognized as API response."""
        resp = httpx.Response(
            status_code=200,
            headers={"content-type": "application/json"},
            text='{"ok": true}',
            request=httpx.Request("GET", BASE_URL),
        )
        assert scanner._is_api_response(resp) is True

    def test_is_api_response_json_body(self, scanner: EndpointDiscoveryScanner):
        """Body starting with { or [ should be recognized even without JSON content-type."""
        resp = httpx.Response(
            status_code=200,
            headers={"content-type": "text/plain"},
            text='{"data": []}',
            request=httpx.Request("GET", BASE_URL),
        )
        assert scanner._is_api_response(resp) is True

    def test_is_api_response_error(self, scanner: EndpointDiscoveryScanner):
        """4xx/5xx responses should not be considered API responses."""
        resp = httpx.Response(
            status_code=404,
            headers={"content-type": "application/json"},
            text='{"error": "not found"}',
            request=httpx.Request("GET", BASE_URL),
        )
        assert scanner._is_api_response(resp) is False

    def test_is_api_response_html(self, scanner: EndpointDiscoveryScanner):
        """HTML responses should not be considered API responses."""
        resp = httpx.Response(
            status_code=200,
            headers={"content-type": "text/html"},
            text="<html>hello</html>",
            request=httpx.Request("GET", BASE_URL),
        )
        assert scanner._is_api_response(resp) is False

    # --- Parameterized path extraction ---

    @pytest.mark.asyncio
    async def test_extract_parameterized_colon_paths(
        self, scanner: EndpointDiscoveryScanner
    ):
        """Paths with :param notation should be extracted."""
        content = '"/users/:id/posts"'
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_parameterized_paths(content, BASE_URL, endpoints)

        assert len(endpoints) == 1
        ep = list(endpoints.values())[0]
        assert "/users/:id/posts" in ep.url
        assert ep.source_pattern == "parameterized_path"

    @pytest.mark.asyncio
    async def test_extract_parameterized_brace_paths(
        self, scanner: EndpointDiscoveryScanner
    ):
        """Paths with {param} notation should be extracted."""
        content = '"/items/{item_id}/details"'
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._extract_parameterized_paths(content, BASE_URL, endpoints)

        assert len(endpoints) == 1
        ep = list(endpoints.values())[0]
        assert "/items/{item_id}/details" in ep.url

    # --- Multiple sources combined ---

    @pytest.mark.asyncio
    async def test_multiple_sources_combined(
        self, scanner: EndpointDiscoveryScanner
    ):
        """Different extraction methods should all contribute endpoints."""
        content = '''
            fetch("/api/a");
            axios.get("/api/b");
            .open("POST", "/api/c");
            .from("table_d");
        '''
        endpoints = _run_static_extraction(scanner, content)

        urls = [ep.url for ep in endpoints.values()]
        assert any("/api/a" in u for u in urls)
        assert any("/api/b" in u for u in urls)
        assert any("/api/c" in u for u in urls)
        assert any("/rest/v1/table_d" in u for u in urls)

    # --- Supabase probing ---

    @pytest.mark.asyncio
    async def test_probe_supabase_urls(self, scanner: EndpointDiscoveryScanner):
        """Should probe Supabase URLs and extract tables from OpenAPI."""
        openapi_spec = json.dumps({"paths": {"/users": {"get": {}}}})
        mock_response = httpx.Response(
            status_code=200,
            headers={"content-type": "application/json"},
            text=openapi_spec,
            request=httpx.Request("GET", "https://abc.supabase.co/rest/v1/"),
        )

        with patch("isitsecure.engine.scanners.endpoint_discovery.RateLimitedClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            endpoints: dict[str, DiscoveredEndpoint] = {}
            await scanner._probe_supabase_urls(
                {"https://abc.supabase.co"}, endpoints, anon_key="test-key"
            )

            assert len(endpoints) > 0

    @pytest.mark.asyncio
    async def test_probe_supabase_urls_http_error(
        self, scanner: EndpointDiscoveryScanner
    ):
        """HTTP errors during Supabase probing should be handled gracefully."""
        with patch("isitsecure.engine.scanners.endpoint_discovery.RateLimitedClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=httpx.HTTPError("timeout"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            endpoints: dict[str, DiscoveredEndpoint] = {}
            # Should not raise
            await scanner._probe_supabase_urls(
                {"https://abc.supabase.co"}, endpoints
            )
            assert len(endpoints) == 0


# --- OpenAPI / Swagger spec discovery ---


class TestOpenAPISpecParsing:
    """Parsing an OpenAPI/Swagger spec into DiscoveredEndpoints."""

    def test_openapi3_paths_methods_and_params(self, scanner):
        spec = {
            "openapi": "3.0.1",
            "servers": [{"url": ""}],
            "paths": {
                "/users/v1/{username}": {
                    "get": {"parameters": [
                        {"name": "username", "in": "path"}]},
                    "delete": {},
                },
                "/search": {
                    "get": {"parameters": [{"name": "q", "in": "query"}]},
                },
            },
        }
        endpoints: dict[str, DiscoveredEndpoint] = {}
        n = scanner._parse_openapi_spec(
            spec, "http://api.local/openapi.json", endpoints)
        assert n == 3
        by_url = {(e.method.value, e.url): e for e in endpoints.values()}
        get_user = by_url[("GET", "http://api.local/users/v1/{username}")]
        assert get_user.has_path_params
        assert get_user.path_param_names == ["username"]
        assert get_user.source_pattern == "openapi"
        search = by_url[("GET", "http://api.local/search")]
        assert search.query_param_names == ["q"]

    def test_templated_segment_without_declared_param(self, scanner):
        spec = {"openapi": "3.0.0", "servers": [{"url": ""}],
                "paths": {"/books/{id}": {"get": {}}}}
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._parse_openapi_spec(spec, "http://x/openapi.json", endpoints)
        ep = next(iter(endpoints.values()))
        assert ep.has_path_params and ep.path_param_names == ["id"]

    def test_swagger2_host_and_basepath(self, scanner):
        spec = {"swagger": "2.0", "host": "api.example.com",
                "basePath": "/v2", "schemes": ["https"],
                "paths": {"/pets": {"get": {}}}}
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._parse_openapi_spec(spec, "http://ignored/swagger.json", endpoints)
        ep = next(iter(endpoints.values()))
        assert ep.url == "https://api.example.com/v2/pets"

    def test_empty_servers_falls_back_to_spec_origin(self, scanner):
        spec = {"openapi": "3.0.0", "servers": [{"url": ""}],
                "paths": {"/ping": {"get": {}}}}
        endpoints: dict[str, DiscoveredEndpoint] = {}
        scanner._parse_openapi_spec(spec, "http://host:5001/openapi.json", endpoints)
        ep = next(iter(endpoints.values()))
        assert ep.url == "http://host:5001/ping"

    def test_non_json_spec_returns_none(self, scanner):
        assert scanner._try_parse_spec("<html>not json</html>") is None
