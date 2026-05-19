"""Tests for the AuthenticatedCrawler."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from isitsecure.engine.constants import AuthenticatedCrawlerConfig
from isitsecure.engine.enums import EndpointCategory
from isitsecure.engine.models import InterceptedRequest
from isitsecure.engine.scanners.authenticated_crawler import (
    AuthenticatedCrawler,
)


def _make_crawler(**kwargs) -> AuthenticatedCrawler:
    """Create a test AuthenticatedCrawler with sensible defaults."""
    defaults = {
        "base_url": "https://app.example.com",
        "email": "test@example.com",
        "password": "password123",
    }
    defaults.update(kwargs)
    return AuthenticatedCrawler(**defaults)


class TestIsApiCall:
    """Tests for AuthenticatedCrawler._is_api_call."""

    def test_supabase_rest_url(self):
        crawler = _make_crawler()
        assert crawler._is_api_call("https://xyz.supabase.co/rest/v1/profiles?select=id") is True

    def test_api_route(self):
        crawler = _make_crawler()
        assert crawler._is_api_call("https://app.example.com/api/users/123") is True

    def test_functions_v1_route(self):
        crawler = _make_crawler()
        assert crawler._is_api_call("https://xyz.supabase.co/functions/v1/my-function") is True

    def test_rpc_route(self):
        crawler = _make_crawler()
        assert crawler._is_api_call("https://xyz.supabase.co/rpc/get_stats") is True

    def test_trpc_route(self):
        crawler = _make_crawler()
        assert crawler._is_api_call("https://app.example.com/trpc/deals.list") is True

    def test_static_js_file(self):
        crawler = _make_crawler()
        assert crawler._is_api_call("https://app.example.com/static/bundle.js") is False

    def test_static_css_file(self):
        crawler = _make_crawler()
        assert crawler._is_api_call("https://app.example.com/styles/main.css") is False

    def test_static_image(self):
        crawler = _make_crawler()
        assert crawler._is_api_call("https://app.example.com/images/logo.png") is False

    def test_favicon(self):
        crawler = _make_crawler()
        assert crawler._is_api_call("https://app.example.com/favicon.ico") is False

    def test_map_file(self):
        crawler = _make_crawler()
        assert crawler._is_api_call("https://app.example.com/bundle.js.map") is False

    def test_non_api_html_page(self):
        crawler = _make_crawler()
        assert crawler._is_api_call("https://app.example.com/dashboard") is False


class TestExtractIds:
    """Tests for AuthenticatedCrawler._extract_ids."""

    def test_extract_uuids(self):
        crawler = _make_crawler()
        body = json.dumps({"id": "550e8400-e29b-41d4-a716-446655440000", "name": "Test"})
        ids = crawler._extract_ids(body)
        assert "550e8400-e29b-41d4-a716-446655440000" in ids

    def test_extract_numeric_ids(self):
        crawler = _make_crawler()
        body = json.dumps({"id": 12345, "user_id": 67890, "name": "Test"})
        ids = crawler._extract_ids(body)
        assert "12345" in ids
        assert "67890" in ids

    def test_extract_empty_body(self):
        crawler = _make_crawler()
        assert crawler._extract_ids("") == []

    def test_extract_multiple_uuids(self):
        crawler = _make_crawler()
        body = json.dumps([
            {"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
            {"id": "11111111-2222-3333-4444-555555555555"},
        ])
        ids = crawler._extract_ids(body)
        assert "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" in ids
        assert "11111111-2222-3333-4444-555555555555" in ids

    def test_deduplicates_ids(self):
        crawler = _make_crawler()
        body = json.dumps([
            {"id": "550e8400-e29b-41d4-a716-446655440000"},
            {"parent_id": "550e8400-e29b-41d4-a716-446655440000"},
        ])
        ids = crawler._extract_ids(body)
        assert ids.count("550e8400-e29b-41d4-a716-446655440000") == 1

    def test_non_json_body_still_extracts_uuids(self):
        crawler = _make_crawler()
        body = "Resource ID: 550e8400-e29b-41d4-a716-446655440000 created."
        ids = crawler._extract_ids(body)
        assert "550e8400-e29b-41d4-a716-446655440000" in ids


class TestBuildEndpoints:
    """Tests for AuthenticatedCrawler._build_endpoints."""

    def test_builds_from_intercepted_requests(self):
        crawler = _make_crawler()
        crawler._intercepted = [
            InterceptedRequest(
                url="https://xyz.supabase.co/rest/v1/profiles?select=*",
                method="GET",
                response_status=200,
                response_body_preview='[{"id": "abc"}]',
                resource_ids_found=["abc"],
            ),
            InterceptedRequest(
                url="https://app.example.com/api/users/123",
                method="POST",
                response_status=201,
                response_body_preview="{}",
            ),
        ]
        endpoints = crawler._build_endpoints()
        assert len(endpoints) == 2
        assert all(ep.requires_auth is True for ep in endpoints)

    def test_deduplicates_by_method_and_path(self):
        crawler = _make_crawler()
        crawler._intercepted = [
            InterceptedRequest(
                url="https://xyz.supabase.co/rest/v1/profiles?select=*",
                method="GET",
                response_status=200,
            ),
            InterceptedRequest(
                url="https://xyz.supabase.co/rest/v1/profiles?select=id",
                method="GET",
                response_status=200,
            ),
        ]
        endpoints = crawler._build_endpoints()
        assert len(endpoints) == 1

    def test_different_methods_not_deduped(self):
        """GET and POST to same path should both appear."""
        crawler = _make_crawler()
        crawler._intercepted = [
            InterceptedRequest(
                url="https://app.example.com/api/items",
                method="GET",
                response_status=200,
            ),
            InterceptedRequest(
                url="https://app.example.com/api/items",
                method="POST",
                response_status=201,
            ),
        ]
        endpoints = crawler._build_endpoints()
        assert len(endpoints) == 2

    def test_categorizes_user_endpoints(self):
        crawler = _make_crawler()
        crawler._intercepted = [
            InterceptedRequest(
                url="https://app.example.com/api/user/profile",
                method="GET",
                response_status=200,
            ),
        ]
        endpoints = crawler._build_endpoints()
        assert endpoints[0].category == EndpointCategory.USER_DATA

    def test_categorizes_admin_endpoints(self):
        crawler = _make_crawler()
        crawler._intercepted = [
            InterceptedRequest(
                url="https://app.example.com/api/admin/users",
                method="GET",
                response_status=200,
            ),
        ]
        endpoints = crawler._build_endpoints()
        assert endpoints[0].category == EndpointCategory.ADMIN


class TestExtractSupabaseTables:
    """Tests for _extract_supabase_tables."""

    def test_extracts_table_names(self):
        crawler = _make_crawler()
        crawler._intercepted = [
            InterceptedRequest(
                url="https://xyz.supabase.co/rest/v1/profiles?select=*",
                method="GET", response_status=200,
            ),
            InterceptedRequest(
                url="https://xyz.supabase.co/rest/v1/deals?select=id",
                method="GET", response_status=200,
            ),
            InterceptedRequest(
                url="https://xyz.supabase.co/rest/v1/profiles?select=id",
                method="GET", response_status=200,
            ),
        ]
        tables = crawler._extract_supabase_tables()
        assert "profiles" in tables
        assert "deals" in tables
        assert len(tables) == 2  # No duplicates

    def test_skips_rpc(self):
        crawler = _make_crawler()
        crawler._intercepted = [
            InterceptedRequest(
                url="https://xyz.supabase.co/rest/v1/rpc/get_stats",
                method="POST", response_status=200,
            ),
        ]
        tables = crawler._extract_supabase_tables()
        assert "rpc" not in tables


class TestAggregateResourceIds:
    """Tests for _aggregate_resource_ids."""

    def test_groups_ids_by_path(self):
        crawler = _make_crawler()
        crawler._intercepted = [
            InterceptedRequest(
                url="https://app.example.com/api/users/1",
                method="GET", response_status=200,
                resource_ids_found=["uuid-aaa", "uuid-bbb"],
            ),
            InterceptedRequest(
                url="https://app.example.com/api/orders/5",
                method="GET", response_status=200,
                resource_ids_found=["uuid-ccc"],
            ),
        ]
        result = crawler._aggregate_resource_ids()
        assert "uuid-aaa" in result["/api/users/1"]
        assert "uuid-bbb" in result["/api/users/1"]
        assert "uuid-ccc" in result["/api/orders/5"]

    def test_supabase_rest_extracts_table_name(self):
        crawler = _make_crawler()
        crawler._intercepted = [
            InterceptedRequest(
                url="https://xyz.supabase.co/rest/v1/profiles?select=*",
                method="GET", response_status=200,
                resource_ids_found=["uuid-123"],
            ),
        ]
        result = crawler._aggregate_resource_ids()
        assert "profiles" in result
        assert "uuid-123" in result["profiles"]

    def test_deduplicates_ids_per_group(self):
        crawler = _make_crawler()
        crawler._intercepted = [
            InterceptedRequest(
                url="https://app.example.com/api/items",
                method="GET", response_status=200,
                resource_ids_found=["id-1", "id-1", "id-2"],
            ),
        ]
        result = crawler._aggregate_resource_ids()
        assert result["/api/items"].count("id-1") == 1


class TestSameOriginAndNormalize:
    """Tests for URL helpers."""

    def test_same_origin_true(self):
        crawler = _make_crawler()
        assert crawler._is_same_origin("https://app.example.com/dashboard") is True

    def test_same_origin_false_external(self):
        crawler = _make_crawler()
        assert crawler._is_same_origin("https://google.com/search") is False

    def test_same_origin_false_analytics(self):
        crawler = _make_crawler()
        assert crawler._is_same_origin("https://sentry.io/log") is False

    def test_same_origin_false_static_asset(self):
        crawler = _make_crawler()
        assert crawler._is_same_origin("https://app.example.com/bundle.js") is False

    def test_normalize_strips_fragment(self):
        crawler = _make_crawler()
        assert crawler._normalize_url("https://app.example.com/page#section") == "https://app.example.com/page"

    def test_normalize_strips_query(self):
        crawler = _make_crawler()
        assert crawler._normalize_url("https://app.example.com/page?foo=1") == "https://app.example.com/page"


class TestCrawlWithMockPlaywright:
    """Integration-style tests for the full crawl flow with mocked Playwright."""

    @pytest.mark.asyncio
    async def test_crawl_returns_error_when_playwright_unavailable(self):
        crawler = _make_crawler()
        with patch(
            "isitsecure.engine.scanners.authenticated_crawler.async_playwright",
            None,
        ):
            result = await crawler.crawl()

        assert len(result.errors) > 0
        assert AuthenticatedCrawlerConfig.ERROR_PLAYWRIGHT_UNAVAILABLE in result.errors[0]

    @pytest.mark.asyncio
    async def test_login_fills_form_and_submits(self):
        crawler = _make_crawler()

        mock_page = AsyncMock()
        mock_page.url = "https://app.example.com/dashboard"  # Post-login URL

        # query_selector returns an element for the right selectors
        async def mock_qs(selector):
            if "email" in selector or "password" in selector or "submit" in selector:
                el = AsyncMock()
                el.fill = AsyncMock()
                el.click = AsyncMock()
                return el
            return None

        mock_page.query_selector = mock_qs

        result = await crawler._login(mock_page)
        assert result is True

    @pytest.mark.asyncio
    async def test_login_fails_when_still_on_login_page(self):
        crawler = _make_crawler()

        mock_page = AsyncMock()
        mock_page.url = "https://app.example.com/login"  # Still on login

        async def mock_qs(selector):
            el = AsyncMock()
            el.fill = AsyncMock()
            el.click = AsyncMock()
            return el

        mock_page.query_selector = mock_qs

        result = await crawler._login(mock_page)
        assert result is False

    @pytest.mark.asyncio
    async def test_seed_link_queue_includes_common_paths(self):
        crawler = _make_crawler(seed_routes=["/marketplace"])
        crawler._seed_link_queue()

        urls = list(crawler._link_queue)
        url_paths = [u.replace("https://app.example.com", "") for u in urls]
        assert "/dashboard" in url_paths
        assert "/marketplace" in url_paths
        assert "/profile" in url_paths

    @pytest.mark.asyncio
    async def test_token_extraction_from_json(self):
        raw = json.dumps({
            "currentSession": {
                "access_token": "my-jwt-token",
                "refresh_token": "my-refresh",
            }
        })
        from isitsecure.engine.auth.browser_login_helper import (
            extract_token_from_json,
        )
        token = extract_token_from_json(raw)
        assert token == "my-jwt-token"


class TestCategorizeUrl:
    """Tests for _categorize_url using configurable rules."""

    def test_admin_category(self):
        assert AuthenticatedCrawler._categorize_url(
            "https://app.example.com/api/admin/users"
        ) == EndpointCategory.ADMIN

    def test_auth_category(self):
        assert AuthenticatedCrawler._categorize_url(
            "https://app.example.com/api/auth/callback"
        ) == EndpointCategory.AUTH

    def test_user_data_category(self):
        assert AuthenticatedCrawler._categorize_url(
            "https://app.example.com/api/user/profile"
        ) == EndpointCategory.USER_DATA

    def test_file_access_category(self):
        assert AuthenticatedCrawler._categorize_url(
            "https://app.example.com/api/upload/image"
        ) == EndpointCategory.FILE_ACCESS

    def test_payment_category(self):
        assert AuthenticatedCrawler._categorize_url(
            "https://app.example.com/api/payment/checkout"
        ) == EndpointCategory.PAYMENT

    def test_default_crud_category(self):
        assert AuthenticatedCrawler._categorize_url(
            "https://app.example.com/api/deals/123"
        ) == EndpointCategory.RESOURCE_CRUD

    def test_account_is_user_data(self):
        assert AuthenticatedCrawler._categorize_url(
            "https://app.example.com/api/account/settings"
        ) == EndpointCategory.USER_DATA


class TestHasPathIds:
    """Tests for _has_path_ids."""

    def test_uuid_in_path(self):
        crawler = _make_crawler()
        assert crawler._has_path_ids(
            "/marketplace/550e8400-e29b-41d4-a716-446655440000"
        ) is True

    def test_numeric_id_in_path(self):
        crawler = _make_crawler()
        assert crawler._has_path_ids("/users/12345") is True

    def test_no_ids_in_path(self):
        crawler = _make_crawler()
        assert crawler._has_path_ids("/dashboard/settings") is False

    def test_empty_path(self):
        crawler = _make_crawler()
        assert crawler._has_path_ids("/") is False


class TestFilterSupabaseQueries:
    """Tests for _filter_supabase_queries."""

    def test_filters_supabase_rest_requests(self):
        crawler = _make_crawler()
        crawler._intercepted = [
            InterceptedRequest(
                url="https://xyz.supabase.co/rest/v1/profiles?select=*",
                method="GET", response_status=200,
            ),
            InterceptedRequest(
                url="https://app.example.com/api/users",
                method="GET", response_status=200,
            ),
            InterceptedRequest(
                url="https://xyz.supabase.co/rest/v1/deals?select=id",
                method="GET", response_status=200,
            ),
        ]
        result = crawler._filter_supabase_queries()
        assert len(result) == 2
        assert all("/rest/v1/" in r.url for r in result)


class TestIsStaticAsset:
    """Tests for _is_static_asset."""

    def test_js_file(self):
        assert AuthenticatedCrawler._is_static_asset("/bundle.js") is True

    def test_css_file(self):
        assert AuthenticatedCrawler._is_static_asset("/style.css") is True

    def test_webp_image(self):
        assert AuthenticatedCrawler._is_static_asset("/image.webp") is True

    def test_html_not_static(self):
        assert AuthenticatedCrawler._is_static_asset("/page.html") is False

    def test_api_path_not_static(self):
        assert AuthenticatedCrawler._is_static_asset("/api/users") is False


class TestExtractAuthHeaders:
    """Tests for _extract_auth_headers."""

    @pytest.mark.asyncio
    async def test_extracts_auth_from_intercepted_requests(self):
        crawler = _make_crawler()
        crawler._intercepted = [
            InterceptedRequest(
                url="https://xyz.supabase.co/rest/v1/profiles",
                method="GET", response_status=200,
                request_headers={
                    "authorization": "Bearer a-very-long-jwt-token-that-is-real",
                },
            ),
        ]

        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(return_value=None)

        headers = await crawler._extract_auth_headers(mock_page)
        assert "Authorization" in headers
        assert "Bearer" in headers["Authorization"]

    @pytest.mark.asyncio
    async def test_extracts_apikey_from_intercepted_requests(self):
        crawler = _make_crawler()
        crawler._intercepted = [
            InterceptedRequest(
                url="https://xyz.supabase.co/rest/v1/profiles",
                method="GET", response_status=200,
                request_headers={"apikey": "my-anon-key"},
            ),
        ]

        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(return_value=None)

        headers = await crawler._extract_auth_headers(mock_page)
        assert headers["apikey"] == "my-anon-key"

    @pytest.mark.asyncio
    async def test_prefers_browser_storage_token(self):
        crawler = _make_crawler()
        crawler._intercepted = []

        mock_page = AsyncMock()

        async def mock_evaluate(script):
            if "access_token" in script and "localStorage" in script:
                return "storage-token"
            return None

        mock_page.evaluate = mock_evaluate

        headers = await crawler._extract_auth_headers(mock_page)
        assert "Bearer storage-token" in headers.get("Authorization", "")
