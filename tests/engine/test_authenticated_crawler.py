"""Tests for the AuthenticatedCrawler."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from isitsecure.engine.constants import (
    AuthenticatedCrawlerConfig,
    BrowserSignupConfig,
)
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

    def test_same_origin_false_javascript_scheme_matching_netloc(self):
        # netloc matches the base but the scheme is javascript: — must be rejected so a
        # crafted form action can't smuggle a non-HTTP URL past the origin gate.
        crawler = _make_crawler()
        assert (
            crawler._is_same_origin("javascript://app.example.com/alert(1)") is False
        )

    def test_same_origin_false_data_scheme(self):
        crawler = _make_crawler()
        assert crawler._is_same_origin("data://app.example.com/x") is False

    def test_same_origin_true_http_scheme(self):
        # A plain http:// URL on the same host is still a valid origin.
        crawler = _make_crawler()
        assert crawler._is_same_origin("http://app.example.com/dashboard") is True

    def test_normalize_strips_fragment(self):
        crawler = _make_crawler()
        assert crawler._normalize_url("https://app.example.com/page#section") == "https://app.example.com/page"

    def test_normalize_strips_query(self):
        crawler = _make_crawler()
        assert crawler._normalize_url("https://app.example.com/page?foo=1") == "https://app.example.com/page"


class TestDeepCrawlBudgets:
    """The pentest-only ``deep`` opt-in widens the page/network-idle budgets WITHOUT
    touching the scan (default) path — which stays byte-identical."""

    def test_scan_default_budgets_are_the_scan_constants(self):
        # Scan builds the crawler with no ``deep`` kwarg (see engine/agent.py); the budgets
        # it uses must equal the shared scan constants exactly — proof scan is unchanged.
        crawler = _make_crawler()                       # no deep kwarg == the scan path
        assert crawler._deep is False
        assert crawler._max_pages == AuthenticatedCrawlerConfig.MAX_PAGES_TO_VISIT
        assert (crawler._bfs_network_idle_timeout_ms
                == AuthenticatedCrawlerConfig.BFS_NETWORK_IDLE_TIMEOUT_MS)

    def test_explicit_deep_false_matches_scan_defaults(self):
        crawler = _make_crawler(deep=False)
        assert crawler._max_pages == AuthenticatedCrawlerConfig.MAX_PAGES_TO_VISIT
        assert (crawler._bfs_network_idle_timeout_ms
                == AuthenticatedCrawlerConfig.BFS_NETWORK_IDLE_TIMEOUT_MS)

    def test_deep_widens_page_and_network_idle_budgets(self):
        deep = _make_crawler(deep=True)
        assert deep._deep is True
        assert deep._max_pages == AuthenticatedCrawlerConfig.DEEP_MAX_PAGES_TO_VISIT
        assert (deep._bfs_network_idle_timeout_ms
                == AuthenticatedCrawlerConfig.DEEP_BFS_NETWORK_IDLE_TIMEOUT_MS)
        # The deep budgets are strictly larger than the scan defaults (deeper, not equal).
        assert deep._max_pages > AuthenticatedCrawlerConfig.MAX_PAGES_TO_VISIT
        assert (deep._bfs_network_idle_timeout_ms
                > AuthenticatedCrawlerConfig.BFS_NETWORK_IDLE_TIMEOUT_MS)


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


class TestFormInteractionSafeMode:
    """safe_mode gates the blind, un-audited button-clicking (pentest crawl path) but
    still surfaces each form's action target so the write-flow is not thrown away."""

    @pytest.mark.asyncio
    async def test_safe_mode_suppresses_blind_button_clicks(self):
        # In safe_mode no button (icon-only / non-English / "Confirm") is ever clicked:
        # the button-clicking path (query_selector_all + .click) is never reached.
        crawler = _make_crawler(safe_mode=True)
        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(return_value=[])
        await crawler._interact_with_forms(mock_page, "https://app.example.com/x")
        mock_page.query_selector_all.assert_not_called()

    @pytest.mark.asyncio
    async def test_safe_mode_records_form_action_targets(self):
        # gate-through, not blanket-suppress: the form's method + action URL + field names
        # are recorded as a discovered endpoint so the planner can drive the write-flow
        # through the floored http_request — without the crawler submitting anything.
        crawler = _make_crawler(safe_mode=True)
        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(return_value=[
            {"action": "/profile/update", "method": "POST", "fields": ["bio", "name"]},
        ])
        await crawler._interact_with_forms(mock_page, "https://app.example.com/profile")
        ep = crawler._html_endpoints["POST:https://app.example.com/profile/update"]
        assert ep.method.value == "POST"
        assert ep.query_param_names == ["bio", "name"]
        assert ep.requires_auth is True
        assert ep.source_pattern == AuthenticatedCrawlerConfig.SAFE_MODE_FORM_SOURCE_PATTERN
        mock_page.query_selector_all.assert_not_called()   # nothing submitted

    @pytest.mark.asyncio
    async def test_safe_mode_empty_action_targets_current_page(self):
        # A form with no action posts to the current page — recorded at page_url.
        crawler = _make_crawler(safe_mode=True)
        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(return_value=[
            {"action": "", "method": "post", "fields": ["q"]},
        ])
        await crawler._interact_with_forms(mock_page, "https://app.example.com/search")
        assert "POST:https://app.example.com/search" in crawler._html_endpoints

    @pytest.mark.asyncio
    async def test_safe_mode_skips_cross_origin_form_action(self):
        crawler = _make_crawler(safe_mode=True)
        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(return_value=[
            {"action": "https://evil.example/steal", "method": "POST", "fields": ["x"]},
        ])
        await crawler._interact_with_forms(mock_page, "https://app.example.com/profile")
        assert crawler._html_endpoints == {}

    @pytest.mark.asyncio
    async def test_safe_mode_rejects_javascript_scheme_form_action(self):
        # A crafted action="javascript://<base-netloc>/..." matches netloc but is not an
        # HTTP(S) origin — the scheme gate in _is_same_origin must keep it out of the store.
        crawler = _make_crawler(safe_mode=True)
        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(return_value=[
            {"action": "javascript://app.example.com/steal", "method": "POST",
             "fields": ["x"]},
        ])
        await crawler._interact_with_forms(mock_page, "https://app.example.com/profile")
        assert crawler._html_endpoints == {}

    @pytest.mark.asyncio
    async def test_safe_mode_records_http_scheme_form_action(self):
        # The counterpart: a same-host http(s) action IS recorded.
        crawler = _make_crawler(safe_mode=True)
        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(return_value=[
            {"action": "http://app.example.com/api/x", "method": "POST",
             "fields": ["x"]},
        ])
        await crawler._interact_with_forms(mock_page, "https://app.example.com/profile")
        assert "POST:http://app.example.com/api/x" in crawler._html_endpoints

    @pytest.mark.asyncio
    async def test_safe_mode_form_extraction_failure_is_swallowed(self):
        crawler = _make_crawler(safe_mode=True)
        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(side_effect=RuntimeError("evaluate boom"))
        await crawler._interact_with_forms(mock_page, "https://app.example.com/x")
        assert crawler._html_endpoints == {}   # no crash, nothing recorded

    @pytest.mark.asyncio
    async def test_default_mode_still_clicks_buttons(self):
        # Default (scan) behavior is preserved byte-for-byte: buttons are discovered and
        # clicked so form-triggered endpoints are still captured.
        crawler = _make_crawler()   # safe_mode defaults to False
        mock_page = AsyncMock()
        mock_page.evaluate = AsyncMock(
            return_value=[{"index": 0, "text": "Confirm", "tag": "BUTTON"}])
        btn = AsyncMock()
        mock_page.query_selector_all = AsyncMock(return_value=[btn])
        with patch(
            "isitsecure.engine.scanners.authenticated_crawler.asyncio.sleep",
            new=AsyncMock(),
        ):
            await crawler._interact_with_forms(mock_page)
        mock_page.evaluate.assert_called_once()
        btn.click.assert_awaited_once()


class TestSafeModeCrawlSurfacesFormTargets:
    """End-to-end: a safe_mode <form> target must not just land in the internal
    _html_endpoints dict — it must surface through _build_endpoints() into the
    discovered_endpoints that crawl() RETURNS (what the pentest tool folds into
    state.endpoints). This closes the gap the earlier tests left (they asserted only
    the internal dict)."""

    @staticmethod
    def _mock_playwright(mock_page):
        browser = AsyncMock()
        context = AsyncMock()
        browser.new_context = AsyncMock(return_value=context)
        context.new_page = AsyncMock(return_value=mock_page)
        pw = AsyncMock()
        pw.chromium.launch = AsyncMock(return_value=browser)
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=pw)
        cm.__aexit__ = AsyncMock(return_value=None)
        return MagicMock(return_value=cm)

    @pytest.mark.asyncio
    async def test_form_target_surfaces_in_returned_endpoints(self):
        crawler = _make_crawler(safe_mode=True)

        mock_page = AsyncMock()
        mock_page.url = "https://app.example.com/dashboard"
        mock_page.on = MagicMock()  # handler registration is sync (not awaited)
        mock_page.content = AsyncMock(return_value="")

        async def evaluate(script, *args, **kwargs):
            # The form-target extraction queries document.querySelectorAll('form');
            # link discovery queries 'a[href]'. Only the form path yields a target.
            if "'form'" in script:
                return [
                    {"action": "/api/x", "method": "POST", "fields": ["bio"]},
                ]
            return []

        mock_page.evaluate = AsyncMock(side_effect=evaluate)

        with (
            patch(
                "isitsecure.engine.scanners.authenticated_crawler.async_playwright",
                self._mock_playwright(mock_page),
            ),
            patch.object(
                AuthenticatedCrawler, "_login", new=AsyncMock(return_value=True)
            ),
            patch.object(
                AuthenticatedCrawler,
                "_extract_auth_headers",
                new=AsyncMock(return_value={}),
            ),
            patch(
                "isitsecure.engine.scanners.authenticated_crawler.asyncio.sleep",
                new=AsyncMock(),
            ),
        ):
            result = await crawler.crawl()

        form_eps = [
            ep for ep in result.discovered_endpoints
            if ep.url == "https://app.example.com/api/x"
        ]
        assert form_eps, "safe_mode form target must surface in returned endpoints"
        ep = form_eps[0]
        assert ep.method.value == "POST"
        assert (
            ep.source_pattern
            == AuthenticatedCrawlerConfig.SAFE_MODE_FORM_SOURCE_PATTERN
        )
        assert ep.query_param_names == ["bio"]


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


class TestExtractAuthHeadersCookies:
    """#111 — capture session cookies (not just bearer tokens) for HTTP scanners."""

    @pytest.mark.asyncio
    async def test_captures_session_cookies(self):
        crawler = _make_crawler()
        page = MagicMock()
        page.context.cookies = AsyncMock(return_value=[
            {"name": "connect.sid", "value": "s%3Aabc"},
            {"name": "csrf", "value": "xyz"},
        ])
        with patch(
            "isitsecure.engine.scanners.authenticated_crawler.BrowserLoginHelper.extract_token",
            AsyncMock(return_value=None),
        ):
            headers = await crawler._extract_auth_headers(page)
        assert headers.get("Cookie") == "connect.sid=s%3Aabc; csrf=xyz"

    @pytest.mark.asyncio
    async def test_no_cookies_no_header(self):
        crawler = _make_crawler()
        page = MagicMock()
        page.context.cookies = AsyncMock(return_value=[])
        with patch(
            "isitsecure.engine.scanners.authenticated_crawler.BrowserLoginHelper.extract_token",
            AsyncMock(return_value=None),
        ):
            headers = await crawler._extract_auth_headers(page)
        assert "Cookie" not in headers


# ---------------------------------------------------------------------------
# Browser self-registration (signup) — pentest-only path; scan NEVER calls it
# ---------------------------------------------------------------------------


def _field(idx, name="", type="text", **kw):
    """A field-metadata dict shaped like the signup field-enumerator returns."""
    base = {"idx": idx, "name": name, "id": "", "type": type,
            "placeholder": "", "aria": "", "label": "", "required": False}
    base.update(kw)
    return base


class _MockInput:
    def __init__(self, idx, page):
        self.idx = idx
        self.page = page

    async def fill(self, value):
        self.page.filled[self.idx] = value

    async def check(self):
        self.page.checked.add(self.idx)

    async def click(self):
        pass


class _MockSubmit:
    def __init__(self, page):
        self.page = page

    async def click(self):
        self.page.submitted = True
        if self.page.on_submit:
            self.page.on_submit()


class _SignupMockPage:
    """A deterministic mock Playwright page for the signup flow: ``evaluate`` dispatches
    on the marker comment in each JS snippet; ``query_selector`` returns fillable inputs
    (by index) and a submit button; a submit click can fire a caller-supplied side effect
    (modelling the signup XHR the interception captures)."""

    def __init__(self, *, fields=None, has_form=True, captcha=False, page_text="",
                 register_link="", submit_ok=True, on_submit=None, form_by_url=None):
        self._fields = fields or []
        self._has_form = has_form
        self._captcha = captcha
        self._page_text = page_text
        self._register_link = register_link
        self._submit_ok = submit_ok
        self.on_submit = on_submit
        self._form_by_url = form_by_url
        self.url = "about:blank"
        self.filled = {}
        self.checked = set()
        self.navigations = []
        self.submitted = False

    def on(self, *args, **kwargs):          # interception registration is sync
        return None

    async def goto(self, url, **kwargs):
        self.navigations.append(url)
        self.url = url

    async def wait_for_load_state(self, *args, **kwargs):
        return None

    async def close(self):
        return None

    async def evaluate(self, script, *args):
        if "find-register-link" in script:
            return self._register_link
        if "has-signup-form" in script:
            if self._form_by_url is not None:
                return self._form_by_url.get(self.url, False)
            return self._has_form
        if "enum-signup-fields" in script:
            return self._fields
        if "detect-captcha" in script:
            return self._captcha
        if "signup-page-text" in script:
            return self._page_text
        return None

    async def query_selector(self, selector):
        if "signup-idx" in selector:
            return _MockInput(int(selector.split('"')[1]), self)
        if selector in BrowserSignupConfig.SUBMIT_BUTTON_SELECTORS and self._submit_ok:
            return _MockSubmit(self)
        return None


def _no_priv(name):
    """A synthesize stand-in mirroring the API-path exclusion: refuse privilege fields."""
    return None if name.lower() in ("isadmin", "role", "admin") else f"syn-{name}"


class TestBrowserSignupRunFlow:
    """The in-browser signup flow (_run_signup) with a mocked page — no real browser."""

    def _happy_fields(self):
        return [
            _field(0, "email", "email", required=True),
            _field(1, "password", "password", required=True),
            _field(2, "passwordRepeat", "password", required=True),
            _field(3, "username", "text", required=True),
            _field(4, "isAdmin", "checkbox"),          # privilege → must never be filled
        ]

    def _page_that_captures(self, crawler, endpoint="/api/Users", status=201, **kw):
        def on_submit():
            crawler._intercepted.append(InterceptedRequest(
                url=f"https://app.example.com{endpoint}", method="POST",
                response_status=status))
        return _SignupMockPage(on_submit=on_submit, **kw)

    @pytest.mark.asyncio
    async def test_happy_path_captures_endpoint_and_credentials(self):
        crawler = _make_crawler()
        page = self._page_that_captures(crawler, fields=self._happy_fields())
        result = await crawler._run_signup(
            page, "agent@x.com", "pw123", "agent_1", _no_priv,
            register_url="https://app.example.com/register")
        assert result.success is True
        assert result.signup_endpoint == "/api/Users"
        assert result.status_code == 201
        assert result.email == "agent@x.com" and result.password == "pw123"  # noqa: S105
        assert result.username == "agent_1"
        # Field-fill: email, BOTH passwords, and username picked correctly.
        assert page.filled[0] == "agent@x.com"
        assert page.filled[1] == "pw123" and page.filled[2] == "pw123"
        assert page.filled[3] == "agent_1"
        # Privilege field is NEVER filled or checked.
        assert 4 not in page.filled and 4 not in page.checked
        assert page.submitted is True

    @pytest.mark.asyncio
    async def test_prefers_signup_shaped_post_over_arbitrary_last_call(self):
        # Two POSTs captured: a non-signup tracking call fired LAST and the real signup
        # call. The signup-shaped path (/api/Users) must be the one reported.
        crawler = _make_crawler()

        def on_submit():
            crawler._intercepted.append(InterceptedRequest(
                url="https://app.example.com/api/Users", method="POST",
                response_status=201))
            crawler._intercepted.append(InterceptedRequest(
                url="https://app.example.com/api/track", method="POST",
                response_status=200))

        page = _SignupMockPage(fields=self._happy_fields(), on_submit=on_submit)
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "u", _no_priv,
            register_url="https://app.example.com/register")
        assert result.success and result.signup_endpoint == "/api/Users"

    @pytest.mark.asyncio
    async def test_non_2xx_signup_call_is_not_success(self):
        crawler = _make_crawler()
        page = self._page_that_captures(
            crawler, endpoint="/api/Users", status=500,
            fields=self._happy_fields())
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "u", _no_priv,
            register_url="https://app.example.com/register")
        assert result.success is False
        assert result.signup_endpoint == "/api/Users" and result.status_code == 500
        assert "returned 500" in result.error

    @pytest.mark.asyncio
    async def test_no_signup_xhr_captured_is_honest_failure(self):
        crawler = _make_crawler()
        page = _SignupMockPage(fields=self._happy_fields(), on_submit=None)
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "u", _no_priv,
            register_url="https://app.example.com/register")
        assert result.success is False
        assert result.error == BrowserSignupConfig.ERROR_NO_SIGNUP_XHR

    @pytest.mark.asyncio
    async def test_captcha_wall_is_reported_and_form_not_submitted(self):
        crawler = _make_crawler()
        page = _SignupMockPage(fields=self._happy_fields(), captcha=True)
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "u", _no_priv,
            register_url="https://app.example.com/register")
        assert result.success is False
        assert "CAPTCHA" in result.blocked_reason
        assert page.submitted is False           # never attempts to defeat the wall
        assert page.filled == {}                 # never even fills

    @pytest.mark.asyncio
    async def test_email_verification_wall_reported(self):
        crawler = _make_crawler()
        page = _SignupMockPage(fields=self._happy_fields(),
                               page_text="Please verify your email to continue")
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "u", _no_priv,
            register_url="https://app.example.com/register")
        assert result.blocked_reason == BrowserSignupConfig.BLOCKED_EMAIL_VERIFY
        assert page.submitted is False

    @pytest.mark.asyncio
    async def test_sms_verification_wall_reported(self):
        crawler = _make_crawler()
        page = _SignupMockPage(fields=self._happy_fields(),
                               page_text="Enter the verification code we sent by SMS")
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "u", _no_priv,
            register_url="https://app.example.com/register")
        assert result.blocked_reason == BrowserSignupConfig.BLOCKED_SMS_VERIFY

    @pytest.mark.asyncio
    async def test_no_register_page_found_is_failure(self):
        crawler = _make_crawler()
        page = _SignupMockPage(register_link="", form_by_url={})
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "u", _no_priv, register_url=None)
        assert result.success is False
        assert result.error == BrowserSignupConfig.ERROR_NO_REGISTER_PAGE

    @pytest.mark.asyncio
    async def test_missing_password_field_is_fields_not_found(self):
        crawler = _make_crawler()
        page = _SignupMockPage(fields=[_field(0, "email", "email")])
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "u", _no_priv,
            register_url="https://app.example.com/register")
        assert result.success is False
        assert result.error == BrowserSignupConfig.ERROR_FIELDS_NOT_FOUND

    @pytest.mark.asyncio
    async def test_submit_button_missing_is_submit_failed(self):
        crawler = _make_crawler()
        page = _SignupMockPage(
            fields=[_field(0, "email", "email"), _field(1, "password", "password")],
            submit_ok=False)
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "u", _no_priv,
            register_url="https://app.example.com/register")
        assert result.success is False
        assert result.error == BrowserSignupConfig.ERROR_SUBMIT_FAILED


class TestBrowserSignupPageDiscovery:
    """Finding the register page: link discovery, then common-route fallback."""

    @pytest.mark.asyncio
    async def test_follows_register_link(self):
        crawler = _make_crawler()
        page = _SignupMockPage(
            register_link="/register",
            form_by_url={"https://app.example.com/register": True})
        assert await crawler._goto_register_page(page, None) is True
        assert "https://app.example.com/register" in page.navigations

    @pytest.mark.asyncio
    async def test_falls_back_to_common_route(self):
        crawler = _make_crawler()
        page = _SignupMockPage(
            register_link="",
            form_by_url={"https://app.example.com/#/register": True})
        assert await crawler._goto_register_page(page, None) is True
        assert any("/#/register" in nav for nav in page.navigations)

    @pytest.mark.asyncio
    async def test_explicit_register_url_used_first(self):
        crawler = _make_crawler()
        page = _SignupMockPage(
            form_by_url={"https://app.example.com/join": True})
        assert await crawler._goto_register_page(
            page, "https://app.example.com/join") is True
        assert page.navigations[0] == "https://app.example.com/join"

    @pytest.mark.asyncio
    async def test_navigation_exception_is_swallowed(self):
        crawler = _make_crawler()
        page = _SignupMockPage(form_by_url={})

        async def boom(url, **kwargs):
            raise RuntimeError("nav failed")

        page.goto = boom
        assert await crawler._goto_register_page(page, None) is False


class TestBrowserSignupFieldFilling:
    """Field classification + the privilege exclusion, exercised directly."""

    @pytest.mark.asyncio
    async def test_consent_checkbox_is_checked(self):
        crawler = _make_crawler()
        page = _SignupMockPage(fields=[
            _field(0, "email", "email"),
            _field(1, "password", "password"),
            _field(2, "acceptTerms", "checkbox"),
        ])
        def synth(name):
            return True if "accept" in name.lower() else "x"

        assert await crawler._fill_signup_form(page, "a@x", "pw", "u", synth) is True
        assert 2 in page.checked

    @pytest.mark.asyncio
    async def test_other_text_field_synthesized(self):
        crawler = _make_crawler()
        page = _SignupMockPage(fields=[
            _field(0, "email", "email"),
            _field(1, "password", "password"),
            _field(2, "firstName", "text"),
        ])
        assert await crawler._fill_signup_form(page, "a@x", "pw", "u", _no_priv) is True
        assert page.filled[2] == "syn-firstName"

    @pytest.mark.asyncio
    async def test_privilege_field_is_never_filled(self):
        crawler = _make_crawler()
        page = _SignupMockPage(fields=[
            _field(0, "email", "email"),
            _field(1, "password", "password"),
            _field(2, "isAdmin", "text"),          # privilege as a plain text input
            _field(3, "role", "checkbox"),         # privilege as a checkbox
        ])
        assert await crawler._fill_signup_form(page, "a@x", "pw", "u", _no_priv) is True
        assert 2 not in page.filled and 3 not in page.checked

    @pytest.mark.asyncio
    async def test_captcha_input_field_is_skipped(self):
        crawler = _make_crawler()
        page = _SignupMockPage(fields=[
            _field(0, "email", "email"),
            _field(1, "password", "password"),
            _field(2, "g-recaptcha-response", "text"),
        ])
        assert await crawler._fill_signup_form(page, "a@x", "pw", "u", _no_priv) is True
        assert 2 not in page.filled

    @pytest.mark.asyncio
    async def test_username_field_by_label(self):
        crawler = _make_crawler()
        page = _SignupMockPage(fields=[
            _field(0, "", "email"),
            _field(1, "", "password"),
            _field(2, "", "text", label="Choose a username"),
        ])
        assert await crawler._fill_signup_form(page, "a@x", "pw", "handle9", _no_priv)
        assert page.filled[2] == "handle9"

    @pytest.mark.asyncio
    async def test_field_enumeration_failure_is_false(self):
        crawler = _make_crawler()
        page = _SignupMockPage()

        async def boom(script, *args):
            raise RuntimeError("evaluate boom")

        page.evaluate = boom
        assert await crawler._fill_signup_form(page, "a@x", "pw", "u", _no_priv) is False


class TestBrowserSignupWrapper:
    """The public signup() wrapper: playwright lifecycle, unavailability, crashes."""

    @staticmethod
    def _mock_pw(page):
        browser = AsyncMock()
        context = AsyncMock()
        browser.new_context = AsyncMock(return_value=context)
        context.new_page = AsyncMock(return_value=page)
        browser.close = AsyncMock()
        pw = AsyncMock()
        pw.chromium.launch = AsyncMock(return_value=browser)
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=pw)
        cm.__aexit__ = AsyncMock(return_value=None)
        return MagicMock(return_value=cm)

    @pytest.mark.asyncio
    async def test_signup_returns_unavailable_when_playwright_missing(self):
        crawler = _make_crawler(email="agent@x.com", password="pw")  # noqa: S106
        with patch(
            "isitsecure.engine.scanners.authenticated_crawler.async_playwright", None,
        ):
            result = await crawler.signup(username="agent_1")
        assert result.success is False
        assert result.error == AuthenticatedCrawlerConfig.ERROR_PLAYWRIGHT_UNAVAILABLE
        # email/password default to the crawler's constructor credentials.
        assert result.email == "agent@x.com" and result.password == "pw"  # noqa: S105
        assert result.username == "agent_1"

    @pytest.mark.asyncio
    async def test_signup_end_to_end_through_wrapper(self):
        crawler = _make_crawler()

        def on_submit():
            crawler._intercepted.append(InterceptedRequest(
                url="https://app.example.com/api/Users", method="POST",
                response_status=201))

        page = _SignupMockPage(fields=[
            _field(0, "email", "email"),
            _field(1, "password", "password"),
            _field(2, "username", "text"),
        ], on_submit=on_submit)
        with patch(
            "isitsecure.engine.scanners.authenticated_crawler.async_playwright",
            self._mock_pw(page),
        ):
            result = await crawler.signup(
                username="agent_1", email="a@x.com", password="pw",  # noqa: S106
                register_url="https://app.example.com/register")
        assert result.success is True and result.signup_endpoint == "/api/Users"

    @pytest.mark.asyncio
    async def test_signup_browser_crash_is_a_result_not_raise(self):
        crawler = _make_crawler()
        pw = AsyncMock()
        pw.chromium.launch = AsyncMock(side_effect=RuntimeError("chromium boom"))
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=pw)
        cm.__aexit__ = AsyncMock(return_value=None)
        with patch(
            "isitsecure.engine.scanners.authenticated_crawler.async_playwright",
            MagicMock(return_value=cm),
        ):
            result = await crawler.signup(username="agent_1")
        assert result.success is False and "chromium boom" in result.error


class TestScanNeverCallsSignup:
    """Scan-safety: the scan/crawl path must NEVER invoke the pentest-only signup()."""

    @staticmethod
    def _mock_playwright(mock_page):
        browser = AsyncMock()
        context = AsyncMock()
        browser.new_context = AsyncMock(return_value=context)
        context.new_page = AsyncMock(return_value=mock_page)
        pw = AsyncMock()
        pw.chromium.launch = AsyncMock(return_value=browser)
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=pw)
        cm.__aexit__ = AsyncMock(return_value=None)
        return MagicMock(return_value=cm)

    @pytest.mark.asyncio
    async def test_crawl_does_not_invoke_signup(self):
        crawler = _make_crawler()
        mock_page = AsyncMock()
        mock_page.url = "https://app.example.com/dashboard"
        mock_page.on = MagicMock()
        mock_page.content = AsyncMock(return_value="")
        mock_page.evaluate = AsyncMock(return_value=[])

        signup_spy = AsyncMock()
        with (
            patch(
                "isitsecure.engine.scanners.authenticated_crawler.async_playwright",
                self._mock_playwright(mock_page),
            ),
            patch.object(AuthenticatedCrawler, "_login", new=AsyncMock(return_value=True)),
            patch.object(AuthenticatedCrawler, "_extract_auth_headers",
                         new=AsyncMock(return_value={})),
            patch.object(AuthenticatedCrawler, "signup", new=signup_spy),
            patch(
                "isitsecure.engine.scanners.authenticated_crawler.asyncio.sleep",
                new=AsyncMock(),
            ),
        ):
            await crawler.crawl()
        signup_spy.assert_not_called()
