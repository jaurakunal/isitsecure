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
        self.key_presses = []
        self.keyboard = _MockKeyboard(self)

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


# ---------------------------------------------------------------------------
# LLM-driven form comprehension: perceive → understand → execute → adapt
# ---------------------------------------------------------------------------

from isitsecure.engine.models import (  # noqa: E402
    FormField,
    FormFillAction,
    FormFillPlan,
    FormPerception,
)

_P0 = '[data-isitsecure-perceive-idx="0"]'
_P1 = '[data-isitsecure-perceive-idx="1"]'
_P2 = '[data-isitsecure-perceive-idx="2"]'
_P3 = '[data-isitsecure-perceive-idx="3"]'


def _pfield(locator, **kw):
    """A perceived-field dict shaped like the perception JS returns (now incl. the canonical
    ``control_kind`` and the lazy-overlay ``overlay`` flag)."""
    base = {"locator": locator, "tag": "input", "type": "text", "name": "", "id": "",
            "label": "", "placeholder": "", "aria": "", "required": False, "value": "",
            "options": [], "control_kind": "other", "overlay": False}
    base.update(kw)
    return base


class _MockKeyboard:
    def __init__(self, page):
        self.page = page

    async def press(self, key):
        self.page.key_presses.append(key)


class _PerceiveElement:
    def __init__(self, page, key, *, opens=None, intercept=False):
        self.page = page
        self.key = key
        # The overlay ``opens`` when THIS element is clicked (an inner trigger opens its base
        # widget, so it may differ from the click-record ``key``).
        self._opens = opens if opens is not None else key
        # A pointer-intercepted element box: a plain (non-force) click raises, mirroring
        # Playwright's "… subtree intercepts pointer events".
        self._intercept = intercept

    async def fill(self, value):
        self.page.filled[self.key] = value

    async def check(self):
        self.page.checked.add(self.key)

    async def uncheck(self):
        self.page.checked.discard(self.key)
        self.page.unchecked.add(self.key)

    async def is_visible(self):
        return True

    async def click(self, force=False):
        if self._intercept and not force:
            raise RuntimeError("element is not clickable: subtree intercepts pointer events")
        self.page.clicks.append(self.key)
        if force:
            self.page.force_clicks.append(self.key)
        # Clicking an overlay trigger "opens" it, exposing its options to a subsequent
        # read-overlay-options evaluate (models the lazy CDK/portal render).
        if self._opens in self.page._overlay_map:
            self.page._open_options = list(self.page._overlay_map[self._opens])


class _PerceiveMockPage:
    """A mock Playwright page for the LLM signup path: ``evaluate`` dispatches on the JS
    marker; ``screenshot`` returns bytes; ``query_selector``/``select_option`` drive the
    executor. ``on_submit(attempt)`` models the signup XHR the interception would capture."""

    def __init__(self, *, fields=None, submit=True, screenshot=b"PNGBYTES",
                 has_form=True, on_submit=None, page_text="", captcha=False,
                 perceive_error=False, screenshot_error=False, form_gone_after_submit=False,
                 custom_options=None, select_label_raises=False, overlay_map=None,
                 choose_match=True, read_overlay_raises=False, missing_triggers=None,
                 widget_triggers=None, intercept_plain=None):
        self._fields = fields if fields is not None else []
        self._submit = submit
        self._screenshot = screenshot
        self._has_form = has_form
        self.on_submit = on_submit
        self._page_text = page_text
        self._captcha = captcha
        self._perceive_error = perceive_error
        self._screenshot_error = screenshot_error
        self._form_gone_after_submit = form_gone_after_submit
        self._custom_options = set(custom_options or ())
        self._select_label_raises = select_label_raises
        self._overlay_map = overlay_map or {}
        self._choose_match = choose_match
        self._read_overlay_raises = read_overlay_raises
        self._missing_triggers = set(missing_triggers or ())
        # Base locators whose inner ``.mat-mdc-select-trigger`` descendant exists (clicking it
        # opens the base widget), and base locators whose element box is pointer-intercepted so
        # a plain click raises (force-click still works).
        self._widget_triggers = set(widget_triggers or ())
        self._intercept_plain = set(intercept_plain or ())
        self._open_options = []
        self.url = "https://app.example.com/#/register"
        self.filled = {}
        self.checked = set()
        self.unchecked = set()
        self.clicks = []
        self.selected = []
        self.chosen = []
        self.state_sets = []
        self.key_presses = []
        self.force_clicks = []
        self.navigations = []
        self.submitted = False
        self.submit_count = 0
        self._has_form_calls = 0
        self.keyboard = _MockKeyboard(self)

    def on(self, *a, **k):
        return None

    async def goto(self, url, **k):
        self.navigations.append(url)
        self.url = url

    async def wait_for_load_state(self, *a, **k):
        return None

    async def close(self):
        return None

    async def screenshot(self, *a, **k):
        if self._screenshot_error:
            raise RuntimeError("screenshot boom")
        return self._screenshot

    async def evaluate(self, script, *args):
        if "perceive-form" in script:
            if self._perceive_error:
                raise RuntimeError("perceive boom")
            return {"fields": self._fields, "submit":
                    '[data-isitsecure-perceive-submit="1"]' if self._submit else ""}
        if "read-overlay-options" in script:
            if self._read_overlay_raises:
                raise RuntimeError("read overlay boom")
            return list(self._open_options)
        if "choose-option" in script:
            cfg = args[0]
            self.chosen.append((cfg["locator"], cfg["value"]))
            return self._choose_match
        if "set-control-state" in script:
            cfg = args[0]
            self.state_sets.append((cfg["locator"], cfg["checked"]))
            return cfg["checked"]
        if "find-register-link" in script:
            return ""
        if "has-signup-form" in script:
            if self.submitted and self._form_gone_after_submit:
                return False
            return self._has_form
        if "detect-captcha" in script:
            return self._captcha
        if "signup-page-text" in script:
            return self._page_text
        return None

    async def select_option(self, locator, **kwargs):
        if "label" in kwargs and self._select_label_raises:
            raise RuntimeError("no such label")
        self.selected.append((locator, kwargs))

    async def query_selector(self, selector):
        if selector in self._missing_triggers:
            return None
        # A compound inner-trigger selector "<locator> <trigger-sel>": present only when the
        # base widget is configured to expose a real trigger; clicking it opens the base.
        for trig in BrowserSignupConfig.OVERLAY_TRIGGER_SELECTORS:
            suffix = f" {trig}"
            if selector.endswith(suffix):
                base = selector[: -len(suffix)]
                if base in self._widget_triggers:
                    return _PerceiveElement(self, base, opens=base)
                return None
        if "perceive-idx" in selector:
            return _PerceiveElement(
                self, selector, intercept=selector in self._intercept_plain
            )
        if self._submit and selector in BrowserSignupConfig.SUBMIT_BUTTON_SELECTORS:
            return _SubmitElement(self)
        if selector in self._custom_options:
            return _PerceiveElement(self, selector)
        return None


class _SubmitElement:
    def __init__(self, page):
        self.page = page

    async def click(self):
        self.page.submitted = True
        self.page.submit_count += 1
        if self.page.on_submit:
            self.page.on_submit(self.page.submit_count)


class TestPerceiveForm:
    async def test_perceives_fields_options_screenshot_and_submit(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(fields=[
            _pfield(_P0, tag="input", type="email", name="email", label="Email",
                    required=True),
            _pfield(_P1, tag="input", type="password", name="password", required=True),
            _pfield(_P2, tag="mat-select", type="mat-select", name="securityQuestion",
                    label="Security Question", required=True,
                    options=["Favorite color?", "First pet?"]),
        ])
        perception = await crawler._perceive_form(page)
        assert isinstance(perception, FormPerception)
        assert [f.locator for f in perception.fields] == [_P0, _P1, _P2]
        dropdown = perception.fields[2]
        assert dropdown.tag == "mat-select"
        assert dropdown.options == ["Favorite color?", "First pet?"]
        assert perception.submit_locator == '[data-isitsecure-perceive-submit="1"]'
        # screenshot is base64 of b"PNGBYTES"
        import base64 as _b64
        assert perception.screenshot_b64 == _b64.b64encode(b"PNGBYTES").decode()
        assert perception.page_url == "https://app.example.com/#/register"

    async def test_perceive_evaluate_error_is_empty(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(perceive_error=True)
        perception = await crawler._perceive_form(page)
        assert perception.fields == []

    async def test_perceive_drops_field_without_locator(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(fields=[_pfield(""), _pfield(_P0, name="email")])
        perception = await crawler._perceive_form(page)
        assert [f.locator for f in perception.fields] == [_P0]

    async def test_screenshot_failure_yields_empty_string(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(fields=[_pfield(_P0)], screenshot_error=True)
        perception = await crawler._perceive_form(page)
        assert perception.screenshot_b64 == ""

    async def test_oversized_screenshot_dropped(self):
        crawler = _make_crawler()
        big = b"x" * (BrowserSignupConfig.SCREENSHOT_MAX_BYTES + 1)
        page = _PerceiveMockPage(fields=[_pfield(_P0)], screenshot=big)
        perception = await crawler._perceive_form(page)
        assert perception.screenshot_b64 == ""

    async def test_empty_screenshot_yields_empty_string(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(fields=[_pfield(_P0)], screenshot=b"")
        perception = await crawler._perceive_form(page)
        assert perception.screenshot_b64 == ""


def _idx(i):
    return f'[data-isitsecure-perceive-idx="{i}"]'


class TestPerceiveTaxonomy:
    """Perception carries the canonical ``control_kind`` for every kind and OPENS lazy overlay
    dropdowns (mat-select / listbox) to enumerate options that render only once opened."""

    async def test_classifies_every_kind_and_enumerates_overlays(self):
        crawler = _make_crawler()
        # The full mix the JS classifier produces (JS is mocked; the dicts carry control_kind).
        fields = [
            _pfield(_idx(0), tag="select", type="select", control_kind="single_select",
                    options=["US", "CA"]),
            _pfield(_idx(1), tag="select", type="select", control_kind="multi_select",
                    options=["A", "B"]),                                   # <select multiple>
            _pfield(_idx(2), tag="mat-select", type="mat-select",
                    control_kind="single_select", overlay=True, options=[]),  # lazy overlay
            _pfield(_idx(3), tag="input", type="radio", control_kind="radio_group",
                    name="gender", options=["Male", "Female"]),           # native radio group
            _pfield(_idx(4), tag="mat-radio-group", type="mat-radio-group",
                    control_kind="radio_group", options=["Free", "Pro"]),
            _pfield(_idx(5), tag="input", type="checkbox", control_kind="checkbox",
                    name="terms"),                                        # native checkbox
            _pfield(_idx(6), tag="mat-slide-toggle", type="mat-slide-toggle",
                    control_kind="toggle", name="notify"),
            _pfield(_idx(7), tag="div", type="div", control_kind="multi_select",
                    overlay=True, options=[]),  # [role=listbox][aria-multiselectable]
        ]
        page = _PerceiveMockPage(
            fields=fields, overlay_map={_idx(2): ["Q1", "Q2", "Q3"], _idx(7): ["X", "Y"]},
        )
        perception = await crawler._perceive_form(page)
        kinds = {f.locator: f.control_kind for f in perception.fields}
        assert kinds == {
            _idx(0): "single_select", _idx(1): "multi_select", _idx(2): "single_select",
            _idx(3): "radio_group", _idx(4): "radio_group", _idx(5): "checkbox",
            _idx(6): "toggle", _idx(7): "multi_select",
        }
        opts = {f.locator: f.options for f in perception.fields}
        assert opts[_idx(0)] == ["US", "CA"]              # native, inline
        assert opts[_idx(3)] == ["Male", "Female"]        # radio group, inline
        assert opts[_idx(2)] == ["Q1", "Q2", "Q3"]        # mat-select, via overlay OPEN
        assert opts[_idx(7)] == ["X", "Y"]                # listbox, via overlay OPEN
        assert page.clicks.count(_idx(2)) == 1 and page.clicks.count(_idx(7)) == 1
        assert page.key_presses == ["Escape", "Escape"]   # each overlay closed after read

    async def test_overlay_read_error_yields_empty_and_still_closes(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(
            fields=[_pfield(_idx(0), tag="mat-select", type="mat-select",
                            control_kind="single_select", overlay=True, options=[])],
            overlay_map={_idx(0): ["x"]}, read_overlay_raises=True,
        )
        perception = await crawler._perceive_form(page)
        assert perception.fields[0].options == []
        assert page.key_presses == ["Escape"]

    async def test_overlay_trigger_absent_yields_empty(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(
            fields=[_pfield(_idx(0), tag="mat-select", type="mat-select",
                            control_kind="single_select", overlay=True, options=[])],
            missing_triggers={_idx(0)},
        )
        perception = await crawler._perceive_form(page)
        assert perception.fields[0].options == []
        assert page.clicks == [] and page.key_presses == []   # never opened

    async def test_overlay_enumeration_is_bounded(self):
        crawler = _make_crawler()
        cap = BrowserSignupConfig.MAX_OVERLAY_ENUMERATIONS
        n = cap + 2
        fields = [_pfield(_idx(i), tag="mat-select", type="mat-select",
                          control_kind="single_select", overlay=True, options=[])
                  for i in range(n)]
        page = _PerceiveMockPage(
            fields=fields, overlay_map={_idx(i): ["opt"] for i in range(n)})
        perception = await crawler._perceive_form(page)
        enumerated = [f for f in perception.fields if f.options]
        assert len(enumerated) == cap                     # bounded — the last 2 stay empty

    async def test_inline_options_skip_overlay_open(self):
        # An overlay-flagged field that already has inline options is NOT re-opened.
        crawler = _make_crawler()
        page = _PerceiveMockPage(
            fields=[_pfield(_idx(0), tag="mat-select", type="mat-select",
                            control_kind="single_select", overlay=True,
                            options=["already", "here"])],
            overlay_map={_idx(0): ["nope"]})
        perception = await crawler._perceive_form(page)
        assert perception.fields[0].options == ["already", "here"]
        assert page.clicks == []


def _synth(name):
    """A synthesize stand-in mirroring the API-path exclusion: refuse privilege fields."""
    return None if name.lower() in ("isadmin", "role", "admin") else f"syn-{name}"


class TestApplyFillPlan:
    async def test_type_select_native_and_check_dispatch(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage()
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="input", type="email", name="email"),
            FormField(locator=_P1, tag="select", name="country",
                      options=["US", "CA"]),
            FormField(locator=_P2, tag="input", type="checkbox", name="terms"),
        ])
        plan = FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="type", value="a@x.com"),
            FormFillAction(locator=_P1, action="select", value="US"),
            FormFillAction(locator=_P2, action="check", value="true"),
        ])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert page.filled[_P0] == "a@x.com"
        assert page.selected == [(_P1, {"label": "US"})]
        assert _P2 in page.checked

    async def test_custom_dropdown_open_then_click_option(self):
        crawler = _make_crawler()
        option_selector = 'mat-option:has-text("Favorite color?")'
        page = _PerceiveMockPage(custom_options={option_selector})
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="mat-select", name="securityQuestion",
                      options=["Favorite color?"]),
        ])
        plan = FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="select", value="Favorite color?"),
        ])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        # the trigger was clicked (opened) and the option element was clicked
        assert _P0 in page.clicks
        assert option_selector in page.clicks

    async def test_native_select_label_falls_back_to_value(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(select_label_raises=True)
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="select", name="country", options=["US"]),
        ])
        plan = FormFillPlan(actions=[FormFillAction(locator=_P0, action="select", value="US")])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert page.selected == [(_P0, {"value": "US"})]

    async def test_executor_strips_privilege_action(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage()
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="input", type="email", name="email"),
            FormField(locator=_P1, tag="input", type="checkbox", name="isAdmin"),
        ])
        plan = FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="type", value="a@x.com"),
            FormFillAction(locator=_P1, action="check", value="true"),   # privilege — stripped
        ])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert page.filled[_P0] == "a@x.com"
        assert _P1 not in page.checked                       # never filled

    async def test_backfills_required_field_the_plan_omitted(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage()
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="input", type="email", name="email"),
            FormField(locator=_P1, tag="input", type="text", name="phone", required=True),
            FormField(locator=_P2, tag="input", type="password", name="password",
                      required=True),                          # password: never backfilled
            FormField(locator=_P3, tag="input", type="checkbox", name="isAdmin",
                      required=True),                          # privilege: never backfilled
        ])
        plan = FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="type", value="a@x.com"),
        ])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert page.filled[_P1] == "syn-phone"                # required + omitted → backfilled
        assert _P2 not in page.filled                         # password left to the LLM
        assert _P3 not in page.checked                        # privilege never set

    async def test_backfill_checkbox_and_select(self):
        crawler = _make_crawler()

        def synth(name):
            return True if name == "terms" else "opt-a"

        page = _PerceiveMockPage()
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="input", type="checkbox", name="terms", required=True),
            FormField(locator=_P1, tag="select", name="plan", required=True,
                      options=["opt-a", "opt-b"]),
        ])
        await crawler._apply_fill_plan(page, FormFillPlan(), perception, synth)
        assert _P0 in page.checked
        assert page.selected == [(_P1, {"label": "opt-a"})]


class TestApplyFillPlanTaxonomy:
    """One driver per canonical kind, dispatched on the perceived field's ``control_kind``."""

    async def test_multi_select_native_passes_whole_list(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage()
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="select", name="tags",
                      control_kind="multi_select", options=["A", "B", "C"])])
        plan = FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="select_multi", values=["A", "C"])])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert page.selected == [(_P0, {"label": ["A", "C"]})]

    async def test_multi_select_native_falls_back_to_value_kwarg(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(select_label_raises=True)
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="select", name="tags",
                      control_kind="multi_select", options=["A"])])
        plan = FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="select_multi", values=["A"])])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert page.selected == [(_P0, {"value": ["A"]})]

    async def test_multi_select_overlay_opens_and_clicks_each(self):
        crawler = _make_crawler()
        sel_music = '[role="option"]:has-text("Music")'
        sel_art = '[role="option"]:has-text("Art")'
        page = _PerceiveMockPage(custom_options={sel_music, sel_art})
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="mat-select", name="interests",
                      control_kind="multi_select", options=["Music", "Art", "Sports"])])
        plan = FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="select_multi", values=["Music", "Art"])])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert _P0 in page.clicks                       # opened
        assert sel_music in page.clicks and sel_art in page.clicks
        assert page.key_presses == ["Escape"]           # closed after

    async def test_multi_select_empty_values_is_noop(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage()
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="select", control_kind="multi_select", options=["A"])])
        plan = FormFillPlan(actions=[FormFillAction(locator=_P0, action="select_multi")])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert page.selected == []

    async def test_radio_group_choose_clicks_matching_option(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage()
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="mat-radio-group", name="plan",
                      control_kind="radio_group", options=["Free", "Pro"])])
        plan = FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="choose", value="Pro")])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert page.chosen == [(_P0, "Pro")]

    async def test_checkbox_mat_uses_set_state(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage()
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="mat-checkbox", name="terms",
                      control_kind="checkbox")])
        plan = FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="check", value="true")])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert page.state_sets == [(_P0, True)]

    async def test_checkbox_native_uncheck(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage()
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="input", type="checkbox", name="news",
                      control_kind="checkbox")])
        plan = FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="uncheck", value="false")])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert _P0 in page.unchecked and _P0 not in page.checked

    async def test_toggle_off_via_set_state(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage()
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="mat-slide-toggle", name="notify",
                      control_kind="toggle")])
        plan = FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="toggle", value="false")])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert page.state_sets == [(_P0, False)]

    async def test_toggle_role_switch_on(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage()
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="div", control_kind="toggle", name="darkmode")])
        plan = FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="toggle", value="true")])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert page.state_sets == [(_P0, True)]

    async def test_privilege_field_never_driven_across_kinds(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage()
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="mat-select", name="role",
                      control_kind="single_select", options=["user", "admin"]),
            FormField(locator=_P1, tag="mat-slide-toggle", name="isAdmin",
                      control_kind="toggle")])
        plan = FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="select", value="admin"),   # role — refused
            FormFillAction(locator=_P1, action="toggle", value="true")])   # isAdmin — refused
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert page.clicks == [] and page.state_sets == []

    async def test_unknown_kind_and_verb_fall_back_to_harmless_text_fill(self):
        # An unclassified control ("other") with an unknown verb resolves, via tag/type/options
        # inference, to a plain text fill — never an unexpected widget interaction.
        crawler = _make_crawler()
        page = _PerceiveMockPage()
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="div", control_kind="other")])
        plan = FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="frobnicate", value="x")])
        await crawler._apply_fill_plan(page, plan, perception, _synth)
        assert page.filled == {_P0: "x"}                  # text fill, no widget driver
        assert page.clicks == [] and page.state_sets == []

    async def test_backfill_radio_and_toggle_and_multiselect(self):
        crawler = _make_crawler()

        def synth(name):
            return {"plan": "Pro", "notify": "true", "tags": "A"}.get(name, f"syn-{name}")

        page = _PerceiveMockPage()
        perception = FormPerception(fields=[
            FormField(locator=_P0, tag="mat-radio-group", name="plan",
                      control_kind="radio_group", required=True, options=["Free", "Pro"]),
            FormField(locator=_P1, tag="mat-slide-toggle", name="notify",
                      control_kind="toggle", required=True),
            FormField(locator=_P2, tag="mat-select", name="tags",
                      control_kind="multi_select", required=True, options=["A", "B"]),
        ])
        await crawler._apply_fill_plan(page, FormFillPlan(), perception, synth)
        assert page.chosen == [(_P0, "Pro")]              # radio_group backfilled
        assert page.state_sets == [(_P1, True)]           # toggle backfilled on
        assert _P2 in page.clicks                         # multi_select overlay opened


class TestLLMSignupFlow:
    def _fields(self):
        return [
            _pfield(_P0, tag="input", type="email", name="email", required=True),
            _pfield(_P1, tag="input", type="password", name="password", required=True),
            _pfield(_P2, tag="input", type="text", name="username", required=True),
        ]

    def _plan(self):
        return FormFillPlan(actions=[
            FormFillAction(locator=_P0, action="type", value="a@x.com"),
            FormFillAction(locator=_P1, action="type", value="pw"),
            FormFillAction(locator=_P2, action="type", value="agent_1"),
        ])

    def _capturing_filler(self, plan):
        record = {}

        async def filler(perception, identity, goal):
            record["perception"] = perception
            record["identity"] = identity
            record["goal"] = goal
            return plan
        return filler, record

    async def test_end_to_end_success(self):
        crawler = _make_crawler()

        def on_submit(attempt):
            crawler._intercepted.append(InterceptedRequest(
                url="https://app.example.com/api/Users", method="POST",
                response_status=201))
        page = _PerceiveMockPage(fields=self._fields(), on_submit=on_submit)
        filler, record = self._capturing_filler(self._plan())
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "agent_1", _synth, None, filler)
        assert result.success and result.signup_endpoint == "/api/Users"
        assert page.filled[_P0] == "a@x.com" and page.filled[_P2] == "agent_1"
        assert record["identity"] == {"email": "a@x.com", "password": "pw",
                                      "username": "agent_1"}
        assert record["goal"] == BrowserSignupConfig.FORM_FILLER_GOAL

    async def test_end_to_end_with_mat_select_overlay(self):
        # Juice-Shop-shaped: a lazy mat-select whose options render only when opened. Perception
        # opens it to enumerate the real options, the LLM picks one, the executor drives the
        # dropdown, and the intercepted POST /api/Users -> 201 proves the account was created.
        crawler = _make_crawler()

        def on_submit(attempt):
            crawler._intercepted.append(InterceptedRequest(
                url="https://app.example.com/api/Users", method="POST", response_status=201))

        fields = [
            _pfield(_P0, tag="input", type="email", name="email",
                    control_kind="text", required=True),
            _pfield(_P1, tag="input", type="password", name="password",
                    control_kind="text", required=True),
            _pfield(_P2, tag="input", type="text", name="username",
                    control_kind="text", required=True),
            _pfield(_P3, tag="mat-select", type="mat-select", name="securityQuestion",
                    control_kind="single_select", overlay=True, options=[], required=True),
        ]
        option_selector = 'mat-option:has-text("First pet?")'
        page = _PerceiveMockPage(fields=fields, on_submit=on_submit,
                                 overlay_map={_P3: ["Favorite color?", "First pet?"]},
                                 custom_options={option_selector})
        captured = {}

        async def filler(perception, identity, goal):
            q = next(f for f in perception.fields if f.locator == _P3)
            captured["options"] = list(q.options)          # the LLM sees REAL options
            return FormFillPlan(actions=[
                FormFillAction(locator=_P0, action="type", value="a@x.com"),
                FormFillAction(locator=_P1, action="type", value="pw"),
                FormFillAction(locator=_P2, action="type", value="agent_1"),
                FormFillAction(locator=_P3, action="select", value="First pet?"),
            ])
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "agent_1", _synth, None, filler)
        assert result.success and result.signup_endpoint == "/api/Users"
        assert captured["options"] == ["Favorite color?", "First pet?"]
        assert option_selector in page.clicks              # the chosen option was clicked

    async def test_adaptive_retry_first_invalid_then_success(self):
        crawler = _make_crawler()

        def on_submit(attempt):
            if attempt >= 2:                                  # only the 2nd submit fires the XHR
                crawler._intercepted.append(InterceptedRequest(
                    url="https://app.example.com/api/Users", method="POST",
                    response_status=201))
        # form stays present after the first (failed) submit so the loop re-perceives
        page = _PerceiveMockPage(fields=self._fields(), on_submit=on_submit)
        filler, _ = self._capturing_filler(self._plan())
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "agent_1", _synth, None, filler)
        assert result.success and page.submit_count == 2

    async def test_gives_up_when_form_gone_after_failed_submit(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(fields=self._fields(), on_submit=None,
                                 form_gone_after_submit=True)
        filler, _ = self._capturing_filler(self._plan())
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "agent_1", _synth, None, filler)
        assert not result.success and page.submit_count == 1   # no retry — form navigated away

    async def test_no_fields_is_honest_failure(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(fields=[])
        filler, _ = self._capturing_filler(self._plan())
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "agent_1", _synth, None, filler)
        assert not result.success
        assert result.error == BrowserSignupConfig.ERROR_FIELDS_NOT_FOUND

    async def test_submit_absent_retries_then_gives_up(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(fields=self._fields(), submit=False)
        filler, _ = self._capturing_filler(self._plan())
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "agent_1", _synth, None, filler)
        assert not result.success
        assert result.error == BrowserSignupConfig.ERROR_SUBMIT_FAILED
        assert page.submit_count == 0

    async def test_form_filler_exception_degrades_to_empty_plan(self):
        crawler = _make_crawler()

        def on_submit(attempt):
            crawler._intercepted.append(InterceptedRequest(
                url="https://app.example.com/api/Users", method="POST",
                response_status=201))

        async def boom(perception, identity, goal):
            raise RuntimeError("filler boom")
        page = _PerceiveMockPage(fields=self._fields(), on_submit=on_submit)
        # An empty plan still backfills required fields and submits; the XHR is captured.
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "agent_1", _synth, None, boom)
        assert result.success

    async def test_wall_is_reported_before_any_fill(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(fields=self._fields(), captcha=True)
        filler, record = self._capturing_filler(self._plan())
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "agent_1", _synth, None, filler)
        assert result.blocked_reason == BrowserSignupConfig.BLOCKED_CAPTCHA
        assert "perception" not in record                     # filler never called

    async def test_no_register_page_fails(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(fields=self._fields(), has_form=False)
        filler, _ = self._capturing_filler(self._plan())
        # _goto_register_page probes routes; has_form=False everywhere -> no register page.
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "agent_1", _synth, None, filler)
        assert result.error == BrowserSignupConfig.ERROR_NO_REGISTER_PAGE

    async def test_no_form_filler_uses_heuristic_fallback(self):
        # form_filler=None -> the legacy heuristic fill still provisions (no regression).
        crawler = _make_crawler()

        def on_submit():                                       # _SignupMockPage calls it argless
            crawler._intercepted.append(InterceptedRequest(
                url="https://app.example.com/api/Users", method="POST",
                response_status=201))
        page = _SignupMockPage(fields=[
            _field(0, "email", "email"),
            _field(1, "password", "password"),
            _field(2, "username", "text"),
        ], on_submit=on_submit)
        result = await crawler._run_signup(
            page, "a@x.com", "pw", "agent_1", _no_priv, None, None)
        assert result.success and result.signup_endpoint == "/api/Users"


# ---------------------------------------------------------------------------
# Real-SPA DOM-interaction robustness: interstitial-overlay dismissal + robust
# custom-widget open (both live-proven on OWASP Juice Shop's register form)
# ---------------------------------------------------------------------------


class _DismissButton:
    """A dismiss control returned by ``query_selector``: visibility + click behaviour."""

    def __init__(self, page, selector, *, visible=True, raises=False):
        self.page = page
        self.selector = selector
        self._visible = visible
        self._raises = raises

    async def is_visible(self):
        return self._visible

    async def click(self, force=False):
        if self._raises:
            raise RuntimeError("click intercepted")
        self.page.dismiss_clicks.append(self.selector)


class _DismissMockPage:
    """A minimal page for ``_dismiss_overlays``: ``query_selector`` returns a configured
    ``_DismissButton`` per selector; the keyboard records Escape presses. ``keyboard_raises``
    models an environment where pressing Escape blows up (must be swallowed)."""

    def __init__(self, *, present=None, keyboard_raises=False):
        self._present = present or {}
        self.dismiss_clicks = []
        self.key_presses = []
        self._keyboard_raises = keyboard_raises
        self.keyboard = self._Keyboard(self)

    class _Keyboard:
        def __init__(self, page):
            self.page = page

        async def press(self, key):
            if self.page._keyboard_raises:
                raise RuntimeError("keyboard detached")
            self.page.key_presses.append(key)

    async def query_selector(self, selector):
        return self._present.get(selector)


class TestDismissOverlays:
    """Fix 1: best-effort, bounded dismissal of interstitial overlays (cookie/welcome/modal)
    that intercept ALL clicks on real SPAs — done before any form interaction."""

    async def test_visible_dismiss_button_is_clicked_and_escape_pressed(self):
        crawler = _make_crawler()
        sel = BrowserSignupConfig.OVERLAY_DISMISS_SELECTORS[0]
        page = _DismissMockPage(present={sel: None})  # start empty; add a real button below
        page._present[sel] = _DismissButton(page, sel, visible=True)
        await crawler._dismiss_overlays(page)
        assert page.dismiss_clicks == [sel]
        assert page.key_presses == ["Escape"]        # Escape always pressed once

    async def test_invisible_dismiss_control_is_skipped(self):
        crawler = _make_crawler()
        sel = BrowserSignupConfig.OVERLAY_DISMISS_SELECTORS[0]
        page = _DismissMockPage(present={sel: None})
        page._present[sel] = _DismissButton(page, sel, visible=False)
        await crawler._dismiss_overlays(page)
        assert page.dismiss_clicks == []             # not visible → never clicked
        assert page.key_presses == ["Escape"]

    async def test_multiple_overlays_are_bounded(self):
        crawler = _make_crawler()
        # Present MORE visible dismiss controls than the cap; only the cap-many are clicked.
        n = BrowserSignupConfig.MAX_OVERLAY_DISMISSALS + 2
        selectors = BrowserSignupConfig.OVERLAY_DISMISS_SELECTORS[:n]
        page = _DismissMockPage()
        for sel in selectors:
            page._present[sel] = _DismissButton(page, sel, visible=True)
        await crawler._dismiss_overlays(page)
        assert len(page.dismiss_clicks) == BrowserSignupConfig.MAX_OVERLAY_DISMISSALS
        assert page.dismiss_clicks == list(
            selectors[: BrowserSignupConfig.MAX_OVERLAY_DISMISSALS]
        )

    async def test_no_overlays_present_is_noop_but_still_escapes(self):
        crawler = _make_crawler()
        page = _DismissMockPage(present={})
        await crawler._dismiss_overlays(page)
        assert page.dismiss_clicks == []
        assert page.key_presses == ["Escape"]

    async def test_dismiss_click_that_raises_is_swallowed(self):
        crawler = _make_crawler()
        sel = BrowserSignupConfig.OVERLAY_DISMISS_SELECTORS[0]
        page = _DismissMockPage()
        page._present[sel] = _DismissButton(page, sel, visible=True, raises=True)
        await crawler._dismiss_overlays(page)      # must not raise
        assert page.dismiss_clicks == []
        assert page.key_presses == ["Escape"]

    async def test_escape_failure_is_swallowed(self):
        crawler = _make_crawler()
        page = _DismissMockPage(present={}, keyboard_raises=True)
        await crawler._dismiss_overlays(page)      # must not raise
        assert page.key_presses == []

    async def test_dismiss_runs_before_perceive_in_signup_flow(self):
        # Assert the overlay dismissal happens up front, before the form is perceived.
        crawler = _make_crawler()

        def on_submit(attempt):
            crawler._intercepted.append(InterceptedRequest(
                url="https://app.example.com/api/Users", method="POST",
                response_status=201))
        page = _PerceiveMockPage(fields=[
            _pfield(_P0, tag="input", type="email", name="email", required=True),
            _pfield(_P1, tag="input", type="password", name="password", required=True),
        ], on_submit=on_submit)

        order = []
        orig_dismiss = crawler._dismiss_overlays
        orig_perceive = crawler._perceive_form

        async def spy_dismiss(p):
            order.append("dismiss")
            return await orig_dismiss(p)

        async def spy_perceive(p):
            order.append("perceive")
            return await orig_perceive(p)

        crawler._dismiss_overlays = spy_dismiss
        crawler._perceive_form = spy_perceive

        async def filler(perception, identity, goal):
            return FormFillPlan(actions=[
                FormFillAction(locator=_P0, action="type", value="a@x.com"),
                FormFillAction(locator=_P1, action="type", value="pw")])

        result = await crawler._run_signup(
            page, "a@x.com", "pw", "agent_1", _synth, None, filler)
        assert result.success
        assert order[0] == "dismiss"
        assert order.index("dismiss") < order.index("perceive")


class TestOpenOverlayWidget:
    """Fix 2: opening a custom overlay widget via its REAL trigger, with a force-click
    fallback when the element box is pointer-intercepted by an overlapping label/overlay."""

    async def test_prefers_real_inner_trigger(self):
        # The widget exposes a .mat-mdc-select-trigger; clicking it opens the CDK overlay.
        crawler = _make_crawler()
        page = _PerceiveMockPage(widget_triggers={_P0}, overlay_map={_P0: ["Q1", "Q2"]})
        opened = await crawler._open_overlay_widget(page, _P0)
        assert opened is True
        assert _P0 in page.clicks                    # the trigger click opened the base widget
        assert page.force_clicks == []               # trigger worked → no force needed
        assert page._open_options == ["Q1", "Q2"]

    async def test_plain_intercepted_falls_back_to_force_click(self):
        # No inner trigger; the element box is pointer-intercepted, so a plain click raises
        # and the code retries with a force click, which opens the overlay.
        crawler = _make_crawler()
        page = _PerceiveMockPage(intercept_plain={_P0}, overlay_map={_P0: ["A"]})
        opened = await crawler._open_overlay_widget(page, _P0)
        assert opened is True
        assert page.force_clicks == [_P0]            # opened via the force fallback
        assert page._open_options == ["A"]

    async def test_plain_click_opens_when_not_intercepted(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(overlay_map={_P0: ["A"]})
        opened = await crawler._open_overlay_widget(page, _P0)
        assert opened is True
        assert page.clicks == [_P0] and page.force_clicks == []

    async def test_widget_absent_returns_false(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(missing_triggers={_P0})
        assert await crawler._open_overlay_widget(page, _P0) is False

    async def test_query_selector_raising_returns_false(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage()

        async def boom(selector):
            raise RuntimeError("query boom")

        page.query_selector = boom
        assert await crawler._open_overlay_widget(page, _P0) is False

    async def test_force_click_also_failing_returns_false(self):
        # Element box is intercepted AND force-click also raises → honest False (no open).
        crawler = _make_crawler()
        page = _PerceiveMockPage()

        class _AlwaysRaises:
            async def click(self, force=False):
                raise RuntimeError("still intercepted" if not force else "force failed")

        async def qs(selector):
            # No inner trigger; the base element always raises on click.
            for trig in BrowserSignupConfig.OVERLAY_TRIGGER_SELECTORS:
                if selector.endswith(f" {trig}"):
                    return None
            return _AlwaysRaises()

        page.query_selector = qs
        assert await crawler._open_overlay_widget(page, _P0) is False

    async def test_inner_trigger_click_raising_falls_through_to_force(self):
        # The inner trigger exists but its click raises; the code falls through to the
        # element box, whose plain click is intercepted, then force-opens.
        crawler = _make_crawler()
        page = _PerceiveMockPage(intercept_plain={_P0}, overlay_map={_P0: ["A"]})

        base_qs = page.query_selector

        async def qs(selector):
            for trig in BrowserSignupConfig.OVERLAY_TRIGGER_SELECTORS:
                if selector.endswith(f" {trig}"):
                    class _RaisingTrigger:
                        async def click(self, force=False):
                            raise RuntimeError("trigger detached")
                    return _RaisingTrigger()
            return await base_qs(selector)

        page.query_selector = qs
        opened = await crawler._open_overlay_widget(page, _P0)
        assert opened is True
        assert page.force_clicks == [_P0]

    async def test_enumerate_overlay_uses_robust_open_under_interception(self):
        # _enumerate_overlay_options must open a pointer-intercepted mat-select via the force
        # fallback and still read the lazily-rendered options.
        crawler = _make_crawler()
        page = _PerceiveMockPage(intercept_plain={_P2},
                                 overlay_map={_P2: ["Q1", "Q2", "Q3"]})
        opts = await crawler._enumerate_overlay_options(page, _P2)
        assert opts == ["Q1", "Q2", "Q3"]
        assert page.force_clicks == [_P2]            # opened via robust open, not a plain click
        assert page.key_presses == ["Escape"]        # closed after read

    async def test_select_option_uses_robust_open_under_interception(self):
        # _select_option must open a pointer-intercepted custom dropdown via the real trigger,
        # then click the chosen option.
        crawler = _make_crawler()
        option_selector = 'mat-option:has-text("First pet?")'
        page = _PerceiveMockPage(widget_triggers={_P2}, overlay_map={_P2: ["First pet?"]},
                                 custom_options={option_selector})
        field = FormField(locator=_P2, tag="mat-select", name="securityQuestion",
                          options=["First pet?"])
        await crawler._select_option(page, _P2, "First pet?", field)
        assert _P2 in page.clicks                    # opened via the real trigger
        assert option_selector in page.clicks        # chosen option clicked

    async def test_inner_trigger_query_raising_falls_through_to_plain_click(self):
        # If querying the inner trigger itself raises, the widget still opens via a plain click.
        crawler = _make_crawler()
        page = _PerceiveMockPage(overlay_map={_P0: ["A"]})
        base_qs = page.query_selector

        async def qs(selector):
            for trig in BrowserSignupConfig.OVERLAY_TRIGGER_SELECTORS:
                if selector.endswith(f" {trig}"):
                    raise RuntimeError("inner query boom")
            return await base_qs(selector)

        page.query_selector = qs
        opened = await crawler._open_overlay_widget(page, _P0)
        assert opened is True
        assert page.clicks == [_P0] and page.force_clicks == []

    async def test_enumerate_overlay_absent_widget_yields_empty(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(missing_triggers={_P0})
        assert await crawler._enumerate_overlay_options(page, _P0) == []

    async def test_select_option_absent_widget_is_noop(self):
        crawler = _make_crawler()
        page = _PerceiveMockPage(missing_triggers={_P0})
        field = FormField(locator=_P0, tag="mat-select", name="q", options=["x"])
        await crawler._select_option(page, _P0, "x", field)
        assert page.clicks == []
