"""Tests for shared Supabase parsing utilities."""

from isitsecure.engine.shared.supabase_utils import (
    extract_rpc_functions_from_js,
    extract_supabase_table_from_url,
    extract_tables_from_js,
)


class TestExtractSupabaseTableFromUrl:
    """Tests for extract_supabase_table_from_url."""

    def test_extracts_table_from_rest_url(self):
        url = "https://xyz.supabase.co/rest/v1/profiles?select=*"
        assert extract_supabase_table_from_url(url) == "profiles"

    def test_extracts_table_with_subpath(self):
        url = "https://xyz.supabase.co/rest/v1/deals?id=eq.123"
        assert extract_supabase_table_from_url(url) == "deals"

    def test_skips_rpc(self):
        url = "https://xyz.supabase.co/rest/v1/rpc/get_stats"
        assert extract_supabase_table_from_url(url) is None

    def test_returns_none_for_non_supabase_url(self):
        url = "https://api.example.com/users"
        assert extract_supabase_table_from_url(url) is None

    def test_returns_none_for_bare_rest_v1(self):
        url = "https://xyz.supabase.co/rest/v1/"
        assert extract_supabase_table_from_url(url) is None

    def test_returns_none_for_empty_table(self):
        url = "https://xyz.supabase.co/rest/v1/?select=*"
        assert extract_supabase_table_from_url(url) is None

    def test_handles_table_with_path_segment(self):
        url = "https://xyz.supabase.co/rest/v1/orders/123"
        assert extract_supabase_table_from_url(url) == "orders"


class TestExtractTablesFromJs:
    """Tests for extract_tables_from_js — JS bundle parsing."""

    def test_extracts_from_pattern(self):
        js = """
        const { data } = await supabase.from('profiles').select('*');
        const deals = await supabase.from('deals').select('id, title');
        """
        tables = extract_tables_from_js(js)
        assert "profiles" in tables
        assert "deals" in tables

    def test_extracts_from_minified_js(self):
        js = 'n.from("user_settings").select("*").eq("user_id",t)'
        tables = extract_tables_from_js(js)
        assert "user_settings" in tables

    def test_deduplicates(self):
        js = """
        supabase.from('deals').select('*');
        supabase.from('deals').insert({title: 'new'});
        supabase.from('deals').update({title: 'changed'});
        """
        tables = extract_tables_from_js(js)
        assert tables.count("deals") == 1

    def test_returns_empty_for_no_matches(self):
        js = "const x = fetch('/api/users');"
        assert extract_tables_from_js(js) == []

    def test_handles_service_role_app_js(self):
        """Even when REST API is locked down, JS still has .from() calls."""
        js = """
        // Server-side uses service_role, but client SDK still references tables
        const client = createClient(url, anonKey);
        client.from('marketplace_listings').select('*');
        client.from('reviews').select('*').eq('deal_id', id);
        client.from('user_profiles').select('avatar_url');
        """
        tables = extract_tables_from_js(js)
        assert "marketplace_listings" in tables
        assert "reviews" in tables
        assert "user_profiles" in tables


class TestExtractRpcFunctionsFromJs:
    """Tests for extract_rpc_functions_from_js."""

    def test_extracts_rpc_calls(self):
        js = """
        supabase.rpc('get_deal_stats', { deal_id: id });
        supabase.rpc('calculate_revenue');
        """
        funcs = extract_rpc_functions_from_js(js)
        assert "get_deal_stats" in funcs
        assert "calculate_revenue" in funcs

    def test_deduplicates(self):
        js = """
        supabase.rpc('get_stats');
        supabase.rpc('get_stats');
        """
        funcs = extract_rpc_functions_from_js(js)
        assert funcs.count("get_stats") == 1

    def test_returns_empty_for_no_matches(self):
        assert extract_rpc_functions_from_js("const x = 1;") == []
