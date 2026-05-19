"""Tests for RouteAuthAnalyzer."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.route_analyzer import (
    RouteAuthAnalyzer,
)
from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)
from isitsecure.engine.constants import RouteAuthAnalyzerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# --- Fixture: route content samples ---

NO_AUTH_ROUTE = '''
export async function GET(request, { params }) {
    const { id } = params
    const deal = await supabase
        .from('deals')
        .select('*')
        .eq('id', id)
        .single()
    return Response.json(deal.data)
}
'''

AUTH_NO_OWNERSHIP_ROUTE = '''
export async function GET(request, { params }) {
    const { data: { user } } = await supabase.auth.getUser()
    if (!user) return new Response('Unauthorized', { status: 401 })

    const deal = await supabase
        .from('deals')
        .select('*')
        .eq('id', params.id)
        .single()
    return Response.json(deal.data)
}
'''

FULLY_PROTECTED_ROUTE = '''
export async function GET(request, { params }) {
    const { data: { user } } = await supabase.auth.getUser()
    if (!user) return new Response('Unauthorized', { status: 401 })

    const result = z.object({ id: z.string().uuid() }).safeParse(params)
    if (!result.success) return new Response('Bad Request', { status: 400 })

    const deal = await supabase
        .from('deals')
        .select('*')
        .eq('id', result.data.id)
        .eq('user_id', user.id)
        .single()
    return Response.json(deal.data)
}
'''

SERVICE_ROLE_ROUTE = '''
import { supabaseAdmin } from '@/lib/supabase/admin'

export async function POST(request) {
    const { data: { user } } = await supabase.auth.getUser()
    if (!user) return new Response('Unauthorized', { status: 401 })

    const result = await supabaseAdmin
        .from('users')
        .update({ role: 'premium' })
        .eq('id', user.id)
    return Response.json(result)
}
'''

SERVER_ACTION_NO_AUTH = '''
"use server"

export async function createDeal(formData) {
    const title = formData.get('title')
    await supabase.from('deals').insert({ title })
}

export async function deleteDeal(id) {
    await supabase.from('deals').delete().eq('id', id)
}
'''

SERVER_ACTION_WITH_AUTH = '''
"use server"

export async function createDeal(formData) {
    const { data: { user } } = await supabase.auth.getUser()
    if (!user) throw new Error('Unauthorized')

    const title = formData.get('title')
    await supabase.from('deals').insert({ title, user_id: user.id })
}
'''

AUTH_WITH_SUPABASE_OPS_NO_OWNERSHIP = '''
export async function GET(request) {
    const { data: { user } } = await supabase.auth.getUser()
    if (!user) return new Response('Unauthorized', { status: 401 })

    const { data } = await supabase
        .from('reports')
        .select('*')
    return Response.json(data)
}
'''

NO_VALIDATION_WITH_INPUT = '''
export async function POST(request, { params }) {
    const { data: { user } } = await supabase.auth.getUser()
    if (!user) return new Response('Unauthorized', { status: 401 })

    const body = await request.json()
    const deal = await supabase
        .from('deals')
        .insert(body)
        .eq('user_id', user.id)
    return Response.json(deal.data)
}
'''


def _make_route(
    content: str,
    file_path: str = "app/api/deals/[id]/route.ts",
    route_pattern: str = "/api/deals/:id",
    http_methods: list[str] | None = None,
) -> RouteEntry:
    """Helper to create a RouteEntry for testing."""
    return RouteEntry(
        file_path=file_path,
        http_methods=http_methods or ["GET"],
        route_pattern=route_pattern,
        content=content,
    )


def _make_repo(
    routes: list[RouteEntry] | None = None,
    file_index: dict[str, str] | None = None,
) -> RepoSnapshot:
    """Helper to create a minimal RepoSnapshot for testing."""
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/test-repo",
        route_map=routes or [],
        file_index=file_index or {},
    )


class TestRouteAuthAnalyzer:
    """Tests for the RouteAuthAnalyzer scanner."""

    def setup_method(self) -> None:
        self.analyzer = RouteAuthAnalyzer()

    def test_scanner_name(self) -> None:
        assert self.analyzer.scanner_name == RouteAuthAnalyzerConfig.SCANNER_NAME

    # --- Missing Auth Tests ---

    @pytest.mark.asyncio
    async def test_detects_missing_auth(self) -> None:
        """Route with no auth check should be flagged."""
        route = _make_route(NO_AUTH_ROUTE)
        repo = _make_repo(routes=[route])

        findings = await self.analyzer.scan(repo)

        auth_findings = [
            f for f in findings
            if f.title == RouteAuthAnalyzerConfig.TITLE_MISSING_AUTH
        ]
        assert len(auth_findings) >= 1
        assert auth_findings[0].severity == SeverityLevel.HIGH
        assert auth_findings[0].category == FindingCategory.AUTH_WEAKNESS

    @pytest.mark.asyncio
    async def test_no_finding_when_auth_present(self) -> None:
        """Route with getUser() should not flag missing auth."""
        route = _make_route(AUTH_NO_OWNERSHIP_ROUTE)
        repo = _make_repo(routes=[route])

        findings = await self.analyzer.scan(repo)

        auth_findings = [
            f for f in findings
            if f.title == RouteAuthAnalyzerConfig.TITLE_MISSING_AUTH
        ]
        assert len(auth_findings) == 0

    # --- Missing Ownership Tests ---

    @pytest.mark.asyncio
    async def test_detects_missing_ownership_with_user_id(self) -> None:
        """Route with auth but no .eq('user_id', ...) and user-supplied ID -> IDOR risk."""
        route = _make_route(AUTH_NO_OWNERSHIP_ROUTE)
        repo = _make_repo(routes=[route])

        findings = await self.analyzer.scan(repo)

        idor_findings = [
            f for f in findings
            if f.title == RouteAuthAnalyzerConfig.TITLE_IDOR_RISK
        ]
        assert len(idor_findings) == 1
        assert idor_findings[0].severity == SeverityLevel.CRITICAL
        assert idor_findings[0].category == FindingCategory.IDOR

    @pytest.mark.asyncio
    async def test_detects_missing_ownership_supabase_ops(self) -> None:
        """Route with auth + supabase ops but no ownership filter -> missing ownership."""
        route = _make_route(
            AUTH_WITH_SUPABASE_OPS_NO_OWNERSHIP,
            file_path="app/api/reports/route.ts",
            route_pattern="/api/reports",
        )
        repo = _make_repo(routes=[route])

        findings = await self.analyzer.scan(repo)

        ownership_findings = [
            f for f in findings
            if f.title == RouteAuthAnalyzerConfig.TITLE_MISSING_OWNERSHIP
        ]
        assert len(ownership_findings) == 1
        assert ownership_findings[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_no_idor_when_ownership_present(self) -> None:
        """Route with auth AND ownership check should not flag IDOR."""
        route = _make_route(FULLY_PROTECTED_ROUTE)
        repo = _make_repo(routes=[route])

        findings = await self.analyzer.scan(repo)

        idor_findings = [
            f for f in findings
            if f.title in (
                RouteAuthAnalyzerConfig.TITLE_IDOR_RISK,
                RouteAuthAnalyzerConfig.TITLE_MISSING_OWNERSHIP,
            )
        ]
        assert len(idor_findings) == 0

    # --- Service Role Tests ---

    @pytest.mark.asyncio
    async def test_detects_service_role_usage(self) -> None:
        """Route using supabaseAdmin should be flagged."""
        route = _make_route(
            SERVICE_ROLE_ROUTE,
            http_methods=["POST"],
        )
        repo = _make_repo(routes=[route])

        findings = await self.analyzer.scan(repo)

        service_role_findings = [
            f for f in findings
            if f.title == RouteAuthAnalyzerConfig.TITLE_SERVICE_ROLE
        ]
        assert len(service_role_findings) == 1
        assert service_role_findings[0].severity == SeverityLevel.MEDIUM
        assert service_role_findings[0].category == FindingCategory.AUTH_WEAKNESS

    # --- Input Validation Tests ---

    @pytest.mark.asyncio
    async def test_detects_missing_validation(self) -> None:
        """Mutation route with user input but no zod/yup should flag missing validation."""
        route = _make_route(NO_AUTH_ROUTE, http_methods=["POST"])
        repo = _make_repo(routes=[route])

        findings = await self.analyzer.scan(repo)

        validation_findings = [
            f for f in findings
            if f.title == RouteAuthAnalyzerConfig.TITLE_MISSING_VALIDATION
        ]
        assert len(validation_findings) >= 1
        assert validation_findings[0].severity == SeverityLevel.MEDIUM
        assert validation_findings[0].category == FindingCategory.INJECTION_RISK

    @pytest.mark.asyncio
    async def test_no_validation_finding_when_zod_present(self) -> None:
        """Route with z.object().safeParse() should not flag validation."""
        route = _make_route(FULLY_PROTECTED_ROUTE)
        repo = _make_repo(routes=[route])

        findings = await self.analyzer.scan(repo)

        validation_findings = [
            f for f in findings
            if f.title == RouteAuthAnalyzerConfig.TITLE_MISSING_VALIDATION
        ]
        assert len(validation_findings) == 0

    # --- Server Action Tests ---

    @pytest.mark.asyncio
    async def test_detects_server_action_no_auth(self) -> None:
        """'use server' file without getUser() should flag each exported function."""
        repo = _make_repo(
            file_index={"app/actions/deals.ts": SERVER_ACTION_NO_AUTH},
        )

        findings = await self.analyzer.scan(repo)

        action_findings = [
            f for f in findings
            if f.title == RouteAuthAnalyzerConfig.TITLE_SERVER_ACTION_NO_AUTH
        ]
        assert len(action_findings) == 2
        func_names = [f.description for f in action_findings]
        assert any("createDeal" in d for d in func_names)
        assert any("deleteDeal" in d for d in func_names)
        assert all(f.severity == SeverityLevel.HIGH for f in action_findings)

    @pytest.mark.asyncio
    async def test_no_finding_for_auth_server_action(self) -> None:
        """'use server' with getUser() should not flag."""
        repo = _make_repo(
            file_index={"app/actions/deals.ts": SERVER_ACTION_WITH_AUTH},
        )

        findings = await self.analyzer.scan(repo)

        action_findings = [
            f for f in findings
            if f.title == RouteAuthAnalyzerConfig.TITLE_SERVER_ACTION_NO_AUTH
        ]
        assert len(action_findings) == 0

    # --- Fully Protected Route ---

    @pytest.mark.asyncio
    async def test_fully_protected_route_no_findings(self) -> None:
        """Route with auth + ownership + validation should have 0 findings."""
        route = _make_route(FULLY_PROTECTED_ROUTE)
        repo = _make_repo(routes=[route])

        findings = await self.analyzer.scan(repo)

        assert len(findings) == 0

    # --- Empty Route ---

    @pytest.mark.asyncio
    async def test_empty_content_no_findings(self) -> None:
        """Route with empty content should produce no findings."""
        route = _make_route("")
        repo = _make_repo(routes=[route])

        findings = await self.analyzer.scan(repo)

        assert len(findings) == 0

    # --- Helper Method Tests ---

    def test_has_auth_check_getUser(self) -> None:
        assert self.analyzer._has_auth_check(
            "const user = await supabase.auth.getUser()",
        )

    def test_has_auth_check_getSession(self) -> None:
        assert self.analyzer._has_auth_check(
            "const session = await getSession()",
        )

    def test_has_auth_check_clerk(self) -> None:
        assert self.analyzer._has_auth_check(
            "const user = await currentUser()",
        )

    def test_has_auth_check_verifyToken(self) -> None:
        assert self.analyzer._has_auth_check(
            "const decoded = await verifyToken(token)",
        )

    def test_has_auth_check_negative(self) -> None:
        assert not self.analyzer._has_auth_check(
            "const data = await fetchData()",
        )

    def test_has_ownership_check_user_id(self) -> None:
        assert self.analyzer._has_ownership_check(
            '.eq("user_id", user.id)',
        )

    def test_has_ownership_check_owner_id(self) -> None:
        assert self.analyzer._has_ownership_check(
            ".eq('owner_id', session.user.id)",
        )

    def test_has_ownership_check_negative(self) -> None:
        assert not self.analyzer._has_ownership_check(
            ".eq('id', params.id)",
        )

    def test_uses_service_role(self) -> None:
        assert self.analyzer._uses_service_role(
            "import { supabaseAdmin } from",
        )

    def test_uses_service_role_env_var(self) -> None:
        assert self.analyzer._uses_service_role(
            "process.env.SUPABASE_SERVICE_ROLE",
        )

    def test_uses_service_role_negative(self) -> None:
        assert not self.analyzer._uses_service_role(
            "import { supabase } from '@/lib/supabase'",
        )

    def test_has_input_validation_safeParse(self) -> None:
        assert self.analyzer._has_input_validation(
            "const result = schema.safeParse(body)",
        )

    def test_has_input_validation_zod(self) -> None:
        assert self.analyzer._has_input_validation(
            "const schema = z.object({ name: z.string() })",
        )

    def test_has_input_validation_negative(self) -> None:
        assert not self.analyzer._has_input_validation(
            "const body = await request.json()",
        )

    def test_extract_supabase_operations(self) -> None:
        ops = self.analyzer._extract_supabase_operations(
            '.from("deals").select("*")',
        )
        assert "deals.select" in ops

    def test_extract_supabase_operations_insert(self) -> None:
        ops = self.analyzer._extract_supabase_operations(
            ".from('users').insert({ name })",
        )
        assert "users.insert" in ops

    def test_extract_supabase_rpc(self) -> None:
        ops = self.analyzer._extract_supabase_operations(
            '.rpc("get_user_deals")',
        )
        assert "rpc:get_user_deals" in ops

    def test_extract_supabase_operations_empty(self) -> None:
        ops = self.analyzer._extract_supabase_operations(
            "const x = 1 + 2",
        )
        assert ops == []

    def test_find_relevant_line_export_function(self) -> None:
        content = "import foo\n\nexport async function GET(req) {}\n"
        route = _make_route(content, http_methods=["GET"])
        line = self.analyzer._find_relevant_line(content, route)
        assert line == 3

    def test_find_relevant_line_fallback_export(self) -> None:
        content = "import foo\n\nexport default handler\n"
        route = _make_route(content, http_methods=["POST"])
        line = self.analyzer._find_relevant_line(content, route)
        assert line == 3

    def test_find_relevant_line_empty_content(self) -> None:
        route = _make_route("", http_methods=["GET"])
        line = self.analyzer._find_relevant_line("", route)
        assert line is None
