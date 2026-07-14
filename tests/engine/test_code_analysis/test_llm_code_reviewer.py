"""Tests for LLM-powered security code reviewer."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from isitsecure.engine.code_analysis.llm_code_reviewer import (
    LLMCodeReviewer,
)
from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)
from isitsecure.engine.constants import LLMCodeReviewConfig
from isitsecure.engine.enums import BackendType, FrameworkType
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# --- Fixtures ---

RISKY_ROUTE_CONTENT = """
export async function GET(request, { params }) {
    const { id } = params
    const deal = await supabase
        .from('deals')
        .select('*')
        .eq('id', id)
        .single()
    return Response.json(deal.data)
}
"""

SAFE_ROUTE_CONTENT = """
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
"""

LLM_RESPONSE_WITH_FINDINGS = """
```json
[
    {
        "severity": "CRITICAL",
        "title": "Missing ownership check",
        "description": "Any user can read any deal by ID without ownership verification",
        "line_number": 5,
        "fix_code": ".eq('user_id', user.id)"
    }
]
```
"""

LLM_RESPONSE_NO_FINDINGS = "[]"

LLM_RESPONSE_MALFORMED = "This is not valid JSON at all"


def _make_mock_llm(response_text: str) -> MagicMock:
    """Create a mock LLM client that returns the given text."""
    mock = MagicMock()
    mock.generate_with_system = AsyncMock(return_value=response_text)
    mock.model_name = "mock-model"
    return mock


def _make_repo(
    routes: list[RouteEntry] | None = None,
    file_index: dict[str, str] | None = None,
) -> RepoSnapshot:
    """Create a mock RepoSnapshot."""
    return RepoSnapshot(
        repo_url="https://github.com/test/app",
        branch="main",
        clone_path="/tmp/test",
        framework=FrameworkType.NEXTJS,
        backend=BackendType.SUPABASE,
        route_map=routes or [],
        file_index=file_index or {},
    )


class TestLLMCodeReviewer:
    """Tests for the LLMCodeReviewer class."""

    def test_scanner_name(self) -> None:
        mock_llm = _make_mock_llm("")
        reviewer = LLMCodeReviewer(llm_client=mock_llm)
        assert reviewer.scanner_name == LLMCodeReviewConfig.SCANNER_NAME

    @pytest.mark.asyncio
    async def test_reviews_risky_route(self) -> None:
        """Route without auth should be sent to LLM for review."""
        mock_llm = _make_mock_llm(LLM_RESPONSE_WITH_FINDINGS)
        reviewer = LLMCodeReviewer(llm_client=mock_llm)

        route = RouteEntry(
            file_path="app/api/deals/[id]/route.ts",
            route_pattern="/api/deals/:id",
            http_methods=["GET"],
            content=RISKY_ROUTE_CONTENT,
        )
        repo = _make_repo(routes=[route])

        findings = await reviewer.scan(repo)
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.CRITICAL
        assert findings[0].title == "Missing ownership check"
        # Classified from the finding text: a missing ownership check is an
        # access-control / IDOR issue, not the AUTH_WEAKNESS catch-all.
        assert findings[0].category == FindingCategory.IDOR
        assert findings[0].line_number == 5
        assert findings[0].confidence == LLMCodeReviewConfig.CONFIDENCE_LLM_FINDING
        mock_llm.generate_with_system.assert_called_once()

    @pytest.mark.asyncio
    async def test_skips_safe_route(self) -> None:
        """Route with full auth+ownership should NOT be sent to LLM."""
        mock_llm = _make_mock_llm(LLM_RESPONSE_NO_FINDINGS)
        reviewer = LLMCodeReviewer(llm_client=mock_llm)

        route = RouteEntry(
            file_path="app/api/deals/[id]/route.ts",
            route_pattern="/api/deals/:id",
            http_methods=["GET"],
            content=SAFE_ROUTE_CONTENT,
        )
        repo = _make_repo(routes=[route])

        findings = await reviewer.scan(repo)
        assert len(findings) == 0
        # LLM should NOT have been called
        mock_llm.generate_with_system.assert_not_called()

    @pytest.mark.asyncio
    async def test_handles_llm_error(self) -> None:
        """LLM call fails should return empty findings, not crash."""
        mock_llm = _make_mock_llm("")
        mock_llm.generate_with_system = AsyncMock(
            side_effect=Exception("API error")
        )
        reviewer = LLMCodeReviewer(llm_client=mock_llm)

        route = RouteEntry(
            file_path="app/api/deals/[id]/route.ts",
            route_pattern="/api/deals/:id",
            http_methods=["GET"],
            content=RISKY_ROUTE_CONTENT,
        )
        repo = _make_repo(routes=[route])

        findings = await reviewer.scan(repo)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_handles_malformed_llm_response(self) -> None:
        """LLM returns non-JSON should return empty findings."""
        mock_llm = _make_mock_llm(LLM_RESPONSE_MALFORMED)
        reviewer = LLMCodeReviewer(llm_client=mock_llm)

        route = RouteEntry(
            file_path="app/api/deals/[id]/route.ts",
            route_pattern="/api/deals/:id",
            http_methods=["GET"],
            content=RISKY_ROUTE_CONTENT,
        )
        repo = _make_repo(routes=[route])

        findings = await reviewer.scan(repo)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_parallel_reviews_multiple_routes(self) -> None:
        """Multiple routes should be reviewed in parallel batches."""
        mock_llm = _make_mock_llm(LLM_RESPONSE_NO_FINDINGS)
        reviewer = LLMCodeReviewer(llm_client=mock_llm)

        routes = [
            RouteEntry(
                file_path=f"app/api/route{i}/route.ts",
                route_pattern=f"/api/route{i}",
                http_methods=["POST"],
                content=RISKY_ROUTE_CONTENT,
            )
            for i in range(5)
        ]
        repo = _make_repo(routes=routes)

        await reviewer.scan(repo)
        # All 5 routes should be reviewed
        assert mock_llm.generate_with_system.call_count == 5

    @pytest.mark.asyncio
    async def test_unlimited_tokens_reviews_all(self) -> None:
        """With MAX_TOTAL_INPUT_TOKENS=0 (unlimited), all routes are reviewed."""
        mock_llm = _make_mock_llm(LLM_RESPONSE_NO_FINDINGS)
        reviewer = LLMCodeReviewer(llm_client=mock_llm)
        # Pre-set high token count — should NOT stop with unlimited budget
        reviewer._total_tokens_used = 999_999

        route = RouteEntry(
            file_path="app/api/deals/[id]/route.ts",
            route_pattern="/api/deals/:id",
            http_methods=["GET"],
            content=RISKY_ROUTE_CONTENT,
        )
        repo = _make_repo(routes=[route])

        assert LLMCodeReviewConfig.MAX_TOTAL_INPUT_TOKENS == 0
        await reviewer.scan(repo)
        # Should still call LLM since budget is unlimited
        assert mock_llm.generate_with_system.call_count >= 1

    @pytest.mark.asyncio
    async def test_respects_max_files(self) -> None:
        """Should not review more than MAX_FILES_TO_REVIEW routes."""
        mock_llm = _make_mock_llm(LLM_RESPONSE_NO_FINDINGS)
        reviewer = LLMCodeReviewer(llm_client=mock_llm)

        # Create more risky routes than MAX_FILES_TO_REVIEW
        routes = [
            RouteEntry(
                file_path=f"app/api/route{i}/route.ts",
                route_pattern=f"/api/route{i}",
                http_methods=["GET"],
                content=RISKY_ROUTE_CONTENT,
            )
            for i in range(LLMCodeReviewConfig.MAX_FILES_TO_REVIEW + 10)
        ]
        repo = _make_repo(routes=routes)

        await reviewer.scan(repo)
        assert (
            mock_llm.generate_with_system.call_count
            <= LLMCodeReviewConfig.MAX_FILES_TO_REVIEW
        )

    @pytest.mark.asyncio
    async def test_skips_large_files(self) -> None:
        """Files exceeding MAX_FILE_SIZE_CHARS should be skipped."""
        mock_llm = _make_mock_llm(LLM_RESPONSE_NO_FINDINGS)
        reviewer = LLMCodeReviewer(llm_client=mock_llm)

        route = RouteEntry(
            file_path="app/api/huge/route.ts",
            route_pattern="/api/huge",
            http_methods=["GET"],
            content="x" * (LLMCodeReviewConfig.MAX_FILE_SIZE_CHARS + 1),
        )
        repo = _make_repo(routes=[route])

        await reviewer.scan(repo)
        mock_llm.generate_with_system.assert_not_called()

    @pytest.mark.asyncio
    async def test_reviews_rls_policies(self) -> None:
        """Should review migration SQL if present."""
        mock_llm = _make_mock_llm(LLM_RESPONSE_NO_FINDINGS)
        reviewer = LLMCodeReviewer(llm_client=mock_llm)

        repo = _make_repo(
            file_index={
                "supabase/migrations/001.sql": "CREATE TABLE deals (id uuid);"
            }
        )

        await reviewer.scan(repo)
        # LLM should be called for RLS review
        assert mock_llm.generate_with_system.call_count >= 1

    @pytest.mark.asyncio
    async def test_no_rls_review_without_migrations(self) -> None:
        """Should NOT call LLM for RLS if no migration files exist."""
        mock_llm = _make_mock_llm(LLM_RESPONSE_NO_FINDINGS)
        reviewer = LLMCodeReviewer(llm_client=mock_llm)

        repo = _make_repo(file_index={})

        await reviewer.scan(repo)
        mock_llm.generate_with_system.assert_not_called()


class TestParseLLMFindings:
    """Tests for JSON response parsing."""

    def test_parse_findings_json(self) -> None:
        reviewer = LLMCodeReviewer(llm_client=MagicMock())
        findings = reviewer._parse_llm_findings(
            LLM_RESPONSE_WITH_FINDINGS, "test.ts"
        )
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.CRITICAL
        assert findings[0].line_number == 5

    def test_parse_empty_array(self) -> None:
        reviewer = LLMCodeReviewer(llm_client=MagicMock())
        findings = reviewer._parse_llm_findings("[]", "test.ts")
        assert len(findings) == 0

    def test_parse_malformed_json(self) -> None:
        reviewer = LLMCodeReviewer(llm_client=MagicMock())
        findings = reviewer._parse_llm_findings("not json", "test.ts")
        assert len(findings) == 0

    def test_parse_unknown_severity_defaults_to_medium(self) -> None:
        reviewer = LLMCodeReviewer(llm_client=MagicMock())
        response = '[{"severity": "UNKNOWN", "title": "test", "description": "d"}]'
        findings = reviewer._parse_llm_findings(response, "test.ts")
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.MEDIUM

    def test_parse_skips_non_dict_items(self) -> None:
        reviewer = LLMCodeReviewer(llm_client=MagicMock())
        response = '["not a dict", {"severity": "HIGH", "title": "t", "description": "d"}]'
        findings = reviewer._parse_llm_findings(response, "test.ts")
        assert len(findings) == 1


class TestHelpers:
    """Tests for helper methods."""

    def test_extract_table_names(self) -> None:
        reviewer = LLMCodeReviewer(llm_client=MagicMock())
        tables = reviewer._extract_table_names('.from("deals").select("*")')
        assert "deals" in tables

    def test_extract_rpc_names(self) -> None:
        reviewer = LLMCodeReviewer(llm_client=MagicMock())
        tables = reviewer._extract_table_names('.rpc("get_user_deals")')
        assert "rpc:get_user_deals" in tables

    def test_extract_multiple_tables(self) -> None:
        reviewer = LLMCodeReviewer(llm_client=MagicMock())
        content = '.from("deals").select("*"); .from("users").select("*")'
        tables = reviewer._extract_table_names(content)
        assert "deals" in tables
        assert "users" in tables

    def test_has_risk_indicators_no_auth(self) -> None:
        from isitsecure.engine.code_analysis.review_triggers import RiskIndicatorTrigger
        trigger = RiskIndicatorTrigger()
        assert trigger._has_risk_indicators(RISKY_ROUTE_CONTENT) is True

    def test_has_risk_indicators_safe(self) -> None:
        from isitsecure.engine.code_analysis.review_triggers import RiskIndicatorTrigger
        trigger = RiskIndicatorTrigger()
        assert trigger._has_risk_indicators(SAFE_ROUTE_CONTENT) is False

    def test_has_risk_indicators_service_role(self) -> None:
        from isitsecure.engine.code_analysis.review_triggers import RiskIndicatorTrigger
        trigger = RiskIndicatorTrigger()
        content = """
        const { data: { user } } = await supabase.auth.getUser()
        const admin = createClient(url, service_role)
        """
        assert trigger._has_risk_indicators(content) is True

    def test_collect_migration_sql(self) -> None:
        reviewer = LLMCodeReviewer(llm_client=MagicMock())
        repo = _make_repo(
            file_index={
                "supabase/migrations/001.sql": "CREATE TABLE t1;",
                "supabase/migrations/002.sql": "CREATE TABLE t2;",
                "src/app/page.tsx": "not sql",
            }
        )
        sql = reviewer._collect_migration_sql(repo)
        assert "CREATE TABLE t1" in sql
        assert "CREATE TABLE t2" in sql
        assert "not sql" not in sql
