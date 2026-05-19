"""Tests for review trigger strategies and PrioritizedRouteSelector."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)
from isitsecure.engine.code_analysis.review_triggers import (
    CrossScannerFlaggedTrigger,
    FinancialOperationTrigger,
    PrioritizedRouteSelector,
    ReviewTriggerProtocol,
    RiskIndicatorTrigger,
    StateMutationTrigger,
)
from isitsecure.engine.constants import LLMCodeReviewConfig
from isitsecure.engine.enums import ReviewTriggerType
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_repo(routes=None):
    return RepoSnapshot(
        repo_url="test",
        branch="main",
        clone_path="/tmp",
        route_map=routes or [],
    )


def _make_route(
    pattern,
    methods=None,
    content="",
    file_path="src/route.ts",
    has_auth_check=None,
):
    return RouteEntry(
        file_path=file_path,
        http_methods=methods or ["GET"],
        route_pattern=pattern,
        content=content,
        has_auth_check=has_auth_check,
    )


def _make_finding(
    title="Test",
    scanner="test",
    file_path="src/test.ts",
):
    return CodeFinding(
        scanner_name=scanner,
        severity=SeverityLevel.HIGH,
        category=FindingCategory.AUTH_WEAKNESS,
        title=title,
        description="desc",
        file_path=file_path,
        confidence=0.9,
    )


# ---------------------------------------------------------------------------
# TestFinancialOperationTrigger
# ---------------------------------------------------------------------------


class TestFinancialOperationTrigger:
    """Tests for FinancialOperationTrigger."""

    def setup_method(self):
        self.trigger = FinancialOperationTrigger()

    def test_selects_route_with_payment_in_pattern(self):
        route = _make_route(
            "/trpc/purchase.initiatePurchase",
            content="const handler = async () => {}",
        )
        repo = _make_repo([route])
        result = self.trigger.select_routes(repo, [])
        assert len(result) == 1
        assert result[0].route_pattern == "/trpc/purchase.initiatePurchase"

    def test_selects_route_with_checkout_in_pattern(self):
        route = _make_route(
            "/api/checkout/create",
            content="export async function POST() { return {} }",
        )
        repo = _make_repo([route])
        result = self.trigger.select_routes(repo, [])
        assert len(result) == 1
        assert result[0].route_pattern == "/api/checkout/create"

    def test_skips_health_endpoint(self):
        """GET /health with 'payout' in file content but not in pattern."""
        route = _make_route(
            "/health",
            methods=["GET"],
            content="// This service handles payout monitoring",
        )
        repo = _make_repo([route])
        result = self.trigger.select_routes(repo, [])
        assert len(result) == 0

    def test_requires_mutation_for_content_match(self):
        """GET with financial content should be skipped (no mutation method)."""
        route = _make_route(
            "/api/dashboard",
            methods=["GET"],
            content="const balance = getBalance(); const stripe = initStripe();",
        )
        repo = _make_repo([route])
        result = self.trigger.select_routes(repo, [])
        assert len(result) == 0

    def test_mutation_with_multiple_financial_patterns(self):
        """POST with 2+ financial patterns in content should be selected."""
        route = _make_route(
            "/api/process",
            methods=["POST"],
            content=(
                "const payment = await stripe.charges.create({ amount });\n"
                "const balance = await getBalance(userId);\n"
            ),
            file_path="src/process.ts",
        )
        repo = _make_repo([route])
        result = self.trigger.select_routes(repo, [])
        assert len(result) == 1
        assert result[0].file_path == "src/process.ts"

    def test_trigger_type_is_financial(self):
        assert self.trigger.trigger_type == ReviewTriggerType.FINANCIAL_OPERATION


# ---------------------------------------------------------------------------
# TestCrossScannerFlaggedTrigger
# ---------------------------------------------------------------------------


class TestCrossScannerFlaggedTrigger:
    """Tests for CrossScannerFlaggedTrigger."""

    def setup_method(self):
        self.trigger = CrossScannerFlaggedTrigger()

    def test_selects_route_querying_flagged_table(self):
        """SAST flagged table 'developer_apps', route content has .from('developer_apps')."""
        finding = _make_finding(
            title="Missing RLS on table 'developer_apps'",
        )
        route = _make_route(
            "/api/apps",
            content="const apps = await supabase.from('developer_apps').select('*')",
            file_path="src/apps.ts",
        )
        repo = _make_repo([route])
        result = self.trigger.select_routes(repo, [finding])
        assert len(result) == 1
        assert result[0].file_path == "src/apps.ts"

    def test_no_sast_findings_returns_empty(self):
        route = _make_route("/api/data", content="some content")
        repo = _make_repo([route])
        result = self.trigger.select_routes(repo, [])
        assert len(result) == 0

    def test_no_matching_tables_returns_empty(self):
        """SAST flagged table 'users', but route queries 'orders'."""
        finding = _make_finding(title="Missing RLS on table 'users'")
        route = _make_route(
            "/api/orders",
            content="const data = await supabase.from('orders').select('*')",
        )
        repo = _make_repo([route])
        result = self.trigger.select_routes(repo, [finding])
        assert len(result) == 0

    def test_trigger_type_is_cross_scanner(self):
        assert self.trigger.trigger_type == ReviewTriggerType.CROSS_SCANNER_FLAGGED


# ---------------------------------------------------------------------------
# TestStateMutationTrigger
# ---------------------------------------------------------------------------


class TestStateMutationTrigger:
    """Tests for StateMutationTrigger."""

    def setup_method(self):
        self.trigger = StateMutationTrigger()

    def test_selects_route_with_mutation_and_conditional(self):
        """Content has .insert( and if ( -> should be selected."""
        route = _make_route(
            "/api/create",
            content=(
                "if (user.role === 'admin') {\n"
                "  await db.insert({ name });\n"
                "}"
            ),
        )
        repo = _make_repo([route])
        result = self.trigger.select_routes(repo, [])
        assert len(result) == 1

    def test_skips_mutation_without_conditional(self):
        route = _make_route(
            "/api/create",
            content="await db.insert({ name: 'test' });",
        )
        repo = _make_repo([route])
        result = self.trigger.select_routes(repo, [])
        assert len(result) == 0

    def test_skips_conditional_without_mutation(self):
        route = _make_route(
            "/api/check",
            content="if (user.role === 'admin') { return true; }",
        )
        repo = _make_repo([route])
        result = self.trigger.select_routes(repo, [])
        assert len(result) == 0

    def test_trigger_type_is_state_mutation(self):
        assert self.trigger.trigger_type == ReviewTriggerType.STATE_MUTATION


# ---------------------------------------------------------------------------
# TestRiskIndicatorTrigger
# ---------------------------------------------------------------------------


class TestRiskIndicatorTrigger:
    """Tests for RiskIndicatorTrigger."""

    def setup_method(self):
        self.trigger = RiskIndicatorTrigger()

    def test_selects_route_without_auth(self):
        """Content has no auth patterns -> flagged as risky."""
        route = _make_route(
            "/api/public",
            content=(
                "export async function GET(request) {\n"
                "  const data = await fetch('/external');\n"
                "  return Response.json(data);\n"
                "}"
            ),
        )
        repo = _make_repo([route])
        result = self.trigger.select_routes(repo, [])
        assert len(result) == 1

    def test_skips_route_with_auth(self):
        """Content has getUser() -> auth is present -> not risky on its own."""
        route = _make_route(
            "/api/protected",
            content=(
                "const { data: { user } } = await supabase.auth.getUser();\n"
                "if (!user) return new Response('Unauthorized', { status: 401 });\n"
                "return Response.json({ ok: true });\n"
            ),
        )
        repo = _make_repo([route])
        result = self.trigger.select_routes(repo, [])
        assert len(result) == 0

    def test_trigger_type_is_risk_indicator(self):
        assert self.trigger.trigger_type == ReviewTriggerType.RISK_INDICATOR


# ---------------------------------------------------------------------------
# TestPrioritizedRouteSelector
# ---------------------------------------------------------------------------


class TestPrioritizedRouteSelector:
    """Tests for PrioritizedRouteSelector."""

    def test_deduplicates_by_file_path(self):
        """Same file selected by 2 triggers -> only first (higher priority) wins."""
        route = _make_route(
            "/api/checkout",
            methods=["POST"],
            content=(
                "if (user) {\n"
                "  await db.insert({ amount });\n"
                "  const payment = await stripe.charges.create({ amount });\n"
                "  const balance = checkBalance();\n"
                "}"
            ),
            file_path="src/checkout.ts",
        )
        repo = _make_repo([route])

        # Both FinancialOperationTrigger (pattern match) and
        # StateMutationTrigger (insert + if) would select this route.
        selector = PrioritizedRouteSelector()
        result = selector.select_routes(repo, [])

        # Only one entry — financial trigger wins (priority 0).
        file_paths = [r.file_path for r, _ in result]
        assert file_paths.count("src/checkout.ts") == 1
        # The winning trigger should be FINANCIAL_OPERATION (priority 0).
        assert result[0][1] == ReviewTriggerType.FINANCIAL_OPERATION

    def test_priority_order(self):
        """Financial trigger routes appear before risk indicator routes."""
        financial_route = _make_route(
            "/api/payment",
            content="process payment here",
            file_path="src/payment.ts",
        )
        risky_route = _make_route(
            "/api/public",
            content="export async function GET(req) { return fetch('/data'); }",
            file_path="src/public.ts",
        )
        repo = _make_repo([financial_route, risky_route])

        selector = PrioritizedRouteSelector()
        result = selector.select_routes(repo, [])

        # Financial should come first in results.
        trigger_types = [t for _, t in result]
        if ReviewTriggerType.FINANCIAL_OPERATION in trigger_types:
            fin_idx = trigger_types.index(ReviewTriggerType.FINANCIAL_OPERATION)
            if ReviewTriggerType.RISK_INDICATOR in trigger_types:
                risk_idx = trigger_types.index(ReviewTriggerType.RISK_INDICATOR)
                assert fin_idx < risk_idx

    def test_respects_max_files(self):
        """More routes than max_files -> only max_files returned."""
        routes = [
            _make_route(
                f"/api/endpoint-{i}",
                content=f"export function handler{i}() {{ return {i}; }}",
                file_path=f"src/route{i}.ts",
            )
            for i in range(10)
        ]
        repo = _make_repo(routes)

        selector = PrioritizedRouteSelector()
        result = selector.select_routes(repo, [], max_files=3)
        assert len(result) <= 3

    def test_skips_empty_content(self):
        route = _make_route("/api/empty", content="")
        repo = _make_repo([route])

        selector = PrioritizedRouteSelector()
        result = selector.select_routes(repo, [])
        assert len(result) == 0

    def test_skips_oversized_files(self):
        """Content > MAX_FILE_SIZE_CHARS should be skipped."""
        oversized_content = "x" * (LLMCodeReviewConfig.MAX_FILE_SIZE_CHARS + 1)
        route = _make_route(
            "/api/huge",
            content=oversized_content,
            file_path="src/huge.ts",
        )
        repo = _make_repo([route])

        # Use RiskIndicatorTrigger alone (no auth -> risky) so the route
        # would be selected if not oversized.
        selector = PrioritizedRouteSelector(
            triggers=[RiskIndicatorTrigger()],
        )
        result = selector.select_routes(repo, [])
        assert len(result) == 0

    def test_default_triggers_created(self):
        """Verify 4 default triggers in correct priority order."""
        selector = PrioritizedRouteSelector()
        triggers = selector._triggers

        assert len(triggers) == 4
        assert isinstance(triggers[0], FinancialOperationTrigger)
        assert isinstance(triggers[1], CrossScannerFlaggedTrigger)
        assert isinstance(triggers[2], StateMutationTrigger)
        assert isinstance(triggers[3], RiskIndicatorTrigger)

        # Priorities are strictly ascending.
        priorities = [t.priority for t in triggers]
        assert priorities == sorted(priorities)
        assert len(set(priorities)) == 4  # all distinct


# ---------------------------------------------------------------------------
# TestReviewTriggerProtocol
# ---------------------------------------------------------------------------


class TestReviewTriggerProtocol:
    """Verify all concrete triggers satisfy the ReviewTriggerProtocol."""

    @pytest.mark.parametrize(
        "trigger_cls",
        [
            FinancialOperationTrigger,
            CrossScannerFlaggedTrigger,
            StateMutationTrigger,
            RiskIndicatorTrigger,
        ],
    )
    def test_implements_protocol(self, trigger_cls):
        instance = trigger_cls()
        assert isinstance(instance, ReviewTriggerProtocol)
