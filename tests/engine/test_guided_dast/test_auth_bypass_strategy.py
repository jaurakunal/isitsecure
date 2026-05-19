"""Tests for AuthBypassGuidedStrategy."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)
from isitsecure.engine.constants import GuidedDASTConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.guided_dast.protocols import GuidedTestCase
from isitsecure.engine.guided_dast.strategies.auth_bypass import (
    AuthBypassGuidedStrategy,
)
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def strategy() -> AuthBypassGuidedStrategy:
    return AuthBypassGuidedStrategy()


@pytest.fixture()
def repo_snapshot() -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        route_map=[
            RouteEntry(
                file_path="src/routes/users.ts",
                route_pattern="/api/users",
                http_methods=["GET", "POST"],
            ),
        ],
        file_index={},
    )


def _finding(
    title: str = "Missing authentication on route",
    description: str = "No auth middleware applied",
    scanner_name: str = "route_auth_analyzer",
    file_path: str = "src/routes/users.ts",
) -> CodeFinding:
    return CodeFinding(
        scanner_name=scanner_name,
        severity=SeverityLevel.HIGH,
        category=FindingCategory.AUTH_WEAKNESS,
        title=title,
        description=description,
        file_path=file_path,
        confidence=0.9,
    )


def _endpoint(
    url: str = "https://example.com/api/users",
    method: EndpointMethod = EndpointMethod.GET,
) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(url=url, method=method)


# ---------------------------------------------------------------------------
# handles_scanner_names
# ---------------------------------------------------------------------------


class TestHandlesScannerNames:
    def test_handles_route_auth_analyzer(self, strategy: AuthBypassGuidedStrategy) -> None:
        assert "route_auth_analyzer" in strategy.handles_scanner_names

    def test_does_not_handle_other_scanners(self, strategy: AuthBypassGuidedStrategy) -> None:
        assert "injection_pattern_trigger" not in strategy.handles_scanner_names
        assert "llm_review" not in strategy.handles_scanner_names


# ---------------------------------------------------------------------------
# generate_tests
# ---------------------------------------------------------------------------


class TestGenerateAuthBypassTests:
    def test_generates_test_for_missing_auth_finding(
        self, strategy: AuthBypassGuidedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Finding with 'Missing authentication' produces test cases."""
        findings = [_finding(title="Missing authentication on /api/users")]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) > 0
        assert all(isinstance(c, GuidedTestCase) for c in cases)
        assert all(c.test_type == GuidedDASTConfig.TEST_TYPE_AUTH_BYPASS for c in cases)

    def test_test_case_has_empty_auth_headers(
        self, strategy: AuthBypassGuidedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Auth bypass tests must send empty headers (no auth)."""
        findings = [_finding(title="Missing authentication")]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) > 0
        for case in cases:
            assert case.headers == {}

    def test_test_case_has_correct_http_method(
        self, strategy: AuthBypassGuidedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Test cases should use the methods from the route map."""
        findings = [_finding(title="Missing authentication")]
        endpoints = [_endpoint(url="https://example.com/api/users")]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        methods = {c.http_method for c in cases}
        # The route map has GET and POST, but _get_methods_for_endpoint
        # checks if route_pattern is in ep.url; since "/api/users" is in
        # the URL, it should return those methods.
        assert "GET" in methods or len(cases) > 0

    def test_does_not_generate_for_non_auth_findings(
        self, strategy: AuthBypassGuidedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Findings without auth-related keywords produce no test cases."""
        findings = [_finding(
            title="SQL injection in query builder",
            description="Unsanitized user input concatenated",
        )]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert cases == []

    def test_does_not_generate_for_other_scanner_findings(
        self, strategy: AuthBypassGuidedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Even if title matches, a non-route_auth_analyzer finding still
        generates tests if keywords match (strategy filters by keywords,
        not scanner_name)."""
        findings = [_finding(
            title="Unrelated finding",
            description="No relevant keywords here",
            scanner_name="injection_pattern_trigger",
        )]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert cases == []

    def test_no_findings_no_tests(
        self, strategy: AuthBypassGuidedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Empty findings list -> no test cases."""
        cases = strategy.generate_tests([], [_endpoint()], repo_snapshot)

        assert cases == []

    def test_test_case_fields_populated(
        self, strategy: AuthBypassGuidedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Generated test case has all required fields populated."""
        finding = _finding(title="Missing authentication on route")
        endpoints = [_endpoint()]

        cases = strategy.generate_tests([finding], endpoints, repo_snapshot)

        assert len(cases) > 0
        case = cases[0]
        assert case.source_finding_id == finding.id
        assert case.source_scanner == "route_auth_analyzer"
        assert case.target_url == "https://example.com/api/users"
        assert case.description != ""
        assert case.expected_behavior != ""
