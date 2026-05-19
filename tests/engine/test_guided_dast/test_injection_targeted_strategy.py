"""Tests for InjectionTargetedStrategy."""

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
from isitsecure.engine.guided_dast.strategies.injection_targeted import (
    InjectionTargetedStrategy,
)
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def strategy() -> InjectionTargetedStrategy:
    return InjectionTargetedStrategy()


@pytest.fixture()
def repo_snapshot() -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        route_map=[
            RouteEntry(
                file_path="src/routes/search.ts",
                route_pattern="/api/search",
                http_methods=["GET"],
            ),
        ],
        file_index={},
    )


def _finding(
    title: str = "SQL injection risk in search endpoint",
    description: str = "Unsanitized user input in parameter 'query' used in SQL",
    file_path: str = "src/routes/search.ts",
    code_snippet: str = "db.raw(`SELECT * FROM items WHERE name = '${query}'`)",
) -> CodeFinding:
    return CodeFinding(
        scanner_name="injection_pattern_trigger",
        severity=SeverityLevel.CRITICAL,
        category=FindingCategory.INJECTION_RISK,
        title=title,
        description=description,
        file_path=file_path,
        code_snippet=code_snippet,
        confidence=0.9,
    )


def _endpoint(
    url: str = "https://example.com/api/search",
    method: EndpointMethod = EndpointMethod.GET,
) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(url=url, method=method)


# ---------------------------------------------------------------------------
# handles_scanner_names
# ---------------------------------------------------------------------------


class TestHandlesScannerNames:
    def test_handles_injection_pattern_trigger(
        self, strategy: InjectionTargetedStrategy,
    ) -> None:
        assert "injection_pattern_trigger" in strategy.handles_scanner_names

    def test_handles_llm_review(self, strategy: InjectionTargetedStrategy) -> None:
        assert "llm_review" in strategy.handles_scanner_names

    def test_does_not_handle_other_scanners(
        self, strategy: InjectionTargetedStrategy,
    ) -> None:
        assert "route_auth_analyzer" not in strategy.handles_scanner_names


# ---------------------------------------------------------------------------
# generate_tests
# ---------------------------------------------------------------------------


class TestGenerateInjectionTests:
    def test_generates_for_injection_finding(
        self, strategy: InjectionTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Finding with injection keywords produces test cases."""
        findings = [_finding()]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) > 0
        assert all(isinstance(c, GuidedTestCase) for c in cases)

    def test_generates_both_sqli_and_xss(
        self, strategy: InjectionTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Both SQLi and XSS test types are generated."""
        findings = [_finding()]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        test_types = {c.test_type for c in cases}
        assert GuidedDASTConfig.TEST_TYPE_SQLI in test_types
        assert GuidedDASTConfig.TEST_TYPE_XSS in test_types

    def test_targets_specific_parameter(
        self, strategy: InjectionTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Payload targets the parameter name extracted from the finding."""
        findings = [_finding(
            description="Unsanitized user input in parameter 'searchTerm'",
        )]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) > 0
        param_names = set()
        for case in cases:
            if case.payload:
                param_names.update(case.payload.keys())
        assert "searchTerm" in param_names

    def test_falls_back_to_generic_params(
        self, strategy: InjectionTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """When no param name extractable, uses generic fallback params."""
        findings = [_finding(
            description="SQL injection found",
            code_snippet="db.query(userInput)",
        )]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) > 0
        param_names = set()
        for case in cases:
            if case.payload:
                param_names.update(case.payload.keys())
        # Should use fallback params
        assert param_names & {"q", "search", "input"}

    def test_does_not_generate_for_non_injection(
        self, strategy: InjectionTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Finding without injection keywords produces no tests."""
        findings = [_finding(
            title="Missing rate limiting",
            description="No rate limit on this route",
        )]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert cases == []

    def test_no_findings_no_tests(
        self, strategy: InjectionTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Empty findings -> empty result."""
        cases = strategy.generate_tests([], [_endpoint()], repo_snapshot)

        assert cases == []

    def test_test_case_fields(
        self, strategy: InjectionTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Test case has correct source and target info."""
        finding = _finding()
        ep = _endpoint()

        cases = strategy.generate_tests([finding], [ep], repo_snapshot)

        assert len(cases) > 0
        case = cases[0]
        assert case.source_finding_id == finding.id
        assert case.source_scanner == "injection_pattern_trigger"
        assert case.target_url == ep.url
        assert case.http_method == "GET"
        assert case.description != ""
        assert case.expected_behavior == GuidedDASTConfig.EXPECTED_INJECTION

    def test_sqli_payloads_in_payload_values(
        self, strategy: InjectionTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """SQLi test cases contain SQL injection payload strings."""
        findings = [_finding()]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        sqli_cases = [c for c in cases if c.test_type == GuidedDASTConfig.TEST_TYPE_SQLI]
        assert len(sqli_cases) > 0
        payload_values = [list(c.payload.values())[0] for c in sqli_cases if c.payload]
        # Check that at least one known SQLi payload is present
        assert any("OR" in v or "UNION" in v or "DROP" in v for v in payload_values)
