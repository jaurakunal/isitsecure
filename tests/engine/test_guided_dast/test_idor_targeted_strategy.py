"""Tests for IDORTargetedStrategy."""

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
from isitsecure.engine.guided_dast.strategies.idor_targeted import (
    IDORTargetedStrategy,
)
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def strategy() -> IDORTargetedStrategy:
    return IDORTargetedStrategy()


@pytest.fixture()
def repo_snapshot() -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        route_map=[
            RouteEntry(
                file_path="src/routes/users.ts",
                route_pattern="/api/users/:id",
                http_methods=["GET"],
            ),
        ],
        file_index={},
    )


def _finding(
    title: str = "Missing ownership check",
    description: str = "No ownership validation for user_id",
    file_path: str = "src/routes/users.ts",
    code_snippet: str = "const user_id = req.params.id;",
) -> CodeFinding:
    return CodeFinding(
        scanner_name="route_auth_analyzer",
        severity=SeverityLevel.HIGH,
        category=FindingCategory.IDOR,
        title=title,
        description=description,
        file_path=file_path,
        code_snippet=code_snippet,
        confidence=0.9,
    )


def _endpoint(
    url: str = "https://example.com/api/users/123",
    method: EndpointMethod = EndpointMethod.GET,
    path_param_names: list[str] | None = None,
) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(
        url=url,
        method=method,
        path_param_names=path_param_names or [],
    )


# ---------------------------------------------------------------------------
# handles_scanner_names
# ---------------------------------------------------------------------------


class TestHandlesScannerNames:
    def test_handles_route_auth_analyzer(self, strategy: IDORTargetedStrategy) -> None:
        assert "route_auth_analyzer" in strategy.handles_scanner_names


# ---------------------------------------------------------------------------
# generate_tests
# ---------------------------------------------------------------------------


class TestGenerateIDORTests:
    def test_generates_for_ownership_finding(
        self, strategy: IDORTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Finding mentioning 'ownership' produces IDOR test cases."""
        findings = [_finding(title="Missing ownership check on /api/users/:id")]
        endpoints = [_endpoint(path_param_names=["id"])]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) == 1
        assert cases[0].test_type == GuidedDASTConfig.TEST_TYPE_IDOR
        assert isinstance(cases[0], GuidedTestCase)

    def test_includes_correct_param_name_from_endpoint(
        self, strategy: IDORTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Payload uses the path parameter name from the endpoint."""
        findings = [_finding()]
        endpoints = [_endpoint(path_param_names=["userId"])]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) == 1
        assert cases[0].payload is not None
        assert "userId" in cases[0].payload

    def test_falls_back_to_snippet_param(
        self, strategy: IDORTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """When endpoint has no path_param_names, extracts from code snippet."""
        findings = [_finding(code_snippet="const user_id = req.params.user_id;")]
        endpoints = [_endpoint(path_param_names=[])]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) == 1
        assert cases[0].payload is not None
        assert "user_id" in cases[0].payload

    def test_probe_id_is_known_value(
        self, strategy: IDORTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """The swapped ID value is the fixed probe UUID."""
        findings = [_finding()]
        endpoints = [_endpoint(path_param_names=["id"])]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert cases[0].payload["id"] == IDORTargetedStrategy._PROBE_ID

    def test_does_not_generate_for_non_idor_findings(
        self, strategy: IDORTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Finding without IDOR keywords produces no tests."""
        findings = [_finding(
            title="SQL injection in query",
            description="Unsanitized input concatenated",
        )]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert cases == []

    def test_no_findings_no_tests(
        self, strategy: IDORTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Empty findings -> empty result."""
        cases = strategy.generate_tests([], [_endpoint()], repo_snapshot)

        assert cases == []

    def test_test_case_fields(
        self, strategy: IDORTargetedStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Test case has correct source fields and target URL."""
        finding = _finding()
        ep = _endpoint(path_param_names=["id"])

        cases = strategy.generate_tests([finding], [ep], repo_snapshot)

        case = cases[0]
        assert case.source_finding_id == finding.id
        assert case.source_scanner == "route_auth_analyzer"
        assert case.target_url == ep.url
        assert case.http_method == "GET"
        assert case.description != ""
        assert case.expected_behavior == GuidedDASTConfig.EXPECTED_IDOR
