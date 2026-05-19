"""Tests for MassAssignmentSchemaStrategy."""

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
from isitsecure.engine.guided_dast.strategies.mass_assignment import (
    MassAssignmentSchemaStrategy,
)
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def strategy() -> MassAssignmentSchemaStrategy:
    return MassAssignmentSchemaStrategy()


@pytest.fixture()
def repo_snapshot() -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        route_map=[
            RouteEntry(
                file_path="src/db/schema.ts",
                route_pattern="/api/users",
                http_methods=["POST", "PUT"],
            ),
        ],
        file_index={},
    )


def _finding(
    title: str = "Schema exposes role field",
    description: str = "Table users has a role column",
    code_snippet: str = "role: text('role').default('user')",
    file_path: str = "src/db/schema.ts",
    scanner_name: str = "drizzle_schema_analyzer",
) -> CodeFinding:
    return CodeFinding(
        scanner_name=scanner_name,
        severity=SeverityLevel.MEDIUM,
        category=FindingCategory.PRIVILEGE_ESCALATION,
        title=title,
        description=description,
        file_path=file_path,
        code_snippet=code_snippet,
        confidence=0.8,
    )


def _endpoint(
    url: str = "https://example.com/api/users",
    method: EndpointMethod = EndpointMethod.POST,
) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(url=url, method=method)


# ---------------------------------------------------------------------------
# handles_scanner_names
# ---------------------------------------------------------------------------


class TestHandlesScannerNames:
    def test_handles_drizzle_schema_analyzer(
        self, strategy: MassAssignmentSchemaStrategy,
    ) -> None:
        assert "drizzle_schema_analyzer" in strategy.handles_scanner_names

    def test_handles_prisma_schema_analyzer(
        self, strategy: MassAssignmentSchemaStrategy,
    ) -> None:
        assert "prisma_schema_analyzer" in strategy.handles_scanner_names

    def test_does_not_handle_other_scanners(
        self, strategy: MassAssignmentSchemaStrategy,
    ) -> None:
        assert "route_auth_analyzer" not in strategy.handles_scanner_names


# ---------------------------------------------------------------------------
# generate_tests
# ---------------------------------------------------------------------------


class TestGenerateMassAssignmentTests:
    def test_generates_for_role_field(
        self, strategy: MassAssignmentSchemaStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Finding with 'role' field produces mass assignment tests."""
        findings = [_finding(
            title="Schema exposes role field",
            code_snippet="role: text('role').default('user')",
        )]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) > 0
        assert all(isinstance(c, GuidedTestCase) for c in cases)
        assert all(
            c.test_type == GuidedDASTConfig.TEST_TYPE_MASS_ASSIGNMENT for c in cases
        )

    def test_generates_for_admin_field(
        self, strategy: MassAssignmentSchemaStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Finding with 'isAdmin' field produces mass assignment tests."""
        findings = [_finding(
            title="Schema exposes admin flag",
            description="isAdmin boolean column",
            code_snippet="isAdmin: boolean('isAdmin').default(false)",
        )]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) > 0

    def test_payload_contains_field_name(
        self, strategy: MassAssignmentSchemaStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Payload includes the exact privileged field name from the finding."""
        findings = [_finding(code_snippet="role: text('role').default('user')")]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) > 0
        for case in cases:
            assert case.payload is not None
            assert "role" in case.payload

    def test_uses_mutation_methods(
        self, strategy: MassAssignmentSchemaStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Test cases use POST, PUT, and PATCH methods."""
        findings = [_finding()]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        methods = {c.http_method for c in cases}
        assert methods == {"POST", "PUT", "PATCH"}

    def test_no_privileged_fields_no_tests(
        self, strategy: MassAssignmentSchemaStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Finding without privileged field names produces no tests."""
        findings = [_finding(
            title="Schema has email column",
            description="email field in users table",
            code_snippet="email: text('email').notNull()",
        )]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert cases == []

    def test_no_findings_no_tests(
        self, strategy: MassAssignmentSchemaStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Empty findings -> empty result."""
        cases = strategy.generate_tests([], [_endpoint()], repo_snapshot)

        assert cases == []

    def test_test_case_fields(
        self, strategy: MassAssignmentSchemaStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Test case has correct source and target info."""
        finding = _finding()
        ep = _endpoint()

        cases = strategy.generate_tests([finding], [ep], repo_snapshot)

        assert len(cases) > 0
        case = cases[0]
        assert case.source_finding_id == finding.id
        assert case.source_scanner == "drizzle_schema_analyzer"
        assert case.target_url == ep.url
        assert case.description != ""
        assert case.expected_behavior == GuidedDASTConfig.EXPECTED_MASS_ASSIGNMENT
