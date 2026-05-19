"""Tests for RLSBypassStrategy."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)
from isitsecure.engine.constants import GuidedDASTConfig, SharedPatterns
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.guided_dast.protocols import GuidedTestCase
from isitsecure.engine.guided_dast.strategies.rls_bypass import (
    RLSBypassStrategy,
)
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MOCK_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSJ9.fake"


@pytest.fixture()
def strategy() -> RLSBypassStrategy:
    return RLSBypassStrategy()


@pytest.fixture()
def repo_snapshot() -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        route_map=[],
        file_index={
            ".env.local": f"NEXT_PUBLIC_SUPABASE_ANON_KEY={MOCK_ANON_KEY}",
        },
    )


@pytest.fixture()
def repo_snapshot_no_key() -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        route_map=[],
        file_index={},
    )


def _finding(
    title: str = "Table 'profiles' has no RLS policy",
    description: str = "Missing RLS on table 'profiles'",
    code_snippet: str = "create table profiles (id uuid, name text);",
) -> CodeFinding:
    return CodeFinding(
        scanner_name="rls_policy_analyzer",
        severity=SeverityLevel.CRITICAL,
        category=FindingCategory.RLS_MISCONFIGURATION,
        title=title,
        description=description,
        file_path="supabase/migrations/001.sql",
        code_snippet=code_snippet,
        confidence=0.95,
    )


def _supabase_endpoint(
    url: str = "https://abcdef.supabase.co/rest/v1/profiles",
) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(url=url, method=EndpointMethod.GET)


# ---------------------------------------------------------------------------
# handles_scanner_names
# ---------------------------------------------------------------------------


class TestHandlesScannerNames:
    def test_handles_rls_policy_analyzer(self, strategy: RLSBypassStrategy) -> None:
        assert "rls_policy_analyzer" in strategy.handles_scanner_names

    def test_does_not_handle_other_scanners(self, strategy: RLSBypassStrategy) -> None:
        assert "route_auth_analyzer" not in strategy.handles_scanner_names
        assert "llm_review" not in strategy.handles_scanner_names


# ---------------------------------------------------------------------------
# generate_tests
# ---------------------------------------------------------------------------


class TestGenerateRLSBypassTests:
    def test_generates_for_missing_rls_finding(
        self, strategy: RLSBypassStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Finding with 'no RLS' produces test cases."""
        findings = [_finding()]
        endpoints = [_supabase_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) > 0
        assert all(isinstance(c, GuidedTestCase) for c in cases)
        assert all(
            c.test_type == GuidedDASTConfig.TEST_TYPE_RLS_BYPASS for c in cases
        )

    def test_target_url_is_supabase_rest_query(
        self, strategy: RLSBypassStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Target URL is a direct Supabase REST API query with select=*."""
        findings = [_finding()]
        endpoints = [_supabase_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) > 0
        for case in cases:
            assert "/rest/v1/" in case.target_url
            assert "select=*" in case.target_url

    def test_uses_anon_key_in_headers(
        self, strategy: RLSBypassStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Headers include the anon key from repo files."""
        findings = [_finding()]
        endpoints = [_supabase_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) > 0
        case = cases[0]
        assert SharedPatterns.HEADER_APIKEY in case.headers
        assert case.headers[SharedPatterns.HEADER_APIKEY] == MOCK_ANON_KEY
        assert SharedPatterns.HEADER_AUTHORIZATION in case.headers
        assert MOCK_ANON_KEY in case.headers[SharedPatterns.HEADER_AUTHORIZATION]

    def test_uses_get_method(
        self, strategy: RLSBypassStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """RLS bypass queries use GET."""
        findings = [_finding()]
        endpoints = [_supabase_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert all(c.http_method == "GET" for c in cases)

    def test_extracts_table_name_from_finding(
        self, strategy: RLSBypassStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Table name from finding appears in the target URL."""
        findings = [_finding(
            title="Table 'orders' has no RLS policy",
            description="Missing RLS on table 'orders'",
        )]
        endpoints = [_supabase_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) > 0
        assert any("orders" in c.target_url for c in cases)

    def test_does_not_generate_for_non_rls_findings(
        self, strategy: RLSBypassStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Finding without RLS keywords produces no tests."""
        findings = [CodeFinding(
            scanner_name="rls_policy_analyzer",
            severity=SeverityLevel.LOW,
            category=FindingCategory.RLS_MISCONFIGURATION,
            title="RLS policy exists but is permissive",
            description="Policy allows all authenticated users",
            file_path="supabase/migrations/001.sql",
            confidence=0.5,
        )]
        endpoints = [_supabase_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert cases == []

    def test_no_supabase_url_returns_empty(
        self, strategy: RLSBypassStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """No Supabase endpoint in discovered endpoints -> no tests."""
        findings = [_finding()]
        non_supabase_endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/api/users",
                method=EndpointMethod.GET,
            ),
        ]

        cases = strategy.generate_tests(findings, non_supabase_endpoints, repo_snapshot)

        assert cases == []

    def test_no_findings_no_tests(
        self, strategy: RLSBypassStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Empty findings -> empty result."""
        cases = strategy.generate_tests(
            [], [_supabase_endpoint()], repo_snapshot,
        )

        assert cases == []

    def test_handles_missing_anon_key(
        self, strategy: RLSBypassStrategy, repo_snapshot_no_key: RepoSnapshot,
    ) -> None:
        """Still generates tests when anon key is not found (empty string)."""
        findings = [_finding()]
        endpoints = [_supabase_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot_no_key)

        assert len(cases) > 0
        case = cases[0]
        assert case.headers[SharedPatterns.HEADER_APIKEY] == ""

    def test_test_case_fields(
        self, strategy: RLSBypassStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Test case has correct source and description."""
        finding = _finding()
        endpoints = [_supabase_endpoint()]

        cases = strategy.generate_tests([finding], endpoints, repo_snapshot)

        assert len(cases) > 0
        case = cases[0]
        assert case.source_finding_id == finding.id
        assert case.source_scanner == "rls_policy_analyzer"
        assert case.description != ""
        assert case.expected_behavior == GuidedDASTConfig.EXPECTED_RLS_BYPASS
