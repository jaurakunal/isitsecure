"""Tests for RaceConditionStrategy."""

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
from isitsecure.engine.guided_dast.strategies.race_condition import (
    RaceConditionStrategy,
)
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def strategy() -> RaceConditionStrategy:
    return RaceConditionStrategy()


@pytest.fixture()
def repo_snapshot() -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        route_map=[
            RouteEntry(
                file_path="src/routes/checkout.ts",
                route_pattern="/api/checkout",
                http_methods=["POST"],
            ),
            RouteEntry(
                file_path="src/routes/transfer.ts",
                route_pattern="/api/transfer",
                http_methods=["POST"],
            ),
        ],
        file_index={},
    )


def _finding(
    title: str = "Potential race condition in balance check",
    description: str = "TOCTOU: balance read and debit are not atomic",
    file_path: str = "src/routes/transfer.ts",
    code_snippet: str = "const balance = await getBalance(userId);",
) -> CodeFinding:
    return CodeFinding(
        scanner_name="llm_review",
        severity=SeverityLevel.HIGH,
        category=FindingCategory.AUTH_WEAKNESS,
        title=title,
        description=description,
        file_path=file_path,
        code_snippet=code_snippet,
        confidence=0.85,
    )


def _payment_finding() -> CodeFinding:
    return CodeFinding(
        scanner_name="llm_review",
        severity=SeverityLevel.HIGH,
        category=FindingCategory.AUTH_WEAKNESS,
        title="Race condition in payment processing",
        description="TOCTOU in checkout payment flow",
        file_path="src/routes/checkout.ts",
        code_snippet="const charge = await stripe.charges.create(amount);",
        confidence=0.9,
    )


def _endpoint(
    url: str = "https://example.com/api/transfer",
    method: EndpointMethod = EndpointMethod.POST,
) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(url=url, method=method)


# ---------------------------------------------------------------------------
# handles_scanner_names
# ---------------------------------------------------------------------------


class TestHandlesScannerNames:
    def test_handles_llm_review(self, strategy: RaceConditionStrategy) -> None:
        assert "llm_review" in strategy.handles_scanner_names

    def test_does_not_handle_other_scanners(self, strategy: RaceConditionStrategy) -> None:
        assert "route_auth_analyzer" not in strategy.handles_scanner_names


# ---------------------------------------------------------------------------
# generate_tests
# ---------------------------------------------------------------------------


class TestGenerateRaceConditionTests:
    def test_generates_concurrent_tests_for_race_finding(
        self, strategy: RaceConditionStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Finding with 'race condition' produces concurrent test cases."""
        findings = [_finding()]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) == GuidedDASTConfig.RACE_CONCURRENT_REQUESTS
        assert all(isinstance(c, GuidedTestCase) for c in cases)
        assert all(
            c.test_type == GuidedDASTConfig.TEST_TYPE_RACE_CONDITION for c in cases
        )

    def test_correct_number_of_concurrent_requests(
        self, strategy: RaceConditionStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Number of test cases equals RACE_CONCURRENT_REQUESTS."""
        findings = [_finding()]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) == GuidedDASTConfig.RACE_CONCURRENT_REQUESTS

    def test_all_use_post_method(
        self, strategy: RaceConditionStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """All concurrent requests use POST."""
        findings = [_finding()]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert all(c.http_method == "POST" for c in cases)

    def test_payment_endpoint_marked_dry_run(
        self, strategy: RaceConditionStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Payment endpoints have dry_run=True."""
        findings = [_payment_finding()]
        endpoints = [DiscoveredEndpoint(
            url="https://example.com/api/checkout",
            method=EndpointMethod.POST,
        )]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) > 0
        assert all(c.dry_run is True for c in cases)

    def test_non_payment_endpoint_not_dry_run(
        self, strategy: RaceConditionStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Non-payment endpoints have dry_run=False."""
        findings = [_finding()]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) > 0
        assert all(c.dry_run is False for c in cases)

    def test_does_not_generate_for_non_race_findings(
        self, strategy: RaceConditionStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Finding without race condition keywords produces no tests."""
        findings = [CodeFinding(
            scanner_name="llm_review",
            severity=SeverityLevel.MEDIUM,
            category=FindingCategory.INJECTION_RISK,
            title="SQL injection risk",
            description="Unsanitized input in query",
            file_path="src/routes/transfer.ts",
            confidence=0.8,
        )]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert cases == []

    def test_no_findings_no_tests(
        self, strategy: RaceConditionStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Empty findings -> empty result."""
        cases = strategy.generate_tests([], [_endpoint()], repo_snapshot)

        assert cases == []

    def test_toctou_keyword_triggers(
        self, strategy: RaceConditionStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Finding with 'toctou' keyword also triggers generation."""
        findings = [_finding(
            title="TOCTOU vulnerability in balance deduction",
            description="Time-of-check to time-of-use gap",
        )]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        assert len(cases) == GuidedDASTConfig.RACE_CONCURRENT_REQUESTS

    def test_batch_index_in_payload(
        self, strategy: RaceConditionStrategy, repo_snapshot: RepoSnapshot,
    ) -> None:
        """Each test case has a unique _race_batch index in payload."""
        findings = [_finding()]
        endpoints = [_endpoint()]

        cases = strategy.generate_tests(findings, endpoints, repo_snapshot)

        batch_indices = [c.payload["_race_batch"] for c in cases]
        assert batch_indices == list(range(GuidedDASTConfig.RACE_CONCURRENT_REQUESTS))
