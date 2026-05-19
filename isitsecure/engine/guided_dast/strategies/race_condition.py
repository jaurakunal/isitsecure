"""Race condition guided DAST strategy.

Generates concurrent request test cases for endpoints where LLM review
identified potential race conditions.
"""

from __future__ import annotations

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import GuidedDASTConfig
from isitsecure.engine.guided_dast.protocols import GuidedTestCase
from isitsecure.engine.guided_dast.route_endpoint_matcher import (
    RouteEndpointMatcher,
)
from isitsecure.engine.models import DiscoveredEndpoint


class RaceConditionStrategy:
    """Generates concurrent request tests for race condition endpoints.

    Creates multiple identical POST requests to be sent concurrently,
    targeting endpoints where LLM code review found race condition risks.
    Payment endpoints are marked as dry_run.
    """

    _RACE_KEYWORDS = ("race condition", "toctou", "time-of-check")
    _PAYMENT_KEYWORDS = ("payment", "charge", "checkout", "billing", "invoice")

    def __init__(self) -> None:
        self._matcher = RouteEndpointMatcher()

    @property
    def handles_scanner_names(self) -> list[str]:
        return ["llm_review"]

    def generate_tests(
        self,
        code_findings: list[CodeFinding],
        endpoints: list[DiscoveredEndpoint],
        repo_snapshot: RepoSnapshot,
    ) -> list[GuidedTestCase]:
        """Generate concurrent request test cases for race conditions."""
        test_cases: list[GuidedTestCase] = []

        for finding in code_findings:
            if not self._is_race_condition_finding(finding):
                continue

            matched_endpoints = self._matcher.find_endpoints_for_file(
                finding.file_path, repo_snapshot.route_map, endpoints,
            )

            is_payment = self._is_payment_endpoint(finding)

            for ep in matched_endpoints:
                # Generate N concurrent identical requests
                for i in range(GuidedDASTConfig.RACE_CONCURRENT_REQUESTS):
                    test_cases.append(GuidedTestCase(
                        source_finding_id=finding.id,
                        source_scanner=finding.scanner_name,
                        test_type=GuidedDASTConfig.TEST_TYPE_RACE_CONDITION,
                        target_url=ep.url,
                        http_method="POST",
                        payload={"_race_batch": i},
                        description=GuidedDASTConfig.DESC_RACE_CONDITION.format(
                            batch=i + 1,
                            total=GuidedDASTConfig.RACE_CONCURRENT_REQUESTS,
                            url=ep.url,
                        ),
                        expected_behavior=GuidedDASTConfig.EXPECTED_RACE_CONDITION,
                        dry_run=is_payment,
                    ))

        return test_cases

    def _is_race_condition_finding(self, finding: CodeFinding) -> bool:
        """Check if the finding indicates a race condition."""
        combined = (finding.title + " " + finding.description).lower()
        return any(kw in combined for kw in self._RACE_KEYWORDS)

    def _is_payment_endpoint(self, finding: CodeFinding) -> bool:
        """Check if the finding relates to a payment endpoint."""
        combined = (
            finding.title + " " + finding.description + " " + finding.file_path
        ).lower()
        return any(kw in combined for kw in self._PAYMENT_KEYWORDS)
