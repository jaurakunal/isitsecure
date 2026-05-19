"""Auth bypass guided DAST strategy.

Generates test cases for endpoints identified by SAST as missing
authentication or authorization checks.
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


class AuthBypassGuidedStrategy:
    """Generates DAST tests for endpoints with missing auth checks.

    Handles findings from route_auth_analyzer that mention missing
    authentication or authorization.
    """

    # Keywords in finding titles/descriptions that indicate auth bypass risk
    _AUTH_MISSING_KEYWORDS = ("missing authentication", "missing authorization", "no auth")

    def __init__(self) -> None:
        self._matcher = RouteEndpointMatcher()

    @property
    def handles_scanner_names(self) -> list[str]:
        return ["route_auth_analyzer"]

    def generate_tests(
        self,
        code_findings: list[CodeFinding],
        endpoints: list[DiscoveredEndpoint],
        repo_snapshot: RepoSnapshot,
    ) -> list[GuidedTestCase]:
        """Generate auth bypass test cases for unauthenticated access."""
        test_cases: list[GuidedTestCase] = []

        for finding in code_findings:
            if not self._is_auth_bypass_finding(finding):
                continue

            matched_endpoints = self._matcher.find_endpoints_for_file(
                finding.file_path, repo_snapshot.route_map, endpoints,
            )

            for ep in matched_endpoints:
                # Test each HTTP method the route supports
                methods = self._get_methods_for_endpoint(ep, repo_snapshot)
                for method in methods:
                    test_cases.append(GuidedTestCase(
                        source_finding_id=finding.id,
                        source_scanner=finding.scanner_name,
                        test_type=GuidedDASTConfig.TEST_TYPE_AUTH_BYPASS,
                        target_url=ep.url,
                        http_method=method,
                        headers={},  # No auth headers — testing unauthenticated access
                        description=GuidedDASTConfig.DESC_AUTH_BYPASS.format(
                            method=method, url=ep.url,
                        ),
                        expected_behavior=GuidedDASTConfig.EXPECTED_AUTH_BYPASS,
                    ))

        return test_cases

    def _is_auth_bypass_finding(self, finding: CodeFinding) -> bool:
        """Check if the finding indicates missing auth."""
        combined = (finding.title + " " + finding.description).lower()
        return any(kw in combined for kw in self._AUTH_MISSING_KEYWORDS)

    @staticmethod
    def _get_methods_for_endpoint(
        ep: DiscoveredEndpoint,
        repo_snapshot: RepoSnapshot,
    ) -> list[str]:
        """Get HTTP methods for an endpoint from the route map."""
        for route in repo_snapshot.route_map:
            if route.route_pattern and route.route_pattern in ep.url:
                if route.http_methods:
                    return route.http_methods
        return [ep.method.value]
