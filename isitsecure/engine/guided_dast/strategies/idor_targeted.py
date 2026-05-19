"""IDOR-targeted guided DAST strategy.

Generates test cases for endpoints where SAST found missing ownership
checks or IDOR-risk indicators, probing with swapped IDs.
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


class IDORTargetedStrategy:
    """Generates IDOR probe tests using parameter names from SAST findings.

    Targets endpoints where route_auth_analyzer found missing ownership
    checks, swapping the specific parameter identified in the code.
    """

    _IDOR_KEYWORDS = ("ownership", "idor", "object reference", "user_id check")
    _PROBE_ID = "00000000-0000-0000-0000-000000000001"

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
        """Generate IDOR probe test cases with swapped IDs."""
        test_cases: list[GuidedTestCase] = []

        for finding in code_findings:
            if not self._is_idor_finding(finding):
                continue

            matched_endpoints = self._matcher.find_endpoints_for_file(
                finding.file_path, repo_snapshot.route_map, endpoints,
            )

            for ep in matched_endpoints:
                param_name = self._extract_param_name(finding, ep)
                test_cases.append(GuidedTestCase(
                    source_finding_id=finding.id,
                    source_scanner=finding.scanner_name,
                    test_type=GuidedDASTConfig.TEST_TYPE_IDOR,
                    target_url=ep.url,
                    http_method=ep.method.value,
                    payload={param_name: self._PROBE_ID} if param_name else None,
                    description=GuidedDASTConfig.DESC_IDOR.format(
                        param=param_name or "id", url=ep.url,
                    ),
                    expected_behavior=GuidedDASTConfig.EXPECTED_IDOR,
                ))

        return test_cases

    def _is_idor_finding(self, finding: CodeFinding) -> bool:
        """Check if the finding indicates IDOR risk."""
        combined = (finding.title + " " + finding.description).lower()
        return any(kw in combined for kw in self._IDOR_KEYWORDS)

    @staticmethod
    def _extract_param_name(
        finding: CodeFinding,
        ep: DiscoveredEndpoint,
    ) -> str | None:
        """Extract the parameter name from the finding or endpoint."""
        # Prefer parameter names from endpoint discovery
        if ep.path_param_names:
            return ep.path_param_names[0]
        if ep.query_param_names:
            return ep.query_param_names[0]
        # Fallback: look for common ID param names in the code snippet
        snippet = finding.code_snippet.lower()
        for param in ("user_id", "userId", "id", "uuid"):
            if param.lower() in snippet:
                return param
        return None
