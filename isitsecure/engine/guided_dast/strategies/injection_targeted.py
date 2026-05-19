"""Injection-targeted guided DAST strategy.

Generates SQLi and XSS payloads targeting specific parameters identified
by SAST injection pattern analysis.
"""

from __future__ import annotations

import re

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import GuidedDASTConfig
from isitsecure.engine.guided_dast.protocols import GuidedTestCase
from isitsecure.engine.guided_dast.route_endpoint_matcher import (
    RouteEndpointMatcher,
)
from isitsecure.engine.models import DiscoveredEndpoint


class InjectionTargetedStrategy:
    """Generates injection test cases using parameter names from SAST findings.

    Targets the specific parameters that SAST identified as vulnerable
    to injection, using both SQLi and XSS payloads.
    """

    _INJECTION_KEYWORDS = ("injection", "unsanitized", "user input", "sql", "xss")

    _SQLI_PAYLOADS = (
        "' OR '1'='1' --",
        "1; DROP TABLE users --",
        "' UNION SELECT NULL, NULL --",
    )

    _XSS_PAYLOADS = (
        "<script>alert(1)</script>",
        "'\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    )

    _PARAM_NAME_PATTERN = re.compile(
        r"(?:parameter|param|field|input|variable)\s+['\"`]?(\w+)['\"`]?",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        self._matcher = RouteEndpointMatcher()

    @property
    def handles_scanner_names(self) -> list[str]:
        return ["injection_pattern_trigger", "llm_review"]

    def generate_tests(
        self,
        code_findings: list[CodeFinding],
        endpoints: list[DiscoveredEndpoint],
        repo_snapshot: RepoSnapshot,
    ) -> list[GuidedTestCase]:
        """Generate injection test cases with targeted payloads."""
        test_cases: list[GuidedTestCase] = []

        for finding in code_findings:
            if not self._is_injection_finding(finding):
                continue

            param_names = self._extract_param_names(finding)
            if not param_names:
                param_names = ["q", "search", "input"]  # Fallback generic params

            matched_endpoints = self._matcher.find_endpoints_for_file(
                finding.file_path, repo_snapshot.route_map, endpoints,
            )

            for ep in matched_endpoints:
                for param in param_names:
                    # SQLi payloads
                    for payload in self._SQLI_PAYLOADS:
                        test_cases.append(GuidedTestCase(
                            source_finding_id=finding.id,
                            source_scanner=finding.scanner_name,
                            test_type=GuidedDASTConfig.TEST_TYPE_SQLI,
                            target_url=ep.url,
                            http_method=ep.method.value,
                            payload={param: payload},
                            description=GuidedDASTConfig.DESC_INJECTION.format(
                                injection_type="SQLi", param=param, url=ep.url,
                            ),
                            expected_behavior=GuidedDASTConfig.EXPECTED_INJECTION,
                        ))

                    # XSS payloads
                    for payload in self._XSS_PAYLOADS:
                        test_cases.append(GuidedTestCase(
                            source_finding_id=finding.id,
                            source_scanner=finding.scanner_name,
                            test_type=GuidedDASTConfig.TEST_TYPE_XSS,
                            target_url=ep.url,
                            http_method=ep.method.value,
                            payload={param: payload},
                            description=GuidedDASTConfig.DESC_INJECTION.format(
                                injection_type="XSS", param=param, url=ep.url,
                            ),
                            expected_behavior=GuidedDASTConfig.EXPECTED_INJECTION,
                        ))

        return test_cases

    def _is_injection_finding(self, finding: CodeFinding) -> bool:
        """Check if the finding indicates injection risk."""
        combined = (finding.title + " " + finding.description).lower()
        return any(kw in combined for kw in self._INJECTION_KEYWORDS)

    def _extract_param_names(self, finding: CodeFinding) -> list[str]:
        """Extract parameter names from the finding description or snippet."""
        combined = finding.description + " " + finding.code_snippet
        matches = self._PARAM_NAME_PATTERN.findall(combined)
        return list(dict.fromkeys(matches))  # Deduplicate preserving order
