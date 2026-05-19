"""Mass assignment guided DAST strategy.

Generates test cases that attempt to set privileged fields (role, admin,
payment amounts) based on schema analysis findings.
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


class MassAssignmentSchemaStrategy:
    """Generates mass assignment tests using exact field names from schema analysis.

    Targets endpoints with POST/PUT/PATCH that accept the schema's
    privileged fields (role, isAdmin, price, amount).
    """

    _PRIVILEGED_FIELD_PATTERNS = (
        re.compile(r"\brole\b", re.IGNORECASE),
        re.compile(r"\bis_?admin\b", re.IGNORECASE),
        re.compile(r"\badmin\b", re.IGNORECASE),
        re.compile(r"\bprice\b", re.IGNORECASE),
        re.compile(r"\bamount\b", re.IGNORECASE),
        re.compile(r"\bpermission", re.IGNORECASE),
    )

    _MUTATION_METHODS = ("POST", "PUT", "PATCH")

    # Field name -> malicious test value
    _FIELD_PAYLOADS: dict[str, str | int | bool] = {
        "role": "admin",
        "isAdmin": True,
        "is_admin": True,
        "admin": True,
        "price": 0,
        "amount": 0,
        "permissions": "superadmin",
    }

    def __init__(self) -> None:
        self._matcher = RouteEndpointMatcher()

    @property
    def handles_scanner_names(self) -> list[str]:
        return ["drizzle_schema_analyzer", "prisma_schema_analyzer"]

    def generate_tests(
        self,
        code_findings: list[CodeFinding],
        endpoints: list[DiscoveredEndpoint],
        repo_snapshot: RepoSnapshot,
    ) -> list[GuidedTestCase]:
        """Generate mass assignment test cases with privileged fields."""
        test_cases: list[GuidedTestCase] = []

        for finding in code_findings:
            field_names = self._extract_privileged_fields(finding)
            if not field_names:
                continue

            matched_endpoints = self._matcher.find_endpoints_for_file(
                finding.file_path, repo_snapshot.route_map, endpoints,
            )

            for ep in matched_endpoints:
                for method in self._MUTATION_METHODS:
                    payload = self._build_payload(field_names)
                    test_cases.append(GuidedTestCase(
                        source_finding_id=finding.id,
                        source_scanner=finding.scanner_name,
                        test_type=GuidedDASTConfig.TEST_TYPE_MASS_ASSIGNMENT,
                        target_url=ep.url,
                        http_method=method,
                        payload=payload,
                        description=GuidedDASTConfig.DESC_MASS_ASSIGNMENT.format(
                            fields=", ".join(field_names), url=ep.url,
                        ),
                        expected_behavior=GuidedDASTConfig.EXPECTED_MASS_ASSIGNMENT,
                    ))

        return test_cases

    def _extract_privileged_fields(self, finding: CodeFinding) -> list[str]:
        """Extract privileged field names from the finding's code snippet."""
        combined = finding.title + " " + finding.description + " " + finding.code_snippet
        fields: list[str] = []

        for pattern in self._PRIVILEGED_FIELD_PATTERNS:
            match = pattern.search(combined)
            if match:
                fields.append(match.group(0))

        return fields

    def _build_payload(self, field_names: list[str]) -> dict:
        """Build a payload dict with malicious values for each field."""
        payload: dict = {}
        for field in field_names:
            # Find the closest matching payload key
            field_lower = field.lower().strip()
            for key, value in self._FIELD_PAYLOADS.items():
                if key.lower() in field_lower or field_lower in key.lower():
                    payload[field] = value
                    break
            else:
                # Default: try to escalate
                payload[field] = "admin"
        return payload
