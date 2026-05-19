"""RLS bypass guided DAST strategy.

Generates direct Supabase REST API queries to tables that SAST
identified as missing Row-Level Security policies.
"""

from __future__ import annotations

import re

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import GuidedDASTConfig, SharedPatterns
from isitsecure.engine.guided_dast.protocols import GuidedTestCase
from isitsecure.engine.models import DiscoveredEndpoint


class RLSBypassStrategy:
    """Generates direct Supabase REST API queries to tables without RLS.

    Targets tables that rls_policy_analyzer flagged as missing RLS by
    querying them directly via the Supabase REST API with only the
    anon key.
    """

    _RLS_KEYWORDS = ("no rls", "missing rls", "without rls", "rls not enabled")
    _TABLE_NAME_PATTERN = re.compile(
        r"(?:table|relation)\s+['\"`]?(\w+)['\"`]?", re.IGNORECASE,
    )

    def __init__(self) -> None:
        pass

    @property
    def handles_scanner_names(self) -> list[str]:
        return ["rls_policy_analyzer"]

    def generate_tests(
        self,
        code_findings: list[CodeFinding],
        endpoints: list[DiscoveredEndpoint],
        repo_snapshot: RepoSnapshot,
    ) -> list[GuidedTestCase]:
        """Generate direct Supabase REST API queries for tables without RLS."""
        test_cases: list[GuidedTestCase] = []

        # Find Supabase URL from endpoints
        supabase_url = self._find_supabase_url(endpoints)
        anon_key = self._find_anon_key(repo_snapshot)

        if not supabase_url:
            return test_cases

        for finding in code_findings:
            if not self._is_rls_finding(finding):
                continue

            table_names = self._extract_table_names(finding)
            for table in table_names:
                target_url = f"{supabase_url}/rest/v1/{table}?select=*"
                headers = {
                    SharedPatterns.HEADER_APIKEY: anon_key or "",
                    SharedPatterns.HEADER_AUTHORIZATION: (
                        f"{SharedPatterns.BEARER_PREFIX}{anon_key}" if anon_key else ""
                    ),
                }

                test_cases.append(GuidedTestCase(
                    source_finding_id=finding.id,
                    source_scanner=finding.scanner_name,
                    test_type=GuidedDASTConfig.TEST_TYPE_RLS_BYPASS,
                    target_url=target_url,
                    http_method="GET",
                    headers=headers,
                    description=GuidedDASTConfig.DESC_RLS_BYPASS.format(
                        table=table,
                    ),
                    expected_behavior=GuidedDASTConfig.EXPECTED_RLS_BYPASS,
                ))

        return test_cases

    def _is_rls_finding(self, finding: CodeFinding) -> bool:
        """Check if the finding indicates missing RLS."""
        combined = (finding.title + " " + finding.description).lower()
        return any(kw in combined for kw in self._RLS_KEYWORDS)

    def _extract_table_names(self, finding: CodeFinding) -> list[str]:
        """Extract table names from the finding description."""
        combined = finding.title + " " + finding.description + " " + finding.code_snippet
        matches = self._TABLE_NAME_PATTERN.findall(combined)
        return list(dict.fromkeys(matches))

    @staticmethod
    def _find_supabase_url(endpoints: list[DiscoveredEndpoint]) -> str | None:
        """Find the Supabase URL from discovered endpoints."""
        from urllib.parse import urlparse

        for ep in endpoints:
            if "supabase.co" in ep.url:
                parsed = urlparse(ep.url)
                if parsed.hostname:
                    return f"{parsed.scheme}://{parsed.hostname}"
        return None

    @staticmethod
    def _find_anon_key(repo_snapshot: RepoSnapshot) -> str | None:
        """Find the Supabase anon key from repository files."""
        anon_key_pattern = re.compile(
            r"(?:NEXT_PUBLIC_SUPABASE_ANON_KEY|SUPABASE_ANON_KEY|supabaseAnonKey)"
            r"\s*[:=]\s*['\"]?(eyJ[\w.+-]+)['\"]?",
        )
        for content in repo_snapshot.file_index.values():
            match = anon_key_pattern.search(content)
            if match:
                return match.group(1)
        return None
