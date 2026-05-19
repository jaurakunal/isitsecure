"""SAST-Guided DAST runner — executes targeted test cases against live endpoints.

Orchestrates the strategy pattern: each strategy generates test cases
from SAST findings, and this runner executes them via RateLimitedClient,
converting successful probes to DeepFindings.

SRP: This module is responsible ONLY for test case execution and result
     conversion.  Test case generation is delegated to strategies (OCP).
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from isitsecure.engine.constants import GuidedDASTConfig, SharedPatterns
from isitsecure.engine.guided_dast.protocols import (
    GuidedTestCase,
    GuidedTestStrategy,
)
from isitsecure.engine.models import DeepFinding, FindingSource
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.enums import FindingCategory, SeverityLevel

if TYPE_CHECKING:
    from isitsecure.engine.code_analysis.models import CodeFinding
    from isitsecure.engine.code_analysis.protocols import RepoSnapshot
    from isitsecure.engine.models import DiscoveredEndpoint

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity mapping: test_type -> (severity, category)
# ---------------------------------------------------------------------------

_TEST_TYPE_METADATA: dict[str, tuple[SeverityLevel, FindingCategory]] = {
    GuidedDASTConfig.TEST_TYPE_AUTH_BYPASS: (
        SeverityLevel.CRITICAL, FindingCategory.AUTH_WEAKNESS,
    ),
    GuidedDASTConfig.TEST_TYPE_IDOR: (
        SeverityLevel.HIGH, FindingCategory.IDOR,
    ),
    GuidedDASTConfig.TEST_TYPE_MASS_ASSIGNMENT: (
        SeverityLevel.HIGH, FindingCategory.PRIVILEGE_ESCALATION,
    ),
    GuidedDASTConfig.TEST_TYPE_RACE_CONDITION: (
        SeverityLevel.MEDIUM, FindingCategory.AUTH_WEAKNESS,
    ),
    GuidedDASTConfig.TEST_TYPE_SQLI: (
        SeverityLevel.CRITICAL, FindingCategory.INJECTION_RISK,
    ),
    GuidedDASTConfig.TEST_TYPE_XSS: (
        SeverityLevel.HIGH, FindingCategory.INJECTION_RISK,
    ),
    GuidedDASTConfig.TEST_TYPE_RLS_BYPASS: (
        SeverityLevel.CRITICAL, FindingCategory.RLS_MISCONFIGURATION,
    ),
}

# Status codes that indicate a successful probe (vulnerability confirmed)
_SUCCESS_STATUS_CODES = {200, 201, 202, 204}

# Status codes that indicate access was denied (expected behavior)
_DENIED_STATUS_CODES = {401, 403, 404, 405}


class SASTGuidedDASTRunner:
    """Executes SAST-guided DAST test cases against the running application.

    Constructor takes a list of strategies (OCP — new strategies added
    without modifying this runner).
    """

    def __init__(self, strategies: list[GuidedTestStrategy]) -> None:
        self._strategies = strategies

    async def run(
        self,
        code_findings: list[CodeFinding],
        endpoints: list[DiscoveredEndpoint],
        repo_snapshot: RepoSnapshot,
        existing_findings: list[DeepFinding],
    ) -> list[DeepFinding]:
        """Generate and execute SAST-guided DAST test cases.

        Args:
            code_findings: All SAST code findings from Phase 7.
            endpoints: Live discovered endpoints from Phase 2.
            repo_snapshot: Repository snapshot for context.
            existing_findings: Findings already discovered (for dedup).

        Returns:
            List of new DeepFindings from confirmed probes.
        """
        # Phase 1: Generate test cases from all strategies
        all_test_cases = self._generate_all_tests(
            code_findings, endpoints, repo_snapshot,
        )

        if not all_test_cases:
            logger.info(GuidedDASTConfig.MSG_NO_TESTS)
            return []

        # Phase 2: Deduplicate against existing findings
        test_cases = self._deduplicate(all_test_cases, existing_findings)

        # Phase 3: Prioritize by source finding severity, cap at MAX
        test_cases = self._prioritize_and_cap(test_cases, code_findings)

        logger.info(
            GuidedDASTConfig.MSG_EXECUTING.format(count=len(test_cases)),
        )

        # Phase 4: Execute test cases
        results = await self._execute_tests(test_cases)

        logger.info(
            GuidedDASTConfig.MSG_COMPLETED.format(
                confirmed=len(results), total=len(test_cases),
            ),
        )

        return results

    # ------------------------------------------------------------------
    # Test generation
    # ------------------------------------------------------------------

    def _generate_all_tests(
        self,
        code_findings: list[CodeFinding],
        endpoints: list[DiscoveredEndpoint],
        repo_snapshot: RepoSnapshot,
    ) -> list[GuidedTestCase]:
        """Generate test cases from all strategies."""
        all_tests: list[GuidedTestCase] = []

        for strategy in self._strategies:
            # Filter findings to those this strategy handles
            relevant_findings = [
                f for f in code_findings
                if f.scanner_name in strategy.handles_scanner_names
            ]
            if not relevant_findings:
                continue

            try:
                tests = strategy.generate_tests(
                    relevant_findings, endpoints, repo_snapshot,
                )
                all_tests.extend(tests)
            except Exception as e:
                logger.warning(
                    GuidedDASTConfig.MSG_STRATEGY_FAILED.format(
                        strategy=type(strategy).__name__, error=str(e),
                    ),
                )

        return all_tests

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate(
        test_cases: list[GuidedTestCase],
        existing_findings: list[DeepFinding],
    ) -> list[GuidedTestCase]:
        """Remove test cases that target already-confirmed vulnerabilities."""
        existing_keys: set[str] = set()
        for f in existing_findings:
            if f.endpoint_url:
                key = f"{f.endpoint_url}:{f.category.value}"
                existing_keys.add(key)

        deduped: list[GuidedTestCase] = []
        seen_keys: set[str] = set()

        for tc in test_cases:
            key = f"{tc.target_url}:{tc.test_type}:{tc.http_method}"
            finding_key = f"{tc.target_url}:{tc.test_type}"

            if key in seen_keys or finding_key in existing_keys:
                continue

            seen_keys.add(key)
            deduped.append(tc)

        return deduped

    # ------------------------------------------------------------------
    # Prioritization
    # ------------------------------------------------------------------

    def _prioritize_and_cap(
        self,
        test_cases: list[GuidedTestCase],
        code_findings: list[CodeFinding],
    ) -> list[GuidedTestCase]:
        """Sort by source finding severity (CRITICAL first), cap at MAX."""
        severity_rank = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
        }

        # Build a map of finding_id -> severity
        finding_severity: dict[str, SeverityLevel] = {
            f.id: f.severity for f in code_findings
        }

        def sort_key(tc: GuidedTestCase) -> int:
            sev = finding_severity.get(tc.source_finding_id, SeverityLevel.LOW)
            return severity_rank.get(sev, 4)

        sorted_cases = sorted(test_cases, key=sort_key)
        return sorted_cases[:GuidedDASTConfig.MAX_TEST_CASES]

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    async def _execute_tests(
        self,
        test_cases: list[GuidedTestCase],
    ) -> list[DeepFinding]:
        """Execute test cases and convert successful probes to DeepFindings."""
        findings: list[DeepFinding] = []

        async with RateLimitedClient(
            max_concurrent=GuidedDASTConfig.MAX_CONCURRENT,
            delay_seconds=GuidedDASTConfig.PROBE_DELAY,
            timeout_seconds=GuidedDASTConfig.HTTP_TIMEOUT,
            user_agent=GuidedDASTConfig.USER_AGENT,
        ) as client:
            # Group race condition tests for concurrent execution
            race_batches: dict[str, list[GuidedTestCase]] = {}
            normal_tests: list[GuidedTestCase] = []

            for tc in test_cases:
                if tc.test_type == GuidedDASTConfig.TEST_TYPE_RACE_CONDITION:
                    key = f"{tc.target_url}:{tc.source_finding_id}"
                    race_batches.setdefault(key, []).append(tc)
                else:
                    normal_tests.append(tc)

            # Execute normal tests sequentially (rate-limited)
            for tc in normal_tests:
                result = await self._execute_single_test(client, tc)
                if result:
                    findings.append(result)

            # Execute race condition batches concurrently
            for batch_key, batch in race_batches.items():
                results = await self._execute_race_batch(client, batch)
                findings.extend(results)

        return findings

    async def _execute_single_test(
        self,
        client: RateLimitedClient,
        test_case: GuidedTestCase,
    ) -> DeepFinding | None:
        """Execute a single test case and return a DeepFinding if vulnerable."""
        if test_case.dry_run:
            logger.info(
                GuidedDASTConfig.MSG_DRY_RUN.format(url=test_case.target_url),
            )
            return None

        try:
            kwargs: dict = {}
            if test_case.payload:
                kwargs["json"] = test_case.payload
            if test_case.headers:
                kwargs["headers"] = test_case.headers

            response = await client.request(
                test_case.http_method, test_case.target_url, **kwargs,
            )

            if response.status_code in _SUCCESS_STATUS_CODES:
                return self._test_case_to_finding(
                    test_case, response.status_code, response.text[:500],
                )

        except Exception as e:
            logger.debug(
                GuidedDASTConfig.MSG_PROBE_ERROR.format(
                    url=test_case.target_url, error=str(e),
                ),
            )

        return None

    async def _execute_race_batch(
        self,
        client: RateLimitedClient,
        batch: list[GuidedTestCase],
    ) -> list[DeepFinding]:
        """Execute a batch of race condition tests concurrently."""
        if not batch:
            return []

        # Skip dry-run batches
        if batch[0].dry_run:
            logger.info(
                GuidedDASTConfig.MSG_DRY_RUN.format(url=batch[0].target_url),
            )
            return []

        findings: list[DeepFinding] = []

        try:
            coros = []
            for tc in batch:
                kwargs: dict = {}
                if tc.payload:
                    kwargs["json"] = tc.payload
                if tc.headers:
                    kwargs["headers"] = tc.headers
                coros.append(client.request(tc.http_method, tc.target_url, **kwargs))

            responses = await asyncio.gather(*coros, return_exceptions=True)

            # Check if multiple requests succeeded (indicates race condition)
            success_count = sum(
                1 for r in responses
                if not isinstance(r, Exception) and r.status_code in _SUCCESS_STATUS_CODES
            )

            if success_count > 1:
                first_tc = batch[0]
                findings.append(self._test_case_to_finding(
                    first_tc,
                    200,
                    GuidedDASTConfig.EVIDENCE_RACE_CONDITION.format(
                        count=success_count,
                        total=len(batch),
                    ),
                ))

        except Exception as e:
            logger.debug(
                GuidedDASTConfig.MSG_PROBE_ERROR.format(
                    url=batch[0].target_url, error=str(e),
                ),
            )

        return findings

    # ------------------------------------------------------------------
    # Conversion
    # ------------------------------------------------------------------

    @staticmethod
    def _test_case_to_finding(
        test_case: GuidedTestCase,
        status_code: int,
        response_preview: str,
    ) -> DeepFinding:
        """Convert a successful probe to a DeepFinding."""
        severity, category = _TEST_TYPE_METADATA.get(
            test_case.test_type,
            (SeverityLevel.MEDIUM, FindingCategory.AUTH_WEAKNESS),
        )

        return DeepFinding(
            source=FindingSource.SAST_GUIDED_DAST,
            category=category,
            severity=severity,
            title=GuidedDASTConfig.FINDING_TITLE.format(
                test_type=test_case.test_type.replace("_", " ").title(),
                url=test_case.target_url,
            ),
            description=test_case.description,
            evidence=GuidedDASTConfig.FINDING_EVIDENCE.format(
                method=test_case.http_method,
                url=test_case.target_url,
                status=status_code,
            ),
            confidence=GuidedDASTConfig.CONFIDENCE_CONFIRMED,
            scanner_name=GuidedDASTConfig.SCANNER_NAME,
            endpoint_url=test_case.target_url,
            http_method=test_case.http_method,
            request_payload=str(test_case.payload) if test_case.payload else None,
            response_preview=response_preview,
            related_finding_ids=[test_case.source_finding_id],
        )
