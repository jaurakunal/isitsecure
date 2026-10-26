"""SAST-Guided DAST runner — executes targeted test cases against live endpoints.

Orchestrates the strategy pattern: each strategy generates test cases
from SAST findings, and this runner executes them via RateLimitedClient,
converting successful probes to DeepFindings.

SRP: This module is responsible ONLY for test case execution and result
     conversion.  Test case generation is delegated to strategies (OCP).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx

from isitsecure.engine.constants import GuidedDASTConfig
from isitsecure.engine.guided_dast import evidence
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
        self._catch_all_cache: dict[str, httpx.Response | None] = {}

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
    def _url_key(url: str) -> str:
        """Endpoint identity without query string or fragment."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    @classmethod
    def _deduplicate(
        cls,
        test_cases: list[GuidedTestCase],
        existing_findings: list[DeepFinding],
    ) -> list[GuidedTestCase]:
        """Remove test cases that target already-confirmed vulnerabilities."""
        existing_keys: set[str] = set()
        for f in existing_findings:
            if f.endpoint_url:
                existing_keys.add(
                    f"{cls._url_key(f.endpoint_url)}:{f.category.value}",
                )

        deduped: list[GuidedTestCase] = []
        seen_keys: set[str] = set()

        for tc in test_cases:
            _, category = _TEST_TYPE_METADATA.get(
                tc.test_type, (None, None),
            )
            finding_key = (
                f"{cls._url_key(tc.target_url)}:{category.value}"
                if category else ""
            )
            # The payload is part of the identity: the race batch is N
            # requests to one url/method that differ only by payload.
            payload_key = json.dumps(tc.payload, sort_keys=True, default=str)
            key = f"{tc.target_url}:{tc.test_type}:{tc.http_method}:{payload_key}"

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
        self._catch_all_cache = {}

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

    @staticmethod
    def _request_kwargs(
        method: str, payload: dict | None, headers: dict,
    ) -> dict:
        """Put the payload where the server reads it for this method.

        GET/HEAD/DELETE/OPTIONS carry parameters in the query string; a JSON
        body on those is ignored by almost every server, so the parameter
        would never reach the code the probe is aimed at.
        """
        kwargs: dict = {}
        if payload:
            if method.upper() in GuidedDASTConfig.QUERY_METHODS:
                kwargs["params"] = payload
            else:
                kwargs["json"] = payload
        if headers:
            kwargs["headers"] = headers
        return kwargs

    async def _send(
        self,
        client: RateLimitedClient,
        tc: GuidedTestCase,
        payload: dict | None = None,
    ) -> httpx.Response:
        """Send a test case (optionally with a replacement payload)."""
        body = tc.payload if payload is None else payload
        return await client.request(
            tc.http_method,
            tc.target_url,
            **self._request_kwargs(tc.http_method, body, tc.headers),
        )

    async def _catch_all(
        self, client: RateLimitedClient, url: str,
    ) -> httpx.Response | None:
        """Response of a path that cannot exist on the same origin (cached)."""
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in self._catch_all_cache:
            try:
                self._catch_all_cache[origin] = await client.request(
                    "GET", origin + GuidedDASTConfig.CATCH_ALL_PATH,
                )
            except Exception:
                self._catch_all_cache[origin] = None
        return self._catch_all_cache[origin]

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
            response = await self._send(client, test_case)
            verdict = await self._judge(client, test_case, response)
            if verdict:
                severity, confidence, note = verdict
                return self._test_case_to_finding(
                    test_case, response.status_code, response.text[:500],
                    severity=severity, confidence=confidence, note=note,
                )

        except Exception as e:
            logger.debug(
                GuidedDASTConfig.MSG_PROBE_ERROR.format(
                    url=test_case.target_url, error=str(e),
                ),
            )

        return None

    # ------------------------------------------------------------------
    # Verdicts: the response body decides, never the status code alone
    # ------------------------------------------------------------------

    async def _judge(
        self,
        client: RateLimitedClient,
        tc: GuidedTestCase,
        response: httpx.Response,
    ) -> tuple[SeverityLevel, float, str] | None:
        """Return (severity, confidence, evidence note) or None for no finding."""
        ok = response.status_code in _SUCCESS_STATUS_CODES
        t = tc.test_type
        cfg = GuidedDASTConfig

        if t == cfg.TEST_TYPE_SQLI:
            return await self._judge_sqli(client, tc, response)

        if not ok:
            return None

        if t == cfg.TEST_TYPE_XSS:
            value = next(iter((tc.payload or {}).values()), None)
            if isinstance(value, str) and evidence.reflects_unescaped(response, value):
                return (SeverityLevel.HIGH, cfg.CONFIDENCE_BODY_EVIDENCE,
                        cfg.EVIDENCE_REFLECTED)
            return None

        if t == cfg.TEST_TYPE_RLS_BYPASS:
            parsed = evidence.json_body(response)
            if isinstance(parsed, list) and parsed:
                return (SeverityLevel.CRITICAL, cfg.CONFIDENCE_CONFIRMED,
                        cfg.EVIDENCE_DATA)
            return None  # `[]` is what a table WITH RLS returns to the anon key

        if t == cfg.TEST_TYPE_IDOR:
            return await self._judge_idor(client, tc, response)

        if t == cfg.TEST_TYPE_MASS_ASSIGNMENT:
            if evidence.is_html(response) or not response.text.strip():
                return None
            if tc.payload and evidence.echoes_field(
                evidence.json_body(response), tc.payload,
            ):
                return (SeverityLevel.HIGH, cfg.CONFIDENCE_BODY_EVIDENCE,
                        cfg.EVIDENCE_FIELD_ECHOED)
            return (SeverityLevel.LOW, cfg.CONFIDENCE_WEAK, cfg.EVIDENCE_UNVERIFIED)

        if t == cfg.TEST_TYPE_AUTH_BYPASS:
            return await self._judge_auth_bypass(client, tc, response)

        return None

    async def _judge_sqli(
        self,
        client: RateLimitedClient,
        tc: GuidedTestCase,
        response: httpx.Response,
    ) -> tuple[SeverityLevel, float, str] | None:
        cfg = GuidedDASTConfig
        benign = {k: cfg.BENIGN_VALUE for k in (tc.payload or {})}
        signature = evidence.sql_error(response)
        if signature:
            baseline = await self._send(client, tc, benign)
            if not evidence.sql_error(baseline):
                return (SeverityLevel.CRITICAL, cfg.CONFIDENCE_BODY_EVIDENCE,
                        cfg.EVIDENCE_SQL_ERROR.format(signature=signature))
            return None
        if response.status_code >= 500:
            baseline = await self._send(client, tc, benign)
            if baseline.status_code < 500:
                return (SeverityLevel.MEDIUM, cfg.CONFIDENCE_PARTIAL,
                        cfg.EVIDENCE_SERVER_ERROR.format(status=response.status_code))
        return None

    async def _judge_idor(
        self,
        client: RateLimitedClient,
        tc: GuidedTestCase,
        response: httpx.Response,
    ) -> tuple[SeverityLevel, float, str] | None:
        cfg = GuidedDASTConfig
        if not tc.payload or evidence.is_html(response):
            return None
        if not evidence.has_data(evidence.json_body(response)):
            return None
        other = {k: cfg.BASELINE_ID for k in tc.payload}
        baseline = await self._send(client, tc, other)
        if baseline.status_code == response.status_code and baseline.text == response.text:
            # Same body whatever the id: static data, not per-object access.
            return (SeverityLevel.LOW, cfg.CONFIDENCE_WEAK, cfg.EVIDENCE_UNVERIFIED)
        return (SeverityLevel.MEDIUM, cfg.CONFIDENCE_PARTIAL, cfg.EVIDENCE_DATA)

    async def _judge_auth_bypass(
        self,
        client: RateLimitedClient,
        tc: GuidedTestCase,
        response: httpx.Response,
    ) -> tuple[SeverityLevel, float, str] | None:
        cfg = GuidedDASTConfig
        if not response.text.strip():
            return None
        shell = await self._catch_all(client, tc.target_url)
        if shell is not None and evidence.same_page(response, shell):
            return None  # the app answers every path with this page
        if evidence.has_data(evidence.json_body(response)):
            return (SeverityLevel.CRITICAL, cfg.CONFIDENCE_BODY_EVIDENCE,
                    cfg.EVIDENCE_DATA)
        return (SeverityLevel.MEDIUM, cfg.CONFIDENCE_WEAK, cfg.EVIDENCE_UNVERIFIED)

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
            responses = await asyncio.gather(
                *(self._send(client, tc) for tc in batch),
                return_exceptions=True,
            )

            # Successful, non-HTML responses only: an HTML shell "succeeds"
            # for every request and says nothing about server-side state.
            successes = [
                r for r in responses
                if not isinstance(r, Exception)
                and r.status_code in _SUCCESS_STATUS_CODES
                and not evidence.is_html(r)
            ]
            success_count = len(successes)

            if success_count > 1:
                # Distinct bodies (e.g. two different ids created) are some
                # evidence of duplicated work; identical bodies are not.
                distinct = len({r.text for r in successes}) > 1
                findings.append(self._test_case_to_finding(
                    batch[0],
                    successes[0].status_code,
                    GuidedDASTConfig.EVIDENCE_RACE_CONDITION.format(
                        count=success_count,
                        total=len(batch),
                    ),
                    severity=SeverityLevel.MEDIUM if distinct else SeverityLevel.LOW,
                    confidence=(
                        GuidedDASTConfig.CONFIDENCE_PARTIAL if distinct
                        else GuidedDASTConfig.CONFIDENCE_WEAK
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
        severity: SeverityLevel | None = None,
        confidence: float | None = None,
        note: str = "",
    ) -> DeepFinding:
        """Convert a probe verdict to a DeepFinding."""
        default_severity, category = _TEST_TYPE_METADATA.get(
            test_case.test_type,
            (SeverityLevel.MEDIUM, FindingCategory.AUTH_WEAKNESS),
        )
        severity = severity or default_severity

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
            ) + note,
            confidence=(
                GuidedDASTConfig.CONFIDENCE_CONFIRMED
                if confidence is None else confidence
            ),
            scanner_name=GuidedDASTConfig.SCANNER_NAME,
            endpoint_url=test_case.target_url,
            http_method=test_case.http_method,
            request_payload=str(test_case.payload) if test_case.payload else None,
            response_preview=response_preview,
            related_finding_ids=[test_case.source_finding_id],
        )
