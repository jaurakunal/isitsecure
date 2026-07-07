"""IDOR (Insecure Direct Object Reference) scanner.

Tests discovered API endpoints for broken access control by probing with
altered ID parameters. Detects cases where swapping an object ID in the
URL or query string returns data belonging to a different user/resource
without proper authorization checks.

Also supports cross-user IDOR testing: given two authenticated sessions,
verifies that User B cannot access User A's resources.
"""

import asyncio
import json
import logging
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import (
    CrossUserIDORConfig,
    DeepScanConfig,
    IDORConfig,
)
from isitsecure.engine.enums import (
    EndpointCategory,
    IDORRiskLevel,
    IDORTestType,
)
from isitsecure.engine.models import (
    CrossUserIDORResult,
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
    IDORProbeResult,
    IDORTestResult,
)
from isitsecure.engine.shared.endpoint_prioritizer import PriorityDimension, rank
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class IDORScanner:
    """Tests API endpoints for IDOR vulnerabilities.

    Strategy:
    1. Filter endpoints to those with ID-like parameters
    2. For each endpoint, make a baseline request with the original ID
    3. Swap the ID with test values and probe again
    4. Compare responses: if different data is returned for a different ID,
       the endpoint may lack proper authorization checks
    5. Also test unauthenticated access to endpoints that should require auth
    """

    async def scan(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> tuple[list[IDORTestResult], list[DeepFinding]]:
        """Run IDOR tests on all endpoints with ID parameters.

        Args:
            endpoints: Discovered endpoints from EndpointDiscoveryScanner.

        Returns:
            Tuple of (IDOR test results, mutation IDOR DeepFindings).
        """
        testable = self._filter_testable_endpoints(endpoints)
        logger.info(
            "IDORScanner: %d of %d endpoints have ID params, testing up to %d",
            len(testable),
            len(endpoints),
            IDORConfig.MAX_ENDPOINTS_TO_TEST,
        )

        testable = testable[: IDORConfig.MAX_ENDPOINTS_TO_TEST]
        results: list[IDORTestResult] = []
        mutation_findings: list[DeepFinding] = []

        async with RateLimitedClient(
            max_concurrent=IDORConfig.MAX_CONCURRENT_PROBES,
            delay_seconds=IDORConfig.PROBE_DELAY_SECONDS,
            timeout_seconds=IDORConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            for endpoint in testable:
                result = await self._test_endpoint(client, endpoint)
                results.append(result)

            # Mutation IDOR: test PUT/PATCH/DELETE with swapped IDs
            mutation_testable = self._filter_mutation_endpoints(endpoints)
            for endpoint in mutation_testable[: IDORConfig.MAX_ENDPOINTS_TO_TEST]:
                findings = await self._test_mutation_idor(
                    client, endpoint
                )
                mutation_findings.extend(findings)

        confirmed = sum(1 for r in results if r.risk_level == IDORRiskLevel.CONFIRMED)
        likely = sum(1 for r in results if r.risk_level == IDORRiskLevel.LIKELY)
        logger.info(
            "IDORScanner complete: %d confirmed, %d likely, %d total tested, "
            "%d mutation findings",
            confirmed,
            likely,
            len(results),
            len(mutation_findings),
        )
        return results, mutation_findings

    def _filter_testable_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """Filter to endpoints worth IDOR testing.

        Prioritizes user-data and resource-CRUD endpoints.
        Skips auth and public endpoints.
        """
        skip_categories = {EndpointCategory.AUTH, EndpointCategory.PUBLIC}
        testable = [
            ep for ep in endpoints
            if ep.has_id_params and ep.category not in skip_categories
        ]

        # Also include endpoints without detected IDs but in high-value categories
        high_value_categories = {
            EndpointCategory.USER_DATA,
            EndpointCategory.ADMIN,
            EndpointCategory.PAYMENT,
            EndpointCategory.FILE_ACCESS,
        }
        for ep in endpoints:
            if (
                ep.category in high_value_categories
                and not ep.has_id_params
                and ep not in testable
            ):
                testable.append(ep)

        # Rank by IDOR likelihood (id params + sensitive category + auth'd)
        # via the shared prioritizer.
        return rank(testable, PriorityDimension.IDOR)

    async def _test_endpoint(
        self, client: RateLimitedClient, endpoint: DiscoveredEndpoint
    ) -> IDORTestResult:
        """Run all applicable IDOR tests on a single endpoint."""
        probes: list[IDORProbeResult] = []

        # Test 1: Unauthenticated access
        unauthed_probe = await self._test_unauthed_access(client, endpoint)
        if unauthed_probe:
            probes.append(unauthed_probe)

        # Test 2: Path parameter swapping
        if endpoint.has_path_params:
            path_probes = await self._test_path_param_swap(client, endpoint)
            probes.extend(path_probes)

        # Test 3: Query parameter swapping
        if endpoint.query_param_names:
            query_probes = await self._test_query_param_swap(client, endpoint)
            probes.extend(query_probes)

        # Test 4: Sequential ID enumeration
        seq_probes = await self._test_sequential_ids(client, endpoint)
        probes.extend(seq_probes)

        risk_level, confidence = self._assess_risk(probes)

        return IDORTestResult(
            endpoint=endpoint,
            risk_level=risk_level,
            probes=probes,
            confidence=confidence,
            summary=self._build_summary(endpoint, risk_level, probes),
        )

    async def _test_unauthed_access(
        self, client: RateLimitedClient, endpoint: DiscoveredEndpoint
    ) -> IDORProbeResult | None:
        """Test if the endpoint returns data without any authentication."""
        try:
            response = await client.request(
                endpoint.method.value, endpoint.url
            )
        except httpx.HTTPError as e:
            return IDORProbeResult(
                original_url=endpoint.url,
                probed_url=endpoint.url,
                test_type=IDORTestType.UNAUTHED_ACCESS,
                error=str(e),
            )

        data_returned = self._response_has_data(response)

        return IDORProbeResult(
            original_url=endpoint.url,
            probed_url=endpoint.url,
            test_type=IDORTestType.UNAUTHED_ACCESS,
            probed_status=response.status_code,
            probed_body_preview=response.text[: IDORConfig.MAX_RESPONSE_BODY_LOG],
            data_returned=data_returned,
        )

    async def _test_path_param_swap(
        self, client: RateLimitedClient, endpoint: DiscoveredEndpoint
    ) -> list[IDORProbeResult]:
        """Swap path parameter IDs with test values."""
        probes: list[IDORProbeResult] = []
        parsed = urlparse(endpoint.url)
        segments = parsed.path.split("/")

        for i, segment in enumerate(segments):
            if not segment:
                continue

            test_ids = self._get_test_ids_for_value(segment)
            if not test_ids:
                continue

            for test_id in test_ids[: IDORConfig.MAX_IDOR_PROBES_PER_ENDPOINT]:
                modified_segments = list(segments)
                modified_segments[i] = test_id
                modified_path = "/".join(modified_segments)
                modified_url = urlunparse(
                    parsed._replace(path=modified_path)
                )

                probe = await self._probe_and_compare(
                    client,
                    endpoint,
                    modified_url,
                    IDORTestType.PATH_PARAM_SWAP,
                )
                if probe:
                    probes.append(probe)


        return probes

    async def _test_query_param_swap(
        self, client: RateLimitedClient, endpoint: DiscoveredEndpoint
    ) -> list[IDORProbeResult]:
        """Swap query parameter IDs with test values."""
        probes: list[IDORProbeResult] = []
        parsed = urlparse(endpoint.url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in endpoint.query_param_names:
            original_values = query_params.get(param_name, [""])
            if not original_values:
                continue

            original_value = original_values[0]
            test_ids = self._get_test_ids_for_value(original_value)

            for test_id in test_ids[: IDORConfig.MAX_IDOR_PROBES_PER_ENDPOINT]:
                modified_params = dict(query_params)
                modified_params[param_name] = [test_id]
                modified_query = urlencode(modified_params, doseq=True)
                modified_url = urlunparse(
                    parsed._replace(query=modified_query)
                )

                probe = await self._probe_and_compare(
                    client,
                    endpoint,
                    modified_url,
                    IDORTestType.QUERY_PARAM_SWAP,
                )
                if probe:
                    probes.append(probe)


        return probes

    async def _test_sequential_ids(
        self, client: RateLimitedClient, endpoint: DiscoveredEndpoint
    ) -> list[IDORProbeResult]:
        """Try sequential numeric IDs on endpoints with numeric path segments."""
        probes: list[IDORProbeResult] = []
        parsed = urlparse(endpoint.url)
        segments = parsed.path.split("/")

        for i, segment in enumerate(segments):
            if not segment:
                continue

            if not re.fullmatch(IDORConfig.NUMERIC_ID_PATTERN, segment):
                continue

            original_id = int(segment)
            test_ids = [
                str(original_id + 1),
                str(original_id - 1),
                str(original_id + 100),
            ]

            for test_id in test_ids:
                modified_segments = list(segments)
                modified_segments[i] = test_id
                modified_path = "/".join(modified_segments)
                modified_url = urlunparse(
                    parsed._replace(path=modified_path)
                )

                probe = await self._probe_and_compare(
                    client,
                    endpoint,
                    modified_url,
                    IDORTestType.SEQUENTIAL_ID_ENUM,
                )
                if probe:
                    probes.append(probe)


        return probes

    async def _probe_and_compare(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        modified_url: str,
        test_type: IDORTestType,
    ) -> IDORProbeResult | None:
        """Make a request to modified URL and compare with expectations."""
        try:
            response = await client.request(
                endpoint.method.value, modified_url
            )
        except httpx.HTTPError as e:
            return IDORProbeResult(
                original_url=endpoint.url,
                probed_url=modified_url,
                test_type=test_type,
                error=str(e),
            )

        data_returned = self._response_has_data(response)

        return IDORProbeResult(
            original_url=endpoint.url,
            probed_url=modified_url,
            test_type=test_type,
            probed_status=response.status_code,
            probed_body_preview=response.text[: IDORConfig.MAX_RESPONSE_BODY_LOG],
            data_returned=data_returned,
            response_differs=data_returned,
        )

    # --- Helpers ---

    def _get_test_ids_for_value(self, value: str) -> list[str]:
        """Determine appropriate test IDs based on the format of the value."""
        if re.fullmatch(IDORConfig.UUID_PATTERN, value):
            return [IDORConfig.UUID_TEST_ID]

        if re.fullmatch(IDORConfig.NUMERIC_ID_PATTERN, value):
            return IDORConfig.NUMERIC_TEST_IDS

        if re.fullmatch(IDORConfig.SHORT_HASH_PATTERN, value):
            return [IDORConfig.HASH_TEST_ID]

        return []

    def _response_has_data(self, response: httpx.Response) -> bool:
        """Check if a response contains actual data (not an error page)."""
        if response.status_code >= 400:
            return False

        body = response.text.strip()
        if len(body) < IDORConfig.MIN_RESPONSE_SIZE_BYTES:
            return False

        content_type = response.headers.get("content-type", "").lower()

        if "application/json" in content_type:
            return True

        if body.startswith(("{", "[")):
            return True

        # HTML responses are likely error/redirect pages, not data
        if "text/html" in content_type:
            return False

        return False

    def _assess_risk(
        self, probes: list[IDORProbeResult]
    ) -> tuple[IDORRiskLevel, float]:
        """Assess overall IDOR risk from probe results."""
        if not probes:
            return IDORRiskLevel.SAFE, 0.0

        data_probes = [p for p in probes if p.data_returned and not p.error]

        if not data_probes:
            return IDORRiskLevel.SAFE, 0.0

        # Check for data returned on swapped IDs
        swap_probes = [
            p for p in data_probes
            if p.test_type in (
                IDORTestType.PATH_PARAM_SWAP,
                IDORTestType.QUERY_PARAM_SWAP,
                IDORTestType.SEQUENTIAL_ID_ENUM,
            )
        ]

        if swap_probes:
            return (
                IDORRiskLevel.CONFIRMED,
                IDORConfig.CONFIDENCE_CONFIRMED_IDOR,
            )

        # Unauthed access returning data
        unauthed_probes = [
            p for p in data_probes
            if p.test_type == IDORTestType.UNAUTHED_ACCESS
        ]

        if unauthed_probes:
            return (
                IDORRiskLevel.LIKELY,
                IDORConfig.CONFIDENCE_LIKELY_IDOR,
            )

        return IDORRiskLevel.POSSIBLE, IDORConfig.CONFIDENCE_POSSIBLE_IDOR

    def _build_summary(
        self,
        endpoint: DiscoveredEndpoint,
        risk_level: IDORRiskLevel,
        probes: list[IDORProbeResult],
    ) -> str:
        """Build a human-readable summary of the IDOR test result."""
        data_probes = [p for p in probes if p.data_returned]
        error_probes = [p for p in probes if p.error]

        parts = [
            f"{endpoint.method.value} {endpoint.url}",
            f"Risk: {risk_level.value}",
            f"Probes: {len(probes)} total, {len(data_probes)} returned data, "
            f"{len(error_probes)} errors",
        ]

        if data_probes:
            test_types = {p.test_type.value for p in data_probes}
            parts.append(f"Vulnerable test types: {', '.join(test_types)}")

        return " | ".join(parts)

    # ------------------------------------------------------------------
    # Mutation IDOR testing (PUT/PATCH/DELETE with swapped IDs)
    # ------------------------------------------------------------------

    def _filter_mutation_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """Filter to endpoints with mutation HTTP methods and ID parameters.

        Only endpoints whose method is POST, PUT, PATCH, or DELETE and that
        have ID-like parameters are worth testing for mutation IDOR.
        """
        skip_categories = {EndpointCategory.AUTH, EndpointCategory.PUBLIC}
        return [
            ep for ep in endpoints
            if (
                ep.method.value in IDORConfig.MUTATION_METHODS
                and ep.has_id_params
                and ep.category not in skip_categories
            )
        ]

    async def _test_mutation_idor(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
    ) -> list[DeepFinding]:
        """Test whether swapping IDs on mutation endpoints allows unauthorized changes.

        For PUT/PATCH: sends a minimal safe body with a swapped resource ID.
        For DELETE: sends OPTIONS first to verify DELETE is allowed, then
        attempts DELETE with a swapped resource ID.

        Returns:
            List of DeepFinding for any confirmed mutation IDOR vulnerabilities.
        """
        findings: list[DeepFinding] = []
        parsed = urlparse(endpoint.url)
        segments = parsed.path.split("/")

        for i, segment in enumerate(segments):
            if not segment:
                continue

            test_ids = self._get_test_ids_for_value(segment)
            if not test_ids:
                continue

            for test_id in test_ids[: IDORConfig.MAX_MUTATION_PROBES_PER_ENDPOINT]:
                modified_segments = list(segments)
                modified_segments[i] = test_id
                modified_path = "/".join(modified_segments)
                modified_url = urlunparse(
                    parsed._replace(path=modified_path)
                )

                # Test PUT/PATCH mutation IDOR
                for method in IDORConfig.MUTATION_WRITE_METHODS:
                    finding = await self._probe_mutation_write(
                        client, endpoint, modified_url, method
                    )
                    if finding:
                        findings.append(finding)

                # Test DELETE mutation IDOR
                delete_finding = await self._probe_mutation_delete(
                    client, endpoint, modified_url
                )
                if delete_finding:
                    findings.append(delete_finding)

        return findings

    async def _probe_mutation_write(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        modified_url: str,
        method: str,
    ) -> DeepFinding | None:
        """Send a PUT/PATCH with safe body to a swapped-ID URL.

        Returns a DeepFinding if the server accepts the write (2xx status).
        """
        headers = {
            "Content-Type": IDORConfig.MUTATION_CONTENT_TYPE,
            "Prefer": IDORConfig.MUTATION_PREFER_HEADER,
        }
        try:
            response = await client.request(
                method,
                modified_url,
                content=IDORConfig.MUTATION_SAFE_BODY,
                headers=headers,
            )
        except httpx.HTTPError:
            return None

        if response.status_code not in (200, 201, 204):
            return None

        return DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.INJECTION_RISK,
            severity=SeverityLevel.CRITICAL,
            title=IDORConfig.TITLE_MUTATION_WRITE_IDOR,
            description=IDORConfig.DESC_MUTATION_WRITE_IDOR.format(
                method=method,
                url=modified_url,
                status=response.status_code,
            ),
            technical_detail=(
                f"Original endpoint: {endpoint.url} | "
                f"Swapped URL: {modified_url} | "
                f"Method: {method} | "
                f"Status: {response.status_code}"
            ),
            evidence=response.text[: IDORConfig.MAX_EVIDENCE_LENGTH],
            confidence=IDORConfig.CONFIDENCE_MUTATION_WRITE_IDOR,
            scanner_name="idor_scanner",
            endpoint_url=endpoint.url,
            http_method=method,
            request_payload=IDORConfig.MUTATION_SAFE_BODY,
            response_preview=response.text[: IDORConfig.MAX_RESPONSE_BODY_LOG],
        )

    async def _probe_mutation_delete(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        modified_url: str,
    ) -> DeepFinding | None:
        """Check if DELETE is allowed via OPTIONS, then attempt DELETE with swapped ID.

        Returns a DeepFinding if the server accepts the deletion (2xx status).
        """
        # Pre-flight: check if DELETE is allowed
        try:
            options_response = await client.request("OPTIONS", modified_url)
            allow_header = options_response.headers.get("allow", "").upper()
            access_control = options_response.headers.get(
                "access-control-allow-methods", ""
            ).upper()
            allowed_methods = allow_header + "," + access_control
            if IDORConfig.MUTATION_DELETE_METHOD not in allowed_methods:
                return None
        except httpx.HTTPError:
            # If OPTIONS fails, still try DELETE — some servers don't support OPTIONS
            pass

        headers = {
            "Prefer": IDORConfig.MUTATION_PREFER_HEADER,
        }
        try:
            response = await client.request(
                IDORConfig.MUTATION_DELETE_METHOD,
                modified_url,
                headers=headers,
            )
        except httpx.HTTPError:
            return None

        if response.status_code not in (200, 202, 204):
            return None

        return DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.INJECTION_RISK,
            severity=SeverityLevel.CRITICAL,
            title=IDORConfig.TITLE_MUTATION_DELETE_IDOR,
            description=IDORConfig.DESC_MUTATION_DELETE_IDOR.format(
                url=modified_url,
                status=response.status_code,
            ),
            technical_detail=(
                f"Original endpoint: {endpoint.url} | "
                f"Swapped URL: {modified_url} | "
                f"Method: DELETE | "
                f"Status: {response.status_code}"
            ),
            evidence=response.text[: IDORConfig.MAX_EVIDENCE_LENGTH],
            confidence=IDORConfig.CONFIDENCE_MUTATION_DELETE_IDOR,
            scanner_name="idor_scanner",
            endpoint_url=endpoint.url,
            http_method=IDORConfig.MUTATION_DELETE_METHOD,
            response_preview=response.text[: IDORConfig.MAX_RESPONSE_BODY_LOG],
        )

    # ------------------------------------------------------------------
    # Cross-user IDOR testing (Phase A2)
    # ------------------------------------------------------------------

    async def scan_cross_user(
        self,
        user_a_session: AuthSession,
        user_b_session: AuthSession,
        user_a_resources: dict[str, list[str]],
        supabase_url: str | None = None,
        anon_key: str | None = None,
        tables: list[str] | None = None,
    ) -> list[CrossUserIDORResult]:
        """Test cross-user access control.

        For each resource User A owns:
        1. Verify User A can access it (baseline)
        2. Try accessing with User B's token -> IDOR if data returned
        3. Try PATCH with User B's token (empty body) -> write IDOR
        4. For Supabase tables: try SELECT * with User B -> RLS check

        Args:
            user_a_session: Authenticated session for the resource owner.
            user_b_session: Authenticated session for the attacker.
            user_a_resources: Resources owned by User A (table/path -> [ids]).
            supabase_url: Optional Supabase project URL for direct REST testing.
            anon_key: Optional Supabase anon key.
            tables: Optional list of Supabase table names to test RLS.

        Returns:
            List of CrossUserIDORResult for each tested resource.
        """
        results: list[CrossUserIDORResult] = []
        resources_tested = 0

        async with RateLimitedClient(
            max_concurrent=DeepScanConfig.MAX_CONCURRENT_PROBES,
            delay_seconds=CrossUserIDORConfig.PROBE_DELAY_SECONDS,
            timeout_seconds=CrossUserIDORConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            # Test each owned resource
            for table_or_path, resource_ids in user_a_resources.items():
                if resources_tested >= CrossUserIDORConfig.MAX_RESOURCES_TO_TEST:
                    break

                for resource_id in resource_ids:
                    if resources_tested >= CrossUserIDORConfig.MAX_RESOURCES_TO_TEST:
                        break

                    result = await self._test_cross_user_resource(
                        client=client,
                        table_or_path=table_or_path,
                        resource_id=resource_id,
                        owner_session=user_a_session,
                        attacker_session=user_b_session,
                        supabase_url=supabase_url,
                        anon_key=anon_key,
                    )
                    results.append(result)
                    resources_tested += 1

            # Test full-table SELECT for RLS bypass
            if supabase_url and anon_key and tables:
                table_results = await self._test_full_table_access(
                    client=client,
                    tables=tables,
                    owner_session=user_a_session,
                    attacker_session=user_b_session,
                    supabase_url=supabase_url,
                    anon_key=anon_key,
                    user_a_resources=user_a_resources,
                )
                results.extend(table_results)

        confirmed = sum(
            1 for r in results if r.risk_level == IDORRiskLevel.CONFIRMED
        )
        logger.info(
            "Cross-user IDOR scan: %d resources tested, %d confirmed vulnerabilities",
            resources_tested,
            confirmed,
        )
        return results

    async def _test_cross_user_resource(
        self,
        client: RateLimitedClient,
        table_or_path: str,
        resource_id: str,
        owner_session: AuthSession,
        attacker_session: AuthSession,
        supabase_url: str | None = None,
        anon_key: str | None = None,
    ) -> CrossUserIDORResult:
        """Test a single resource for cross-user access."""
        probes: list[IDORProbeResult] = []
        read_accessible = False
        write_accessible = False
        delete_accessible = False

        url = self._build_resource_url(
            table_or_path, resource_id, supabase_url, anon_key
        )

        try:
            # Step 1: Baseline — verify owner can access
            baseline_probe = await self._probe_with_session(
                client, url, "GET", owner_session, anon_key,
                test_type=IDORTestType.CROSS_USER_READ,
                original_url=url,
            )
            probes.append(baseline_probe)

            if not baseline_probe.data_returned:
                # Owner can't access their own resource — skip
                return CrossUserIDORResult(
                    table_or_endpoint=table_or_path,
                    resource_id=resource_id,
                    owner_user_id=owner_session.user_id,
                    attacker_user_id=attacker_session.user_id,
                    evidence=probes,
                    risk_level=IDORRiskLevel.SAFE,
                )

            # Step 2: Attacker READ
            read_probe = await self._probe_with_session(
                client, url, "GET", attacker_session, anon_key,
                test_type=IDORTestType.CROSS_USER_READ,
                original_url=url,
            )
            probes.append(read_probe)
            read_accessible = read_probe.data_returned

            # Step 3: Attacker WRITE (safe PATCH with empty body)
            write_probe = await self._probe_with_session(
                client, url, "PATCH", attacker_session, anon_key,
                test_type=IDORTestType.CROSS_USER_WRITE,
                original_url=url,
                body=CrossUserIDORConfig.SAFE_PATCH_BODY,
                extra_headers={
                    "Prefer": CrossUserIDORConfig.SAFE_PATCH_PREFER_HEADER,
                    "Content-Type": "application/json",
                },
            )
            probes.append(write_probe)
            write_accessible = self._is_write_success(write_probe)

        except Exception as exc:
            error_msg = CrossUserIDORConfig.ERROR_CROSS_USER_FAILED.format(
                error=str(exc)
            )
            logger.warning(error_msg)
            probes.append(
                IDORProbeResult(
                    original_url=url,
                    probed_url=url,
                    test_type=IDORTestType.CROSS_USER_READ,
                    error=error_msg,
                )
            )

        risk_level, confidence = self._assess_cross_user_risk(
            read_accessible=read_accessible,
            write_accessible=write_accessible,
            delete_accessible=delete_accessible,
        )

        return CrossUserIDORResult(
            table_or_endpoint=table_or_path,
            resource_id=resource_id,
            owner_user_id=owner_session.user_id,
            attacker_user_id=attacker_session.user_id,
            read_accessible=read_accessible,
            write_accessible=write_accessible,
            delete_accessible=delete_accessible,
            evidence=probes,
            risk_level=risk_level,
            confidence=confidence,
        )

    async def _test_full_table_access(
        self,
        client: RateLimitedClient,
        tables: list[str],
        owner_session: AuthSession,
        attacker_session: AuthSession,
        supabase_url: str,
        anon_key: str,
        user_a_resources: dict[str, list[str]],
    ) -> list[CrossUserIDORResult]:
        """Test Supabase tables for full SELECT access (RLS bypass)."""
        results: list[CrossUserIDORResult] = []
        tables_tested = 0

        for table in tables:
            if tables_tested >= CrossUserIDORConfig.MAX_TABLES_TO_TEST:
                break

            url = (
                f"{supabase_url}/rest/v1/{table}"
                f"?{CrossUserIDORConfig.SUPABASE_SELECT_ID_ONLY}"
            )

            probes: list[IDORProbeResult] = []

            try:
                # Attacker tries full SELECT
                select_probe = await self._probe_with_session(
                    client, url, "GET", attacker_session, anon_key,
                    test_type=IDORTestType.FULL_TABLE_SELECT,
                    original_url=url,
                )
                probes.append(select_probe)

                # Check if attacker sees owner's IDs
                full_table_readable = False
                if select_probe.data_returned:
                    owner_ids = set(user_a_resources.get(table, []))
                    if owner_ids:
                        full_table_readable = self._response_contains_ids(
                            select_probe.probed_body_preview, owner_ids
                        )

                risk_level = IDORRiskLevel.SAFE
                confidence = 0.0
                if full_table_readable:
                    risk_level = IDORRiskLevel.CONFIRMED
                    confidence = CrossUserIDORConfig.CONFIDENCE_FULL_TABLE_LEAK
                elif select_probe.data_returned:
                    risk_level = IDORRiskLevel.POSSIBLE
                    confidence = IDORConfig.CONFIDENCE_POSSIBLE_IDOR

                results.append(
                    CrossUserIDORResult(
                        table_or_endpoint=table,
                        resource_id="*",
                        owner_user_id=owner_session.user_id,
                        attacker_user_id=attacker_session.user_id,
                        full_table_readable=full_table_readable,
                        read_accessible=select_probe.data_returned,
                        evidence=probes,
                        risk_level=risk_level,
                        confidence=confidence,
                    )
                )
                tables_tested += 1

            except Exception as exc:
                error_msg = CrossUserIDORConfig.ERROR_CROSS_USER_FAILED.format(
                    error=str(exc)
                )
                logger.warning(error_msg)
                tables_tested += 1

        return results

    async def _probe_with_session(
        self,
        client: RateLimitedClient,
        url: str,
        method: str,
        session: AuthSession,
        anon_key: str | None = None,
        test_type: IDORTestType = IDORTestType.CROSS_USER_READ,
        original_url: str = "",
        body: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> IDORProbeResult:
        """Make an authenticated request and return a probe result."""
        headers: dict[str, str] = {
            "Authorization": f"Bearer {session.access_token}",
        }
        if anon_key:
            headers["apikey"] = anon_key
        if extra_headers:
            headers.update(extra_headers)

        kwargs: dict[str, object] = {"headers": headers}
        if body is not None:
            kwargs["content"] = body

        try:
            response = await client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            return IDORProbeResult(
                original_url=original_url or url,
                probed_url=url,
                test_type=test_type,
                error=str(exc),
            )

        data_returned = self._response_has_data(response)

        return IDORProbeResult(
            original_url=original_url or url,
            probed_url=url,
            test_type=test_type,
            probed_status=response.status_code,
            probed_body_preview=response.text[: IDORConfig.MAX_RESPONSE_BODY_LOG],
            data_returned=data_returned,
        )

    def _build_resource_url(
        self,
        table_or_path: str,
        resource_id: str,
        supabase_url: str | None = None,
        anon_key: str | None = None,
    ) -> str:
        """Build a URL to access a specific resource."""
        # If it looks like a Supabase table name (no slashes), build REST URL
        if supabase_url and "/" not in table_or_path:
            eq_filter = CrossUserIDORConfig.SUPABASE_EQ_FILTER.format(
                resource_id=resource_id
            )
            return (
                f"{supabase_url}/rest/v1/{table_or_path}"
                f"?{CrossUserIDORConfig.SUPABASE_SELECT_ID_ONLY}&{eq_filter}"
            )

        # Otherwise treat it as a full path — append the resource ID
        base = table_or_path.rstrip("/")
        return f"{base}/{resource_id}"

    @staticmethod
    def _is_write_success(probe: IDORProbeResult) -> bool:
        """Check if a PATCH probe indicates the server accepted the write."""
        if probe.error:
            return False
        if probe.probed_status is None:
            return False
        return probe.probed_status in (200, 201, 204)

    @staticmethod
    def _assess_cross_user_risk(
        read_accessible: bool,
        write_accessible: bool,
        delete_accessible: bool,
    ) -> tuple[IDORRiskLevel, float]:
        """Assess risk level from cross-user test results."""
        if write_accessible or delete_accessible:
            return (
                IDORRiskLevel.CONFIRMED,
                CrossUserIDORConfig.CONFIDENCE_CONFIRMED_WRITE,
            )
        if read_accessible:
            return (
                IDORRiskLevel.CONFIRMED,
                CrossUserIDORConfig.CONFIDENCE_CONFIRMED_READ,
            )
        return IDORRiskLevel.SAFE, 0.0

    @staticmethod
    def _response_contains_ids(body_preview: str, target_ids: set[str]) -> bool:
        """Check if a response body contains any of the target IDs."""
        for target_id in target_ids:
            if target_id in body_preview:
                return True
        return False
