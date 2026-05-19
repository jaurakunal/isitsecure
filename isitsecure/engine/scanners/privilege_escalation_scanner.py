"""Privilege escalation scanner.

Tests if regular users can access admin-level resources or perform
operations beyond their role.  Uses both sessions (admin + regular)
and intercepted requests from the authenticated crawl.

Tests:
1. Admin Supabase tables readable by regular user
2. Role self-elevation (can user PATCH their own role?)
3. Admin API routes accessible by regular user
4. Authenticated endpoint access with regular user
5. Differential response — admin sees more data than regular user
6. Mutation replay — replay admin write ops with regular user token
7. Object-level write — can regular user modify admin's resources?
8. RPC function access — can regular user call server functions?
"""

from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import (
    DeepScanConfig,
    PrivilegeEscalationConfig,
    RLSDeepScanConfig,
    SharedPatterns,
)
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
    InterceptedRequest,
)
from isitsecure.engine.shared.rate_limited_client import (
    RateLimitedClient,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class PrivilegeEscalationScanner:
    """Tests for privilege escalation vulnerabilities."""

    @property
    def scanner_name(self) -> str:
        return PrivilegeEscalationConfig.SCANNER_NAME

    # ------------------------------------------------------------------
    # Finding factory (DRY — all findings share source/category/scanner)
    # ------------------------------------------------------------------

    def _make_finding(
        self,
        severity: SeverityLevel,
        title: str,
        description: str,
        confidence: float,
        endpoint_url: str,
        http_method: str,
        response_preview: str = "",
        request_payload: str | None = None,
    ) -> DeepFinding:
        """Build a privilege escalation finding with common fields."""
        return DeepFinding(
            source=FindingSource.DAST_AUTHENTICATED,
            category=FindingCategory.PRIVILEGE_ESCALATION,
            severity=severity,
            title=title,
            description=description,
            confidence=confidence,
            scanner_name=self.scanner_name,
            endpoint_url=endpoint_url,
            http_method=http_method,
            response_preview=response_preview[
                : PrivilegeEscalationConfig.RESPONSE_PREVIEW_LENGTH
            ],
            request_payload=request_payload,
        )

    # ------------------------------------------------------------------
    # Main scan
    # ------------------------------------------------------------------

    async def scan(
        self,
        regular_user_session: AuthSession,
        admin_session: AuthSession | None = None,
        endpoints: list[DiscoveredEndpoint] | None = None,
        supabase_url: str | None = None,
        anon_key: str | None = None,
        tables: list[str] | None = None,
        intercepted_requests: list[InterceptedRequest] | None = None,
        owned_resource_ids: dict[str, list[str]] | None = None,
        rpc_functions: list[str] | None = None,
    ) -> list[DeepFinding]:
        """Run all privilege escalation tests."""
        findings: list[DeepFinding] = []

        async with RateLimitedClient(
            max_concurrent=PrivilegeEscalationConfig.MAX_CONCURRENT_PROBES,
            delay_seconds=PrivilegeEscalationConfig.PROBE_DELAY_SECONDS,
            timeout_seconds=PrivilegeEscalationConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            # Test 1 + 2: Supabase table tests
            if supabase_url and anon_key and tables:
                for t in tables:
                    if self._is_admin_table(t):
                        f = await self._test_admin_table_access(
                            client, supabase_url, anon_key, t,
                            regular_user_session,
                        )
                        if f:
                            findings.append(f)
                    if self._is_role_table(t):
                        findings.extend(
                            await self._test_role_escalation(
                                client, supabase_url, anon_key, t,
                                regular_user_session,
                            )
                        )

            # Test 3: Admin routes
            admin_eps = [
                e for e in (endpoints or []) if self._is_admin_endpoint(e)
            ]
            for ep in admin_eps:
                f = await self._test_admin_route_access(
                    client, ep, regular_user_session
                )
                if f:
                    findings.append(f)

            # Test 4: Authenticated endpoint access
            auth_eps = [
                e for e in (endpoints or [])
                if e.requires_auth and not self._is_admin_endpoint(e)
            ]
            for ep in auth_eps[
                : PrivilegeEscalationConfig.MAX_AUTH_ENDPOINTS_TO_TEST
            ]:
                f = await self._test_authenticated_endpoint_access(
                    client, ep, regular_user_session
                )
                if f:
                    findings.append(f)

            # Test 5: Differential response
            if admin_session and endpoints:
                findings.extend(
                    await self._test_differential_responses(
                        client, endpoints, admin_session,
                        regular_user_session,
                    )
                )

            # Test 6: Mutation replay
            if intercepted_requests:
                findings.extend(
                    await self._test_mutation_replay(
                        client, intercepted_requests,
                        regular_user_session,
                    )
                )

            # Test 7: Object-level write
            if supabase_url and anon_key and owned_resource_ids:
                findings.extend(
                    await self._test_object_level_write(
                        client, supabase_url, anon_key,
                        owned_resource_ids, regular_user_session,
                    )
                )

            # Test 8: RPC function access
            if supabase_url and anon_key and rpc_functions:
                findings.extend(
                    await self._test_rpc_function_access(
                        client, supabase_url, anon_key,
                        regular_user_session, rpc_functions,
                    )
                )

        logger.info(
            "PrivilegeEscalation: %d findings (tables=%d, endpoints=%d, "
            "mutations=%d, resources=%d, rpc=%d)",
            len(findings),
            len(tables or []),
            len(endpoints or []),
            len(intercepted_requests or []),
            sum(len(v) for v in (owned_resource_ids or {}).values()),
            len(rpc_functions or []),
        )
        return findings

    # ------------------------------------------------------------------
    # Test 1: Admin table access
    # ------------------------------------------------------------------

    async def _test_admin_table_access(
        self, client: RateLimitedClient, supabase_url: str,
        anon_key: str, table: str, session: AuthSession,
    ) -> DeepFinding | None:
        url = (
            f"{supabase_url}/rest/v1/{table}"
            f"?{RLSDeepScanConfig.SELECT_ID_ONLY}"
            f"&{RLSDeepScanConfig.LIMIT_ONE}"
        )
        headers = self._build_supabase_headers(session, anon_key)
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code in PrivilegeEscalationConfig.SUCCESS_READ_CODES:
                body = resp.text.strip()
                if body and body != "[]":
                    return self._make_finding(
                        SeverityLevel.HIGH,
                        PrivilegeEscalationConfig.TITLE_ADMIN_TABLE.format(table=table),
                        PrivilegeEscalationConfig.DESC_ADMIN_TABLE.format(table=table),
                        PrivilegeEscalationConfig.CONFIDENCE_ADMIN_TABLE_ACCESS,
                        url, "GET", body,
                    )
        except Exception as exc:
            logger.debug(
                PrivilegeEscalationConfig.ERROR_ADMIN_TABLE_FAILED.format(
                    table=table, error=str(exc)
                )
            )
        return None

    # ------------------------------------------------------------------
    # Test 2: Role self-elevation
    # ------------------------------------------------------------------

    async def _test_role_escalation(
        self, client: RateLimitedClient, supabase_url: str,
        anon_key: str, table: str, session: AuthSession,
    ) -> list[DeepFinding]:
        findings: list[DeepFinding] = []
        url = f"{supabase_url}/rest/v1/{table}?user_id=eq.{session.user_id}"
        headers = self._build_supabase_headers(session, anon_key)
        headers[SharedPatterns.HEADER_CONTENT_TYPE] = SharedPatterns.CONTENT_TYPE_JSON
        headers["Prefer"] = RLSDeepScanConfig.SAFE_WRITE_PREFER

        for field, value in PrivilegeEscalationConfig.ROLE_ESCALATION_FIELDS:
            payload = json.dumps({field: value})
            try:
                resp = await client.patch(url, content=payload, headers=headers)
                if resp.status_code in PrivilegeEscalationConfig.SUCCESS_WRITE_CODES:
                    findings.append(self._make_finding(
                        SeverityLevel.CRITICAL,
                        PrivilegeEscalationConfig.TITLE_ROLE_ESCALATION.format(table=table),
                        PrivilegeEscalationConfig.DESC_ROLE_ESCALATION.format(
                            table=table, field=field, value=value,
                        ),
                        PrivilegeEscalationConfig.CONFIDENCE_ROLE_ESCALATION,
                        url, "PATCH", resp.text, payload,
                    ))
            except Exception as exc:
                logger.debug(
                    PrivilegeEscalationConfig.ERROR_PRIV_ESC_FAILED.format(error=str(exc))
                )
        return findings

    # ------------------------------------------------------------------
    # Test 3: Admin route access
    # ------------------------------------------------------------------

    async def _test_admin_route_access(
        self, client: RateLimitedClient,
        endpoint: DiscoveredEndpoint, session: AuthSession,
    ) -> DeepFinding | None:
        headers = self._build_auth_headers(session)
        try:
            resp = await client.get(endpoint.url, headers=headers)
            if resp.status_code in PrivilegeEscalationConfig.SUCCESS_READ_CODES:
                path = urlparse(endpoint.url).path
                return self._make_finding(
                    SeverityLevel.HIGH,
                    PrivilegeEscalationConfig.TITLE_ADMIN_ROUTE.format(path=path),
                    PrivilegeEscalationConfig.DESC_ADMIN_ROUTE.format(
                        path=path, status=resp.status_code,
                    ),
                    PrivilegeEscalationConfig.CONFIDENCE_ADMIN_ROUTE_ACCESS,
                    endpoint.url, "GET", resp.text,
                )
        except Exception as exc:
            path = urlparse(endpoint.url).path
            logger.debug(
                PrivilegeEscalationConfig.ERROR_ADMIN_ROUTE_FAILED.format(
                    path=path, error=str(exc)
                )
            )
        return None

    # ------------------------------------------------------------------
    # Test 4: Authenticated endpoint access
    # ------------------------------------------------------------------

    async def _test_authenticated_endpoint_access(
        self, client: RateLimitedClient,
        endpoint: DiscoveredEndpoint, session: AuthSession,
    ) -> DeepFinding | None:
        headers = self._build_auth_headers(session)
        try:
            method = endpoint.method.value.upper()
            if method in PrivilegeEscalationConfig.WRITE_METHODS:
                resp = await client.request(
                    method, endpoint.url, headers=headers, json={},
                )
            else:
                resp = await client.get(endpoint.url, headers=headers)

            if resp.status_code in PrivilegeEscalationConfig.SUCCESS_READ_CODES:
                path = urlparse(endpoint.url).path
                return self._make_finding(
                    SeverityLevel.MEDIUM,
                    PrivilegeEscalationConfig.TITLE_AUTH_ENDPOINT.format(path=path),
                    PrivilegeEscalationConfig.DESC_AUTH_ENDPOINT.format(
                        path=path, method=method, status=resp.status_code,
                    ),
                    PrivilegeEscalationConfig.CONFIDENCE_AUTH_ENDPOINT,
                    endpoint.url, method, resp.text,
                )
        except Exception as exc:
            logger.debug(
                PrivilegeEscalationConfig.ERROR_AUTH_ENDPOINT_FAILED.format(
                    path=urlparse(endpoint.url).path, error=str(exc),
                )
            )
        return None

    # ------------------------------------------------------------------
    # Test 5: Differential response (admin vs regular)
    # ------------------------------------------------------------------

    async def _test_differential_responses(
        self, client: RateLimitedClient,
        endpoints: list[DiscoveredEndpoint],
        admin_session: AuthSession, regular_session: AuthSession,
    ) -> list[DeepFinding]:
        findings: list[DeepFinding] = []
        testable = [
            e for e in endpoints
            if e.requires_auth and e.method.value == "GET"
        ]

        for ep in testable[
            : PrivilegeEscalationConfig.MAX_DIFFERENTIAL_ENDPOINTS
        ]:
            try:
                admin_resp = await client.get(
                    ep.url, headers=self._build_auth_headers(admin_session),
                )
                regular_resp = await client.get(
                    ep.url, headers=self._build_auth_headers(regular_session),
                )

                if (
                    admin_resp.status_code not in PrivilegeEscalationConfig.SUCCESS_READ_CODES
                    or regular_resp.status_code not in PrivilegeEscalationConfig.SUCCESS_READ_CODES
                ):
                    continue

                admin_size = len(admin_resp.text)
                regular_size = len(regular_resp.text)

                if (
                    admin_size > PrivilegeEscalationConfig.DIFFERENTIAL_MIN_SIZE
                    and regular_size > PrivilegeEscalationConfig.DIFFERENTIAL_MIN_SIZE
                    and admin_size > regular_size * PrivilegeEscalationConfig.DIFFERENTIAL_SIZE_RATIO
                ):
                    admin_count = self._count_json_records(admin_resp.text)
                    regular_count = self._count_json_records(regular_resp.text)

                    if admin_count > 0 and regular_count > 0 and admin_count > regular_count:
                        path = urlparse(ep.url).path
                        findings.append(self._make_finding(
                            SeverityLevel.HIGH,
                            PrivilegeEscalationConfig.TITLE_DIFFERENTIAL.format(path=path),
                            PrivilegeEscalationConfig.DESC_DIFFERENTIAL.format(
                                path=path,
                                admin_size=admin_size,
                                regular_size=regular_size,
                            ),
                            PrivilegeEscalationConfig.CONFIDENCE_DIFFERENTIAL,
                            ep.url, "GET",
                            f"Admin ({admin_count} records, {admin_size}B) vs "
                            f"Regular ({regular_count} records, {regular_size}B)",
                        ))
            except Exception as exc:
                logger.debug(
                    PrivilegeEscalationConfig.ERROR_DIFFERENTIAL_FAILED.format(
                        path=urlparse(ep.url).path, error=str(exc),
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # Test 6: Mutation replay
    # ------------------------------------------------------------------

    async def _test_mutation_replay(
        self, client: RateLimitedClient,
        intercepted: list[InterceptedRequest],
        regular_session: AuthSession,
    ) -> list[DeepFinding]:
        findings: list[DeepFinding] = []
        mutations = [
            r for r in intercepted
            if r.method.upper() in PrivilegeEscalationConfig.MUTATION_METHODS
            and r.response_status in PrivilegeEscalationConfig.SUCCESS_MUTATION_CODES
        ]

        headers = self._build_auth_headers(regular_session)
        headers[SharedPatterns.HEADER_CONTENT_TYPE] = SharedPatterns.CONTENT_TYPE_JSON

        for req in mutations[
            : PrivilegeEscalationConfig.MAX_MUTATIONS_TO_REPLAY
        ]:
            try:
                method = req.method.upper()
                kwargs: dict = {"headers": headers}
                if req.request_body and method in PrivilegeEscalationConfig.WRITE_METHODS:
                    kwargs["content"] = req.request_body

                resp = await client.request(method, req.url, **kwargs)

                if resp.status_code in PrivilegeEscalationConfig.SUCCESS_MUTATION_CODES:
                    path = urlparse(req.url).path
                    findings.append(self._make_finding(
                        SeverityLevel.HIGH,
                        PrivilegeEscalationConfig.TITLE_MUTATION_REPLAY.format(
                            method=method, path=path,
                        ),
                        PrivilegeEscalationConfig.DESC_MUTATION_REPLAY.format(
                            method=method, path=path, status=resp.status_code,
                        ),
                        PrivilegeEscalationConfig.CONFIDENCE_MUTATION_REPLAY,
                        req.url, method, resp.text, req.request_body,
                    ))
            except Exception as exc:
                logger.debug(
                    PrivilegeEscalationConfig.ERROR_MUTATION_REPLAY_FAILED.format(
                        url=req.url, error=str(exc),
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # Test 7: Object-level write
    # ------------------------------------------------------------------

    async def _test_object_level_write(
        self, client: RateLimitedClient, supabase_url: str,
        anon_key: str, owned_resource_ids: dict[str, list[str]],
        regular_session: AuthSession,
    ) -> list[DeepFinding]:
        findings: list[DeepFinding] = []
        headers = self._build_supabase_headers(regular_session, anon_key)
        headers[SharedPatterns.HEADER_CONTENT_TYPE] = SharedPatterns.CONTENT_TYPE_JSON
        headers["Prefer"] = RLSDeepScanConfig.SAFE_WRITE_PREFER

        tested = 0
        for table, resource_ids in owned_resource_ids.items():
            if "/" in table:
                continue

            for rid in resource_ids:
                if tested >= PrivilegeEscalationConfig.MAX_RESOURCES_FOR_WRITE_TEST:
                    break

                url = f"{supabase_url}/rest/v1/{table}?id=eq.{rid}"
                payload = SharedPatterns.SAFE_PATCH_BODY

                try:
                    resp = await client.patch(url, content=payload, headers=headers)
                    if resp.status_code in PrivilegeEscalationConfig.SUCCESS_WRITE_CODES:
                        findings.append(self._make_finding(
                            SeverityLevel.CRITICAL,
                            PrivilegeEscalationConfig.TITLE_OBJECT_WRITE.format(table=table),
                            PrivilegeEscalationConfig.DESC_OBJECT_WRITE.format(
                                method="PATCH", resource_id=rid,
                                table=table, status=resp.status_code,
                            ),
                            PrivilegeEscalationConfig.CONFIDENCE_OBJECT_WRITE,
                            url, "PATCH", resp.text, payload,
                        ))
                except Exception as exc:
                    logger.debug(
                        PrivilegeEscalationConfig.ERROR_OBJECT_WRITE_FAILED.format(
                            table=table, resource_id=rid, error=str(exc),
                        )
                    )
                tested += 1

        return findings

    # ------------------------------------------------------------------
    # Test 8: RPC function access
    # ------------------------------------------------------------------

    async def _test_rpc_function_access(
        self, client: RateLimitedClient, supabase_url: str,
        anon_key: str, regular_session: AuthSession,
        rpc_functions: list[str],
    ) -> list[DeepFinding]:
        findings: list[DeepFinding] = []
        headers = self._build_supabase_headers(regular_session, anon_key)
        headers[SharedPatterns.HEADER_CONTENT_TYPE] = SharedPatterns.CONTENT_TYPE_JSON

        for func in rpc_functions:
            url = f"{supabase_url}/rest/v1/rpc/{func}"
            try:
                resp = await client.post(
                    url, content=SharedPatterns.SAFE_PATCH_BODY, headers=headers,
                )
                if resp.status_code in PrivilegeEscalationConfig.SUCCESS_READ_CODES:
                    findings.append(self._make_finding(
                        SeverityLevel.HIGH,
                        PrivilegeEscalationConfig.TITLE_RPC_ACCESS.format(function=func),
                        PrivilegeEscalationConfig.DESC_RPC_ACCESS.format(
                            function=func, status=resp.status_code,
                        ),
                        PrivilegeEscalationConfig.CONFIDENCE_RPC_ACCESS,
                        url, "POST", resp.text,
                    ))
            except Exception as exc:
                logger.debug(
                    PrivilegeEscalationConfig.ERROR_RPC_ACCESS_FAILED.format(
                        function=func, error=str(exc),
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_auth_headers(session: AuthSession) -> dict[str, str]:
        return {
            SharedPatterns.HEADER_AUTHORIZATION: (
                f"{SharedPatterns.BEARER_PREFIX}{session.access_token}"
            ),
        }

    @staticmethod
    def _build_supabase_headers(
        session: AuthSession, anon_key: str,
    ) -> dict[str, str]:
        return {
            SharedPatterns.HEADER_AUTHORIZATION: (
                f"{SharedPatterns.BEARER_PREFIX}{session.access_token}"
            ),
            SharedPatterns.HEADER_APIKEY: anon_key,
        }

    @staticmethod
    def _count_json_records(body: str) -> int:
        try:
            data = json.loads(body)
            if isinstance(data, list):
                return len(data)
            if isinstance(data, dict):
                for key in PrivilegeEscalationConfig.JSON_RECORD_KEYS:
                    if isinstance(data.get(key), list):
                        return len(data[key])
                return 1
        except (json.JSONDecodeError, TypeError):
            pass
        return 0

    @staticmethod
    def _is_admin_table(table: str) -> bool:
        table_lower = table.lower()
        return any(
            ind in table_lower
            for ind in PrivilegeEscalationConfig.ADMIN_INDICATORS
        )

    @staticmethod
    def _is_role_table(table: str) -> bool:
        table_lower = table.lower()
        return any(
            ind in table_lower
            for ind in PrivilegeEscalationConfig.ROLE_INDICATORS
        )

    @staticmethod
    def _is_admin_endpoint(endpoint: DiscoveredEndpoint) -> bool:
        path = urlparse(endpoint.url).path.lower()
        return any(
            ind in path
            for ind in PrivilegeEscalationConfig.ADMIN_PATH_INDICATORS
        )
