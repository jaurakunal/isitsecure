"""Live Supabase RLS testing scanner.

Systematically tests every Supabase table's Row Level Security policies
using real authenticated tokens:

1. Anon key access: Can unauthenticated users read/write?
2. Cross-user access: Can User B read/write User A's data?
3. RPC function access: Can unauthenticated users call functions?

Unlike the SAST RLS analyzer (C3) which reads migration files, this scanner
ACTIVELY probes the live Supabase REST API.
"""

import json
import logging

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import (
    DeepScanConfig,
    RLSDeepScanConfig,
)
from isitsecure.engine.models import (
    DeepFinding,
    FindingSource,
)
from isitsecure.engine.shared.progress import emit
from isitsecure.engine.shared.rate_limited_client import (
    RateLimitedClient,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class RLSDeepScanner:
    """Tests Supabase RLS policies by probing the live REST API.

    Three test tiers:
    - Tier 1 (anon key only): Test SELECT and INSERT with just the anon key
    - Tier 2 (single user): Implicitly covered by anon vs. auth comparison
    - Tier 3 (cross-user): Test if User B can see User A's data
    """

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return RLSDeepScanConfig.SCANNER_NAME

    async def scan(
        self,
        supabase_url: str,
        anon_key: str,
        tables: list[str],
        rpc_functions: list[str] | None = None,
        user_a_session: AuthSession | None = None,
        user_b_session: AuthSession | None = None,
    ) -> list[DeepFinding]:
        """Test all tables for RLS violations.

        Args:
            supabase_url: Supabase project URL (e.g. https://xyz.supabase.co).
            anon_key: Supabase anon/public key.
            tables: List of table names to test.
            rpc_functions: Optional list of RPC function names to test.
            user_a_session: Optional session for the resource owner.
            user_b_session: Optional session for the attacker.

        Returns:
            List of DeepFinding for detected RLS issues.
        """
        findings: list[DeepFinding] = []

        async with RateLimitedClient(
            max_concurrent=RLSDeepScanConfig.MAX_CONCURRENT_PROBES,
            delay_seconds=RLSDeepScanConfig.PROBE_DELAY_SECONDS,
            timeout_seconds=RLSDeepScanConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
            extra_headers={"apikey": anon_key},
        ) as client:
            for table in tables[: RLSDeepScanConfig.MAX_TABLES_TO_TEST]:
                emit(f"RLS: checking table '{table}'")
                # Tier 1: Anon access
                anon_findings = await self._test_anon_access(
                    client, supabase_url, table
                )
                findings.extend(anon_findings)

                # Tier 3: Cross-user access
                if user_a_session and user_b_session:
                    cross_findings = await self._test_cross_user_access(
                        client,
                        supabase_url,
                        table,
                        anon_key,
                        user_a_session,
                        user_b_session,
                    )
                    findings.extend(cross_findings)

            # Test RPC functions
            if rpc_functions:
                for func in rpc_functions:
                    rpc_finding = await self._test_rpc_access(
                        client, supabase_url, func
                    )
                    if rpc_finding:
                        findings.append(rpc_finding)

        return findings

    # ------------------------------------------------------------------
    # Tier 1: Anonymous access
    # ------------------------------------------------------------------

    async def _test_anon_access(
        self,
        client: RateLimitedClient,
        supabase_url: str,
        table: str,
    ) -> list[DeepFinding]:
        """Test if table is readable/writable with just the anon key."""
        findings: list[DeepFinding] = []

        # SELECT test
        read_finding = await self._test_anon_read(client, supabase_url, table)
        if read_finding:
            findings.append(read_finding)

        # INSERT test (safe — empty body with return=minimal)
        write_finding = await self._test_anon_write(client, supabase_url, table)
        if write_finding:
            findings.append(write_finding)

        return findings

    async def _test_anon_read(
        self,
        client: RateLimitedClient,
        supabase_url: str,
        table: str,
    ) -> DeepFinding | None:
        """Test if a table is readable with just the anon key."""
        # Select all columns (limit 1) so we can detect sensitive columns and
        # escalate severity — but never put the row VALUES in the report.
        url = (
            f"{supabase_url}/rest/v1/{table}"
            f"?{RLSDeepScanConfig.SELECT_ALL}"
            f"&{RLSDeepScanConfig.LIMIT_ONE}"
        )
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                body = resp.text.strip()
                if body and body != "[]":
                    data = json.loads(body)
                    rows = data if isinstance(data, list) else [data]
                    count = len(rows)
                    columns = sorted({
                        k for r in rows if isinstance(r, dict) for k in r
                    })
                    sensitive = self._sensitive_columns(columns)
                    # Redacted preview: column NAMES only, never PII values.
                    preview = (
                        f"columns: {', '.join(columns)}" if columns
                        else "(non-object rows)"
                    )
                    if sensitive:
                        return DeepFinding(
                            source=FindingSource.DAST_AUTHENTICATED,
                            category=FindingCategory.RLS_MISCONFIGURATION,
                            severity=SeverityLevel.CRITICAL,
                            title=RLSDeepScanConfig.TITLE_ANON_READ_SENSITIVE.format(
                                table=table
                            ),
                            description=RLSDeepScanConfig.DESC_ANON_READ_SENSITIVE.format(
                                table=table, count=count,
                                columns=", ".join(sensitive),
                            ),
                            confidence=RLSDeepScanConfig.CONFIDENCE_ANON_READ,
                            scanner_name=self.scanner_name,
                            endpoint_url=url,
                            http_method="GET",
                            response_preview=preview[:300],
                        )
                    return DeepFinding(
                        source=FindingSource.DAST_AUTHENTICATED,
                        category=FindingCategory.RLS_MISCONFIGURATION,
                        severity=SeverityLevel.HIGH,
                        title=RLSDeepScanConfig.TITLE_ANON_READ.format(
                            table=table
                        ),
                        description=RLSDeepScanConfig.DESC_ANON_READ.format(
                            table=table, count=count
                        ),
                        confidence=RLSDeepScanConfig.CONFIDENCE_ANON_READ,
                        scanner_name=self.scanner_name,
                        endpoint_url=url,
                        http_method="GET",
                        response_preview=preview[:300],
                    )
        except Exception as exc:
            logger.debug(
                RLSDeepScanConfig.ERROR_RLS_SCAN_FAILED.format(
                    table=table, error=str(exc)
                )
            )
        return None

    async def _test_anon_write(
        self,
        client: RateLimitedClient,
        supabase_url: str,
        table: str,
    ) -> DeepFinding | None:
        """Test if a table is writable with just the anon key."""
        url = f"{supabase_url}/rest/v1/{table}"
        try:
            resp = await client.post(
                url,
                content=RLSDeepScanConfig.SAFE_WRITE_BODY,
                headers={
                    "Content-Type": "application/json",
                    "Prefer": RLSDeepScanConfig.SAFE_WRITE_PREFER,
                },
            )
            status = resp.status_code
            description: str | None = None
            confidence = RLSDeepScanConfig.CONFIDENCE_ANON_WRITE

            if status in (200, 201):
                # A row was actually created — anon write is confirmed.
                description = RLSDeepScanConfig.DESC_ANON_WRITE.format(table=table)
            elif status == 400 and self._write_passed_rls(resp.text):
                # 400 with an integrity-constraint code (not an RLS denial) means
                # the row cleared the RLS policy and only failed a column
                # constraint — anon write is exposed (inferred).
                description = RLSDeepScanConfig.DESC_ANON_WRITE_INFERRED.format(
                    table=table
                )
                confidence = RLSDeepScanConfig.CONFIDENCE_ANON_WRITE_INFERRED

            if description is not None:
                return DeepFinding(
                    source=FindingSource.DAST_AUTHENTICATED,
                    category=FindingCategory.RLS_MISCONFIGURATION,
                    severity=SeverityLevel.CRITICAL,
                    title=RLSDeepScanConfig.TITLE_ANON_WRITE.format(
                        table=table
                    ),
                    description=description,
                    confidence=confidence,
                    scanner_name=self.scanner_name,
                    endpoint_url=url,
                    http_method="POST",
                    request_payload=RLSDeepScanConfig.SAFE_WRITE_BODY,
                    response_preview=resp.text[:300],
                )
        except Exception as exc:
            logger.debug(
                RLSDeepScanConfig.ERROR_RLS_SCAN_FAILED.format(
                    table=table, error=str(exc)
                )
            )
        return None

    @staticmethod
    def _sensitive_columns(columns: list[str]) -> list[str]:
        """Return columns whose name marks the table as holding sensitive data."""
        out: list[str] = []
        for col in columns:
            low = col.lower()
            if any(m in low for m in RLSDeepScanConfig.SENSITIVE_COLUMN_NAMES):
                out.append(col)
        return out

    @staticmethod
    def _write_passed_rls(body: str) -> bool:
        """True if a 400 response is a column-constraint error (the row cleared
        the RLS policy) rather than an RLS denial. Keys on the PostgREST error
        ``code``: ``42501`` = RLS-blocked; class ``23`` = integrity constraint.
        """
        try:
            code = str(json.loads(body).get("code", ""))
        except Exception:
            code = ""
        if code == RLSDeepScanConfig.PG_RLS_DENIED_CODE:
            return False
        if RLSDeepScanConfig.RLS_DENY_MESSAGE in body.lower():
            return False
        return code.startswith(RLSDeepScanConfig.PG_CONSTRAINT_CODE_CLASS)

    # ------------------------------------------------------------------
    # Tier 3: Cross-user access
    # ------------------------------------------------------------------

    async def _test_cross_user_access(
        self,
        client: RateLimitedClient,
        supabase_url: str,
        table: str,
        anon_key: str,
        session_a: AuthSession,
        session_b: AuthSession,
    ) -> list[DeepFinding]:
        """Test if User B can read User A's rows."""
        findings: list[DeepFinding] = []

        url = (
            f"{supabase_url}/rest/v1/{table}"
            f"?{RLSDeepScanConfig.SELECT_ID_ONLY}"
            f"&{RLSDeepScanConfig.LIMIT_ONE}"
        )
        headers_a = {
            "Authorization": f"Bearer {session_a.access_token}",
            "apikey": anon_key,
        }
        headers_b = {
            "Authorization": f"Bearer {session_b.access_token}",
            "apikey": anon_key,
        }

        try:
            # Step 1: Get User A's rows
            resp_a = await client.get(url, headers=headers_a)
            if resp_a.status_code != 200:
                return findings

            body_a = resp_a.text.strip()
            if not body_a or body_a == "[]":
                return findings

            rows_a = json.loads(body_a)
            if not rows_a or not isinstance(rows_a, list):
                return findings

            a_ids = {str(r.get("id", "")) for r in rows_a if r.get("id")}
            if not a_ids:
                return findings

            # Step 2: Try reading with User B's token
            resp_b = await client.get(url, headers=headers_b)
            if resp_b.status_code != 200:
                return findings

            body_b = resp_b.text.strip()
            if not body_b or body_b == "[]":
                return findings

            rows_b = json.loads(body_b)
            if not rows_b or not isinstance(rows_b, list):
                return findings

            b_ids = {str(r.get("id", "")) for r in rows_b if r.get("id")}
            overlap = a_ids & b_ids

            if overlap:
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_AUTHENTICATED,
                        category=FindingCategory.IDOR,
                        severity=SeverityLevel.CRITICAL,
                        title=RLSDeepScanConfig.TITLE_CROSS_USER_READ.format(
                            table=table
                        ),
                        description=RLSDeepScanConfig.DESC_CROSS_USER_READ.format(
                            table=table, count=len(overlap)
                        ),
                        confidence=RLSDeepScanConfig.CONFIDENCE_CROSS_USER_READ,
                        scanner_name=self.scanner_name,
                        endpoint_url=url,
                        http_method="GET",
                        evidence=f"Overlapping IDs: {sorted(overlap)[:5]}",
                    )
                )

        except Exception as exc:
            logger.debug(
                RLSDeepScanConfig.ERROR_RLS_SCAN_FAILED.format(
                    table=table, error=str(exc)
                )
            )

        return findings

    # ------------------------------------------------------------------
    # RPC function testing
    # ------------------------------------------------------------------

    async def _test_rpc_access(
        self,
        client: RateLimitedClient,
        supabase_url: str,
        func: str,
    ) -> DeepFinding | None:
        """Test if an RPC function is callable without authentication."""
        url = f"{supabase_url}/rest/v1/rpc/{func}"
        try:
            resp = await client.post(
                url,
                content=RLSDeepScanConfig.SAFE_WRITE_BODY,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                return DeepFinding(
                    source=FindingSource.DAST_AUTHENTICATED,
                    category=FindingCategory.EXPOSED_API_ENDPOINT,
                    severity=SeverityLevel.HIGH,
                    title=RLSDeepScanConfig.TITLE_RPC_NO_AUTH.format(
                        func=func
                    ),
                    description=RLSDeepScanConfig.DESC_RPC_NO_AUTH.format(
                        func=func
                    ),
                    confidence=RLSDeepScanConfig.CONFIDENCE_ANON_READ,
                    scanner_name=self.scanner_name,
                    endpoint_url=url,
                    http_method="POST",
                    response_preview=resp.text[:300],
                )
        except Exception as exc:
            logger.debug(
                RLSDeepScanConfig.ERROR_RPC_SCAN_FAILED.format(
                    func=func, error=str(exc)
                )
            )
        return None
