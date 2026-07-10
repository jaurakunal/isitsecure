"""Race condition / TOCTOU scanner.

Replays state-changing requests (POST/PUT/PATCH) concurrently
to detect time-of-check-to-time-of-use (TOCTOU) vulnerabilities.

Uses a SINGLE shared HTTP client and fires all requests simultaneously
to maximize the chance of a real race condition.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

import httpx

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import (
    DeepScanConfig,
    RaceConditionConfig,
)
from isitsecure.engine.models import (
    DeepFinding,
    FindingSource,
    InterceptedRequest,
)
from isitsecure.engine.shared.auth_headers import build_replay_headers
from isitsecure.engine.shared.progress import emit
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class RaceConditionScanner:
    """Tests for race condition vulnerabilities by concurrent request replay."""

    @property
    def scanner_name(self) -> str:
        return RaceConditionConfig.SCANNER_NAME

    async def scan(
        self,
        intercepted_requests: list[InterceptedRequest],
        session: AuthSession,
    ) -> list[DeepFinding]:
        """Send N concurrent copies of each mutation and check for double-success."""
        findings: list[DeepFinding] = []

        mutations = [
            r for r in intercepted_requests
            if r.method.upper() in RaceConditionConfig.WRITE_METHODS
            and r.response_status in RaceConditionConfig.SUCCESS_STATUS_CODES
            and r.request_body
        ]

        # Deduplicate by URL path
        seen_paths: set[str] = set()
        unique_mutations: list[InterceptedRequest] = []
        for req in mutations:
            path = urlparse(req.url).path
            if path not in seen_paths:
                seen_paths.add(path)
                unique_mutations.append(req)

        for req in unique_mutations[: RaceConditionConfig.MAX_MUTATIONS_TO_TEST]:
            finding = await self._test_race(req, session)
            if finding:
                findings.append(finding)

        logger.info(
            "RaceConditionScanner: %d findings from %d mutations tested",
            len(findings), len(unique_mutations),
        )
        return findings

    async def _test_race(
        self,
        req: InterceptedRequest,
        session: AuthSession,
    ) -> DeepFinding | None:
        """Send N concurrent copies via a SINGLE client for true concurrency."""
        headers = build_replay_headers(session, req)
        method = req.method.upper()

        emit(f"race-condition: {method} {req.url}")

        # Use a single shared client — critical for real race condition testing
        async with httpx.AsyncClient(
            timeout=RaceConditionConfig.HTTP_TIMEOUT_SECONDS,
            follow_redirects=True,
        ) as client:

            async def send_one() -> int:
                try:
                    resp = await client.request(
                        method, req.url,
                        headers=headers,
                        content=req.request_body,
                    )
                    return resp.status_code
                except Exception:
                    return 0

            try:
                tasks = [
                    send_one()
                    for _ in range(RaceConditionConfig.CONCURRENT_REQUESTS)
                ]
                statuses = await asyncio.gather(*tasks)
            except Exception as exc:
                logger.debug(
                    RaceConditionConfig.ERROR_RACE_FAILED.format(
                        url=req.url, error=str(exc),
                    )
                )
                return None

        success_count = sum(
            1 for s in statuses
            if s in RaceConditionConfig.SUCCESS_STATUS_CODES
        )

        if success_count >= RaceConditionConfig.SUCCESS_THRESHOLD:
            path = urlparse(req.url).path
            return DeepFinding(
                source=FindingSource.DAST_AUTHENTICATED,
                category=FindingCategory.AUTH_WEAKNESS,
                severity=SeverityLevel.HIGH,
                title=RaceConditionConfig.TITLE_RACE_CONDITION.format(
                    method=method, path=path, count=success_count,
                ),
                description=RaceConditionConfig.DESC_RACE_CONDITION.format(
                    total=RaceConditionConfig.CONCURRENT_REQUESTS,
                    method=method, path=path, count=success_count,
                ),
                confidence=RaceConditionConfig.CONFIDENCE_RACE,
                scanner_name=self.scanner_name,
                endpoint_url=req.url,
                http_method=method,
                request_payload=req.request_body[
                    : RaceConditionConfig.RESPONSE_PREVIEW_LENGTH
                ] if req.request_body else "",
                response_preview=f"Concurrent results: {list(statuses)}",
            )

        return None
