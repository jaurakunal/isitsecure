"""Password reset flow security scanner.

Tests the password reset / forgot-password flow for:
1. Email enumeration — different responses for valid vs invalid emails
2. Rate limiting — can an attacker flood reset requests?
3. Token leakage — is the reset token exposed in the API response?
"""

from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import urlparse

import httpx

from isitsecure.engine.constants import (
    DeepScanConfig,
    PasswordResetConfig,
)
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot
from isitsecure.engine.shared.progress import emit

logger = logging.getLogger(__name__)


class PasswordResetScanner:
    """Tests password reset flow for enumeration, rate limiting, and token leaks.

    Implements DASTScannerProtocol so it can be added to the main
    DAST scanner list and run automatically.
    """

    @property
    def scanner_name(self) -> str:
        return PasswordResetConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        return [FindingCategory.AUTH_WEAKNESS]

    _TOKEN_RES = [
        re.compile(p, re.IGNORECASE)
        for p in PasswordResetConfig.TOKEN_PATTERNS
    ]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Find and test password reset endpoints."""
        findings: list[DeepFinding] = []

        reset_endpoints = self._filter_reset_endpoints(endpoints)
        if not reset_endpoints:
            logger.info("PasswordResetScanner: no reset endpoints found")
            return findings

        async with httpx.AsyncClient(
            timeout=PasswordResetConfig.HTTP_TIMEOUT_SECONDS,
            follow_redirects=True,
            headers={"User-Agent": DeepScanConfig.USER_AGENT},
        ) as client:
            for ep in reset_endpoints:
                path = urlparse(ep.url).path
                # Test 1: Email enumeration
                emit(f"password-reset: email enumeration on {path}")
                enum_finding = await self._test_email_enumeration(client, ep)
                if enum_finding:
                    findings.append(enum_finding)

                await asyncio.sleep(PasswordResetConfig.PROBE_DELAY_SECONDS)

                # Test 2: Rate limiting
                emit(f"password-reset: rate limiting on {path}")
                rate_finding = await self._test_rate_limiting(client, ep)
                if rate_finding:
                    findings.append(rate_finding)

                # Test 3: Token leakage
                emit(f"password-reset: token leakage on {path}")
                token_finding = await self._test_token_leakage(client, ep)
                if token_finding:
                    findings.append(token_finding)

        logger.info(
            "PasswordResetScanner: %d findings from %d reset endpoints",
            len(findings), len(reset_endpoints),
        )
        return findings

    # ------------------------------------------------------------------
    # Test 1: Email enumeration
    # ------------------------------------------------------------------

    async def _test_email_enumeration(
        self, client: httpx.AsyncClient, endpoint: DiscoveredEndpoint,
    ) -> DeepFinding | None:
        """Send reset requests with valid-looking and nonexistent emails.

        If the server responds differently, accounts can be enumerated.
        """
        path = urlparse(endpoint.url).path

        try:
            resp_nonexistent = await client.post(
                endpoint.url,
                json={"email": PasswordResetConfig.TEST_NONEXISTENT_EMAIL},
            )
            await asyncio.sleep(PasswordResetConfig.PROBE_DELAY_SECONDS)

            resp_valid = await client.post(
                endpoint.url,
                json={"email": PasswordResetConfig.TEST_VALID_LOOKING_EMAIL},
            )

            # Different status codes → enumerable
            status_diff = resp_nonexistent.status_code != resp_valid.status_code
            # Significantly different body sizes → enumerable
            size_a = len(resp_nonexistent.text)
            size_b = len(resp_valid.text)
            size_diff = abs(size_a - size_b) > PasswordResetConfig.ENUM_SIZE_DIFF_THRESHOLD

            if status_diff or size_diff:
                return DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.AUTH_WEAKNESS,
                    severity=SeverityLevel.MEDIUM,
                    title=PasswordResetConfig.TITLE_RESET_ENUM,
                    description=PasswordResetConfig.DESC_RESET_ENUM.format(
                        path=path,
                        status_a=resp_nonexistent.status_code,
                        status_b=resp_valid.status_code,
                        size_a=size_a,
                        size_b=size_b,
                    ),
                    confidence=PasswordResetConfig.CONFIDENCE_ENUM,
                    scanner_name=self.scanner_name,
                    endpoint_url=endpoint.url,
                    http_method="POST",
                    response_preview=(
                        f"Nonexistent: {resp_nonexistent.status_code} ({size_a}B) | "
                        f"Valid-looking: {resp_valid.status_code} ({size_b}B)"
                    ),
                )
        except Exception as exc:
            logger.debug(
                PasswordResetConfig.ERROR_RESET_FAILED.format(
                    path=path, error=str(exc),
                )
            )
        return None

    # ------------------------------------------------------------------
    # Test 2: Rate limiting
    # ------------------------------------------------------------------

    async def _test_rate_limiting(
        self, client: httpx.AsyncClient, endpoint: DiscoveredEndpoint,
    ) -> DeepFinding | None:
        """Send multiple rapid reset requests to check for rate limiting."""
        path = urlparse(endpoint.url).path
        try:
            success_count = 0
            for _ in range(PasswordResetConfig.RATE_LIMIT_BURST_COUNT):
                resp = await client.post(
                    endpoint.url,
                    json={"email": PasswordResetConfig.TEST_VALID_LOOKING_EMAIL},
                )
                if resp.status_code in PasswordResetConfig.SUCCESS_STATUS_CODES:
                    success_count += 1
                elif resp.status_code == PasswordResetConfig.RATE_LIMITED_STATUS:
                    # Rate limited — good
                    return None

            if success_count >= PasswordResetConfig.RATE_LIMIT_BURST_COUNT:
                return DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.AUTH_WEAKNESS,
                    severity=SeverityLevel.MEDIUM,
                    title=PasswordResetConfig.TITLE_RESET_NO_LIMIT,
                    description=PasswordResetConfig.DESC_RESET_NO_LIMIT.format(
                        path=path, count=success_count,
                    ),
                    confidence=PasswordResetConfig.CONFIDENCE_NO_RATE_LIMIT,
                    scanner_name=self.scanner_name,
                    endpoint_url=endpoint.url,
                    http_method="POST",
                    response_preview=f"{success_count}/{PasswordResetConfig.RATE_LIMIT_BURST_COUNT} requests accepted",
                )
        except Exception as exc:
            logger.debug(
                PasswordResetConfig.ERROR_RESET_FAILED.format(
                    path=path, error=str(exc),
                )
            )
        return None

    # ------------------------------------------------------------------
    # Test 3: Token leakage
    # ------------------------------------------------------------------

    async def _test_token_leakage(
        self, client: httpx.AsyncClient, endpoint: DiscoveredEndpoint,
    ) -> DeepFinding | None:
        """Check if the reset response body contains a token."""
        path = urlparse(endpoint.url).path

        try:
            resp = await client.post(
                endpoint.url,
                json={"email": PasswordResetConfig.TEST_VALID_LOOKING_EMAIL},
            )

            for pattern in self._TOKEN_RES:
                match = pattern.search(resp.text)
                if match:
                    return DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.AUTH_WEAKNESS,
                        severity=SeverityLevel.CRITICAL,
                        title=PasswordResetConfig.TITLE_RESET_TOKEN_LEAK,
                        description=PasswordResetConfig.DESC_RESET_TOKEN_LEAK.format(
                            path=path,
                        ),
                        confidence=PasswordResetConfig.CONFIDENCE_TOKEN_IN_RESPONSE,
                        scanner_name=self.scanner_name,
                        endpoint_url=endpoint.url,
                        http_method="POST",
                        response_preview=resp.text[
                            : PasswordResetConfig.RESPONSE_PREVIEW_LENGTH
                        ],
                    )
        except Exception as exc:
            logger.debug(
                PasswordResetConfig.ERROR_RESET_FAILED.format(
                    path=path, error=str(exc),
                )
            )
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _filter_reset_endpoints(
        endpoints: list[DiscoveredEndpoint],
    ) -> list[DiscoveredEndpoint]:
        """Filter endpoints that look like password reset."""
        matched: list[DiscoveredEndpoint] = []
        for ep in endpoints:
            url_lower = ep.url.lower()
            if any(
                indicator in url_lower
                for indicator in PasswordResetConfig.RESET_PATH_INDICATORS
            ):
                matched.append(ep)
        return matched
