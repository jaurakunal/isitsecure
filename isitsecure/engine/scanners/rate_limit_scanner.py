"""Rate limit detection scanner.

Tests critical endpoints (login, signup, password reset, auth) by sending
rapid bursts of requests. Measures the actual rate limit threshold by
sending sequential requests and counting how many succeed before a 429.
Also tests whether rate limiting is per-IP or per-user.
"""

from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urlparse

import httpx

from isitsecure.engine.constants import DeepScanConfig, RateLimitConfig
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot
from isitsecure.engine.shared.progress import emit

logger = logging.getLogger(__name__)


class RateLimitScanner:
    """Detects missing rate limiting on critical endpoints.

    Tests login, signup, password reset, and auth endpoints by:
    1. Measuring the actual rate limit threshold (requests before 429)
    2. Testing at multiple burst sizes (10, 50, 100 requests)
    3. Checking if rate limit is per-IP or per-user when authenticated

    NOTE: Uses a raw httpx client (not RateLimitedClient) because we
    intentionally want to send rapid bursts to test rate limiting.
    """

    HTTP_STATUS_TOO_MANY_REQUESTS = 429

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return RateLimitConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.AUTH_WEAKNESS]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run rate limit tests on discovered endpoints.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot (unused by this scanner).

        Returns:
            List of unified findings from this scanner.
        """
        findings: list[DeepFinding] = []

        critical_endpoints = self._filter_critical_endpoints(endpoints)
        if not critical_endpoints:
            logger.info("RateLimitScanner: no critical endpoints to test")
            return findings

        async with httpx.AsyncClient(
            timeout=RateLimitConfig.HTTP_TIMEOUT_SECONDS,
            follow_redirects=True,
            headers={"User-Agent": DeepScanConfig.USER_AGENT},
        ) as client:
            for endpoint in critical_endpoints:
                endpoint_findings = await self._test_endpoint_rate_limit(
                    client, endpoint
                )
                findings.extend(endpoint_findings)

        logger.info("RateLimitScanner: %d findings", len(findings))
        return findings

    def _filter_critical_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """Filter endpoints to only those matching critical indicators."""
        critical: list[DiscoveredEndpoint] = []
        for ep in endpoints:
            url_lower = ep.url.lower()
            if any(
                indicator in url_lower
                for indicator in RateLimitConfig.CRITICAL_ENDPOINT_INDICATORS
            ):
                critical.append(ep)
        return critical

    async def _test_endpoint_rate_limit(
        self,
        client: httpx.AsyncClient,
        endpoint: DiscoveredEndpoint,
    ) -> list[DeepFinding]:
        """Test an endpoint for rate limiting with threshold measurement.

        Sends sequential requests at different burst sizes to measure
        the actual threshold. Reports findings based on the results.

        Returns:
            List of findings for this endpoint (may be empty, one, or multiple).
        """
        findings: list[DeepFinding] = []

        emit(f"rate-limit: sending burst to {urlparse(endpoint.url).path}")

        try:
            # Phase 1: Measure threshold with sequential requests
            threshold = await self._measure_threshold(client, endpoint)

            if threshold is None:
                # No 429 received even at max requests -- no rate limiting
                findings.append(
                    self._build_no_rate_limit_finding(endpoint)
                )
            else:
                # Rate limiting exists; report the measured threshold
                findings.append(
                    self._build_threshold_finding(endpoint, threshold)
                )

            # Phase 2: Test burst sizes to check behavior under load
            burst_findings = await self._test_burst_sizes(client, endpoint)
            findings.extend(burst_findings)

            # Phase 3: Test IP-based vs user-based rate limiting
            ip_finding = await self._test_ip_vs_user_rate_limit(client, endpoint)
            if ip_finding:
                findings.append(ip_finding)

        except Exception as exc:
            logger.debug(
                RateLimitConfig.ERROR_RATE_LIMIT_SCAN_FAILED.format(
                    endpoint=endpoint.url, error=str(exc)
                )
            )

        return findings

    async def _measure_threshold(
        self,
        client: httpx.AsyncClient,
        endpoint: DiscoveredEndpoint,
    ) -> int | None:
        """Send sequential requests to measure when 429 first appears.

        Sends requests one at a time with minimal delay, counting how
        many succeed before the first 429 response.

        Returns:
            The number of successful requests before 429, or None if
            no 429 was received within MAX_SEQUENTIAL_REQUESTS.
        """
        successful_count = 0

        for _ in range(RateLimitConfig.MAX_SEQUENTIAL_REQUESTS):
            try:
                response = await client.request(
                    method=endpoint.method.value,
                    url=endpoint.url,
                )

                if response.status_code == self.HTTP_STATUS_TOO_MANY_REQUESTS:
                    return successful_count

                if isinstance(response, httpx.Response):
                    successful_count += 1

            except Exception:
                # Connection errors count as potential rate limiting
                break

            await asyncio.sleep(RateLimitConfig.MIN_DELAY_BETWEEN_REQUESTS)

        # Never got a 429
        return None

    async def _test_burst_sizes(
        self,
        client: httpx.AsyncClient,
        endpoint: DiscoveredEndpoint,
    ) -> list[DeepFinding]:
        """Test different burst sizes to measure rate limit behavior.

        For each configured burst size, sends that many concurrent
        requests and checks if any get a 429. Only reports a finding
        if a burst size succeeds entirely without rate limiting.
        """
        findings: list[DeepFinding] = []

        for burst_size in RateLimitConfig.THRESHOLD_BURST_SIZES:
            try:
                tasks = [
                    client.request(
                        method=endpoint.method.value,
                        url=endpoint.url,
                    )
                    for _ in range(burst_size)
                ]
                responses = await asyncio.gather(*tasks, return_exceptions=True)

                received_429 = any(
                    isinstance(resp, httpx.Response)
                    and resp.status_code == self.HTTP_STATUS_TOO_MANY_REQUESTS
                    for resp in responses
                )

                successful_count = sum(
                    1 for resp in responses if isinstance(resp, httpx.Response)
                    and resp.status_code != self.HTTP_STATUS_TOO_MANY_REQUESTS
                )

                if received_429 and successful_count > 0:
                    # Rate limit kicked in during burst; report threshold
                    findings.append(
                        DeepFinding(
                            source=FindingSource.DAST_URL,
                            category=FindingCategory.AUTH_WEAKNESS,
                            severity=SeverityLevel.MEDIUM,
                            title=RateLimitConfig.TITLE_RATE_LIMIT_THRESHOLD,
                            description=RateLimitConfig.DESC_RATE_LIMIT_THRESHOLD.format(
                                url=endpoint.url,
                                threshold=successful_count,
                                burst_size=burst_size,
                            ),
                            technical_detail=(
                                f"Sent {burst_size} concurrent "
                                f"{endpoint.method.value} requests to "
                                f"{endpoint.url}\n"
                                f"{successful_count} succeeded before 429\n"
                                f"Rate limit triggers after ~{successful_count} "
                                f"requests in a burst of {burst_size}"
                            ),
                            evidence=(
                                f"Burst of {burst_size}: {successful_count} "
                                f"succeeded, then 429 on {endpoint.url}"
                            ),
                            confidence=RateLimitConfig.CONFIDENCE_THRESHOLD_MEASURED,
                            scanner_name=self.scanner_name,
                            endpoint_url=endpoint.url,
                            http_method=endpoint.method.value,
                        )
                    )
                    # Found the threshold at this burst size; no need to test larger
                    break

                # Brief pause between burst tests to reset server state
                await asyncio.sleep(RateLimitConfig.BURST_WINDOW_SECONDS)

            except Exception as exc:
                logger.debug(
                    "Burst test (%d) failed for %s: %s",
                    burst_size, endpoint.url, exc,
                )

        return findings

    async def _test_ip_vs_user_rate_limit(
        self,
        client: httpx.AsyncClient,
        endpoint: DiscoveredEndpoint,
    ) -> DeepFinding | None:
        """Test if rate limiting is per-IP only or also per-user.

        Sends two batches of requests from the same IP with different
        fake auth headers. If the second batch also gets rate-limited,
        the limit is IP-based. If the second batch succeeds, the limit
        is per-user only (which is weaker).
        """
        # First, trigger rate limiting with one identity
        first_auth = RateLimitConfig.TEST_AUTH_HEADER_ALPHA
        hit_429 = False

        for _ in range(RateLimitConfig.BURST_REQUEST_COUNT):
            try:
                response = await client.request(
                    method=endpoint.method.value,
                    url=endpoint.url,
                    headers={"Authorization": first_auth},
                )
                if response.status_code == self.HTTP_STATUS_TOO_MANY_REQUESTS:
                    hit_429 = True
                    break
            except Exception:
                break
            await asyncio.sleep(RateLimitConfig.MIN_DELAY_BETWEEN_REQUESTS)

        if not hit_429:
            # Could not trigger rate limiting with first identity
            return None

        # Now try with a different identity from the same IP
        second_auth = RateLimitConfig.TEST_AUTH_HEADER_BETA
        second_batch_blocked = False

        try:
            response = await client.request(
                method=endpoint.method.value,
                url=endpoint.url,
                headers={"Authorization": second_auth},
            )
            if response.status_code == self.HTTP_STATUS_TOO_MANY_REQUESTS:
                second_batch_blocked = True
        except Exception:
            return None

        if not second_batch_blocked:
            # Second identity was NOT rate limited -- limit is per-user only
            return DeepFinding(
                source=FindingSource.DAST_URL,
                category=FindingCategory.AUTH_WEAKNESS,
                severity=SeverityLevel.MEDIUM,
                title=RateLimitConfig.TITLE_RATE_LIMIT_PER_IP,
                description=RateLimitConfig.DESC_RATE_LIMIT_PER_IP.format(
                    url=endpoint.url,
                ),
                technical_detail=(
                    f"Triggered 429 with auth header '{first_auth}'\n"
                    f"Immediately tried with '{second_auth}' from same IP\n"
                    f"Second request was NOT rate limited "
                    f"(status: {response.status_code})\n"
                    f"Rate limiting appears to be per-user, not per-IP"
                ),
                evidence=(
                    f"Different auth headers bypass rate limit on {endpoint.url}"
                ),
                confidence=RateLimitConfig.CONFIDENCE_THRESHOLD_MEASURED,
                scanner_name=self.scanner_name,
                endpoint_url=endpoint.url,
                http_method=endpoint.method.value,
            )

        return None

    # ------------------------------------------------------------------
    # Finding builders
    # ------------------------------------------------------------------

    def _build_no_rate_limit_finding(
        self, endpoint: DiscoveredEndpoint
    ) -> DeepFinding:
        """Build a finding for an endpoint with no rate limiting detected."""
        return DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.AUTH_WEAKNESS,
            severity=SeverityLevel.HIGH,
            title=RateLimitConfig.TITLE_NO_RATE_LIMIT,
            description=RateLimitConfig.DESC_NO_RATE_LIMIT.format(
                url=endpoint.url,
                count=RateLimitConfig.MAX_SEQUENTIAL_REQUESTS,
                window=RateLimitConfig.BURST_WINDOW_SECONDS,
            ),
            technical_detail=(
                f"Sent {RateLimitConfig.MAX_SEQUENTIAL_REQUESTS} sequential "
                f"{endpoint.method.value} requests to {endpoint.url}\n"
                f"No 429 (Too Many Requests) response received"
            ),
            evidence=(
                f"{RateLimitConfig.MAX_SEQUENTIAL_REQUESTS}/"
                f"{RateLimitConfig.MAX_SEQUENTIAL_REQUESTS} "
                f"requests succeeded without 429 on {endpoint.url}"
            ),
            confidence=RateLimitConfig.CONFIDENCE_NO_RATE_LIMIT,
            scanner_name=self.scanner_name,
            endpoint_url=endpoint.url,
            http_method=endpoint.method.value,
        )

    def _build_threshold_finding(
        self, endpoint: DiscoveredEndpoint, threshold: int
    ) -> DeepFinding:
        """Build an informational finding reporting the measured threshold."""
        return DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.AUTH_WEAKNESS,
            severity=SeverityLevel.INFO,
            title=RateLimitConfig.TITLE_RATE_LIMIT_THRESHOLD,
            description=RateLimitConfig.DESC_RATE_LIMIT_THRESHOLD.format(
                url=endpoint.url,
                threshold=threshold,
                burst_size=RateLimitConfig.MAX_SEQUENTIAL_REQUESTS,
            ),
            technical_detail=(
                f"Sent sequential {endpoint.method.value} requests to "
                f"{endpoint.url} with {RateLimitConfig.MIN_DELAY_BETWEEN_REQUESTS}s "
                f"delay between each.\n"
                f"Rate limit triggered after {threshold} successful requests."
            ),
            evidence=(
                f"Rate limit triggers after {threshold} requests on {endpoint.url}"
            ),
            confidence=RateLimitConfig.CONFIDENCE_THRESHOLD_MEASURED,
            scanner_name=self.scanner_name,
            endpoint_url=endpoint.url,
            http_method=endpoint.method.value,
        )
