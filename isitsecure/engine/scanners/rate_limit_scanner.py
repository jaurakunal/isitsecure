"""Rate limit detection scanner.

Tests critical endpoints (login, signup, password reset, auth) by sending
rapid bursts of requests. Measures the actual rate limit threshold by
sending sequential requests and counting how many succeed before a 429.
Also tests whether rate limiting is per-IP or per-user.
"""

from __future__ import annotations

import asyncio
import logging
from typing import NamedTuple
from urllib.parse import urlparse

import httpx

from isitsecure.engine.constants import DeepScanConfig, RateLimitConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.auth_aware import AuthAwareScanner
from isitsecure.engine.shared.progress import emit
from isitsecure.engine.shared.time_budget import TimeBudget
from isitsecure.engine.shared.verdict import Reply, Verdict, absolutize, unreachable_reason

logger = logging.getLogger(__name__)

TITLE_RATE_LIMIT_INCONCLUSIVE = "Rate limiting could not be assessed"
DESC_RATE_LIMIT_INCONCLUSIVE = (
    "Rate limiting on {url} could not be assessed: {reason}. This is a coverage "
    "statement, not a finding: the endpoint was neither shown to be limited nor "
    "shown to be unlimited."
)
CONFIDENCE_INCONCLUSIVE = 0.50

# One flaky 502 in 150 must not hide an unprotected login endpoint, but a run
# that is mostly error pages says nothing. Unusable replies (transport errors,
# 5xx, missing endpoint, HTML shell) are tolerated up to this fraction of the
# planned requests, and never this many in a row.
MAX_UNUSABLE_FRACTION = 0.05
MAX_CONSECUTIVE_UNUSABLE = 5


class ThresholdProbe(NamedTuple):
    """Outcome of the sequential pass: how many requests were processed and the verdict.

    ``verdict.vulnerable`` means every request was processed and none was
    limited; a 429 is NOT_PROVEN; anything that stopped the run is INCONCLUSIVE.
    """

    processed: int
    verdict: Verdict
    limited: bool = False


def _has_retry_after(response: object) -> bool:
    """True when the response carries a non-empty Retry-After header."""
    try:
        value = response.headers.get("retry-after")  # type: ignore[attr-defined]
    except Exception:
        return False
    return isinstance(value, str) and bool(value.strip())


def _reply_of(response: object, method: str) -> Reply:
    """The status/body an oracle reasons about, tolerant of partial response stubs."""
    status = getattr(response, "status_code", 0)
    body = getattr(response, "text", "")
    return Reply(
        status if isinstance(status, int) else 0,
        body if isinstance(body, str) else "",
        method,
    )


class RateLimitScanner(AuthAwareScanner):
    """Detects missing rate limiting on critical endpoints.

    Tests login, signup, password reset, and auth endpoints by:
    1. Measuring the actual rate limit threshold (requests before 429)
    2. Testing at multiple burst sizes (10, 50, 100 requests)
    3. Checking if rate limit is per-IP or per-user when authenticated

    NOTE: Uses a raw httpx client (not RateLimitedClient) because we
    intentionally want to send rapid bursts to test rate limiting.

    Auth-aware (#119): on an authenticated deep scan the orchestrator injects the
    session so behind-login critical endpoints are reachable and the burst tests
    measure the authenticated user's rate limit (the realistic attacker). The
    per-IP-vs-per-user test is the one exception — it MUST vary the identity, so
    it strips the injected session (see ``_identity_headers``).
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
            headers={"User-Agent": DeepScanConfig.USER_AGENT, **(self.auth_headers or {})},
        ) as client:
            # Stop cooperatively before the runner's hard timeout cancels us
            # (which discards every finding so far). Rate-limit tests are
            # burst-heavy, so a large endpoint set can outrun the budget.
            budget = TimeBudget()
            for endpoint in critical_endpoints:
                if budget.expired():
                    logger.info("RateLimitScanner: time budget reached, stopping early")
                    break
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

        if absolutize(endpoint.url) is None:
            # Nothing was sent, so nothing can be said about the endpoint.
            return [
                self._build_inconclusive_finding(
                    endpoint, "the URL is relative, so no request could be sent"
                )
            ]

        try:
            # Phase 1: Measure threshold with sequential requests
            probe = await self._measure_threshold(client, endpoint)

            if probe.limited:
                # Rate limiting exists; report the measured threshold
                findings.append(
                    self._build_threshold_finding(endpoint, probe.processed)
                )
            elif probe.verdict.vulnerable:
                # Every request was processed and none was limited
                findings.append(
                    self._build_no_rate_limit_finding(endpoint, probe.processed)
                )
            else:
                # Could not tell (dropped connection, error pages, no endpoint):
                # a throttle, WAF or flaky server is never proof that nothing
                # limits requests. Surface the observed cut-off as informational.
                findings.append(
                    self._build_inconclusive_finding(
                        endpoint, probe.verdict.evidence, probe.processed
                    )
                )

            # Phase 2: Test burst sizes to check behavior under load. Skipped
            # when the sequential pass already reported a threshold (same
            # title and locus, would only duplicate it).
            if probe.verdict.vulnerable or (
                not probe.verdict.conclusive and probe.processed == 0
            ):
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
    ) -> ThresholdProbe:
        """Send sequential requests to measure when 429 first appears.

        Sends requests one at a time with minimal delay, counting how
        many processed responses arrive before the first 429 response. A
        response only counts as processed when it says something about the
        endpoint (not status 0, a 5xx, a missing endpoint or an HTML page).
        400/401/403/422 DO count as processed: a limiter normally runs before
        validation and credential checks, and this scanner sends empty bodies,
        so a login endpoint rejecting every request is still reachable by an
        attacker at full speed.

        Isolated unusable replies are tolerated (see ``MAX_UNUSABLE_FRACTION``
        and ``MAX_CONSECUTIVE_UNUSABLE``). A 5xx carrying ``Retry-After`` may
        come from a limiter or WAF, so it ends the run as INCONCLUSIVE.

        Returns:
            ``ThresholdProbe``. A 429 sets ``limited`` and ``processed`` is
            the threshold. Reaching MAX_SEQUENTIAL_REQUESTS with the unusable
            replies within tolerance and no 429 is PROVEN (no rate limiting).
            Too many unusable replies, or a possible limiter signal, is
            INCONCLUSIVE.
        """
        processed = 0
        unusable = 0
        consecutive = 0
        planned = RateLimitConfig.MAX_SEQUENTIAL_REQUESTS
        method = endpoint.method.value

        for sent in range(1, planned + 1):
            reason: str | None
            try:
                response = await client.request(method=method, url=endpoint.url)
            except Exception as exc:
                reason = f"connection error ({type(exc).__name__})"
            else:
                if response.status_code == self.HTTP_STATUS_TOO_MANY_REQUESTS:
                    return ThresholdProbe(
                        processed, Verdict.not_proven("rate limit observed"), True
                    )
                if _has_retry_after(response) and response.status_code >= 500:
                    return ThresholdProbe(
                        processed,
                        Verdict.inconclusive(
                            f"HTTP {response.status_code} with Retry-After on "
                            f"request {sent}: possibly a limiter or WAF"
                        ),
                    )
                reason = unreachable_reason(_reply_of(response, method))

            if reason is None:
                processed += 1
                consecutive = 0
            else:
                unusable += 1
                consecutive += 1
                if (
                    consecutive >= MAX_CONSECUTIVE_UNUSABLE
                    or unusable > MAX_UNUSABLE_FRACTION * planned
                ):
                    return ThresholdProbe(
                        processed,
                        Verdict.inconclusive(
                            f"{unusable} of {sent} requests were unusable "
                            f"({consecutive} in a row); last: {reason}"
                        ),
                    )
            await asyncio.sleep(RateLimitConfig.MIN_DELAY_BETWEEN_REQUESTS)

        return ThresholdProbe(
            processed,
            Verdict.proven(
                f"{processed}/{planned} requests processed, no 429"
                f" ({unusable} unusable)"
            ),
        )

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
                    and unreachable_reason(_reply_of(resp, endpoint.method.value))
                    is None
                )

                if received_429 and successful_count > 0:
                    # Rate limit kicked in during burst; report threshold
                    findings.append(
                        DeepFinding(
                            source=FindingSource.DAST_URL,
                            category=FindingCategory.AUTH_WEAKNESS,
                            severity=SeverityLevel.INFO,
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

    def _identity_headers(self, auth_value: str) -> dict[str, str]:
        """Headers for a single synthetic identity in the IP-vs-user test.

        The per-IP-vs-per-user test relies on two DISTINCT identities. If the
        scan injected a real session (#119), it would ride on every request and
        collapse both identities into the same authenticated user, so we blank
        every injected auth header for these requests and set only the test one.
        """
        return {**{name: "" for name in (self.auth_headers or {})},
                "Authorization": auth_value}

    async def _test_ip_vs_user_rate_limit(
        self,
        client: httpx.AsyncClient,
        endpoint: DiscoveredEndpoint,
    ) -> DeepFinding | None:
        """Test whether the rate limit is keyed on the client-supplied identity.

        Trips the limit with one fake Authorization header, then retries from
        the same IP with a different one. If the second request is NOT
        limited, the limiter is keyed on the (attacker-controlled)
        Authorization header, so rotating it bypasses the limit. If it is also
        limited, the limit is keyed on the IP.
        """
        # First, trigger rate limiting with one identity
        first_auth = RateLimitConfig.TEST_AUTH_HEADER_ALPHA
        hit_429 = False

        for _ in range(RateLimitConfig.BURST_REQUEST_COUNT):
            try:
                response = await client.request(
                    method=endpoint.method.value,
                    url=endpoint.url,
                    headers=self._identity_headers(first_auth),
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
                headers=self._identity_headers(second_auth),
            )
            if response.status_code == self.HTTP_STATUS_TOO_MANY_REQUESTS:
                second_batch_blocked = True
            elif unreachable_reason(_reply_of(response, endpoint.method.value)):
                # An error page is not a request that got through the limiter.
                return None
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
                    f"The limit is keyed on the client-supplied Authorization "
                    f"header, not on the IP: rotating it bypasses the limit"
                ),
                evidence=(
                    f"Rotating the Authorization header bypasses the rate "
                    f"limit on {endpoint.url}"
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
        self, endpoint: DiscoveredEndpoint, processed: int | None = None
    ) -> DeepFinding:
        """Build a finding for an endpoint with no rate limiting detected."""
        total = RateLimitConfig.MAX_SEQUENTIAL_REQUESTS
        if processed is None:
            processed = total
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
                f"{processed}/{total} "
                f"requests succeeded without 429 on {endpoint.url}"
            ),
            confidence=RateLimitConfig.CONFIDENCE_NO_RATE_LIMIT,
            scanner_name=self.scanner_name,
            endpoint_url=endpoint.url,
            http_method=endpoint.method.value,
        )

    def _build_inconclusive_finding(
        self,
        endpoint: DiscoveredEndpoint,
        reason: str,
        processed: int = 0,
    ) -> DeepFinding:
        """Build an informational "could not test" finding (not a vulnerability)."""
        return DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.AUTH_WEAKNESS,
            severity=SeverityLevel.INFO,
            title=TITLE_RATE_LIMIT_INCONCLUSIVE,
            description=DESC_RATE_LIMIT_INCONCLUSIVE.format(
                url=endpoint.url, reason=reason
            ),
            technical_detail=(
                f"{processed} usable responses received from "
                f"{endpoint.method.value} {endpoint.url} before the run stopped.\n"
                f"{reason}"
            ),
            evidence=f"Inconclusive on {endpoint.url}: {reason}",
            confidence=CONFIDENCE_INCONCLUSIVE,
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
