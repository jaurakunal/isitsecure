"""HTTP configuration probe scanner.

Runs 4 lightweight checks against discovered endpoints:
1. HTTP method tampering — TRACE, OPTIONS revealing dangerous methods
2. Host header injection — password reset poisoning, routing abuse
3. Verbose error pages — stack traces, framework disclosure in 4xx/5xx
4. Directory listing / sensitive file exposure — .git, .env, backups

SRP: Each check is a separate method.  ``scan()`` aggregates results.
OCP: New checks are added as new methods, not by modifying existing ones.
DIP: Depends on ``DASTScannerProtocol`` abstraction and config constants.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from isitsecure.engine.constants import DeepScanConfig, HTTPProbeConfig
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.rate_limited_client import (
    RateLimitedClient,
)
from isitsecure.engine.shared.url_utils import inject_query_param
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


class HTTPProbeScanner:
    """Probes HTTP configuration for misconfigurations and info leaks.

    Implements DASTScannerProtocol.
    """

    @property
    def scanner_name(self) -> str:
        return HTTPProbeConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        return [
            FindingCategory.INFO_DISCLOSURE,
            FindingCategory.AUTH_WEAKNESS,
        ]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run all HTTP probe checks."""
        if not endpoints:
            return []

        findings: list[DeepFinding] = []
        base_url = self._extract_base_url(endpoints)
        if not base_url:
            return []

        # Select representative endpoints (up to 5)
        test_endpoints = endpoints[: HTTPProbeConfig.MAX_ENDPOINTS_TO_TEST]

        async with RateLimitedClient(
            max_concurrent=HTTPProbeConfig.MAX_CONCURRENT,
            delay_seconds=HTTPProbeConfig.PROBE_DELAY,
            timeout_seconds=DeepScanConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            findings.extend(
                await self._check_method_tampering(test_endpoints, client)
            )
            findings.extend(
                await self._check_host_header_injection(
                    base_url, test_endpoints, client,
                )
            )
            findings.extend(
                await self._check_verbose_errors(base_url, client)
            )
            findings.extend(
                await self._check_directory_listing(base_url, client)
            )
            findings.extend(
                await self._check_crlf_injection(
                    test_endpoints, client,
                )
            )

        logger.info(
            "HTTPProbeScanner: %d findings from %d endpoints",
            len(findings),
            len(test_endpoints),
        )
        return findings

    # ------------------------------------------------------------------
    # Check 1: HTTP Method Tampering
    # ------------------------------------------------------------------

    async def _check_method_tampering(
        self,
        endpoints: list[DiscoveredEndpoint],
        client: RateLimitedClient,
    ) -> list[DeepFinding]:
        """Check for dangerous HTTP methods (TRACE, unexpected PUT/DELETE)."""
        findings: list[DeepFinding] = []
        tested: set[str] = set()

        for ep in endpoints[: HTTPProbeConfig.MAX_METHOD_TEST_ENDPOINTS]:
            if ep.url in tested:
                continue
            tested.add(ep.url)

            try:
                # OPTIONS request to discover allowed methods
                resp = await client.request("OPTIONS", ep.url)
                allow = resp.headers.get("allow", "")
                if not allow:
                    allow = resp.headers.get(
                        "access-control-allow-methods", ""
                    )

                if allow:
                    methods = {
                        m.strip().upper() for m in allow.split(",")
                    }
                    for dangerous in HTTPProbeConfig.DANGEROUS_METHODS:
                        if dangerous in methods:
                            findings.append(self._build_finding(
                                endpoint_url=ep.url,
                                title=HTTPProbeConfig.TITLE_DANGEROUS_METHOD.format(
                                    method=dangerous, url=ep.url,
                                ),
                                description=HTTPProbeConfig.DESC_DANGEROUS_METHOD.format(
                                    method=dangerous, url=ep.url,
                                    allow_header=allow,
                                ),
                                severity=(
                                    SeverityLevel.HIGH
                                    if dangerous == "TRACE"
                                    else SeverityLevel.MEDIUM
                                ),
                                confidence=HTTPProbeConfig.CONFIDENCE_METHOD_TAMPERING,
                            ))

                # TRACE request — check if it echoes back
                trace_resp = await client.request("TRACE", ep.url)
                if trace_resp.status_code == 200:
                    body = trace_resp.text[:500]
                    if "TRACE" in body or "Host:" in body:
                        findings.append(self._build_finding(
                            endpoint_url=ep.url,
                            title=HTTPProbeConfig.TITLE_TRACE_ENABLED.format(
                                url=ep.url,
                            ),
                            description=HTTPProbeConfig.DESC_TRACE_ENABLED.format(
                                url=ep.url,
                            ),
                            severity=SeverityLevel.HIGH,
                            confidence=HTTPProbeConfig.CONFIDENCE_TRACE,
                        ))
                        break  # One TRACE finding is enough

            except Exception as e:
                logger.debug("Method tampering check failed for %s: %s", ep.url, e)

        return findings

    # ------------------------------------------------------------------
    # Check 2: Host Header Injection
    # ------------------------------------------------------------------

    async def _check_host_header_injection(
        self,
        base_url: str,
        endpoints: list[DiscoveredEndpoint],
        client: RateLimitedClient,
    ) -> list[DeepFinding]:
        """Check if the app reflects a forged Host header."""
        findings: list[DeepFinding] = []
        evil_host = HTTPProbeConfig.FORGED_HOST

        # Test homepage + first few endpoints
        test_urls = [base_url]
        test_urls.extend(
            ep.url for ep in endpoints[:2] if ep.url != base_url
        )

        for url in test_urls:
            for header_name in HTTPProbeConfig.HOST_HEADERS:
                try:
                    resp = await client.get(
                        url, headers={header_name: evil_host},
                    )
                    body = resp.text[:5000]

                    if evil_host in body:
                        findings.append(self._build_finding(
                            endpoint_url=url,
                            title=HTTPProbeConfig.TITLE_HOST_INJECTION.format(
                                header=header_name,
                            ),
                            description=HTTPProbeConfig.DESC_HOST_INJECTION.format(
                                url=url, header=header_name,
                                host=evil_host,
                            ),
                            severity=SeverityLevel.HIGH,
                            confidence=HTTPProbeConfig.CONFIDENCE_HOST_INJECTION,
                        ))
                        return findings  # One finding is enough

                    # Check Location header for redirects
                    location = resp.headers.get("location", "")
                    if evil_host in location:
                        findings.append(self._build_finding(
                            endpoint_url=url,
                            title=HTTPProbeConfig.TITLE_HOST_INJECTION.format(
                                header=header_name,
                            ),
                            description=HTTPProbeConfig.DESC_HOST_INJECTION.format(
                                url=url, header=header_name,
                                host=evil_host,
                            ),
                            severity=SeverityLevel.HIGH,
                            confidence=HTTPProbeConfig.CONFIDENCE_HOST_INJECTION,
                        ))
                        return findings

                except Exception as e:
                    logger.debug("Host header check failed for %s: %s", url, e)

        return findings

    # ------------------------------------------------------------------
    # Check 3: Verbose Error Pages
    # ------------------------------------------------------------------

    async def _check_verbose_errors(
        self,
        base_url: str,
        client: RateLimitedClient,
    ) -> list[DeepFinding]:
        """Check if error responses leak sensitive information."""
        findings: list[DeepFinding] = []

        for path in HTTPProbeConfig.ERROR_TRIGGER_PATHS:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code < 400:
                    continue

                body = resp.text[:10000]
                for pattern in HTTPProbeConfig.ERROR_LEAK_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(self._build_finding(
                            endpoint_url=url,
                            title=HTTPProbeConfig.TITLE_VERBOSE_ERROR.format(
                                url=url,
                            ),
                            description=HTTPProbeConfig.DESC_VERBOSE_ERROR.format(
                                url=url,
                                status=resp.status_code,
                            ),
                            severity=SeverityLevel.MEDIUM,
                            confidence=HTTPProbeConfig.CONFIDENCE_VERBOSE_ERROR,
                        ))
                        return findings  # One finding is enough

            except Exception as e:
                logger.debug("Error page check failed for %s: %s", url, e)

        return findings

    # ------------------------------------------------------------------
    # Check 4: Directory Listing / Sensitive Files
    # ------------------------------------------------------------------

    async def _check_directory_listing(
        self,
        base_url: str,
        client: RateLimitedClient,
    ) -> list[DeepFinding]:
        """Check for directory listing and sensitive file exposure."""
        findings: list[DeepFinding] = []

        for path, check_type, indicator in HTTPProbeConfig.SENSITIVE_PATHS:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    continue

                body = resp.text[:5000]

                if check_type == "content" and indicator in body:
                    severity = (
                        SeverityLevel.HIGH
                        if ".git" in path or ".env" in path
                        else SeverityLevel.MEDIUM
                    )
                    findings.append(self._build_finding(
                        endpoint_url=url,
                        title=HTTPProbeConfig.TITLE_SENSITIVE_FILE.format(
                            path=path,
                        ),
                        description=HTTPProbeConfig.DESC_SENSITIVE_FILE.format(
                            url=url, path=path,
                        ),
                        severity=severity,
                        confidence=HTTPProbeConfig.CONFIDENCE_SENSITIVE_FILE,
                    ))

                elif check_type == "listing":
                    if any(
                        p in body
                        for p in HTTPProbeConfig.DIRECTORY_LISTING_INDICATORS
                    ):
                        findings.append(self._build_finding(
                            endpoint_url=url,
                            title=HTTPProbeConfig.TITLE_DIRECTORY_LISTING.format(
                                path=path,
                            ),
                            description=HTTPProbeConfig.DESC_DIRECTORY_LISTING.format(
                                url=url, path=path,
                            ),
                            severity=SeverityLevel.MEDIUM,
                            confidence=HTTPProbeConfig.CONFIDENCE_DIRECTORY_LISTING,
                        ))

            except Exception as e:
                logger.debug("Directory check failed for %s: %s", url, e)

        return findings

    # ------------------------------------------------------------------
    # Check 5: CRLF / Header Injection
    # ------------------------------------------------------------------

    async def _check_crlf_injection(
        self,
        endpoints: list[DiscoveredEndpoint],
        client: RateLimitedClient,
    ) -> list[DeepFinding]:
        """Check if CRLF characters in params inject response headers.

        Injects \\r\\n + a canary header into URL parameters and checks
        if the canary appears in response headers (confirmed header injection).
        """
        findings: list[DeepFinding] = []

        for ep in endpoints[:HTTPProbeConfig.MAX_METHOD_TEST_ENDPOINTS]:
            for param in HTTPProbeConfig.CRLF_PARAM_NAMES:
                for payload in HTTPProbeConfig.CRLF_PAYLOADS:
                    try:
                        url = inject_query_param(ep.url, param, payload)
                        resp = await client.get(url)

                        # Check if our canary header was injected
                        canary = resp.headers.get(
                            HTTPProbeConfig.CRLF_CANARY_HEADER.lower(), ""
                        )
                        if (
                            HTTPProbeConfig.CRLF_CANARY_VALUE in canary
                            or HTTPProbeConfig.CRLF_CANARY_VALUE
                            in resp.headers.get(
                                HTTPProbeConfig.CRLF_CANARY_HEADER, ""
                            )
                        ):
                            findings.append(self._build_finding(
                                endpoint_url=ep.url,
                                title=HTTPProbeConfig.TITLE_CRLF_INJECTION.format(
                                    param=param,
                                ),
                                description=HTTPProbeConfig.DESC_CRLF_INJECTION.format(
                                    url=ep.url, param=param,
                                ),
                                severity=SeverityLevel.HIGH,
                                confidence=HTTPProbeConfig.CONFIDENCE_CRLF,
                            ))
                            return findings  # One confirmed CRLF is enough

                    except Exception as e:
                        logger.debug(
                            "CRLF check failed for %s: %s", ep.url, e,
                        )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_base_url(endpoints: list[DiscoveredEndpoint]) -> str:
        """Extract scheme + host from the first endpoint."""
        if not endpoints:
            return ""
        from urllib.parse import urlparse
        parsed = urlparse(endpoints[0].url)
        return f"{parsed.scheme}://{parsed.netloc}"

    @staticmethod
    def _build_finding(
        *,
        endpoint_url: str,
        title: str,
        description: str,
        severity: SeverityLevel,
        confidence: float,
    ) -> DeepFinding:
        return DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.INFO_DISCLOSURE,
            severity=severity,
            title=title,
            description=description,
            confidence=confidence,
            scanner_name=HTTPProbeConfig.SCANNER_NAME,
            endpoint_url=endpoint_url,
        )
