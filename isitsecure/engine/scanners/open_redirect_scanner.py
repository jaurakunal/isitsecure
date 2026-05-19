"""Open Redirect vulnerability scanner.

Tests endpoints with redirect-like parameters and common redirect paths
by injecting external URLs and checking if the server issues a redirect
to the attacker-controlled destination.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import parse_qs, urlparse

from isitsecure.engine.constants import (
    DeepScanConfig,
    OpenRedirectConfig,
)
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.shared.url_utils import inject_query_param
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


class OpenRedirectScanner:
    """Open Redirect scanner implementing DASTScannerProtocol.

    Identifies endpoints that accept redirect-like parameters or reside
    at common redirect paths, then injects external URLs to detect
    unvalidated redirects.
    """

    HTTP_STATUS_REDIRECT_LOWER = 300
    HTTP_STATUS_REDIRECT_UPPER = 400
    MAX_RESPONSE_PREVIEW_LENGTH = 300

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return OpenRedirectConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.AUTH_WEAKNESS]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run open redirect tests on discovered endpoints.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot (unused by this scanner).

        Returns:
            List of unified findings from this scanner.
        """
        findings: list[DeepFinding] = []

        testable = self._find_redirect_endpoints(endpoints)
        if not testable:
            logger.info("OpenRedirectScanner: no redirect-like endpoints found")
            return findings

        async with RateLimitedClient(
            max_concurrent=OpenRedirectConfig.MAX_CONCURRENT,
            delay_seconds=OpenRedirectConfig.PROBE_DELAY,
            timeout_seconds=OpenRedirectConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
            follow_redirects=False,
        ) as client:
            for endpoint, param_name in testable:
                ep_findings = await self._test_endpoint_param(
                    client, endpoint, param_name
                )
                findings.extend(ep_findings)

        logger.info("OpenRedirectScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Endpoint filtering
    # ------------------------------------------------------------------

    def _find_redirect_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[tuple[DiscoveredEndpoint, str]]:
        """Find endpoints with redirect-like parameters or redirect paths.

        Returns a list of (endpoint, param_name) tuples to test.
        """
        results: list[tuple[DiscoveredEndpoint, str]] = []

        for ep in endpoints:
            # Strategy 1: Check existing query parameters
            parsed = urlparse(ep.url)
            existing_params = parse_qs(parsed.query)
            for param_name in existing_params:
                if param_name.lower() in OpenRedirectConfig.REDIRECT_PARAM_NAMES:
                    results.append((ep, param_name))

            # Strategy 2: Check declared query param names
            for param_name in ep.query_param_names:
                if (
                    param_name.lower() in OpenRedirectConfig.REDIRECT_PARAM_NAMES
                    and (ep, param_name) not in results
                ):
                    results.append((ep, param_name))

            # Strategy 3: Check if the path matches common redirect endpoints
            if self._is_redirect_path(parsed.path) and (ep, OpenRedirectConfig.DEFAULT_REDIRECT_PARAM) not in results:
                # Test with the most common redirect param
                results.append(
                    (ep, OpenRedirectConfig.DEFAULT_REDIRECT_PARAM)
                )

        return results

    def _is_redirect_path(self, path: str) -> bool:
        """Check if the URL path matches known redirect endpoint patterns."""
        path_lower = path.lower()
        return any(
            path_lower.endswith(redirect_path)
            or redirect_path in path_lower
            for redirect_path in OpenRedirectConfig.REDIRECT_PATH_INDICATORS
        )

    # ------------------------------------------------------------------
    # Redirect testing
    # ------------------------------------------------------------------

    async def _test_endpoint_param(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        param_name: str,
    ) -> list[DeepFinding]:
        """Test a single parameter with all redirect payloads."""
        findings: list[DeepFinding] = []

        for payload, payload_label in OpenRedirectConfig.REDIRECT_PAYLOADS:
            finding = await self._send_redirect_probe(
                client, endpoint, param_name, payload, payload_label
            )
            if finding:
                findings.append(finding)
                # One finding per param is sufficient
                break

        return findings

    async def _send_redirect_probe(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        param_name: str,
        payload: str,
        payload_label: str,
    ) -> DeepFinding | None:
        """Inject a redirect payload and check the response."""
        try:
            injected_url = inject_query_param(
                endpoint.url, param_name, payload
            )
            response = await client.get(injected_url)

            # Check 1: HTTP 3xx redirect with Location header
            finding = self._check_redirect_header(
                endpoint, param_name, payload, payload_label,
                response.status_code,
                response.headers.get(OpenRedirectConfig.HEADER_LOCATION, ""),
            )
            if finding:
                return finding

            # Check 2: JavaScript/meta redirect in response body
            finding = self._check_body_redirect(
                endpoint, param_name, payload, payload_label,
                response.text,
            )
            if finding:
                return finding

        except Exception as exc:
            logger.debug(
                OpenRedirectConfig.ERROR_REDIRECT_SCAN_FAILED.format(
                    endpoint=endpoint.url, error=str(exc)
                )
            )

        return None

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    def _check_redirect_header(
        self,
        endpoint: DiscoveredEndpoint,
        param_name: str,
        payload: str,
        payload_label: str,
        status_code: int,
        location: str,
    ) -> DeepFinding | None:
        """Check if a 3xx response redirects to the attacker domain."""
        if not (
            self.HTTP_STATUS_REDIRECT_LOWER
            <= status_code
            < self.HTTP_STATUS_REDIRECT_UPPER
        ):
            return None

        if not location:
            return None

        # Check if the Location header points to an external domain
        if self._is_external_redirect(location):
            return DeepFinding(
                source=FindingSource.DAST_URL,
                category=FindingCategory.AUTH_WEAKNESS,
                severity=SeverityLevel.HIGH,
                title=OpenRedirectConfig.TITLE_HEADER_REDIRECT,
                description=OpenRedirectConfig.DESC_HEADER_REDIRECT.format(
                    param=param_name,
                    url=endpoint.url,
                    payload=payload,
                    location=location,
                ),
                technical_detail=(
                    f"Injected '{payload}' into param '{param_name}'\n"
                    f"Payload type: {payload_label}\n"
                    f"Response status: {status_code}\n"
                    f"Location header: {location}"
                ),
                evidence=(
                    f"GET {endpoint.url}?{param_name}={payload} -> "
                    f"{status_code} Location: {location}"
                ),
                confidence=OpenRedirectConfig.CONFIDENCE_HEADER_REDIRECT,
                scanner_name=self.scanner_name,
                endpoint_url=endpoint.url,
                http_method="GET",
                request_payload=f"{param_name}={payload}",
            )

        return None

    def _check_body_redirect(
        self,
        endpoint: DiscoveredEndpoint,
        param_name: str,
        payload: str,
        payload_label: str,
        body: str,
    ) -> DeepFinding | None:
        """Check if the response body contains a JavaScript or meta redirect."""
        if not body:
            return None

        body_lower = body.lower()

        for pattern in OpenRedirectConfig.BODY_REDIRECT_PATTERNS:
            if re.search(pattern, body_lower):
                return DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.AUTH_WEAKNESS,
                    severity=SeverityLevel.MEDIUM,
                    title=OpenRedirectConfig.TITLE_BODY_REDIRECT,
                    description=OpenRedirectConfig.DESC_BODY_REDIRECT.format(
                        param=param_name,
                        url=endpoint.url,
                        payload=payload,
                    ),
                    technical_detail=(
                        f"Injected '{payload}' into param '{param_name}'\n"
                        f"Payload type: {payload_label}\n"
                        f"Response body contains redirect pattern"
                    ),
                    evidence=(
                        f"GET {endpoint.url}?{param_name}={payload} -> "
                        f"body contains JS/meta redirect"
                    ),
                    confidence=OpenRedirectConfig.CONFIDENCE_BODY_REDIRECT,
                    scanner_name=self.scanner_name,
                    endpoint_url=endpoint.url,
                    http_method="GET",
                    request_payload=f"{param_name}={payload}",
                    response_preview=body[: self.MAX_RESPONSE_PREVIEW_LENGTH],
                )

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_external_redirect(self, location: str) -> bool:
        """Check if a Location header value points to an external domain."""
        # Protocol-relative URLs like //evil.com
        if location.startswith("//"):
            return True

        parsed = urlparse(location)

        # Absolute URL with a scheme pointing to an evil domain
        if parsed.scheme in (
            OpenRedirectConfig.SCHEME_HTTP,
            OpenRedirectConfig.SCHEME_HTTPS,
        ) and parsed.hostname:
            return any(
                indicator in parsed.hostname
                for indicator in OpenRedirectConfig.EVIL_DOMAIN_INDICATORS
            )

        return False
