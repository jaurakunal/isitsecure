"""Server-Side Request Forgery (SSRF) scanner.

Tests endpoints with URL-accepting parameters by injecting SSRF probes
(internal IPs, cloud metadata endpoints). Checks if the server's response
contains indicators that it fetched the internal resource.
"""

from __future__ import annotations

import logging
from urllib.parse import parse_qs, urlparse

from isitsecure.engine.constants import DeepScanConfig, SSRFConfig
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


class SSRFScanner:
    """Tests for Server-Side Request Forgery vulnerabilities.

    Identifies endpoints with URL-accepting parameters and injects
    internal IP / cloud metadata URLs to detect SSRF.
    """

    HTTP_STATUS_OK_LOWER = 200
    HTTP_STATUS_OK_UPPER = 400

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return SSRFConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.INJECTION_RISK]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run SSRF tests on discovered endpoints.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot (unused by this scanner).

        Returns:
            List of unified findings from this scanner.
        """
        findings: list[DeepFinding] = []

        testable = self._find_url_param_endpoints(endpoints)
        if not testable:
            logger.info("SSRFScanner: no endpoints with URL parameters found")
            return findings

        async with RateLimitedClient(
            max_concurrent=SSRFConfig.MAX_CONCURRENT,
            delay_seconds=SSRFConfig.PROBE_DELAY,
            timeout_seconds=SSRFConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            for endpoint, param_name in testable:
                ep_findings = await self._test_endpoint_param(
                    client, endpoint, param_name
                )
                findings.extend(ep_findings)

        logger.info("SSRFScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Endpoint filtering
    # ------------------------------------------------------------------

    def _find_url_param_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[tuple[DiscoveredEndpoint, str]]:
        """Find endpoints that have URL-accepting parameters.

        Returns a list of (endpoint, param_name) tuples.
        """
        results: list[tuple[DiscoveredEndpoint, str]] = []
        for ep in endpoints:
            # Check query params in the URL
            parsed = urlparse(ep.url)
            existing_params = parse_qs(parsed.query)
            for param_name in existing_params:
                if param_name.lower() in SSRFConfig.URL_PARAM_NAMES:
                    results.append((ep, param_name))

            # Check declared query param names
            for param_name in ep.query_param_names:
                if (
                    param_name.lower() in SSRFConfig.URL_PARAM_NAMES
                    and (ep, param_name) not in results
                ):
                    results.append((ep, param_name))

        return results

    # ------------------------------------------------------------------
    # SSRF testing
    # ------------------------------------------------------------------

    async def _test_endpoint_param(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        param_name: str,
    ) -> list[DeepFinding]:
        """Test a single parameter with all SSRF probes."""
        findings: list[DeepFinding] = []

        for probe_url, probe_label in SSRFConfig.SSRF_PROBES:
            finding = await self._send_ssrf_probe(
                client, endpoint, param_name, probe_url, probe_label
            )
            if finding:
                findings.append(finding)
                # One finding per param is enough
                break

        return findings

    async def _send_ssrf_probe(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        param_name: str,
        probe_url: str,
        probe_label: str,
    ) -> DeepFinding | None:
        """Inject an SSRF probe URL and check the response."""
        try:
            injected_url = inject_query_param(endpoint.url, param_name, probe_url)
            response = await client.get(injected_url)

            if not (
                self.HTTP_STATUS_OK_LOWER
                <= response.status_code
                < self.HTTP_STATUS_OK_UPPER
            ):
                return None

            body = response.text
            if self._response_indicates_ssrf(body):
                return DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.INJECTION_RISK,
                    severity=SeverityLevel.HIGH,
                    title=SSRFConfig.TITLE_SSRF,
                    description=SSRFConfig.DESC_SSRF.format(
                        param=param_name, url=endpoint.url, probe=probe_url
                    ),
                    technical_detail=(
                        f"Injected '{probe_url}' into param '{param_name}'\n"
                        f"Probe type: {probe_label}\n"
                        f"Response contained SSRF indicators"
                    ),
                    evidence=(
                        f"GET {injected_url} -> response suggests internal "
                        f"resource ({probe_label}) was reached"
                    ),
                    confidence=SSRFConfig.CONFIDENCE_SSRF,
                    scanner_name=self.scanner_name,
                    endpoint_url=endpoint.url,
                    http_method="GET",
                    request_payload=f"{param_name}={probe_url}",
                    response_preview=body[:300],
                )

        except Exception as exc:
            logger.debug(
                SSRFConfig.ERROR_SSRF_SCAN_FAILED.format(
                    endpoint=endpoint.url, error=str(exc)
                )
            )

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _response_indicates_ssrf(self, body: str) -> bool:
        """Check if the response body contains SSRF success indicators."""
        body_lower = body.lower()
        return any(
            indicator.lower() in body_lower
            for indicator in SSRFConfig.SSRF_SUCCESS_INDICATORS
        )

