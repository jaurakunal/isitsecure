"""Cross-Origin Resource Sharing (CORS) misconfiguration scanner.

Tests representative endpoints for dangerous CORS configurations:
1. Reflected arbitrary origins in Access-Control-Allow-Origin
2. Null origin allowed
3. Subdomain bypass via suffix matching
4. Wildcard with credentials enabled
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from isitsecure.engine.constants import CORSConfig, DeepScanConfig
from isitsecure.engine.models import (
    DASTProbeCaptureEntry,
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.probe_capture import build_probe_capture
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


class CORSScanner:
    """CORS misconfiguration scanner implementing DASTScannerProtocol.

    Sends preflight-style requests with various Origin headers to detect
    overly permissive CORS policies that could enable credential theft
    or cross-origin data leakage.
    """

    MAX_RESPONSE_PREVIEW_LENGTH = 300

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return CORSConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.AUTH_WEAKNESS]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run CORS misconfiguration tests on representative endpoints.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot (unused by this scanner).

        Returns:
            List of unified findings from this scanner.
        """
        findings: list[DeepFinding] = []

        representative = self._select_representative_endpoints(endpoints)
        if not representative:
            logger.info("CORSScanner: no endpoints to test")
            return findings

        async with RateLimitedClient(
            max_concurrent=CORSConfig.MAX_CONCURRENT,
            delay_seconds=CORSConfig.PROBE_DELAY,
            timeout_seconds=CORSConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            for ep in representative:
                ep_findings = await self._test_endpoint(client, ep)
                findings.extend(ep_findings)

        logger.info("CORSScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Endpoint selection
    # ------------------------------------------------------------------

    def _select_representative_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """Select up to MAX_ENDPOINTS_TO_TEST from different path prefixes.

        Picks endpoints with distinct first two path segments to ensure
        broad coverage across different API areas.
        """
        seen_prefixes: set[str] = set()
        selected: list[DiscoveredEndpoint] = []

        for ep in endpoints:
            parsed = urlparse(ep.url)
            segments = [s for s in parsed.path.split("/") if s]
            prefix = "/".join(segments[:CORSConfig.PATH_PREFIX_DEPTH])

            if prefix not in seen_prefixes:
                seen_prefixes.add(prefix)
                selected.append(ep)

            if len(selected) >= CORSConfig.MAX_ENDPOINTS_TO_TEST:
                break

        return selected

    # ------------------------------------------------------------------
    # CORS testing per endpoint
    # ------------------------------------------------------------------

    async def _test_endpoint(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
    ) -> list[DeepFinding]:
        """Test a single endpoint with all CORS origin probes."""
        findings: list[DeepFinding] = []
        target_host = urlparse(endpoint.url).hostname or ""

        for origin, probe_label in CORSConfig.ORIGIN_PROBES:
            # Replace {target} placeholder with actual target domain
            resolved_origin = origin.replace("{target}", target_host)

            finding = await self._send_cors_probe(
                client, endpoint, resolved_origin, probe_label
            )
            if finding:
                findings.append(finding)
                # One finding per endpoint is sufficient
                break

        return findings

    async def _send_cors_probe(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        origin: str,
        probe_label: str,
    ) -> DeepFinding | None:
        """Send a request with a specific Origin header and analyze CORS response."""
        headers = {"Origin": origin}

        try:
            response = await client.get(endpoint.url, headers=headers)

            acao = response.headers.get(
                CORSConfig.HEADER_ALLOW_ORIGIN, ""
            )
            acac = response.headers.get(
                CORSConfig.HEADER_ALLOW_CREDENTIALS, ""
            ).lower()

            if not acao:
                return None

            credentials_enabled = acac == CORSConfig.CREDENTIALS_TRUE_VALUE

            capture = build_probe_capture(
                method="GET",
                url=endpoint.url,
                headers=dict(response.request.headers),
                body="",
                response_status=response.status_code,
                response_headers=dict(response.headers),
                response_body=response.text,
                elapsed_ms=response.elapsed.total_seconds() * 1000,
                scanner_name=self.scanner_name,
            )

            return self._classify_cors_response(
                endpoint, origin, probe_label,
                acao, credentials_enabled, response.status_code,
                capture=capture,
            )

        except Exception as exc:
            logger.debug(
                CORSConfig.ERROR_CORS_SCAN_FAILED.format(
                    endpoint=endpoint.url, error=str(exc)
                )
            )

        return None

    # ------------------------------------------------------------------
    # Response classification
    # ------------------------------------------------------------------

    def _classify_cors_response(
        self,
        endpoint: DiscoveredEndpoint,
        origin: str,
        probe_label: str,
        acao: str,
        credentials_enabled: bool,
        status_code: int,
        capture: DASTProbeCaptureEntry | None = None,
    ) -> DeepFinding | None:
        """Classify the CORS response into a finding based on severity rules.

        Rules:
        - Wildcard + credentials -> CRITICAL (credential theft)
        - Arbitrary origin reflected -> HIGH
        - Null origin allowed -> HIGH
        - Wildcard without credentials -> MEDIUM (data leakage)
        """
        # Rule 1: Wildcard with credentials is the most dangerous
        if acao == CORSConfig.WILDCARD_ORIGIN and credentials_enabled:
            return self._build_finding(
                endpoint=endpoint,
                severity=SeverityLevel.CRITICAL,
                title=CORSConfig.TITLE_WILDCARD_CREDENTIALS,
                description=CORSConfig.DESC_WILDCARD_CREDENTIALS.format(
                    url=endpoint.url,
                ),
                origin=origin,
                probe_label=probe_label,
                acao=acao,
                credentials_enabled=credentials_enabled,
                status_code=status_code,
                confidence=CORSConfig.CONFIDENCE_WILDCARD_CREDS,
                capture=capture,
            )

        # Rule 2: Arbitrary origin reflected back
        if acao == origin and origin != CORSConfig.WILDCARD_ORIGIN:
            return self._build_finding(
                endpoint=endpoint,
                severity=SeverityLevel.HIGH,
                title=CORSConfig.TITLE_ORIGIN_REFLECTED,
                description=CORSConfig.DESC_ORIGIN_REFLECTED.format(
                    url=endpoint.url, origin=origin,
                ),
                origin=origin,
                probe_label=probe_label,
                acao=acao,
                credentials_enabled=credentials_enabled,
                status_code=status_code,
                confidence=CORSConfig.CONFIDENCE_ORIGIN_REFLECTED,
                capture=capture,
            )

        # Rule 3: Null origin allowed
        if acao == CORSConfig.NULL_ORIGIN:
            return self._build_finding(
                endpoint=endpoint,
                severity=SeverityLevel.HIGH,
                title=CORSConfig.TITLE_NULL_ORIGIN,
                description=CORSConfig.DESC_NULL_ORIGIN.format(
                    url=endpoint.url,
                ),
                origin=origin,
                probe_label=probe_label,
                acao=acao,
                credentials_enabled=credentials_enabled,
                status_code=status_code,
                confidence=CORSConfig.CONFIDENCE_NULL_ORIGIN,
                capture=capture,
            )

        # Rule 4: Wildcard without credentials (data leakage)
        if acao == CORSConfig.WILDCARD_ORIGIN and not credentials_enabled:
            return self._build_finding(
                endpoint=endpoint,
                severity=SeverityLevel.MEDIUM,
                title=CORSConfig.TITLE_WILDCARD_NO_CREDS,
                description=CORSConfig.DESC_WILDCARD_NO_CREDS.format(
                    url=endpoint.url,
                ),
                origin=origin,
                probe_label=probe_label,
                acao=acao,
                credentials_enabled=credentials_enabled,
                status_code=status_code,
                confidence=CORSConfig.CONFIDENCE_WILDCARD_NO_CREDS,
                capture=capture,
            )

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_finding(
        self,
        endpoint: DiscoveredEndpoint,
        severity: SeverityLevel,
        title: str,
        description: str,
        origin: str,
        probe_label: str,
        acao: str,
        credentials_enabled: bool,
        status_code: int,
        confidence: float,
        capture: DASTProbeCaptureEntry | None = None,
    ) -> DeepFinding:
        """Construct a DeepFinding for a CORS misconfiguration."""
        return DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.AUTH_WEAKNESS,
            severity=severity,
            title=title,
            description=description,
            technical_detail=(
                f"Sent Origin: {origin} ({probe_label})\n"
                f"Response Access-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: {credentials_enabled}\n"
                f"Response status: {status_code}"
            ),
            evidence=(
                f"GET {endpoint.url} with Origin: {origin} -> "
                f"ACAO: {acao}, credentials: {credentials_enabled}"
            ),
            confidence=confidence,
            scanner_name=self.scanner_name,
            endpoint_url=endpoint.url,
            http_method="GET",
            request_payload=f"Origin: {origin}",
            probe_captures=[capture] if capture else [],
        )
