"""Security headers scanner.

Tests HTTP response headers for missing or misconfigured security headers:
1. Missing HSTS — enables SSL stripping attacks
2. Missing X-Content-Type-Options — enables MIME-sniffing attacks
3. Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors)
4. Missing Content-Security-Policy — weakens XSS mitigations
5. Missing Permissions-Policy — allows unrestricted browser feature access
6. Missing Referrer-Policy — may leak sensitive URL data
7. Server version disclosure — aids attacker reconnaissance
8. X-Powered-By disclosure — reveals technology stack
"""

from __future__ import annotations

import logging
import re
from enum import Enum

from isitsecure.engine.constants import (
    DeepScanConfig,
    SecurityHeadersScannerConfig,
)
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.rate_limited_client import (
    RateLimitedClient,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


class _HeaderCheckType(str, Enum):
    """Types of header checks performed by the scanner."""

    MISSING_HSTS = "missing_hsts"
    MISSING_CONTENT_TYPE_OPTIONS = "missing_content_type_options"
    MISSING_FRAME_PROTECTION = "missing_frame_protection"
    MISSING_CSP = "missing_csp"
    MISSING_PERMISSIONS_POLICY = "missing_permissions_policy"
    MISSING_REFERRER_POLICY = "missing_referrer_policy"
    SERVER_VERSION_DISCLOSURE = "server_version_disclosure"
    X_POWERED_BY_PRESENT = "x_powered_by_present"


class SecurityHeadersScanner:
    """Security headers scanner implementing DASTScannerProtocol.

    Detects missing or misconfigured HTTP security headers by making
    GET requests to a representative set of endpoints and checking
    response headers.

    SRP: This scanner is responsible ONLY for security header analysis.
    """

    MAX_CONCURRENT_REQUESTS = SecurityHeadersScannerConfig.MAX_CONCURRENT_REQUESTS
    REQUEST_DELAY_SECONDS = SecurityHeadersScannerConfig.REQUEST_DELAY_SECONDS

    # Map each check type to its config attributes
    _MISSING_HEADER_CHECKS: dict[_HeaderCheckType, dict] = {
        _HeaderCheckType.MISSING_HSTS: {
            "header": SecurityHeadersScannerConfig.HEADER_HSTS,
            "severity": SecurityHeadersScannerConfig.SEVERITY_MISSING_HSTS,
            "confidence": SecurityHeadersScannerConfig.CONFIDENCE_MISSING_HSTS,
            "title": SecurityHeadersScannerConfig.TITLE_MISSING_HSTS,
            "desc_template": SecurityHeadersScannerConfig.DESC_MISSING_HSTS,
        },
        _HeaderCheckType.MISSING_CONTENT_TYPE_OPTIONS: {
            "header": SecurityHeadersScannerConfig.HEADER_CONTENT_TYPE_OPTIONS,
            "severity": SecurityHeadersScannerConfig.SEVERITY_MISSING_CONTENT_TYPE_OPTIONS,
            "confidence": SecurityHeadersScannerConfig.CONFIDENCE_MISSING_CONTENT_TYPE_OPTIONS,
            "title": SecurityHeadersScannerConfig.TITLE_MISSING_CONTENT_TYPE_OPTIONS,
            "desc_template": SecurityHeadersScannerConfig.DESC_MISSING_CONTENT_TYPE_OPTIONS,
        },
        _HeaderCheckType.MISSING_CSP: {
            "header": SecurityHeadersScannerConfig.HEADER_CSP,
            "severity": SecurityHeadersScannerConfig.SEVERITY_MISSING_CSP,
            "confidence": SecurityHeadersScannerConfig.CONFIDENCE_MISSING_CSP,
            "title": SecurityHeadersScannerConfig.TITLE_MISSING_CSP,
            "desc_template": SecurityHeadersScannerConfig.DESC_MISSING_CSP,
        },
        _HeaderCheckType.MISSING_PERMISSIONS_POLICY: {
            "header": SecurityHeadersScannerConfig.HEADER_PERMISSIONS_POLICY,
            "severity": SecurityHeadersScannerConfig.SEVERITY_MISSING_PERMISSIONS_POLICY,
            "confidence": SecurityHeadersScannerConfig.CONFIDENCE_MISSING_PERMISSIONS_POLICY,
            "title": SecurityHeadersScannerConfig.TITLE_MISSING_PERMISSIONS_POLICY,
            "desc_template": SecurityHeadersScannerConfig.DESC_MISSING_PERMISSIONS_POLICY,
        },
        _HeaderCheckType.MISSING_REFERRER_POLICY: {
            "header": SecurityHeadersScannerConfig.HEADER_REFERRER_POLICY,
            "severity": SecurityHeadersScannerConfig.SEVERITY_MISSING_REFERRER_POLICY,
            "confidence": SecurityHeadersScannerConfig.CONFIDENCE_MISSING_REFERRER_POLICY,
            "title": SecurityHeadersScannerConfig.TITLE_MISSING_REFERRER_POLICY,
            "desc_template": SecurityHeadersScannerConfig.DESC_MISSING_REFERRER_POLICY,
        },
    }

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return SecurityHeadersScannerConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.MISSING_HEADERS, FindingCategory.INFO_DISCLOSURE]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run security header checks on representative endpoints.

        Picks a small set of representative endpoints (homepage + a few
        API routes), makes GET requests, and checks response headers.
        Deduplicates findings when all tested endpoints share the same
        missing header.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot (unused by this scanner).

        Returns:
            List of unified findings from this scanner.
        """
        representative = self._select_representative_endpoints(endpoints)
        if not representative:
            logger.info("SecurityHeadersScanner: no endpoints to test")
            return []

        raw_findings = await self._check_headers_on_endpoints(representative)

        # Deduplicate: if the same header issue appears on all tested
        # endpoints, report it once (headers are typically server-wide).
        findings = self._deduplicate_findings(raw_findings)

        logger.info("SecurityHeadersScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Endpoint selection
    # ------------------------------------------------------------------

    @staticmethod
    def _select_representative_endpoints(
        endpoints: list[DiscoveredEndpoint],
    ) -> list[str]:
        """Pick a small representative set of endpoint URLs.

        Selects the homepage (root path or shortest URL) plus a few API
        endpoints to test. Security headers are typically set server-wide,
        so testing every endpoint is unnecessary.
        """
        if not endpoints:
            return []

        urls: list[str] = []
        seen: set[str] = set()

        # Sort by URL length to get root/homepage first
        sorted_eps = sorted(endpoints, key=lambda ep: len(ep.url))

        for ep in sorted_eps:
            if ep.url in seen:
                continue
            seen.add(ep.url)
            urls.append(ep.url)
            if len(urls) >= SecurityHeadersScannerConfig.MAX_ENDPOINTS_TO_TEST:
                break

        return urls

    # ------------------------------------------------------------------
    # Header checking
    # ------------------------------------------------------------------

    async def _check_headers_on_endpoints(
        self, urls: list[str]
    ) -> list[DeepFinding]:
        """Make GET requests and check response headers for each URL."""
        findings: list[DeepFinding] = []

        async with RateLimitedClient(
            max_concurrent=self.MAX_CONCURRENT_REQUESTS,
            delay_seconds=self.REQUEST_DELAY_SECONDS,
            timeout_seconds=SecurityHeadersScannerConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            for url in urls:
                url_findings = await self._check_single_endpoint(client, url)
                findings.extend(url_findings)

        return findings

    async def _check_single_endpoint(
        self,
        client: RateLimitedClient,
        url: str,
    ) -> list[DeepFinding]:
        """Check all security headers for a single endpoint."""
        try:
            response = await client.request(method="GET", url=url)
        except Exception as exc:
            logger.debug(
                SecurityHeadersScannerConfig.ERROR_SCAN_FAILED.format(
                    url=url, error=str(exc)
                )
            )
            return []

        # Normalize headers to lowercase keys for consistent lookup
        headers = {k.lower(): v for k, v in response.headers.items()}

        findings: list[DeepFinding] = []

        # Check for missing security headers
        missing_findings = self._check_missing_headers(headers, url)
        findings.extend(missing_findings)

        # Check clickjacking protection (needs special logic: either
        # X-Frame-Options OR CSP frame-ancestors is acceptable)
        frame_finding = self._check_frame_protection(headers, url)
        if frame_finding:
            findings.append(frame_finding)

        # Check X-Content-Type-Options value (must be "nosniff")
        nosniff_finding = self._check_content_type_options_value(headers, url)
        if nosniff_finding:
            findings.append(nosniff_finding)

        # Check information disclosure headers
        disclosure_findings = self._check_info_disclosure_headers(headers, url)
        findings.extend(disclosure_findings)

        return findings

    def _check_missing_headers(
        self,
        headers: dict[str, str],
        url: str,
    ) -> list[DeepFinding]:
        """Check for completely missing security headers."""
        findings: list[DeepFinding] = []

        for check_type, check_config in self._MISSING_HEADER_CHECKS.items():
            header_name = check_config["header"]

            if header_name not in headers:
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.MISSING_HEADERS,
                        severity=check_config["severity"],
                        title=check_config["title"],
                        description=check_config["desc_template"].format(
                            url=url,
                        ),
                        technical_detail=(
                            f"GET {url}\n"
                            f"Missing header: {header_name}"
                        ),
                        evidence=f"Response lacks {header_name} header",
                        confidence=check_config["confidence"],
                        scanner_name=self.scanner_name,
                        endpoint_url=url,
                        http_method="GET",
                    )
                )

        return findings

    def _check_frame_protection(
        self,
        headers: dict[str, str],
        url: str,
    ) -> DeepFinding | None:
        """Check for clickjacking protection.

        Either X-Frame-Options or CSP frame-ancestors is acceptable.
        Only report if BOTH are missing.
        """
        has_xfo = SecurityHeadersScannerConfig.HEADER_FRAME_OPTIONS in headers
        has_csp_frame_ancestors = False

        csp_value = headers.get(SecurityHeadersScannerConfig.HEADER_CSP, "")
        if SecurityHeadersScannerConfig.CSP_FRAME_ANCESTORS_DIRECTIVE in csp_value:
            has_csp_frame_ancestors = True

        if not has_xfo and not has_csp_frame_ancestors:
            return DeepFinding(
                source=FindingSource.DAST_URL,
                category=FindingCategory.MISSING_HEADERS,
                severity=SecurityHeadersScannerConfig.SEVERITY_MISSING_FRAME_PROTECTION,
                title=SecurityHeadersScannerConfig.TITLE_MISSING_FRAME_PROTECTION,
                description=SecurityHeadersScannerConfig.DESC_MISSING_FRAME_PROTECTION.format(
                    url=url,
                ),
                technical_detail=(
                    f"GET {url}\n"
                    f"X-Frame-Options: (not set)\n"
                    f"CSP frame-ancestors: (not set)"
                ),
                evidence=(
                    "Response lacks both X-Frame-Options and "
                    "CSP frame-ancestors directive"
                ),
                confidence=SecurityHeadersScannerConfig.CONFIDENCE_MISSING_FRAME_PROTECTION,
                scanner_name=self.scanner_name,
                endpoint_url=url,
                http_method="GET",
            )

        return None

    @staticmethod
    def _check_content_type_options_value(
        headers: dict[str, str],
        url: str,
    ) -> DeepFinding | None:
        """Check X-Content-Type-Options is set to 'nosniff'.

        If the header is present but not set to 'nosniff', it is
        misconfigured. If the header is absent entirely, it is handled
        by _check_missing_headers.
        """
        header_name = SecurityHeadersScannerConfig.HEADER_CONTENT_TYPE_OPTIONS
        value = headers.get(header_name, "")

        if not value:
            # Missing header — already caught by _check_missing_headers
            return None

        if value.strip().lower() != SecurityHeadersScannerConfig.EXPECTED_CONTENT_TYPE_OPTIONS:
            return DeepFinding(
                source=FindingSource.DAST_URL,
                category=FindingCategory.MISSING_HEADERS,
                severity=SecurityHeadersScannerConfig.SEVERITY_MISSING_CONTENT_TYPE_OPTIONS,
                title=SecurityHeadersScannerConfig.TITLE_MISSING_CONTENT_TYPE_OPTIONS,
                description=SecurityHeadersScannerConfig.DESC_MISSING_CONTENT_TYPE_OPTIONS.format(
                    url=url,
                ),
                technical_detail=(
                    f"GET {url}\n"
                    f"X-Content-Type-Options: {value} (expected: nosniff)"
                ),
                evidence=f"X-Content-Type-Options set to '{value}' instead of 'nosniff'",
                confidence=SecurityHeadersScannerConfig.CONFIDENCE_MISSING_CONTENT_TYPE_OPTIONS,
                scanner_name=SecurityHeadersScannerConfig.SCANNER_NAME,
                endpoint_url=url,
                http_method="GET",
            )

        return None

    def _check_info_disclosure_headers(
        self,
        headers: dict[str, str],
        url: str,
    ) -> list[DeepFinding]:
        """Check for headers that disclose server information."""
        findings: list[DeepFinding] = []

        # Server header with version info
        server_finding = self._check_server_version(headers, url)
        if server_finding:
            findings.append(server_finding)

        # X-Powered-By header
        powered_by_finding = self._check_x_powered_by(headers, url)
        if powered_by_finding:
            findings.append(powered_by_finding)

        return findings

    @staticmethod
    def _check_server_version(
        headers: dict[str, str],
        url: str,
    ) -> DeepFinding | None:
        """Check if Server header exposes version information."""
        server_value = headers.get(
            SecurityHeadersScannerConfig.HEADER_SERVER, ""
        )
        if not server_value:
            return None

        # Only flag if the header includes version numbers
        if re.search(
            SecurityHeadersScannerConfig.SERVER_VERSION_PATTERN, server_value
        ):
            return DeepFinding(
                source=FindingSource.DAST_URL,
                category=FindingCategory.INFO_DISCLOSURE,
                severity=SecurityHeadersScannerConfig.SEVERITY_SERVER_VERSION_DISCLOSURE,
                title=SecurityHeadersScannerConfig.TITLE_SERVER_VERSION_DISCLOSURE,
                description=SecurityHeadersScannerConfig.DESC_SERVER_VERSION_DISCLOSURE.format(
                    url=url,
                    server_value=server_value,
                ),
                technical_detail=(
                    f"GET {url}\n"
                    f"Server: {server_value}"
                ),
                evidence=f"Server: {server_value}",
                confidence=SecurityHeadersScannerConfig.CONFIDENCE_SERVER_VERSION_DISCLOSURE,
                scanner_name=SecurityHeadersScannerConfig.SCANNER_NAME,
                endpoint_url=url,
                http_method="GET",
            )

        return None

    @staticmethod
    def _check_x_powered_by(
        headers: dict[str, str],
        url: str,
    ) -> DeepFinding | None:
        """Check if X-Powered-By header is present."""
        powered_by_value = headers.get(
            SecurityHeadersScannerConfig.HEADER_X_POWERED_BY, ""
        )
        if not powered_by_value:
            return None

        return DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.INFO_DISCLOSURE,
            severity=SecurityHeadersScannerConfig.SEVERITY_X_POWERED_BY_PRESENT,
            title=SecurityHeadersScannerConfig.TITLE_X_POWERED_BY_PRESENT,
            description=SecurityHeadersScannerConfig.DESC_X_POWERED_BY_PRESENT.format(
                url=url,
                powered_by_value=powered_by_value,
            ),
            technical_detail=(
                f"GET {url}\n"
                f"X-Powered-By: {powered_by_value}"
            ),
            evidence=f"X-Powered-By: {powered_by_value}",
            confidence=SecurityHeadersScannerConfig.CONFIDENCE_X_POWERED_BY_PRESENT,
            scanner_name=SecurityHeadersScannerConfig.SCANNER_NAME,
            endpoint_url=url,
            http_method="GET",
        )

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate_findings(
        findings: list[DeepFinding],
    ) -> list[DeepFinding]:
        """Deduplicate findings that appear on every tested endpoint.

        If all tested endpoints report the same missing header, keep
        only one finding (the first occurrence) since the header is
        missing server-wide.
        """
        if not findings:
            return []

        # Group findings by title
        title_groups: dict[str, list[DeepFinding]] = {}
        for finding in findings:
            title_groups.setdefault(finding.title, []).append(finding)

        # Count unique endpoint URLs across all findings
        all_endpoints: set[str] = set()
        for finding in findings:
            if finding.endpoint_url:
                all_endpoints.add(finding.endpoint_url)

        total_endpoints = len(all_endpoints) if all_endpoints else 1

        deduplicated: list[DeepFinding] = []
        for title, group in title_groups.items():
            if len(group) >= total_endpoints and total_endpoints > 1:
                # Same finding on all endpoints — report once with
                # a note that it is server-wide
                representative = group[0]
                representative.technical_detail += (
                    f"\n\nNote: This header is missing on all "
                    f"{total_endpoints} tested endpoints (server-wide issue)."
                )
                deduplicated.append(representative)
            else:
                deduplicated.extend(group)

        return deduplicated
