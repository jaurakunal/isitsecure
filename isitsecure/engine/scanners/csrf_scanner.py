"""Cross-Site Request Forgery (CSRF) detection scanner.

Tests state-changing endpoints for CSRF protection:
1. Forged Origin header accepted (active test)
2. Missing SameSite cookie attribute (passive analysis)
3. Missing CSRF tokens in HTML forms (passive analysis)
"""

from __future__ import annotations

import logging
import re
from http.cookies import SimpleCookie

from isitsecure.engine.constants import CSRFConfig, DeepScanConfig
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.endpoint_prioritizer import PriorityDimension, rank
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


class CSRFScanner:
    """CSRF scanner implementing DASTScannerProtocol.

    Detects missing Cross-Site Request Forgery protections on
    state-changing endpoints and authentication cookies.
    """

    MAX_CONCURRENT_REQUESTS = 3
    REQUEST_DELAY_SECONDS = 0.3
    MAX_RESPONSE_PREVIEW_LENGTH = 300
    FORM_PATTERN = r'<form[^>]*method\s*=\s*["\']?post["\']?[^>]*>(.*?)</form>'
    HIDDEN_INPUT_PATTERN = r'<input[^>]*type\s*=\s*["\']hidden["\']?[^>]*name\s*=\s*["\']([^"\']+)["\']'

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return CSRFConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.AUTH_WEAKNESS]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run CSRF tests on discovered endpoints and snapshot data.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot for cookie and form analysis.

        Returns:
            List of unified findings from this scanner.
        """
        findings: list[DeepFinding] = []

        # Phase 1: Test state-changing endpoints for forged origin acceptance
        state_changing = [
            ep for ep in endpoints
            if ep.method.value in CSRFConfig.STATE_CHANGING_METHODS
        ]

        if state_changing:
            origin_findings = await self._test_forged_origins(state_changing)
            findings.extend(origin_findings)

        # Phase 2: Check cookies for SameSite attribute
        if snapshot:
            cookie_findings = self._check_cookie_samesite(snapshot)
            findings.extend(cookie_findings)

        # Phase 3: Check HTML forms for CSRF tokens
        if snapshot:
            form_findings = self._check_forms_for_csrf_tokens(snapshot)
            findings.extend(form_findings)

        logger.info("CSRFScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Phase 1: Forged Origin testing
    # ------------------------------------------------------------------

    async def _test_forged_origins(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DeepFinding]:
        """Test state-changing endpoints with a forged Origin header."""
        findings: list[DeepFinding] = []

        async with RateLimitedClient(
            max_concurrent=self.MAX_CONCURRENT_REQUESTS,
            delay_seconds=self.REQUEST_DELAY_SECONDS,
            timeout_seconds=CSRFConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            for ep in rank(endpoints, PriorityDimension.CSRF)[: CSRFConfig.MAX_ENDPOINTS_TO_TEST]:
                finding = await self._test_forged_origin(client, ep)
                if finding:
                    findings.append(finding)

        return findings

    async def _test_forged_origin(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
    ) -> DeepFinding | None:
        """Send request with forged Origin header.

        If the endpoint responds with a 2xx status, it does not validate
        the Origin header and is susceptible to CSRF.
        """
        headers = {
            "Origin": CSRFConfig.FORGED_ORIGIN,
            "Referer": CSRFConfig.FORGED_REFERER,
        }

        try:
            response = await client.request(
                method=endpoint.method.value,
                url=endpoint.url,
                headers=headers,
            )

            # 2xx response with forged origin means no origin validation
            if 200 <= response.status_code < 300:
                return DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.AUTH_WEAKNESS,
                    severity=SeverityLevel.HIGH,
                    title=CSRFConfig.TITLE_FORGED_ORIGIN,
                    description=CSRFConfig.DESC_FORGED_ORIGIN.format(
                        method=endpoint.method.value,
                        url=endpoint.url,
                        origin=CSRFConfig.FORGED_ORIGIN,
                    ),
                    technical_detail=(
                        f"Sent {endpoint.method.value} {endpoint.url} with "
                        f"Origin: {CSRFConfig.FORGED_ORIGIN}\n"
                        f"Response status: {response.status_code}"
                    ),
                    evidence=(
                        f"{endpoint.method.value} {endpoint.url} -> "
                        f"{response.status_code} with forged Origin"
                    ),
                    confidence=CSRFConfig.CONFIDENCE_FORGED_ORIGIN_ACCEPTED,
                    scanner_name=self.scanner_name,
                    endpoint_url=endpoint.url,
                    http_method=endpoint.method.value,
                    response_preview=response.text[
                        : self.MAX_RESPONSE_PREVIEW_LENGTH
                    ],
                )

        except Exception as exc:
            logger.debug(
                CSRFConfig.ERROR_CSRF_SCAN_FAILED.format(
                    endpoint=endpoint.url, error=str(exc)
                )
            )

        return None

    # ------------------------------------------------------------------
    # Phase 2: Cookie SameSite analysis
    # ------------------------------------------------------------------

    def _check_cookie_samesite(
        self, snapshot: CodebaseSnapshot
    ) -> list[DeepFinding]:
        """Check cookies in response headers for SameSite attribute."""
        findings: list[DeepFinding] = []

        for cookie_data in snapshot.headers.cookies:
            cookie_name = cookie_data.get("name", "")
            if not cookie_name:
                continue

            samesite = cookie_data.get("samesite", "")

            # Missing SameSite or SameSite=None are both dangerous
            if not samesite or samesite.lower() == "none":
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.AUTH_WEAKNESS,
                        severity=SeverityLevel.MEDIUM,
                        title=CSRFConfig.TITLE_MISSING_SAMESITE,
                        description=CSRFConfig.DESC_MISSING_SAMESITE.format(
                            cookie_name=cookie_name,
                        ),
                        technical_detail=(
                            f"Cookie: {cookie_name}\n"
                            f"SameSite: {samesite or '(not set)'}\n"
                            f"Domain: {snapshot.url}"
                        ),
                        evidence=(
                            f"Cookie '{cookie_name}' missing SameSite attribute"
                        ),
                        confidence=CSRFConfig.CONFIDENCE_MISSING_SAMESITE,
                        scanner_name=self.scanner_name,
                        endpoint_url=snapshot.url,
                    )
                )

        # Also parse Set-Cookie headers from raw_headers
        set_cookie_header = snapshot.headers.raw_headers.get("set-cookie", "")
        if set_cookie_header:
            header_findings = self._parse_set_cookie_header(
                set_cookie_header, snapshot.url
            )
            # Deduplicate by cookie name against already-found cookies
            existing_names = {
                c.get("name", "") for c in snapshot.headers.cookies
            }
            findings.extend(
                f for f in header_findings
                if not any(
                    name in f.technical_detail for name in existing_names
                    if name
                )
            )

        return findings

    def _parse_set_cookie_header(
        self, header_value: str, url: str
    ) -> list[DeepFinding]:
        """Parse raw Set-Cookie header for SameSite analysis."""
        findings: list[DeepFinding] = []
        header_lower = header_value.lower()

        try:
            cookie: SimpleCookie = SimpleCookie()
            cookie.load(header_value)

            for cookie_name, morsel in cookie.items():
                # Check if SameSite is present in the raw header
                samesite = morsel.get("samesite", "")
                if not samesite or samesite.lower() == "none":
                    findings.append(
                        DeepFinding(
                            source=FindingSource.DAST_URL,
                            category=FindingCategory.AUTH_WEAKNESS,
                            severity=SeverityLevel.MEDIUM,
                            title=CSRFConfig.TITLE_MISSING_SAMESITE,
                            description=CSRFConfig.DESC_MISSING_SAMESITE.format(
                                cookie_name=cookie_name,
                            ),
                            technical_detail=(
                                f"Cookie: {cookie_name}\n"
                                f"SameSite: {samesite or '(not set)'}\n"
                                f"Source: Set-Cookie header"
                            ),
                            evidence=(
                                f"Set-Cookie '{cookie_name}' missing SameSite"
                            ),
                            confidence=CSRFConfig.CONFIDENCE_MISSING_SAMESITE,
                            scanner_name=self.scanner_name,
                            endpoint_url=url,
                        )
                    )
        except Exception:
            logger.debug("Failed to parse Set-Cookie header")

        return findings

    # ------------------------------------------------------------------
    # Phase 3: HTML form CSRF token analysis
    # ------------------------------------------------------------------

    def _check_forms_for_csrf_tokens(
        self, snapshot: CodebaseSnapshot
    ) -> list[DeepFinding]:
        """Check HTML forms for hidden CSRF token fields."""
        findings: list[DeepFinding] = []
        html = snapshot.html_content

        if not html:
            return findings

        # Find all POST forms
        forms = re.finditer(
            self.FORM_PATTERN, html, re.IGNORECASE | re.DOTALL
        )

        for form_match in forms:
            form_body = form_match.group(1)

            # Extract hidden input field names
            hidden_names = re.findall(
                self.HIDDEN_INPUT_PATTERN, form_body, re.IGNORECASE
            )

            # Check if any hidden field matches known CSRF token names
            has_csrf_token = any(
                name.lower() in (
                    token_name.lower()
                    for token_name in CSRFConfig.CSRF_TOKEN_FIELD_NAMES
                )
                for name in hidden_names
            )

            if not has_csrf_token:
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.AUTH_WEAKNESS,
                        severity=SeverityLevel.MEDIUM,
                        title=CSRFConfig.TITLE_MISSING_CSRF,
                        description=CSRFConfig.DESC_MISSING_CSRF.format(
                            method="POST", url=snapshot.url,
                        ),
                        technical_detail=(
                            f"HTML form with method=POST found at {snapshot.url}\n"
                            f"Hidden fields: {hidden_names or '(none)'}\n"
                            f"None match known CSRF token names"
                        ),
                        evidence=(
                            f"POST form at {snapshot.url} lacks CSRF token field"
                        ),
                        confidence=CSRFConfig.CONFIDENCE_NO_CSRF_TOKEN,
                        scanner_name=self.scanner_name,
                        endpoint_url=snapshot.url,
                    )
                )

        return findings
