"""Authentication bypass scanner.

Tests for common authentication bypass vulnerabilities:
1. Username enumeration via differential error messages and timing
2. Password reset token leaks in response bodies/headers
3. Account lockout detection (or lack thereof)
4. Default credential testing against login endpoints
5. Authentication header bypass on protected endpoints

IMPORTANT: This scanner is intended for authorized security testing only.
All probes are clearly logged and rate-limited to avoid disruption.
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from isitsecure.engine.constants import (
    AuthBypassConfig,
    DeepScanConfig,
)
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.endpoint_prioritizer import PriorityDimension, rank
from isitsecure.engine.shared.probe_capture import build_probe_capture
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


class AuthBypassScanner:
    """Detects authentication bypass vulnerabilities.

    Implements DASTScannerProtocol. Tests login, signup, and password
    reset endpoints for username enumeration, token leaks, missing
    lockout, default credentials, and auth header bypass.

    All tests are rate-limited and logged as authorized security scans.
    """

    HTTP_STATUS_OK_MIN = 200
    HTTP_STATUS_OK_MAX = 299
    HTTP_STATUS_UNAUTHORIZED = 401
    HTTP_STATUS_FORBIDDEN = 403
    HTTP_STATUS_LOCKED = 423

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return AuthBypassConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.AUTH_WEAKNESS]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run authentication bypass tests on discovered endpoints.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot (unused by this scanner).

        Returns:
            List of unified findings from this scanner.
        """
        findings: list[DeepFinding] = []

        login_endpoints = self._filter_endpoints(
            endpoints, AuthBypassConfig.LOGIN_ENDPOINT_INDICATORS
        )
        reset_endpoints = self._filter_endpoints(
            endpoints, AuthBypassConfig.RESET_ENDPOINT_INDICATORS
        )
        auth_required_endpoints = self._filter_auth_required_endpoints(endpoints)

        if not login_endpoints and not reset_endpoints and not auth_required_endpoints:
            logger.info("AuthBypassScanner: no auth-related endpoints to test")
            return findings

        async with httpx.AsyncClient(
            timeout=AuthBypassConfig.HTTP_TIMEOUT_SECONDS,
            follow_redirects=True,
            headers={"User-Agent": DeepScanConfig.USER_AGENT},
        ) as client:
            # Phase 1: Username enumeration
            for ep in login_endpoints:
                enum_findings = await self._test_username_enumeration(client, ep)
                findings.extend(enum_findings)
                await asyncio.sleep(AuthBypassConfig.PROBE_DELAY_SECONDS)

            # Phase 2: Password reset token leaks
            for ep in reset_endpoints:
                leak_finding = await self._test_reset_token_leak(client, ep)
                if leak_finding:
                    findings.append(leak_finding)
                await asyncio.sleep(AuthBypassConfig.PROBE_DELAY_SECONDS)

            # Phase 3: Account lockout detection
            for ep in login_endpoints:
                lockout_finding = await self._test_account_lockout(client, ep)
                if lockout_finding:
                    findings.append(lockout_finding)
                await asyncio.sleep(AuthBypassConfig.PROBE_DELAY_SECONDS)

            # Phase 4: Default credentials
            for ep in login_endpoints:
                cred_findings = await self._test_default_credentials(client, ep)
                findings.extend(cred_findings)
                await asyncio.sleep(AuthBypassConfig.PROBE_DELAY_SECONDS)

            # Phase 5: Auth header bypass
            for ep in rank(auth_required_endpoints, PriorityDimension.AUTH)[:AuthBypassConfig.MAX_AUTH_BYPASS_ENDPOINTS]:
                bypass_findings = await self._test_auth_header_bypass(client, ep)
                findings.extend(bypass_findings)
                await asyncio.sleep(AuthBypassConfig.PROBE_DELAY_SECONDS)

        logger.info("AuthBypassScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Endpoint filtering
    # ------------------------------------------------------------------

    def _filter_endpoints(
        self,
        endpoints: list[DiscoveredEndpoint],
        indicators: tuple[str, ...],
    ) -> list[DiscoveredEndpoint]:
        """Filter endpoints matching any of the given path indicators."""
        matched: list[DiscoveredEndpoint] = []
        for ep in endpoints:
            url_lower = ep.url.lower()
            if any(indicator in url_lower for indicator in indicators):
                matched.append(ep)
        return matched

    def _filter_auth_required_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """Filter endpoints that should require authentication."""
        return [
            ep for ep in endpoints
            if ep.requires_auth is True
            or any(
                indicator in ep.url.lower()
                for indicator in AuthBypassConfig.AUTH_REQUIRED_INDICATORS
            )
        ]

    # ------------------------------------------------------------------
    # Phase 1: Username enumeration
    # ------------------------------------------------------------------

    async def _test_username_enumeration(
        self,
        client: httpx.AsyncClient,
        endpoint: DiscoveredEndpoint,
    ) -> list[DeepFinding]:
        """Test for username enumeration via differential responses."""
        findings: list[DeepFinding] = []
        logger.debug(
            "AuthBypassScanner: [authorized test] username enumeration on %s",
            endpoint.url,
        )

        try:
            # Request with a known-invalid username
            invalid_payload = {
                "email": AuthBypassConfig.TEST_USERNAME_NONEXISTENT,
                "password": AuthBypassConfig.TEST_PASSWORD_WRONG,
            }
            start_invalid = time.monotonic()
            resp_invalid = await client.post(
                endpoint.url, json=invalid_payload
            )
            time_invalid = time.monotonic() - start_invalid

            await asyncio.sleep(AuthBypassConfig.PROBE_DELAY_SECONDS)

            # Request with a valid-looking username
            valid_payload = {
                "email": AuthBypassConfig.TEST_USERNAME_VALID_LOOKING,
                "password": AuthBypassConfig.TEST_PASSWORD_WRONG,
            }
            start_valid = time.monotonic()
            resp_valid = await client.post(
                endpoint.url, json=valid_payload
            )
            time_valid = time.monotonic() - start_valid

            # Compare error messages
            body_invalid = resp_invalid.text[:AuthBypassConfig.RESPONSE_BODY_PREVIEW_LENGTH]
            body_valid = resp_valid.text[:AuthBypassConfig.RESPONSE_BODY_PREVIEW_LENGTH]

            if self._has_differential_error_messages(body_invalid, body_valid):
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.AUTH_WEAKNESS,
                        severity=SeverityLevel.HIGH,
                        title=AuthBypassConfig.TITLE_USERNAME_ENUMERATION_MESSAGE,
                        description=AuthBypassConfig.DESC_USERNAME_ENUMERATION_MESSAGE.format(
                            url=endpoint.url,
                        ),
                        technical_detail=(
                            f"Endpoint: {endpoint.url}\n"
                            f"Invalid user response: {body_invalid}\n"
                            f"Valid-looking user response: {body_valid}"
                        ),
                        evidence=(
                            f"Different error messages for invalid vs valid-looking "
                            f"usernames on {endpoint.url}"
                        ),
                        confidence=AuthBypassConfig.CONFIDENCE_USERNAME_ENUM_MESSAGE,
                        scanner_name=self.scanner_name,
                        endpoint_url=endpoint.url,
                        http_method="POST",
                    )
                )

            # Compare response times
            time_delta = abs(time_valid - time_invalid)
            if time_delta > AuthBypassConfig.TIMING_DELTA_THRESHOLD_SECONDS:
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.AUTH_WEAKNESS,
                        severity=SeverityLevel.MEDIUM,
                        title=AuthBypassConfig.TITLE_USERNAME_ENUMERATION_TIMING,
                        description=AuthBypassConfig.DESC_USERNAME_ENUMERATION_TIMING.format(
                            url=endpoint.url,
                            delta_ms=int(time_delta * 1000),
                        ),
                        technical_detail=(
                            f"Endpoint: {endpoint.url}\n"
                            f"Invalid user response time: {time_invalid:.3f}s\n"
                            f"Valid-looking user response time: {time_valid:.3f}s\n"
                            f"Delta: {time_delta:.3f}s"
                        ),
                        evidence=(
                            f"Response time delta of {int(time_delta * 1000)}ms "
                            f"between invalid and valid-looking usernames"
                        ),
                        confidence=AuthBypassConfig.CONFIDENCE_USERNAME_ENUM_TIMING,
                        scanner_name=self.scanner_name,
                        endpoint_url=endpoint.url,
                        http_method="POST",
                    )
                )

            # Compare HTTP status codes
            if resp_invalid.status_code != resp_valid.status_code:
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.AUTH_WEAKNESS,
                        severity=SeverityLevel.MEDIUM,
                        title=AuthBypassConfig.TITLE_USERNAME_ENUMERATION_STATUS,
                        description=AuthBypassConfig.DESC_USERNAME_ENUMERATION_STATUS.format(
                            url=endpoint.url,
                            status_invalid=resp_invalid.status_code,
                            status_valid=resp_valid.status_code,
                        ),
                        technical_detail=(
                            f"Endpoint: {endpoint.url}\n"
                            f"Invalid user status: {resp_invalid.status_code}\n"
                            f"Valid-looking user status: {resp_valid.status_code}"
                        ),
                        evidence=(
                            f"Different HTTP status codes: "
                            f"{resp_invalid.status_code} vs {resp_valid.status_code}"
                        ),
                        confidence=AuthBypassConfig.CONFIDENCE_USERNAME_ENUM_STATUS,
                        scanner_name=self.scanner_name,
                        endpoint_url=endpoint.url,
                        http_method="POST",
                    )
                )

        except Exception as exc:
            logger.debug(
                AuthBypassConfig.ERROR_SCAN_FAILED.format(
                    phase="username enumeration",
                    endpoint=endpoint.url,
                    error=str(exc),
                )
            )

        return findings

    @staticmethod
    def _has_differential_error_messages(body_a: str, body_b: str) -> bool:
        """Check if two login error responses reveal different error types.

        Returns True if the responses contain different user-facing error
        messages (e.g., 'User not found' vs 'Invalid password').
        """
        body_a_lower = body_a.lower()
        body_b_lower = body_b.lower()

        # If bodies are identical, no enumeration
        if body_a_lower == body_b_lower:
            return False

        # Check for known differential error phrases
        for invalid_phrase, valid_phrase in AuthBypassConfig.DIFFERENTIAL_ERROR_PAIRS:
            if (
                invalid_phrase in body_a_lower
                and valid_phrase in body_b_lower
            ) or (
                valid_phrase in body_a_lower
                and invalid_phrase in body_b_lower
            ):
                return True

        return False

    # ------------------------------------------------------------------
    # Phase 2: Password reset token leaks
    # ------------------------------------------------------------------

    async def _test_reset_token_leak(
        self,
        client: httpx.AsyncClient,
        endpoint: DiscoveredEndpoint,
    ) -> DeepFinding | None:
        """Test if password reset endpoint leaks tokens in response."""
        logger.debug(
            "AuthBypassScanner: [authorized test] reset token leak on %s",
            endpoint.url,
        )

        try:
            payload = {"email": AuthBypassConfig.TEST_USERNAME_NONEXISTENT}
            resp = await client.post(endpoint.url, json=payload)

            body = resp.text[:AuthBypassConfig.RESPONSE_BODY_PREVIEW_LENGTH]
            headers_str = str(dict(resp.headers))

            # Check response body for token patterns
            token_found_in = self._detect_token_in_content(body, "response body")
            if not token_found_in:
                # Check headers
                token_found_in = self._detect_token_in_content(
                    headers_str, "response headers"
                )

            if token_found_in:
                capture = build_probe_capture(
                    method="POST",
                    url=endpoint.url,
                    headers=dict(resp.request.headers),
                    body=str(payload),
                    response_status=resp.status_code,
                    response_headers=dict(resp.headers),
                    response_body=resp.text,
                    elapsed_ms=resp.elapsed.total_seconds() * 1000,
                    scanner_name=self.scanner_name,
                )
                return DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.AUTH_WEAKNESS,
                    severity=SeverityLevel.HIGH,
                    title=AuthBypassConfig.TITLE_RESET_TOKEN_LEAK,
                    description=AuthBypassConfig.DESC_RESET_TOKEN_LEAK.format(
                        url=endpoint.url,
                        location=token_found_in,
                    ),
                    technical_detail=(
                        f"Endpoint: {endpoint.url}\n"
                        f"Token found in: {token_found_in}\n"
                        f"Response preview: {body}"
                    ),
                    evidence=(
                        f"Reset token visible in {token_found_in} "
                        f"from {endpoint.url}"
                    ),
                    confidence=AuthBypassConfig.CONFIDENCE_RESET_TOKEN_LEAK,
                    scanner_name=self.scanner_name,
                    endpoint_url=endpoint.url,
                    http_method="POST",
                    probe_captures=[capture],
                )

        except Exception as exc:
            logger.debug(
                AuthBypassConfig.ERROR_SCAN_FAILED.format(
                    phase="reset token leak",
                    endpoint=endpoint.url,
                    error=str(exc),
                )
            )

        return None

    @staticmethod
    def _detect_token_in_content(content: str, location_label: str) -> str | None:
        """Check content for token-like patterns. Returns location label if found."""
        content_lower = content.lower()
        for indicator in AuthBypassConfig.TOKEN_LEAK_INDICATORS:
            if indicator in content_lower:
                return location_label
        return None

    # ------------------------------------------------------------------
    # Phase 3: Account lockout detection
    # ------------------------------------------------------------------

    async def _test_account_lockout(
        self,
        client: httpx.AsyncClient,
        endpoint: DiscoveredEndpoint,
    ) -> DeepFinding | None:
        """Test if account gets locked after multiple failed login attempts."""
        logger.debug(
            "AuthBypassScanner: [authorized test] account lockout on %s",
            endpoint.url,
        )

        try:
            # Send multiple failed login attempts
            payload = {
                "email": AuthBypassConfig.TEST_USERNAME_VALID_LOOKING,
                "password": AuthBypassConfig.TEST_PASSWORD_WRONG,
            }

            last_status = None
            for _ in range(AuthBypassConfig.LOCKOUT_ATTEMPT_COUNT):
                resp = await client.post(endpoint.url, json=payload)
                last_status = resp.status_code
                await asyncio.sleep(AuthBypassConfig.LOCKOUT_PROBE_DELAY_SECONDS)

            # After many failures, check if account is locked
            if last_status == self.HTTP_STATUS_LOCKED:
                # Lockout works — this is good, no finding needed
                logger.debug(
                    "AuthBypassScanner: lockout detected (423) on %s — GOOD",
                    endpoint.url,
                )
                return None

            # Try one more request to see if we can still attempt login
            final_resp = await client.post(endpoint.url, json=payload)

            if final_resp.status_code != self.HTTP_STATUS_LOCKED:
                return DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.AUTH_WEAKNESS,
                    severity=SeverityLevel.MEDIUM,
                    title=AuthBypassConfig.TITLE_NO_ACCOUNT_LOCKOUT,
                    description=AuthBypassConfig.DESC_NO_ACCOUNT_LOCKOUT.format(
                        url=endpoint.url,
                        attempts=AuthBypassConfig.LOCKOUT_ATTEMPT_COUNT,
                    ),
                    technical_detail=(
                        f"Endpoint: {endpoint.url}\n"
                        f"Failed attempts sent: {AuthBypassConfig.LOCKOUT_ATTEMPT_COUNT}\n"
                        f"Final response status: {final_resp.status_code}\n"
                        f"Expected: 423 (Locked)"
                    ),
                    evidence=(
                        f"No lockout after {AuthBypassConfig.LOCKOUT_ATTEMPT_COUNT} "
                        f"failed login attempts on {endpoint.url}"
                    ),
                    confidence=AuthBypassConfig.CONFIDENCE_NO_LOCKOUT,
                    scanner_name=self.scanner_name,
                    endpoint_url=endpoint.url,
                    http_method="POST",
                )

        except Exception as exc:
            logger.debug(
                AuthBypassConfig.ERROR_SCAN_FAILED.format(
                    phase="account lockout",
                    endpoint=endpoint.url,
                    error=str(exc),
                )
            )

        return None

    # ------------------------------------------------------------------
    # Phase 4: Default credentials
    # ------------------------------------------------------------------

    async def _test_default_credentials(
        self,
        client: httpx.AsyncClient,
        endpoint: DiscoveredEndpoint,
    ) -> list[DeepFinding]:
        """Test common default credential pairs against login endpoint.

        IMPORTANT: Only tests against discovered login endpoints and uses
        rate limiting between attempts. This is an authorized security test.
        """
        findings: list[DeepFinding] = []
        logger.debug(
            "AuthBypassScanner: [authorized test] default credentials on %s",
            endpoint.url,
        )

        for username, password in AuthBypassConfig.DEFAULT_CREDENTIAL_PAIRS:
            try:
                payload = {"email": username, "password": password}
                resp = await client.post(endpoint.url, json=payload)

                if self._is_successful_auth(resp):
                    capture = build_probe_capture(
                        method="POST",
                        url=endpoint.url,
                        headers=dict(resp.request.headers),
                        body=str(payload),
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body=resp.text,
                        elapsed_ms=resp.elapsed.total_seconds() * 1000,
                        scanner_name=self.scanner_name,
                    )
                    findings.append(
                        DeepFinding(
                            source=FindingSource.DAST_URL,
                            category=FindingCategory.AUTH_WEAKNESS,
                            severity=SeverityLevel.CRITICAL,
                            title=AuthBypassConfig.TITLE_DEFAULT_CREDENTIALS,
                            description=AuthBypassConfig.DESC_DEFAULT_CREDENTIALS.format(
                                url=endpoint.url,
                                username=username,
                            ),
                            technical_detail=(
                                f"Endpoint: {endpoint.url}\n"
                                f"Username: {username}\n"
                                f"Response status: {resp.status_code}\n"
                                f"Auth token present: True"
                            ),
                            evidence=(
                                f"Default credentials '{username}' accepted "
                                f"on {endpoint.url}"
                            ),
                            confidence=AuthBypassConfig.CONFIDENCE_DEFAULT_CREDS,
                            scanner_name=self.scanner_name,
                            endpoint_url=endpoint.url,
                            http_method="POST",
                            probe_captures=[capture],
                        )
                    )
                    # Stop after first confirmed default credential
                    break

                # Rate limit between credential attempts
                await asyncio.sleep(AuthBypassConfig.CREDENTIAL_TEST_DELAY_SECONDS)

            except Exception as exc:
                logger.debug(
                    AuthBypassConfig.ERROR_SCAN_FAILED.format(
                        phase="default credentials",
                        endpoint=endpoint.url,
                        error=str(exc),
                    )
                )

        return findings

    def _is_successful_auth(self, resp: httpx.Response) -> bool:
        """Check if a response indicates successful authentication.

        Looks for 2xx status with auth token indicators in the response body.
        """
        if not (self.HTTP_STATUS_OK_MIN <= resp.status_code <= self.HTTP_STATUS_OK_MAX):
            return False

        body_lower = resp.text.lower()
        return any(
            indicator in body_lower
            for indicator in AuthBypassConfig.AUTH_SUCCESS_INDICATORS
        )

    # ------------------------------------------------------------------
    # Phase 5: Authentication header bypass
    # ------------------------------------------------------------------

    async def _test_auth_header_bypass(
        self,
        client: httpx.AsyncClient,
        endpoint: DiscoveredEndpoint,
    ) -> list[DeepFinding]:
        """Test if protected endpoints can be accessed without proper auth."""
        findings: list[DeepFinding] = []
        logger.debug(
            "AuthBypassScanner: [authorized test] auth header bypass on %s",
            endpoint.url,
        )

        bypass_tests = [
            (
                AuthBypassConfig.BYPASS_LABEL_NO_HEADER,
                {},
            ),
            (
                AuthBypassConfig.BYPASS_LABEL_EMPTY_BEARER,
                {"Authorization": "Bearer "},
            ),
            (
                AuthBypassConfig.BYPASS_LABEL_BASIC_ADMIN,
                {"Authorization": AuthBypassConfig.BASIC_AUTH_ADMIN_HEADER},
            ),
        ]

        for label, headers in bypass_tests:
            try:
                resp = await client.request(
                    method=endpoint.method.value,
                    url=endpoint.url,
                    headers=headers,
                )

                if self.HTTP_STATUS_OK_MIN <= resp.status_code <= self.HTTP_STATUS_OK_MAX:
                    capture = build_probe_capture(
                        method=endpoint.method.value,
                        url=endpoint.url,
                        headers=dict(resp.request.headers),
                        body="",
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body=resp.text,
                        elapsed_ms=resp.elapsed.total_seconds() * 1000,
                        scanner_name=self.scanner_name,
                    )
                    findings.append(
                        DeepFinding(
                            source=FindingSource.DAST_URL,
                            category=FindingCategory.AUTH_WEAKNESS,
                            severity=SeverityLevel.HIGH,
                            title=AuthBypassConfig.TITLE_AUTH_HEADER_BYPASS,
                            description=AuthBypassConfig.DESC_AUTH_HEADER_BYPASS.format(
                                url=endpoint.url,
                                bypass_method=label,
                            ),
                            technical_detail=(
                                f"Endpoint: {endpoint.url}\n"
                                f"Bypass method: {label}\n"
                                f"Headers sent: {headers}\n"
                                f"Response status: {resp.status_code}"
                            ),
                            evidence=(
                                f"Endpoint {endpoint.url} returned "
                                f"{resp.status_code} with {label}"
                            ),
                            confidence=AuthBypassConfig.CONFIDENCE_AUTH_BYPASS,
                            scanner_name=self.scanner_name,
                            endpoint_url=endpoint.url,
                            http_method=endpoint.method.value,
                            probe_captures=[capture],
                        )
                    )
                    # One bypass is enough evidence
                    break

                await asyncio.sleep(AuthBypassConfig.PROBE_DELAY_SECONDS)

            except Exception as exc:
                logger.debug(
                    AuthBypassConfig.ERROR_SCAN_FAILED.format(
                        phase="auth header bypass",
                        endpoint=endpoint.url,
                        error=str(exc),
                    )
                )

        return findings
