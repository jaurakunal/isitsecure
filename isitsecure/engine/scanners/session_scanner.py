"""Session management scanner.

Tests session management for hijacking vulnerabilities:
1. Token storage — checks if JS stores tokens in localStorage
2. Cookie flags — checks HttpOnly and Secure on auth cookies
3. Token expiry — checks JWT exp claim for long-lived tokens
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from typing import Any

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import SessionScanConfig
from isitsecure.engine.shared.jwt_utils import (
    decode_jwt_payload as _shared_decode_jwt_payload,
)
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


class SessionScanner:
    """Tests session management for hijacking vulnerabilities.

    Implements DASTScannerProtocol. Analyzes JavaScript content for
    insecure token storage, checks cookie flags, and validates JWT
    expiration claims.
    """

    JWT_PARTS_COUNT = 3
    JWT_PAYLOAD_INDEX = 1
    SECONDS_PER_HOUR = 3600

    def __init__(self, auth_session: AuthSession | None = None) -> None:
        self._auth_session = auth_session

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return SessionScanConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.AUTH_WEAKNESS]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run session security tests.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot for JS and cookie analysis.

        Returns:
            List of unified findings from this scanner.
        """
        findings: list[DeepFinding] = []

        if snapshot:
            # Phase 1: Scan JS for localStorage token storage
            storage_findings = self._check_localstorage_usage(snapshot)
            findings.extend(storage_findings)

            # Phase 2: Check cookie flags
            cookie_findings = self._check_cookie_flags(snapshot)
            findings.extend(cookie_findings)

        # Phase 3: Check JWT expiry from auth session
        if self._auth_session and self._auth_session.access_token:
            expiry_finding = self._check_token_expiry(
                self._auth_session.access_token
            )
            if expiry_finding:
                findings.append(expiry_finding)

        logger.info("SessionScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Phase 1: localStorage token detection
    # ------------------------------------------------------------------

    def _check_localstorage_usage(
        self, snapshot: CodebaseSnapshot
    ) -> list[DeepFinding]:
        """Check JavaScript content for localStorage token storage patterns."""
        findings: list[DeepFinding] = []
        js_content = snapshot.all_js_content

        if not js_content:
            return findings

        for pattern in SessionScanConfig.LOCALSTORAGE_TOKEN_PATTERNS:
            match = re.search(pattern, js_content)
            if match:
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.AUTH_WEAKNESS,
                        severity=SeverityLevel.HIGH,
                        title=SessionScanConfig.TITLE_TOKEN_IN_LOCALSTORAGE,
                        description=SessionScanConfig.DESC_TOKEN_IN_LOCALSTORAGE,
                        technical_detail=(
                            f"Pattern matched: {pattern}\n"
                            f"Match: {match.group(0)}"
                        ),
                        evidence=match.group(0),
                        confidence=SessionScanConfig.CONFIDENCE_INSECURE_STORAGE,
                        scanner_name=self.scanner_name,
                        endpoint_url=snapshot.url,
                    )
                )
                # One finding per storage issue is enough
                break

        return findings

    # ------------------------------------------------------------------
    # Phase 2: Cookie flag analysis
    # ------------------------------------------------------------------

    def _check_cookie_flags(
        self, snapshot: CodebaseSnapshot
    ) -> list[DeepFinding]:
        """Check auth cookies for HttpOnly and Secure flags."""
        findings: list[DeepFinding] = []

        for cookie_data in snapshot.headers.cookies:
            cookie_name = cookie_data.get("name", "")
            if not cookie_name:
                continue

            # Only check cookies that look like auth cookies
            if not self._is_auth_cookie(cookie_name):
                continue

            # Check HttpOnly
            httponly = cookie_data.get("httponly", False)
            if not httponly:
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.AUTH_WEAKNESS,
                        severity=SeverityLevel.HIGH,
                        title=SessionScanConfig.TITLE_MISSING_HTTPONLY,
                        description=SessionScanConfig.DESC_MISSING_HTTPONLY.format(
                            cookie=cookie_name,
                        ),
                        technical_detail=(
                            f"Cookie: {cookie_name}\n"
                            f"HttpOnly: {httponly}\n"
                            f"Domain: {snapshot.url}"
                        ),
                        evidence=(
                            f"Cookie '{cookie_name}' missing HttpOnly flag"
                        ),
                        confidence=SessionScanConfig.CONFIDENCE_NO_HTTPONLY,
                        scanner_name=self.scanner_name,
                        endpoint_url=snapshot.url,
                    )
                )

            # Check Secure
            secure = cookie_data.get("secure", False)
            if not secure:
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.AUTH_WEAKNESS,
                        severity=SeverityLevel.MEDIUM,
                        title=SessionScanConfig.TITLE_MISSING_SECURE,
                        description=SessionScanConfig.DESC_MISSING_SECURE.format(
                            cookie=cookie_name,
                        ),
                        technical_detail=(
                            f"Cookie: {cookie_name}\n"
                            f"Secure: {secure}\n"
                            f"Domain: {snapshot.url}"
                        ),
                        evidence=(
                            f"Cookie '{cookie_name}' missing Secure flag"
                        ),
                        confidence=SessionScanConfig.CONFIDENCE_NO_SECURE,
                        scanner_name=self.scanner_name,
                        endpoint_url=snapshot.url,
                    )
                )

        return findings

    @staticmethod
    def _is_auth_cookie(cookie_name: str) -> bool:
        """Check if a cookie name matches known auth cookie patterns."""
        name_lower = cookie_name.lower()
        return any(
            auth_name in name_lower
            for auth_name in SessionScanConfig.AUTH_COOKIE_NAMES
        )

    # ------------------------------------------------------------------
    # Phase 3: Token expiry analysis
    # ------------------------------------------------------------------

    def _check_token_expiry(self, token: str) -> DeepFinding | None:
        """Check JWT expiration claim for excessively long expiry."""
        payload = self._decode_jwt_payload(token)
        if payload is None:
            return None

        exp = payload.get("exp")
        if exp is None:
            # Missing exp is handled by JWTScanner, not duplicated here
            return None

        try:
            exp_timestamp = float(exp)
        except (ValueError, TypeError):
            return None

        now = time.time()
        remaining_seconds = exp_timestamp - now

        if remaining_seconds <= 0:
            return None

        remaining_hours = remaining_seconds / self.SECONDS_PER_HOUR

        if remaining_hours > SessionScanConfig.MAX_RECOMMENDED_EXPIRY_HOURS:
            remaining_days = remaining_hours / 24
            return DeepFinding(
                source=FindingSource.DAST_URL,
                category=FindingCategory.AUTH_WEAKNESS,
                severity=SeverityLevel.MEDIUM,
                title=SessionScanConfig.TITLE_LONG_EXPIRY,
                description=SessionScanConfig.DESC_LONG_EXPIRY.format(
                    hours=int(remaining_hours),
                    days=int(remaining_days),
                ),
                technical_detail=(
                    f"JWT exp: {exp_timestamp}\n"
                    f"Current time: {now:.0f}\n"
                    f"Remaining: {remaining_hours:.1f} hours"
                ),
                evidence=(
                    f"Token expires in {int(remaining_hours)} hours "
                    f"({int(remaining_days)} days)"
                ),
                confidence=SessionScanConfig.CONFIDENCE_LONG_EXPIRY,
                scanner_name=self.scanner_name,
            )

        return None

    def _decode_jwt_payload(self, token: str) -> dict[str, Any] | None:
        """Decode JWT payload without verification using base64."""
        return _shared_decode_jwt_payload(token)
