"""Cross-probe DAST analyzer.

Runs after all DAST scanning completes and analyzes the accumulated
HTTP request/response pairs across ALL findings for patterns that
individual scanners miss.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict

from isitsecure.engine.constants import ProbeAnalyzerConfig
from isitsecure.engine.models import (
    DASTProbeCaptureEntry,
    DeepFinding,
    FindingSource,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class ProbeAnalyzer:
    """Analyzes accumulated DAST probe captures for cross-probe patterns.

    Each analysis method is focused on a single concern (SRP) and
    produces zero or more DeepFinding objects.
    """

    async def analyze(self, findings: list[DeepFinding]) -> list[DeepFinding]:
        """Run all cross-probe analyses on DAST findings.

        Args:
            findings: All DAST findings with their probe_captures attached.

        Returns:
            New findings discovered through cross-probe analysis.
        """
        captures = self._extract_captures(findings)
        if not captures:
            return []

        new_findings: list[DeepFinding] = []
        new_findings.extend(self._analyze_response_headers(captures))
        new_findings.extend(self._analyze_cookies(captures))
        new_findings.extend(self._analyze_response_sizes(captures))
        new_findings.extend(self._analyze_timing(captures))
        new_findings.extend(self._analyze_error_fingerprinting(captures))
        new_findings.extend(self._analyze_sensitive_data_exposure(captures))

        logger.info(
            "Probe analyzer produced %d findings from %d captures",
            len(new_findings),
            len(captures),
        )
        return new_findings

    # ------------------------------------------------------------------
    # Capture extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_captures(
        findings: list[DeepFinding],
    ) -> list[DASTProbeCaptureEntry]:
        """Flatten all probe captures from all findings into a single list."""
        captures: list[DASTProbeCaptureEntry] = []
        for finding in findings:
            captures.extend(finding.probe_captures)
        return captures

    # ------------------------------------------------------------------
    # 1. Response header information leakage
    # ------------------------------------------------------------------

    def _analyze_response_headers(
        self, captures: list[DASTProbeCaptureEntry],
    ) -> list[DeepFinding]:
        """Detect information leakage in HTTP response headers.

        Checks for:
        - Internal IP addresses (RFC 1918)
        - Debug headers
        - Backend framework disclosure headers
        - Internal hostnames
        """
        leak_details: dict[str, list[str]] = defaultdict(list)
        ip_re = re.compile(ProbeAnalyzerConfig.INTERNAL_IP_PATTERN)
        hostname_re = re.compile(ProbeAnalyzerConfig.INTERNAL_HOSTNAME_PATTERN)

        for capture in captures:
            for header_name, header_value in capture.response_headers.items():
                lower_name = header_name.lower()

                # Internal IPs
                ip_matches = ip_re.findall(header_value)
                for ip in ip_matches:
                    leak_details["internal_ip"].append(
                        f"{header_name}: {ip} ({capture.request_url})"
                    )

                # Debug headers
                if lower_name in ProbeAnalyzerConfig.DEBUG_HEADERS:
                    leak_details["debug_header"].append(
                        f"{header_name}: {header_value} ({capture.request_url})"
                    )

                # Framework disclosure
                if lower_name in ProbeAnalyzerConfig.FRAMEWORK_HEADERS:
                    leak_details["framework_disclosure"].append(
                        f"{header_name}: {header_value} ({capture.request_url})"
                    )

                # Internal hostnames
                hostname_matches = hostname_re.findall(header_value)
                for hostname in hostname_matches:
                    leak_details["internal_hostname"].append(
                        f"{header_name}: {hostname} ({capture.request_url})"
                    )

        findings: list[DeepFinding] = []
        for leak_type, examples in leak_details.items():
            unique_examples = list(dict.fromkeys(examples))
            details_str = "; ".join(unique_examples[:5])
            findings.append(
                DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.INFO_DISCLOSURE,
                    severity=SeverityLevel.MEDIUM,
                    title=ProbeAnalyzerConfig.TITLE_HEADER_LEAK,
                    description=ProbeAnalyzerConfig.DESC_HEADER_LEAK.format(
                        details=details_str,
                    ),
                    confidence=ProbeAnalyzerConfig.CONFIDENCE_HEADER_LEAK,
                    scanner_name=ProbeAnalyzerConfig.SCANNER_NAME,
                    evidence=f"Leak type: {leak_type}, occurrences: {len(unique_examples)}",
                )
            )
        return findings

    # ------------------------------------------------------------------
    # 2. Cookie security analysis
    # ------------------------------------------------------------------

    def _analyze_cookies(
        self, captures: list[DASTProbeCaptureEntry],
    ) -> list[DeepFinding]:
        """Analyze Set-Cookie headers across all probes.

        Checks session cookies for:
        - Low entropy (short token values)
        """
        cookies: dict[str, str] = {}
        for capture in captures:
            for header_name, header_value in capture.response_headers.items():
                if header_name.lower() == ProbeAnalyzerConfig.SET_COOKIE_HEADER:
                    # Parse cookie name and value
                    parts = header_value.split(";", 1)
                    if "=" in parts[0]:
                        name, value = parts[0].split("=", 1)
                        cookies[name.strip()] = value.strip()

        if not cookies:
            return []

        issues: list[str] = []
        for name, value in cookies.items():
            is_session = any(
                pattern in name.lower()
                for pattern in ProbeAnalyzerConfig.SESSION_COOKIE_NAMES
            )
            if is_session and len(value) < ProbeAnalyzerConfig.MIN_SESSION_TOKEN_LENGTH:
                issues.append(
                    f"Session cookie '{name}' has short value "
                    f"({len(value)} chars < {ProbeAnalyzerConfig.MIN_SESSION_TOKEN_LENGTH})"
                )

        if not issues:
            return []

        severity = SeverityLevel.HIGH if issues else SeverityLevel.MEDIUM
        return [
            DeepFinding(
                source=FindingSource.DAST_URL,
                category=FindingCategory.AUTH_WEAKNESS,
                severity=severity,
                title=ProbeAnalyzerConfig.TITLE_COOKIE_ISSUES,
                description=ProbeAnalyzerConfig.DESC_COOKIE_ISSUES.format(
                    details="; ".join(issues),
                ),
                confidence=ProbeAnalyzerConfig.CONFIDENCE_COOKIE_ISSUES,
                scanner_name=ProbeAnalyzerConfig.SCANNER_NAME,
                evidence=f"Cookies analyzed: {len(cookies)}, issues: {len(issues)}",
            )
        ]

    # ------------------------------------------------------------------
    # 3. Response size anomalies
    # ------------------------------------------------------------------

    def _analyze_response_sizes(
        self, captures: list[DASTProbeCaptureEntry],
    ) -> list[DeepFinding]:
        """Flag responses with body size significantly above the mean.

        Triggers when size > RESPONSE_SIZE_MULTIPLIER * mean AND
        size > RESPONSE_SIZE_MIN_BYTES.
        """
        sizes = [
            (c, len(c.response_body)) for c in captures if c.response_body
        ]
        if not sizes:
            return []

        mean_size = sum(s for _, s in sizes) / len(sizes)
        if mean_size == 0:
            return []

        findings: list[DeepFinding] = []
        seen_urls: set[str] = set()
        for capture, size in sizes:
            ratio = size / mean_size
            if (
                ratio > ProbeAnalyzerConfig.RESPONSE_SIZE_MULTIPLIER
                and size > ProbeAnalyzerConfig.RESPONSE_SIZE_MIN_BYTES
                and capture.request_url not in seen_urls
            ):
                seen_urls.add(capture.request_url)
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.INFO_DISCLOSURE,
                        severity=SeverityLevel.MEDIUM,
                        title=ProbeAnalyzerConfig.TITLE_RESPONSE_SIZE.format(
                            url=capture.request_url,
                        ),
                        description=ProbeAnalyzerConfig.DESC_RESPONSE_SIZE.format(
                            url=capture.request_url,
                            size=size,
                            ratio=ratio,
                            mean=int(mean_size),
                        ),
                        confidence=ProbeAnalyzerConfig.CONFIDENCE_RESPONSE_SIZE,
                        scanner_name=ProbeAnalyzerConfig.SCANNER_NAME,
                        endpoint_url=capture.request_url,
                    )
                )
        return findings

    # ------------------------------------------------------------------
    # 4. Timing anomalies
    # ------------------------------------------------------------------

    def _analyze_timing(
        self, captures: list[DASTProbeCaptureEntry],
    ) -> list[DeepFinding]:
        """Flag probes with response time significantly above the mean.

        Triggers when time > TIMING_MULTIPLIER * mean AND
        time > TIMING_MIN_MS.
        """
        timed = [c for c in captures if c.response_time_ms > 0]
        if not timed:
            return []

        mean_ms = sum(c.response_time_ms for c in timed) / len(timed)
        if mean_ms == 0:
            return []

        slow: list[str] = []
        for capture in timed:
            if (
                capture.response_time_ms > ProbeAnalyzerConfig.TIMING_MULTIPLIER * mean_ms
                and capture.response_time_ms > ProbeAnalyzerConfig.TIMING_MIN_MS
            ):
                slow.append(
                    f"{capture.request_url} ({capture.response_time_ms:.0f}ms)"
                )

        if not slow:
            return []

        unique_slow = list(dict.fromkeys(slow))
        return [
            DeepFinding(
                source=FindingSource.DAST_URL,
                category=FindingCategory.INFO_DISCLOSURE,
                severity=SeverityLevel.LOW,
                title=ProbeAnalyzerConfig.TITLE_TIMING,
                description=ProbeAnalyzerConfig.DESC_TIMING.format(
                    mean_ms=mean_ms,
                    details="; ".join(unique_slow[:5]),
                ),
                confidence=ProbeAnalyzerConfig.CONFIDENCE_TIMING,
                scanner_name=ProbeAnalyzerConfig.SCANNER_NAME,
            )
        ]

    # ------------------------------------------------------------------
    # 5. Error fingerprinting
    # ------------------------------------------------------------------

    def _analyze_error_fingerprinting(
        self, captures: list[DASTProbeCaptureEntry],
    ) -> list[DeepFinding]:
        """Detect backend technology from error responses (status >= 400)."""
        error_captures = [c for c in captures if c.response_status >= 400]
        if not error_captures:
            return []

        detected_techs: set[str] = set()
        for capture in error_captures:
            body = capture.response_body
            for tech_name, patterns in ProbeAnalyzerConfig.TECH_FINGERPRINTS.items():
                for pattern in patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        detected_techs.add(tech_name)
                        break

        if not detected_techs:
            return []

        return [
            DeepFinding(
                source=FindingSource.DAST_URL,
                category=FindingCategory.INFO_DISCLOSURE,
                severity=SeverityLevel.MEDIUM,
                title=ProbeAnalyzerConfig.TITLE_ERROR_FINGERPRINT,
                description=ProbeAnalyzerConfig.DESC_ERROR_FINGERPRINT.format(
                    techs=", ".join(sorted(detected_techs)),
                ),
                confidence=ProbeAnalyzerConfig.CONFIDENCE_ERROR_FINGERPRINT,
                scanner_name=ProbeAnalyzerConfig.SCANNER_NAME,
                evidence=f"Technologies detected: {', '.join(sorted(detected_techs))}",
            )
        ]

    # ------------------------------------------------------------------
    # 6. Sensitive data exposure
    # ------------------------------------------------------------------

    def _analyze_sensitive_data_exposure(
        self, captures: list[DASTProbeCaptureEntry],
    ) -> list[DeepFinding]:
        """Scan response bodies for PII and secrets.

        Checks for:
        - Email addresses (flag if > MIN_UNIQUE_EMAILS_TO_FLAG)
        - API key prefixes (sk_live_, AKIA, ghp_, glpat-)
        - JWT tokens in response body
        """
        findings: list[DeepFinding] = []
        email_re = re.compile(ProbeAnalyzerConfig.EMAIL_PATTERN)
        jwt_re = re.compile(ProbeAnalyzerConfig.JWT_BODY_PATTERN)

        all_emails: set[str] = set()
        api_key_hits: list[tuple[str, str]] = []  # (prefix, url)
        jwt_urls: list[str] = []

        for capture in captures:
            body = capture.response_body
            if not body:
                continue

            # Emails
            emails = email_re.findall(body)
            all_emails.update(emails)

            # API keys
            for prefix in ProbeAnalyzerConfig.API_KEY_PREFIXES:
                if prefix in body:
                    api_key_hits.append((prefix, capture.request_url))

            # JWTs
            if jwt_re.search(body):
                jwt_urls.append(capture.request_url)

        # Email findings
        if len(all_emails) > ProbeAnalyzerConfig.MIN_UNIQUE_EMAILS_TO_FLAG:
            findings.append(
                DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.UNENCRYPTED_PII,
                    severity=SeverityLevel.HIGH,
                    title=ProbeAnalyzerConfig.TITLE_SENSITIVE_EMAILS,
                    description=ProbeAnalyzerConfig.DESC_SENSITIVE_EMAILS.format(
                        count=len(all_emails),
                    ),
                    confidence=ProbeAnalyzerConfig.CONFIDENCE_SENSITIVE_EMAILS,
                    scanner_name=ProbeAnalyzerConfig.SCANNER_NAME,
                    evidence=f"Sample: {', '.join(list(all_emails)[:3])}",
                )
            )

        # API key findings — one per unique prefix
        seen_prefixes: set[str] = set()
        for prefix, url in api_key_hits:
            if prefix not in seen_prefixes:
                seen_prefixes.add(prefix)
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.EXPOSED_SECRETS,
                        severity=SeverityLevel.HIGH,
                        title=ProbeAnalyzerConfig.TITLE_SENSITIVE_API_KEY,
                        description=ProbeAnalyzerConfig.DESC_SENSITIVE_API_KEY.format(
                            prefix=prefix,
                            url=url,
                        ),
                        confidence=ProbeAnalyzerConfig.CONFIDENCE_SENSITIVE_API_KEY,
                        scanner_name=ProbeAnalyzerConfig.SCANNER_NAME,
                        endpoint_url=url,
                    )
                )

        # JWT findings
        if jwt_urls:
            unique_jwt_urls = list(dict.fromkeys(jwt_urls))
            findings.append(
                DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.AUTH_WEAKNESS,
                    severity=SeverityLevel.HIGH,
                    title=ProbeAnalyzerConfig.TITLE_SENSITIVE_JWT,
                    description=ProbeAnalyzerConfig.DESC_SENSITIVE_JWT.format(
                        url=unique_jwt_urls[0],
                    ),
                    confidence=ProbeAnalyzerConfig.CONFIDENCE_SENSITIVE_JWT,
                    scanner_name=ProbeAnalyzerConfig.SCANNER_NAME,
                    endpoint_url=unique_jwt_urls[0],
                    evidence=f"Found in {len(unique_jwt_urls)} response(s)",
                )
            )

        return findings
