"""Client-side configuration exposure scanner.

Front-end bundles frequently leak configuration that should never reach the
browser: internal/localhost/staging URLs, un-replaced ``process.env.X``
placeholders (a build misconfiguration that exposes the variable name), and —
most critically — a Supabase ``service_role`` JWT. A ``service_role`` key
bypasses Row-Level Security entirely, so leaking it to the client is a full
database compromise.

This scanner is passive: it inspects only first-party JS (via the vendor
filter, so minified vendor bundles are not flagged) and the JWTs it decodes.
An ``anon`` Supabase key is expected on the client and is ignored.

Framework-public env prefixes (``NEXT_PUBLIC_``, ``VITE_``, ...) are excluded
because those are intentionally shipped to the browser.
"""

from __future__ import annotations

import logging
import re

from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.jwt_utils import decode_jwt_payload
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


# --- Module-local config ---
_SCANNER_NAME = "client_exposure_scanner"
_MAX_FINDINGS_PER_KIND = 10

# JWTs embedded in client code (header.payload.signature).
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")

# Un-replaced build placeholders — the env var name leaked verbatim because
# the bundler failed to substitute it.
_PROCESS_ENV_RE = re.compile(r"process\.env\.([A-Z][A-Z0-9_]{2,})")
_IMPORT_META_ENV_RE = re.compile(r"import\.meta\.env\.([A-Z][A-Z0-9_]{2,})")

# Internal / non-production hosts that should not be referenced in a shipped
# production bundle.
_INTERNAL_URL_RE = re.compile(
    r"""https?://(?:"""
    r"""localhost"""
    r"""|127\.0\.0\.1"""
    r"""|0\.0\.0\.0"""
    r"""|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"""
    r"""|192\.168\.\d{1,3}\.\d{1,3}"""
    r"""|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"""
    r"""|[a-z0-9.\-]*\.(?:local|internal|test)"""
    r"""|(?:staging|stg|dev|qa|internal|preprod|uat)[a-z0-9.\-]*\.[a-z]{2,}"""
    r""")(?::\d+)?[^\s'"`)]*""",
    re.IGNORECASE,
)

# Env-var name prefixes that frameworks intentionally expose to the client.
_PUBLIC_ENV_PREFIXES = (
    "NEXT_PUBLIC_",
    "VITE_",
    "REACT_APP_",
    "PUBLIC_",
    "VUE_APP_",
    "GATSBY_",
    "EXPO_PUBLIC_",
    "NUXT_PUBLIC_",
)


class ClientExposureScanner:
    """Detects sensitive configuration leaked into client-side JavaScript.

    SRP: This scanner is responsible ONLY for static client-exposure detection
    over first-party JS.
    """

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return _SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.CLIENT_EXPOSURE]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Scan first-party JS for leaked configuration.

        Args:
            endpoints: Discovered endpoints (unused by this scanner).
            snapshot: Codebase snapshot providing first-party JS content.

        Returns:
            List of client-exposure findings.
        """
        if snapshot is None:
            return []

        # first_party_js_content already excludes vendor/framework bundles.
        content = snapshot.first_party_js_content or ""
        if not content.strip():
            return []

        findings: list[DeepFinding] = []
        findings.extend(self._check_service_role_jwt(content, snapshot))
        findings.extend(self._check_internal_urls(content, snapshot))
        findings.extend(self._check_unreplaced_env(content, snapshot))

        logger.info("ClientExposureScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Supabase service_role JWT (CRITICAL)
    # ------------------------------------------------------------------

    def _check_service_role_jwt(
        self,
        content: str,
        snapshot: CodebaseSnapshot,
    ) -> list[DeepFinding]:
        """Flag any JWT whose decoded payload has role == service_role."""
        findings: list[DeepFinding] = []
        seen: set[str] = set()

        for match in _JWT_RE.finditer(content):
            token = match.group(0)
            if token in seen:
                continue
            payload = decode_jwt_payload(token)
            if not payload:
                continue
            role = str(payload.get("role", "")).lower()
            # anon keys are expected on the client — ignore them.
            if role != "service_role":
                continue
            seen.add(token)
            redacted = f"{token[:16]}...{token[-6:]}"
            findings.append(
                DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.CLIENT_EXPOSURE,
                    severity=SeverityLevel.CRITICAL,
                    title="Supabase service_role key exposed in client code",
                    description=(
                        "A JWT with the 'service_role' claim was found embedded "
                        "in client-side JavaScript. The service_role key bypasses "
                        "Row-Level Security and grants full read/write access to "
                        "the entire database. Anyone viewing the page can extract "
                        "it. Rotate the key immediately and only use it "
                        "server-side."
                    ),
                    technical_detail=(
                        f"JWT payload role claim: service_role\n"
                        f"Token (redacted): {redacted}"
                    ),
                    evidence="service_role JWT present in first-party JS bundle",
                    confidence=0.98,
                    scanner_name=self.scanner_name,
                    endpoint_url=snapshot.url,
                )
            )
            if len(findings) >= _MAX_FINDINGS_PER_KIND:
                break

        return findings

    # ------------------------------------------------------------------
    # Internal / non-production URLs
    # ------------------------------------------------------------------

    def _check_internal_urls(
        self,
        content: str,
        snapshot: CodebaseSnapshot,
    ) -> list[DeepFinding]:
        """Flag internal/localhost/staging URLs shipped in the bundle."""
        findings: list[DeepFinding] = []
        seen: set[str] = set()

        for match in _INTERNAL_URL_RE.finditer(content):
            url = match.group(0)
            if url in seen:
                continue
            seen.add(url)
            findings.append(
                DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.CLIENT_EXPOSURE,
                    severity=SeverityLevel.LOW,
                    title="Internal or non-production URL in client bundle",
                    description=(
                        f"The client-side JavaScript references an "
                        f"internal/non-production URL: {url}. This reveals "
                        "internal infrastructure, staging environments, or "
                        "developer endpoints to anyone inspecting the page."
                    ),
                    technical_detail=f"Reference found in first-party JS: {url}",
                    evidence=f"Client bundle contains {url}",
                    confidence=0.75,
                    scanner_name=self.scanner_name,
                    endpoint_url=snapshot.url,
                )
            )
            if len(findings) >= _MAX_FINDINGS_PER_KIND:
                break

        return findings

    # ------------------------------------------------------------------
    # Un-replaced env placeholders
    # ------------------------------------------------------------------

    def _check_unreplaced_env(
        self,
        content: str,
        snapshot: CodebaseSnapshot,
    ) -> list[DeepFinding]:
        """Flag un-substituted process.env / import.meta.env references.

        A raw ``process.env.SECRET_KEY`` surviving into the shipped bundle
        indicates a build misconfiguration and leaks the variable's name.
        Framework-public prefixes are excluded (they are meant to ship).
        """
        findings: list[DeepFinding] = []
        seen: set[str] = set()

        for regex in (_PROCESS_ENV_RE, _IMPORT_META_ENV_RE):
            for match in regex.finditer(content):
                var_name = match.group(1)
                if self._is_public_env(var_name):
                    continue
                if var_name in seen:
                    continue
                seen.add(var_name)
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.CLIENT_EXPOSURE,
                        severity=SeverityLevel.LOW,
                        title="Un-replaced environment variable in client bundle",
                        description=(
                            f"The client-side JavaScript contains an "
                            f"un-substituted environment reference to "
                            f"'{var_name}'. This indicates a build "
                            "misconfiguration and reveals the name of a "
                            "server-side variable that was expected to be "
                            "injected at build time. Ensure only "
                            "explicitly-public variables reach the client."
                        ),
                        technical_detail=(
                            f"Un-replaced reference: {match.group(0)}"
                        ),
                        evidence=f"Client bundle references env var '{var_name}'",
                        confidence=0.7,
                        scanner_name=self.scanner_name,
                        endpoint_url=snapshot.url,
                    )
                )
                if len(findings) >= _MAX_FINDINGS_PER_KIND:
                    return findings

        return findings

    @staticmethod
    def _is_public_env(var_name: str) -> bool:
        """Return True for framework env vars intended to ship to the client."""
        return any(
            var_name.startswith(prefix) for prefix in _PUBLIC_ENV_PREFIXES
        )
