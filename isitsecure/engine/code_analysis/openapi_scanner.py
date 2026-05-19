"""OpenAPI/Swagger specification security scanner.

Scans OpenAPI and Swagger specification files for security
misconfigurations such as missing authentication, insecure transport,
and unprotected sensitive endpoints.

SRP: This scanner is responsible ONLY for analyzing OpenAPI/Swagger
     spec files for security misconfigurations.  It does not analyze
     application code, Docker files, or runtime behavior.

OCP: Implements ``CodeScannerProtocol`` -- added to the sast_scanners
     list without modifying the agent or factory.

DIP: Depends on ``RepoSnapshot`` and ``CodeScannerProtocol``
     (abstractions), never on concrete implementations.
"""

from __future__ import annotations

import json
import logging
import re

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import OpenAPIScannerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class OpenAPIScanner:
    """Scans OpenAPI/Swagger specification files for security issues.

    Checks performed:
    1. No global security scheme defined
    2. HTTP servers (url uses http:// not https://)
    3. Basic auth scheme (type: http, scheme: basic)
    4. API key in query parameter (in: query with type: apiKey)
    5. Endpoints without security override
    6. Sensitive paths without auth (/admin, /users, /payments)

    Implements ``CodeScannerProtocol``.
    """

    @property
    def scanner_name(self) -> str:
        return OpenAPIScannerConfig.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Analyze OpenAPI/Swagger spec files for security issues."""
        findings: list[CodeFinding] = []

        spec_files = self._find_spec_files(repo)

        if not spec_files:
            return findings

        for file_path, content in spec_files.items():
            try:
                findings.extend(self._check_no_global_security(content, file_path))
                findings.extend(self._check_http_servers(content, file_path))
                findings.extend(self._check_basic_auth(content, file_path))
                findings.extend(self._check_apikey_in_query(content, file_path))
                findings.extend(self._check_endpoints_without_security(content, file_path))
                findings.extend(self._check_sensitive_paths(content, file_path))
            except Exception as e:
                logger.warning(
                    OpenAPIScannerConfig.ERROR_ANALYSIS_FAILED.format(
                        file=file_path, error=e
                    )
                )

        logger.info(
            "OpenAPIScanner: %d spec files scanned, %d findings",
            len(spec_files),
            len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # File discovery
    # ------------------------------------------------------------------

    @staticmethod
    def _find_spec_files(repo: RepoSnapshot) -> dict[str, str]:
        """Find OpenAPI/Swagger spec files in the file index."""
        spec_files: dict[str, str] = {}
        for path, content in repo.file_index.items():
            if not any(path.endswith(ext) for ext in OpenAPIScannerConfig.SPEC_EXTENSIONS):
                continue
            if any(
                re.search(marker, content)
                for marker in OpenAPIScannerConfig.SPEC_MARKERS
            ):
                spec_files[path] = content
        return spec_files

    # ------------------------------------------------------------------
    # 1. No global security scheme
    # ------------------------------------------------------------------

    def _check_no_global_security(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check if the spec defines a global security scheme."""
        findings: list[CodeFinding] = []

        has_security_schemes = bool(
            re.search(OpenAPIScannerConfig.SECURITY_SCHEMES_PATTERN, content)
        )
        has_global_security = bool(
            re.search(
                OpenAPIScannerConfig.GLOBAL_SECURITY_PATTERN, content, re.MULTILINE
            )
        )

        if not has_security_schemes or not has_global_security:
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.HIGH,
                    category=FindingCategory.AUTH_WEAKNESS,
                    title=OpenAPIScannerConfig.TITLE_NO_GLOBAL_SECURITY,
                    description=OpenAPIScannerConfig.DESC_NO_GLOBAL_SECURITY.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=OpenAPIScannerConfig.CONFIDENCE_NO_GLOBAL_SECURITY,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # 2. HTTP servers (insecure transport)
    # ------------------------------------------------------------------

    def _check_http_servers(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Find server URLs using http:// instead of https://."""
        findings: list[CodeFinding] = []

        for match in re.finditer(OpenAPIScannerConfig.HTTP_SERVER_PATTERN, content):
            url = match.group(0).strip().rstrip(",").strip('"').strip("'")
            # Skip localhost/development URLs
            if any(
                re.search(skip, url)
                for skip in OpenAPIScannerConfig.LOCALHOST_PATTERNS
            ):
                continue

            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.MEDIUM,
                    category=FindingCategory.MIXED_CONTENT,
                    title=OpenAPIScannerConfig.TITLE_HTTP_SERVER,
                    description=OpenAPIScannerConfig.DESC_HTTP_SERVER.format(
                        file=file_path, url=url
                    ),
                    file_path=file_path,
                    confidence=OpenAPIScannerConfig.CONFIDENCE_HTTP_SERVER,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # 3. Basic auth scheme
    # ------------------------------------------------------------------

    def _check_basic_auth(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for HTTP Basic authentication scheme."""
        findings: list[CodeFinding] = []

        if re.search(
            OpenAPIScannerConfig.BASIC_AUTH_PATTERN, content, re.DOTALL
        ):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.MEDIUM,
                    category=FindingCategory.AUTH_WEAKNESS,
                    title=OpenAPIScannerConfig.TITLE_BASIC_AUTH,
                    description=OpenAPIScannerConfig.DESC_BASIC_AUTH.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=OpenAPIScannerConfig.CONFIDENCE_BASIC_AUTH,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # 4. API key in query parameter
    # ------------------------------------------------------------------

    def _check_apikey_in_query(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for API key passed via query parameter."""
        findings: list[CodeFinding] = []

        if re.search(
            OpenAPIScannerConfig.APIKEY_IN_QUERY_PATTERN, content, re.DOTALL
        ):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.MEDIUM,
                    category=FindingCategory.EXPOSED_SECRETS,
                    title=OpenAPIScannerConfig.TITLE_APIKEY_IN_QUERY,
                    description=OpenAPIScannerConfig.DESC_APIKEY_IN_QUERY.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=OpenAPIScannerConfig.CONFIDENCE_APIKEY_IN_QUERY,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # 5. Endpoints without security override
    # ------------------------------------------------------------------

    def _check_endpoints_without_security(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for path operations that explicitly disable security."""
        findings: list[CodeFinding] = []

        for match in re.finditer(
            OpenAPIScannerConfig.EMPTY_SECURITY_PATTERN, content
        ):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.MEDIUM,
                    category=FindingCategory.AUTH_WEAKNESS,
                    title=OpenAPIScannerConfig.TITLE_EMPTY_SECURITY_OVERRIDE,
                    description=OpenAPIScannerConfig.DESC_EMPTY_SECURITY_OVERRIDE.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=OpenAPIScannerConfig.CONFIDENCE_EMPTY_SECURITY_OVERRIDE,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # 6. Sensitive paths without auth
    # ------------------------------------------------------------------

    def _check_sensitive_paths(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for sensitive paths that might lack authentication."""
        findings: list[CodeFinding] = []

        # Only flag if there is no global security defined
        has_global_security = bool(
            re.search(
                OpenAPIScannerConfig.GLOBAL_SECURITY_PATTERN, content, re.MULTILINE
            )
        )

        if has_global_security:
            return findings

        for pattern in OpenAPIScannerConfig.SENSITIVE_PATH_PATTERNS:
            for match in re.finditer(pattern, content):
                path_segment = match.group(0).strip().rstrip(":").strip('"').strip("'")
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.HIGH,
                        category=FindingCategory.AUTH_WEAKNESS,
                        title=OpenAPIScannerConfig.TITLE_SENSITIVE_PATH.format(
                            path=path_segment
                        ),
                        description=OpenAPIScannerConfig.DESC_SENSITIVE_PATH.format(
                            file=file_path, path=path_segment
                        ),
                        file_path=file_path,
                        confidence=OpenAPIScannerConfig.CONFIDENCE_SENSITIVE_PATH,
                    )
                )

        return findings
