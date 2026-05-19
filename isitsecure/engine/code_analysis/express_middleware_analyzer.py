"""Express.js middleware security analyzer.

SRP: This scanner is responsible ONLY for analyzing Express middleware
     files for security gaps.  Route detection is handled by
     ExpressRouteMapper; this scanner consumes the route_map to
     cross-reference coverage.

OCP: Implements ``CodeScannerProtocol`` — added to the sast_scanners
     list without modifying the agent or factory logic.

DIP: Depends on ``RepoSnapshot`` and ``CodeScannerProtocol``
     (abstractions), never on concrete implementations.
"""

from __future__ import annotations

import logging
import re

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)
from isitsecure.engine.constants import ExpressMiddlewareAnalyzerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class ExpressMiddlewareAnalyzer:
    """Analyzes Express.js middleware for security gaps.

    Checks performed:
    1. Auth middleware existence and quality (strong vs weak verification)
    2. Express routes without auth middleware
    3. Rate limiting presence and implementation quality
    4. Security header coverage
    5. CORS misconfiguration
    6. Tenant isolation middleware (for multi-tenant apps)

    Implements ``CodeScannerProtocol``.
    """

    @property
    def scanner_name(self) -> str:
        return ExpressMiddlewareAnalyzerConfig.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Analyze Express middleware security across the codebase."""
        findings: list[CodeFinding] = []

        # Skip if not an Express backend
        if not self._is_express_codebase(repo):
            return findings

        middleware_files = self._find_middleware_files(repo)

        # 1. Auth middleware analysis
        findings.extend(self._analyze_auth_middleware(middleware_files, repo))

        # 2. Route coverage analysis
        findings.extend(
            self._analyze_route_coverage(middleware_files, repo.route_map)
        )

        # 3. Rate limiting analysis
        findings.extend(self._analyze_rate_limiting(middleware_files, repo))

        # 4. Security headers analysis
        findings.extend(self._analyze_security_headers(middleware_files, repo))

        # 5. CORS analysis
        findings.extend(self._analyze_cors(repo))

        # 6. Tenant isolation analysis
        findings.extend(
            self._analyze_tenant_isolation(middleware_files, repo)
        )

        logger.info(
            "ExpressMiddlewareAnalyzer: %d findings", len(findings)
        )
        return findings

    # ------------------------------------------------------------------
    # Codebase detection
    # ------------------------------------------------------------------

    @staticmethod
    def _is_express_codebase(repo: RepoSnapshot) -> bool:
        """Check if the repo contains an Express.js backend."""
        # Check file_index for Express indicators
        for content in repo.file_index.values():
            if "express" in content and (
                "app.listen(" in content
                or "express()" in content
                or "express.Router()" in content
            ):
                return True
        return False

    # ------------------------------------------------------------------
    # Middleware file discovery
    # ------------------------------------------------------------------

    def _find_middleware_files(
        self, repo: RepoSnapshot
    ) -> dict[str, str]:
        """Find Express middleware files in the file index.

        Returns:
            Mapping of relative file path → content.
        """
        middleware_files: dict[str, str] = {}

        for file_path, content in repo.file_index.items():
            # Check if file is in a middleware directory
            is_in_mw_dir = any(
                f"/{mw_dir}/" in f"/{file_path}"
                for mw_dir in ExpressMiddlewareAnalyzerConfig.MIDDLEWARE_DIR_PATTERNS
            )

            # Or if the filename itself indicates middleware
            is_mw_file = "middleware" in file_path.lower()

            if is_in_mw_dir or is_mw_file:
                middleware_files[file_path] = content

        return middleware_files

    # ------------------------------------------------------------------
    # 1. Auth middleware analysis
    # ------------------------------------------------------------------

    def _analyze_auth_middleware(
        self,
        middleware_files: dict[str, str],
        repo: RepoSnapshot,
    ) -> list[CodeFinding]:
        """Check for auth middleware existence and verification quality."""
        findings: list[CodeFinding] = []

        has_auth_verification = False
        has_auth_enforcement = False
        has_weak_auth = False

        for file_path, content in middleware_files.items():
            # Check for strong auth verification
            if any(
                re.search(pattern, content)
                for pattern in ExpressMiddlewareAnalyzerConfig.AUTH_VERIFICATION_PATTERNS
            ):
                has_auth_verification = True

            # Check for auth enforcement (401/403 responses)
            if any(
                re.search(pattern, content)
                for pattern in ExpressMiddlewareAnalyzerConfig.AUTH_ENFORCEMENT_PATTERNS
            ):
                has_auth_enforcement = True

            # Check for weak auth patterns
            if any(
                re.search(pattern, content, re.MULTILINE)
                for pattern in ExpressMiddlewareAnalyzerConfig.WEAK_AUTH_PATTERNS
            ):
                has_weak_auth = True

                if not has_auth_verification:
                    findings.append(
                        CodeFinding(
                            scanner_name=self.scanner_name,
                            severity=SeverityLevel.HIGH,
                            category=FindingCategory.AUTH_WEAKNESS,
                            title=ExpressMiddlewareAnalyzerConfig.TITLE_WEAK_AUTH,
                            description=ExpressMiddlewareAnalyzerConfig.DESC_WEAK_AUTH.format(
                                file=file_path
                            ),
                            file_path=file_path,
                            confidence=ExpressMiddlewareAnalyzerConfig.CONFIDENCE_WEAK_AUTH,
                        )
                    )

        # Also check non-middleware files (main.js etc.) for auth patterns
        if not has_auth_verification:
            for file_path, content in repo.file_index.items():
                if any(
                    re.search(pattern, content)
                    for pattern in ExpressMiddlewareAnalyzerConfig.AUTH_VERIFICATION_PATTERNS
                ):
                    has_auth_verification = True
                    break

        if not has_auth_verification and not has_weak_auth:
            # Only flag if there are Express routes that need auth
            express_routes = self._get_express_routes(repo.route_map)
            if express_routes:
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.HIGH,
                        category=FindingCategory.AUTH_WEAKNESS,
                        title=ExpressMiddlewareAnalyzerConfig.TITLE_NO_AUTH_MIDDLEWARE,
                        description=ExpressMiddlewareAnalyzerConfig.DESC_NO_AUTH_MIDDLEWARE,
                        file_path="(no middleware file found)",
                        confidence=ExpressMiddlewareAnalyzerConfig.CONFIDENCE_NO_AUTH_MIDDLEWARE,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # 2. Route coverage analysis
    # ------------------------------------------------------------------

    def _analyze_route_coverage(
        self,
        middleware_files: dict[str, str],
        route_map: list[RouteEntry],
    ) -> list[CodeFinding]:
        """Find Express routes that lack auth middleware."""
        findings: list[CodeFinding] = []

        express_routes = self._get_express_routes(route_map)

        for route in express_routes:
            # Skip routes already marked as having auth
            if route.has_auth_check:
                continue

            # Skip legitimately public routes
            if self._is_public_route(route.route_pattern):
                continue

            # Skip routes that don't handle sensitive data
            if not self._is_sensitive_route(route.route_pattern):
                continue

            for method in route.http_methods:
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.MEDIUM,
                        category=FindingCategory.AUTH_WEAKNESS,
                        title=ExpressMiddlewareAnalyzerConfig.TITLE_ROUTE_NO_AUTH.format(
                            route=route.route_pattern
                        ),
                        description=ExpressMiddlewareAnalyzerConfig.DESC_ROUTE_NO_AUTH.format(
                            method=method,
                            route=route.route_pattern,
                            file=route.file_path,
                        ),
                        file_path=route.file_path,
                        confidence=ExpressMiddlewareAnalyzerConfig.CONFIDENCE_ROUTE_UNPROTECTED,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # 3. Rate limiting analysis
    # ------------------------------------------------------------------

    def _analyze_rate_limiting(
        self,
        middleware_files: dict[str, str],
        repo: RepoSnapshot,
    ) -> list[CodeFinding]:
        """Check for rate limiting middleware and implementation quality."""
        findings: list[CodeFinding] = []
        has_rate_limit = False
        rate_limit_file: str = ""

        # Check middleware files first
        for file_path, content in middleware_files.items():
            if any(
                re.search(pattern, content)
                for pattern in ExpressMiddlewareAnalyzerConfig.RATE_LIMIT_PATTERNS
            ):
                has_rate_limit = True
                rate_limit_file = file_path

                # Check for in-memory store (not production-ready)
                if self._uses_in_memory_store(content):
                    findings.append(
                        CodeFinding(
                            scanner_name=self.scanner_name,
                            severity=SeverityLevel.MEDIUM,
                            category=FindingCategory.EXPOSED_API_ENDPOINT,
                            title=ExpressMiddlewareAnalyzerConfig.TITLE_IN_MEMORY_RATE_LIMIT,
                            description=ExpressMiddlewareAnalyzerConfig.DESC_IN_MEMORY_RATE_LIMIT.format(
                                file=file_path
                            ),
                            file_path=file_path,
                            confidence=ExpressMiddlewareAnalyzerConfig.CONFIDENCE_IN_MEMORY_RATE_LIMIT,
                        )
                    )
                break

        # Also check entry files
        if not has_rate_limit:
            for file_path, content in repo.file_index.items():
                if any(
                    re.search(pattern, content)
                    for pattern in ExpressMiddlewareAnalyzerConfig.RATE_LIMIT_PATTERNS
                ):
                    has_rate_limit = True
                    break

        if not has_rate_limit:
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.MEDIUM,
                    category=FindingCategory.EXPOSED_API_ENDPOINT,
                    title=ExpressMiddlewareAnalyzerConfig.TITLE_NO_RATE_LIMIT,
                    description=ExpressMiddlewareAnalyzerConfig.DESC_NO_RATE_LIMIT,
                    file_path="(no rate limit middleware found)",
                    confidence=ExpressMiddlewareAnalyzerConfig.CONFIDENCE_NO_RATE_LIMIT,
                )
            )

        return findings

    @staticmethod
    def _uses_in_memory_store(content: str) -> bool:
        """Detect if rate limiting uses an in-memory store.

        Checks for Map/Object usage without an actual Redis/memcached
        import or client instantiation (not just comments mentioning Redis).
        """
        has_in_memory = bool(
            re.search(r'new\s+Map\s*\(\s*\)', content)
            or re.search(r'memoryStore', content)
        )

        # Check for actual Redis usage (imports or client creation, not comments)
        has_shared_store = bool(
            re.search(r'(?:require|import)\s*.*(?:redis|ioredis|memcached)', content, re.IGNORECASE)
            or re.search(r'new\s+Redis\s*\(', content)
            or re.search(r'createClient\s*\(\s*\{.*redis', content, re.IGNORECASE | re.DOTALL)
        )

        return has_in_memory and not has_shared_store

    # ------------------------------------------------------------------
    # 4. Security headers analysis
    # ------------------------------------------------------------------

    def _analyze_security_headers(
        self,
        middleware_files: dict[str, str],
        repo: RepoSnapshot,
    ) -> list[CodeFinding]:
        """Check for security header middleware."""
        findings: list[CodeFinding] = []

        # Collect all security headers found across all files
        all_content = "\n".join(middleware_files.values())

        # Also check main entry files for inline security headers
        for file_path, content in repo.file_index.items():
            if any(
                name in file_path
                for name in ("main.js", "app.js", "server.js", "index.js")
            ):
                all_content += "\n" + content

        # Check for helmet (covers all headers)
        has_helmet = any(
            re.search(pattern, all_content)
            for pattern in ExpressMiddlewareAnalyzerConfig.HELMET_PATTERNS
        )

        if has_helmet:
            # helmet covers everything — no findings needed
            return findings

        # Check for individual security headers
        for header in ExpressMiddlewareAnalyzerConfig.RECOMMENDED_SECURITY_HEADERS:
            if header not in all_content:
                protection = ExpressMiddlewareAnalyzerConfig.HEADER_PROTECTIONS.get(
                    header, "various attacks"
                )
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.LOW,
                        category=FindingCategory.MISSING_HEADERS,
                        title=ExpressMiddlewareAnalyzerConfig.TITLE_MISSING_SECURITY_HEADERS.format(
                            header=header
                        ),
                        description=ExpressMiddlewareAnalyzerConfig.DESC_MISSING_SECURITY_HEADERS.format(
                            header=header, protection=protection
                        ),
                        file_path="(no security headers middleware)",
                        confidence=ExpressMiddlewareAnalyzerConfig.CONFIDENCE_MISSING_SECURITY_HEADERS,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # 5. CORS analysis
    # ------------------------------------------------------------------

    def _analyze_cors(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Check for dangerous CORS configurations.

        Only flags when origin: '*' AND credentials: true appear in
        the SAME file (same CORS config), not across different files.
        """
        findings: list[CodeFinding] = []

        for file_path, content in repo.file_index.items():
            # Skip files unlikely to contain CORS config
            if "cors" not in content.lower():
                continue

            has_wildcard = bool(
                re.search(
                    ExpressMiddlewareAnalyzerConfig.CORS_WILDCARD_PATTERN,
                    content,
                )
            )
            has_credentials = bool(
                re.search(
                    ExpressMiddlewareAnalyzerConfig.CORS_CREDENTIALS_PATTERN,
                    content,
                )
            )

            if has_wildcard and has_credentials:
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.HIGH,
                        category=FindingCategory.CORS_MISCONFIGURATION,
                        title=ExpressMiddlewareAnalyzerConfig.TITLE_CORS_WILDCARD,
                        description=ExpressMiddlewareAnalyzerConfig.DESC_CORS_WILDCARD.format(
                            file=file_path
                        ),
                        file_path=file_path,
                        confidence=ExpressMiddlewareAnalyzerConfig.CONFIDENCE_CORS_WILDCARD,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # 6. Tenant isolation analysis
    # ------------------------------------------------------------------

    def _analyze_tenant_isolation(
        self,
        middleware_files: dict[str, str],
        repo: RepoSnapshot,
    ) -> list[CodeFinding]:
        """Check for tenant isolation in multi-tenant apps."""
        findings: list[CodeFinding] = []

        # Check if this is a multi-tenant app (look for tenant-related patterns)
        all_content = "\n".join(repo.file_index.values())
        is_multi_tenant = bool(
            re.search(r'tenant[_\-]?id|tenantId|tenant_id', all_content)
            and re.search(r'tenants?\s*=|tenants?\s*\(', all_content)
        )

        if not is_multi_tenant:
            return findings

        # Check if tenant isolation middleware exists
        has_tenant_middleware = any(
            any(
                re.search(pattern, content)
                for pattern in ExpressMiddlewareAnalyzerConfig.TENANT_ISOLATION_PATTERNS
            )
            for content in middleware_files.values()
        )

        # Also check non-middleware files
        if not has_tenant_middleware:
            for content in repo.file_index.values():
                if any(
                    re.search(pattern, content)
                    for pattern in ExpressMiddlewareAnalyzerConfig.TENANT_ISOLATION_PATTERNS
                ):
                    has_tenant_middleware = True
                    break

        if not has_tenant_middleware:
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.HIGH,
                    category=FindingCategory.AUTH_WEAKNESS,
                    title=ExpressMiddlewareAnalyzerConfig.TITLE_NO_TENANT_ISOLATION,
                    description=ExpressMiddlewareAnalyzerConfig.DESC_NO_TENANT_ISOLATION,
                    file_path="(no tenant middleware found)",
                    confidence=ExpressMiddlewareAnalyzerConfig.CONFIDENCE_NO_TENANT_ISOLATION,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_express_routes(route_map: list[RouteEntry]) -> list[RouteEntry]:
        """Filter route_map to Express routes only (exclude tRPC/Next.js)."""
        return [
            r for r in route_map
            if "/trpc/" not in r.route_pattern
            and "route.ts" not in r.file_path
            and "route.js" not in r.file_path
        ]

    @staticmethod
    def _is_public_route(route_pattern: str) -> bool:
        """Check if a route is legitimately public."""
        return any(
            indicator in route_pattern.lower()
            for indicator in ExpressMiddlewareAnalyzerConfig.PUBLIC_ROUTE_INDICATORS
        )

    @staticmethod
    def _is_sensitive_route(route_pattern: str) -> bool:
        """Check if a route handles sensitive data."""
        return any(
            indicator in route_pattern.lower()
            for indicator in ExpressMiddlewareAnalyzerConfig.SENSITIVE_ROUTE_INDICATORS
        )
