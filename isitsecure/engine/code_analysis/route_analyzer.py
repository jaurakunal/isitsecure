"""Route authentication and authorization analyzer.

Analyzes API routes and Server Actions for:
1. Missing authentication checks (no getUser/getSession call)
2. Missing authorization checks (no ownership filter)
3. Service role usage (bypasses RLS)
4. Missing input validation (no zod/yup/joi)
5. IDOR risk (user-supplied ID without ownership check)
6. Server Actions without auth checks

Monorepo-aware: respects ``has_auth_check`` from route mappers
(tRPC, Express, Next.js).  When a route mapper has already confirmed
auth status, this scanner trusts that classification instead of
re-scanning with framework-specific patterns.
"""

from __future__ import annotations

import logging
import re

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)
from isitsecure.engine.constants import RouteAuthAnalyzerConfig
from isitsecure.engine.shared.code_utils import find_line_number
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class RouteAuthAnalyzer:
    """Analyzes API routes and Server Actions for security issues.

    Implements CodeScannerProtocol.
    """

    CONFIDENCE_ROUTE_FINDING = 0.85
    CONFIDENCE_SERVER_ACTION_FINDING = 0.85
    SNIPPET_MAX_LENGTH = 300
    EXPORTED_ASYNC_FUNCTION_PATTERN = r'export\s+async\s+function\s+(\w+)'

    @property
    def scanner_name(self) -> str:
        return RouteAuthAnalyzerConfig.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Analyze all API routes and Server Actions.

        Deduplicates analysis by file: when multiple routes share the
        same file (common in tRPC/Express), file-level checks (service_role,
        validation) are performed ONCE per file. Route-specific checks
        (missing auth, IDOR) use per-route metadata from the route mapper.
        """
        findings: list[CodeFinding] = []

        # Group routes by file to avoid duplicate file-level analysis
        routes_by_file: dict[str, list[RouteEntry]] = {}
        for route in repo.route_map:
            routes_by_file.setdefault(route.file_path, []).append(route)

        # Analyze each file once, then generate per-route findings
        analyzed_files: set[str] = set()
        for file_path, file_routes in routes_by_file.items():
            file_findings = self._analyze_file_routes(
                file_path, file_routes, analyzed_files
            )
            findings.extend(file_findings)

        # Analyze Server Actions from file_index
        server_action_findings = self._analyze_server_actions(repo)
        findings.extend(server_action_findings)

        logger.info(
            "RouteAuthAnalyzer: analyzed %d routes across %d files, %d findings",
            len(repo.route_map),
            len(routes_by_file),
            len(findings),
        )
        return findings

    def _analyze_file_routes(
        self,
        file_path: str,
        routes: list[RouteEntry],
        analyzed_files: set[str],
    ) -> list[CodeFinding]:
        """Analyze routes grouped by file.

        File-level checks (service_role, validation) run once per file.
        Route-level checks (auth, IDOR) use per-route has_auth_check metadata.
        """
        findings: list[CodeFinding] = []

        # Get content from any route (all share the same file content)
        content = routes[0].content if routes else ""
        if not content:
            return findings

        # File-level analysis (run ONCE per file, not per route)
        if file_path not in analyzed_files:
            analyzed_files.add(file_path)

            # Service role check — ONE finding per file
            if self._uses_service_role(content):
                findings.append(self._create_finding(
                    route=routes[0],
                    title=RouteAuthAnalyzerConfig.TITLE_SERVICE_ROLE,
                    description=(
                        f"The file {file_path} uses the Supabase "
                        f"service_role key, which bypasses all Row Level "
                        f"Security policies. Routes: "
                        f"{', '.join(r.route_pattern for r in routes[:5])}"
                        f"{'...' if len(routes) > 5 else ''}"
                    ),
                    severity=SeverityLevel(
                        RouteAuthAnalyzerConfig.SEVERITY_SERVICE_ROLE,
                    ),
                    category=FindingCategory.AUTH_WEAKNESS,
                ))

            # Input validation check — ONE finding per file
            # Only flag if file has user-supplied IDs or Supabase ops
            # but no validation framework (zod/yup/joi)
            has_validation = self._has_input_validation(content)
            has_user_supplied_id = self._has_user_supplied_id(content)
            supabase_ops = self._extract_supabase_operations(content)
            has_mutations = any(
                m in route.http_methods
                for route in routes
                for m in ("POST", "PUT", "PATCH", "DELETE")
            )

            if (
                not has_validation
                and (has_user_supplied_id or supabase_ops)
                and has_mutations
            ):
                findings.append(self._create_finding(
                    route=routes[0],
                    title=RouteAuthAnalyzerConfig.TITLE_MISSING_VALIDATION,
                    description=(
                        f"The file {file_path} accepts user input "
                        f"but does not appear to validate it with zod, "
                        f"yup, joi, or similar. Routes: "
                        f"{', '.join(r.route_pattern for r in routes[:5])}"
                        f"{'...' if len(routes) > 5 else ''}"
                    ),
                    severity=SeverityLevel(
                        RouteAuthAnalyzerConfig.SEVERITY_MISSING_VALIDATION,
                    ),
                    category=FindingCategory.INJECTION_RISK,
                ))

        # Route-level analysis (per route, using mapper metadata)
        for route in routes:
            route_findings = self._analyze_route(route)
            findings.extend(route_findings)

        return findings

    # Routes that are intentionally public — never flag for missing auth
    _PUBLIC_ROUTE_PATTERNS = frozenset({
        "/health", "/ping", "/status", "/ready", "/livez", "/readyz",
        "/", "/docs", "/swagger", "/openapi",
    })

    # Route pattern substrings that indicate intentionally public endpoints
    _PUBLIC_ROUTE_INDICATORS = (
        "/webhook",
        "/stripe",  # Stripe webhooks are signature-verified, not auth-gated
        "marketplace.featured",
        "marketplace.categories",
        "marketplace.search",
        "marketplace.reviews",
        "marketplace.reviewStats",
        "deal.list",
        "deal.get",
        "deal.getChangelogs",
        "user.register",
        "user.resendVerification",
        "user.requestPasswordReset",
    )

    def _analyze_route(self, route: RouteEntry) -> list[CodeFinding]:
        """Analyze a single API route for security issues.

        Monorepo-aware: trusts ``has_auth_check`` from route mappers
        (tRPC, Express, Next.js) before falling back to content-based
        regex detection.

        Note: service_role and validation checks are now file-level
        (handled in ``_analyze_file_routes``), not per-route. This
        prevents N duplicate findings for N routes in the same file.
        """
        findings: list[CodeFinding] = []

        if not route.content:
            return findings

        # Skip intentionally public routes entirely
        if self._is_intentionally_public(route):
            return findings

        # --- Determine auth status ---
        # Priority 1: Trust route mapper's classification
        if route.has_auth_check is True:
            has_auth = True
        elif route.has_auth_check is False:
            has_auth = False
        else:
            # has_auth_check is None (unknown) — fall back to content scan
            has_auth = self._has_auth_check(route.content)

        # Check 1: Missing authentication (only for routes not confirmed by mapper)
        if not has_auth:
            findings.append(self._create_finding(
                route=route,
                title=RouteAuthAnalyzerConfig.TITLE_MISSING_AUTH,
                description=(
                    f"The API route {route.route_pattern} "
                    f"({', '.join(route.http_methods)}) "
                    f"does not appear to check authentication. Any "
                    f"unauthenticated request can access this endpoint."
                ),
                severity=SeverityLevel(
                    RouteAuthAnalyzerConfig.SEVERITY_MISSING_AUTH,
                ),
                category=FindingCategory.AUTH_WEAKNESS,
            ))

        # Check 2: IDOR / ownership — only for Next.js-style routes where
        # each file is a single route handler. For tRPC/Express routes
        # where multiple routes share the same file content, content-level
        # IDOR checks produce false positives (one params.id match → flagged
        # on all 16 routes). The LLM reviewer handles IDOR for those.
        if has_auth and self._is_single_route_file(route):
            has_ownership = self._has_ownership_check(route.content)
            has_user_supplied_id = self._has_user_supplied_id(route.content)
            supabase_ops = self._extract_supabase_operations(route.content)

            if not has_ownership and has_user_supplied_id:
                findings.append(self._create_finding(
                    route=route,
                    title=RouteAuthAnalyzerConfig.TITLE_IDOR_RISK,
                    description=(
                        f"The API route {route.route_pattern} checks "
                        f"authentication but does not verify the authenticated "
                        f"user owns the requested resource. A user-supplied ID "
                        f"is used in a query without an ownership filter."
                    ),
                    severity=SeverityLevel(
                        RouteAuthAnalyzerConfig.SEVERITY_IDOR_RISK,
                    ),
                    category=FindingCategory.IDOR,
                ))
            elif not has_ownership and supabase_ops:
                findings.append(self._create_finding(
                    route=route,
                    title=RouteAuthAnalyzerConfig.TITLE_MISSING_OWNERSHIP,
                    description=(
                        f"The API route {route.route_pattern} checks "
                        f"authentication but does not filter by user ownership. "
                        f"Supabase operations: {', '.join(supabase_ops)}."
                    ),
                    severity=SeverityLevel(
                        RouteAuthAnalyzerConfig.SEVERITY_MISSING_OWNERSHIP,
                    ),
                    category=FindingCategory.AUTH_WEAKNESS,
                ))

        return findings

    @staticmethod
    def _is_single_route_file(route: RouteEntry) -> bool:
        """Check if this route is from a file with a single route handler.

        Next.js route.ts/route.js files contain one route per file, so
        content-level checks (IDOR, ownership) are accurate.

        tRPC router files and Express entry files contain many routes
        sharing the same content, making content-level checks unreliable.
        """
        # Next.js App Router files
        if route.file_path.endswith(("route.ts", "route.js")):
            return True

        # Next.js Pages Router API files
        if "/pages/api/" in route.file_path:
            return True

        # Everything else (tRPC routers, Express files) is multi-route
        return False

    def _is_intentionally_public(self, route: RouteEntry) -> bool:
        """Check if a route is intentionally public and should not be flagged.

        Covers:
        - Health/status endpoints
        - Webhook endpoints (signature-verified, not auth-gated)
        - Public marketplace browse endpoints (publicProcedure in tRPC)
        - Registration/password reset endpoints
        """
        pattern = route.route_pattern

        # Exact matches
        if pattern in self._PUBLIC_ROUTE_PATTERNS:
            return True

        # Substring matches
        if any(ind in pattern for ind in self._PUBLIC_ROUTE_INDICATORS):
            return True

        # Route mapper explicitly marked as public (has_auth_check=False)
        # AND the route is a read-only GET — likely intentionally public
        if (
            route.has_auth_check is False
            and all(m == "GET" for m in route.http_methods)
        ):
            return True

        return False

    def _analyze_server_actions(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Find and analyze Server Actions (files with 'use server')."""
        findings: list[CodeFinding] = []

        for file_path, content in repo.file_index.items():
            if not re.search(
                RouteAuthAnalyzerConfig.USE_SERVER_DIRECTIVE, content,
            ):
                continue

            # This is a server action file
            if not self._has_auth_check(content):
                # Find each exported async function (potential action)
                functions = re.findall(
                    self.EXPORTED_ASYNC_FUNCTION_PATTERN,
                    content,
                )

                for func_name in functions:
                    findings.append(CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel(
                            RouteAuthAnalyzerConfig.SEVERITY_SERVER_ACTION_NO_AUTH,
                        ),
                        category=FindingCategory.AUTH_WEAKNESS,
                        title=RouteAuthAnalyzerConfig.TITLE_SERVER_ACTION_NO_AUTH,
                        description=(
                            f"Server Action '{func_name}' in {file_path} "
                            f"does not check authentication. Server Actions "
                            f"are callable from the client — any user can "
                            f"invoke this action without being logged in."
                        ),
                        file_path=file_path,
                        confidence=self.CONFIDENCE_SERVER_ACTION_FINDING,
                    ))

        return findings

    # ------------------------------------------------------------------
    # LSP validation (Phase 7.5 — called by orchestrator after scan)
    # ------------------------------------------------------------------

    def validate_with_lsp(
        self,
        findings: list[CodeFinding],
        auth_flow_results: dict[str, AuthFlowResult],
    ) -> list[CodeFinding]:
        """Validate regex findings against LSP auth flow analysis.

        - LSP confirms auth exists → suppress "missing auth" finding
        - LSP confirms no auth AND regex agrees → boost confidence
        - LSP traces ownership → suppress IDOR finding

        Args:
            findings: Regex-generated findings from ``scan()``.
            auth_flow_results: LSP auth flow data keyed by
                ``file_path:route_pattern``.

        Returns:
            Filtered findings with LSP validation applied.
        """
        from isitsecure.engine.code_analysis.lsp.protocols import (
            AuthFlowResult,
        )
        from isitsecure.engine.constants import LSPConfig

        if not auth_flow_results:
            return findings

        validated: list[CodeFinding] = []
        suppressed_count = 0

        for finding in findings:
            # Only validate route_auth_analyzer findings
            if finding.scanner_name != self.scanner_name:
                validated.append(finding)
                continue

            # Find matching LSP result
            lsp_result = self._find_lsp_result(finding, auth_flow_results)

            if lsp_result is None:
                # No LSP data for this finding — keep as-is
                validated.append(finding)
                continue

            # Suppress "missing auth" if LSP confirms auth exists
            if (
                finding.title == RouteAuthAnalyzerConfig.TITLE_MISSING_AUTH
                and lsp_result.has_verified_auth
            ):
                finding.lsp_suppressed = True
                suppressed_count += 1
                continue

            # Suppress IDOR if LSP confirms ownership check
            if (
                finding.title == RouteAuthAnalyzerConfig.TITLE_IDOR_RISK
                and lsp_result.has_ownership_check
            ):
                finding.lsp_suppressed = True
                suppressed_count += 1
                continue

            # Suppress "missing ownership" if LSP confirms ownership
            if (
                finding.title == RouteAuthAnalyzerConfig.TITLE_MISSING_OWNERSHIP
                and lsp_result.has_ownership_check
            ):
                finding.lsp_suppressed = True
                suppressed_count += 1
                continue

            # LSP agrees with regex — boost confidence
            if not lsp_result.has_verified_auth:
                finding.confidence = min(
                    LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                    finding.confidence + LSPConfig.CONFIDENCE_LSP_BOOST,
                )
                finding.lsp_validated = True

            validated.append(finding)

        if suppressed_count:
            logger.info(
                LSPConfig.MSG_VALIDATION_COMPLETE.format(
                    confirmed=len(validated),
                    suppressed=suppressed_count,
                )
            )

        return validated

    @staticmethod
    def _find_lsp_result(
        finding: CodeFinding,
        auth_flow_results: dict[str, AuthFlowResult],
    ) -> AuthFlowResult | None:
        """Find the LSP result matching a finding's file and route."""
        from isitsecure.engine.code_analysis.lsp.protocols import (
            AuthFlowResult,
        )

        # Try exact match: file_path:route_pattern
        for key, result in auth_flow_results.items():
            if key.startswith(finding.file_path + ":"):
                return result

        # Try file-only match
        for key, result in auth_flow_results.items():
            if key.startswith(finding.file_path):
                return result

        return None

    def _has_auth_check(self, content: str) -> bool:
        """Check if content contains any authentication check pattern."""
        return any(
            re.search(pattern, content)
            for pattern in RouteAuthAnalyzerConfig.AUTH_CHECK_PATTERNS
        )

    def _has_ownership_check(self, content: str) -> bool:
        """Check if content contains any ownership/authorization check."""
        return any(
            re.search(pattern, content)
            for pattern in RouteAuthAnalyzerConfig.OWNERSHIP_CHECK_PATTERNS
        )

    def _uses_service_role(self, content: str) -> bool:
        """Check if content uses Supabase service_role key."""
        return any(
            re.search(pattern, content)
            for pattern in RouteAuthAnalyzerConfig.SERVICE_ROLE_PATTERNS
        )

    def _has_input_validation(self, content: str) -> bool:
        """Check if content has input validation."""
        return any(
            re.search(pattern, content)
            for pattern in RouteAuthAnalyzerConfig.VALIDATION_PATTERNS
        )

    def _has_user_supplied_id(self, content: str) -> bool:
        """Check if content uses user-supplied ID parameters."""
        return any(
            re.search(pattern, content)
            for pattern in RouteAuthAnalyzerConfig.USER_SUPPLIED_ID_PATTERNS
        )

    def _extract_supabase_operations(self, content: str) -> list[str]:
        """Extract Supabase table operations from content."""
        ops: list[str] = []
        for pattern in RouteAuthAnalyzerConfig.SUPABASE_OPERATION_PATTERNS:
            for match in re.finditer(pattern, content):
                groups = match.groups()
                if len(groups) >= 2:
                    ops.append(f"{groups[0]}.{groups[1]}")
                elif len(groups) == 1:
                    ops.append(f"rpc:{groups[0]}")
        return ops

    def _create_finding(
        self,
        route: RouteEntry,
        title: str,
        description: str,
        severity: SeverityLevel,
        category: FindingCategory,
    ) -> CodeFinding:
        """Create a CodeFinding from route analysis."""
        from isitsecure.engine.shared.code_context import (
            CodeContextExtractor,
        )

        line_number = self._find_relevant_line(route.content, route)

        return CodeFinding(
            scanner_name=self.scanner_name,
            severity=severity,
            category=category,
            title=title,
            description=description,
            file_path=route.file_path,
            line_number=line_number,
            code_snippet=CodeContextExtractor.extract(
                route.content, line_number
            ),
            confidence=self.CONFIDENCE_ROUTE_FINDING,
        )

    def _find_relevant_line(
        self, content: str, route: RouteEntry,
    ) -> int | None:
        """Find the line number of the first exported handler function."""
        if not content:
            return None

        # Look for exported handler functions
        for method in route.http_methods:
            pattern = rf'export\s+(?:async\s+)?function\s+{method}'
            match = re.search(pattern, content)
            if match:
                return find_line_number(content, match.start())

        # Fallback: first export
        match = re.search(r'export\s+', content)
        if match:
            return find_line_number(content, match.start())

        return 1
