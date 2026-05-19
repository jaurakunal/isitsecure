"""Next.js middleware auth coverage analyzer.

Analyzes middleware.ts to determine:
1. Whether auth middleware exists at all
2. Which API routes are covered by the middleware matcher
3. Whether the middleware actually verifies auth tokens (not just cookie exists)
4. Whether the matcher pattern can be bypassed
"""

from __future__ import annotations

import logging
import re

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot, RouteEntry
from isitsecure.engine.constants import MiddlewareAnalyzerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class MiddlewareAnalyzer:
    """Analyzes Next.js middleware for auth coverage gaps.

    Implements CodeScannerProtocol.
    """

    @property
    def scanner_name(self) -> str:
        return MiddlewareAnalyzerConfig.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Analyze middleware coverage across all discovered routes.

        Monorepo-aware: skips the "no middleware found" finding when
        Express middleware files exist (handled by ExpressMiddlewareAnalyzer).
        """
        findings: list[CodeFinding] = []

        middleware_content, middleware_path = self._find_middleware(repo)

        if middleware_content is None:
            # Only flag missing middleware if there are routes AND no
            # Express middleware files exist (Express apps don't use
            # Next.js-style middleware.ts)
            if repo.route_map and not self._has_express_middleware(repo):
                findings.append(self._make_no_middleware_finding())
            return findings

        matchers = self._extract_matcher_patterns(middleware_content)

        if matchers:
            uncovered = self._find_uncovered_routes(repo.route_map, matchers)
            for route in uncovered:
                findings.append(self._make_uncovered_route_finding(
                    route, middleware_path,
                ))

        if self._has_weak_auth(middleware_content) and not self._has_strong_auth(
            middleware_content,
        ):
            findings.append(self._make_weak_auth_finding(middleware_path))

        bypass_findings = self._check_bypass_possibilities(matchers, middleware_path)
        findings.extend(bypass_findings)

        logger.info("MiddlewareAnalyzer: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Middleware discovery
    # ------------------------------------------------------------------

    def _find_middleware(self, repo: RepoSnapshot) -> tuple[str | None, str]:
        """Find the middleware file in the repo snapshot."""
        for mw_name in MiddlewareAnalyzerConfig.MIDDLEWARE_FILE_NAMES:
            for file_path in repo.file_index:
                if file_path == mw_name or file_path.endswith(f"/{mw_name}"):
                    return repo.file_index[file_path], file_path
        return None, ""

    @staticmethod
    def _has_express_middleware(repo: RepoSnapshot) -> bool:
        """Check if the repo has Express-style middleware files.

        When Express middleware exists, the ExpressMiddlewareAnalyzer
        handles auth coverage — this scanner should not duplicate
        with a false "no middleware found" finding.
        """
        express_mw_dirs = ("middleware/", "middlewares/")
        for file_path, content in repo.file_index.items():
            if any(d in file_path for d in express_mw_dirs):
                # Verify it's actually Express middleware (not just any file in a middleware dir)
                if "express" in content or "req, res, next" in content:
                    return True
        return False

    # ------------------------------------------------------------------
    # Matcher extraction
    # ------------------------------------------------------------------

    def _extract_matcher_patterns(self, content: str) -> list[str]:
        """Extract matcher patterns from the middleware config export.

        Handles both array and single-string matcher declarations:
          - ``matcher: ['/api/:path*', '/dashboard/:path*']``
          - ``matcher: '/api/:path*'``
        """
        match = re.search(
            MiddlewareAnalyzerConfig.MATCHER_CONFIG_PATTERN, content, re.DOTALL,
        )
        if not match:
            return []

        raw = match.group(1)
        strings = re.findall(MiddlewareAnalyzerConfig.MATCHER_STRING_PATTERN, raw)
        return strings

    # ------------------------------------------------------------------
    # Route coverage analysis
    # ------------------------------------------------------------------

    def _find_uncovered_routes(
        self, routes: list[RouteEntry], matchers: list[str],
    ) -> list[RouteEntry]:
        """Return API routes not covered by any middleware matcher."""
        return [
            route for route in routes
            if not self._route_matches_any(route.route_pattern, matchers)
        ]

    def _route_matches_any(self, route_pattern: str, matchers: list[str]) -> bool:
        """Check if a route matches at least one middleware matcher pattern."""
        return any(
            self._matches_pattern(route_pattern, matcher)
            for matcher in matchers
        )

    def _matches_pattern(self, route: str, matcher: str) -> bool:
        """Match a route against a single Next.js matcher pattern.

        Supports:
          - ``:path*`` wildcard segments  (``/api/:path*`` matches ``/api/users``)
          - Regex-style matchers           (``/((?!api|_next).*)`` )
          - Literal path prefixes
        """
        # Handle regex-style matchers: /(regex)
        if matcher.startswith("/(") and matcher.endswith(")"):
            regex_body = matcher[1:]  # Strip leading /
            # Next.js applies the regex to the path after the leading /
            route_without_slash = route[1:] if route.startswith("/") else route
            try:
                return bool(re.match(regex_body, route_without_slash))
            except re.error:
                return False

        # Convert Next.js :param* syntax to a regex
        # /api/:path* → ^/api(/.*)?$
        regex = self._matcher_to_regex(matcher)
        return bool(re.match(regex, route))

    @staticmethod
    def _matcher_to_regex(matcher: str) -> str:
        """Convert a Next.js matcher pattern to a Python regex string.

        ``/api/:path*``  → ``^/api(/.*)?$``
        ``/dashboard``   → ``^/dashboard$``
        """
        # Replace /:param* with a wildcard placeholder (consuming the /)
        converted = re.sub(r"/:[a-zA-Z_]+\*", "__WILDCARD__", matcher)
        # Escape remaining regex-special chars
        converted = re.escape(converted)
        # Restore wildcard: matches optional / followed by anything
        converted = converted.replace("__WILDCARD__", "(/.*)?")
        return f"^{converted}$"

    # ------------------------------------------------------------------
    # Auth quality checks
    # ------------------------------------------------------------------

    def _has_weak_auth(self, content: str) -> bool:
        """Check if middleware contains weak auth patterns (cookie-exists only)."""
        return any(
            re.search(pattern, content, re.MULTILINE)
            for pattern in MiddlewareAnalyzerConfig.WEAK_AUTH_PATTERNS
        )

    def _has_strong_auth(self, content: str) -> bool:
        """Check if middleware properly verifies auth tokens/sessions."""
        return any(
            re.search(pattern, content)
            for pattern in MiddlewareAnalyzerConfig.MIDDLEWARE_AUTH_PATTERNS
        )

    # ------------------------------------------------------------------
    # Bypass analysis
    # ------------------------------------------------------------------

    def _check_bypass_possibilities(
        self, matchers: list[str], file_path: str,
    ) -> list[CodeFinding]:
        """Check whether matcher patterns can be bypassed."""
        findings: list[CodeFinding] = []

        for matcher in matchers:
            # Skip regex-style matchers — they have their own semantics
            if matcher.startswith("/("):
                continue

            if MiddlewareAnalyzerConfig.BYPASS_TRAILING_SLASH:
                if not matcher.endswith("*") and not matcher.endswith("/"):
                    findings.append(self._make_bypass_finding(
                        matcher,
                        file_path,
                        MiddlewareAnalyzerConfig.BYPASS_TRAILING_SLASH_DETAIL.format(
                            route=matcher,
                        ),
                    ))

            if MiddlewareAnalyzerConfig.BYPASS_CASE_SENSITIVITY:
                if re.search(r"/[a-z]", matcher) and ":path*" not in matcher:
                    findings.append(self._make_bypass_finding(
                        matcher,
                        file_path,
                        MiddlewareAnalyzerConfig.BYPASS_CASE_SENSITIVITY_DETAIL,
                    ))

        return findings

    # ------------------------------------------------------------------
    # Finding factories
    # ------------------------------------------------------------------

    def _make_no_middleware_finding(self) -> CodeFinding:
        return CodeFinding(
            scanner_name=self.scanner_name,
            severity=SeverityLevel.HIGH,
            category=FindingCategory.AUTH_WEAKNESS,
            title=MiddlewareAnalyzerConfig.TITLE_NO_MIDDLEWARE,
            description=MiddlewareAnalyzerConfig.DESC_NO_MIDDLEWARE,
            file_path="middleware.ts",
            confidence=MiddlewareAnalyzerConfig.CONFIDENCE_NO_MIDDLEWARE,
        )

    def _make_uncovered_route_finding(
        self, route: RouteEntry, middleware_path: str,
    ) -> CodeFinding:
        return CodeFinding(
            scanner_name=self.scanner_name,
            severity=SeverityLevel.MEDIUM,
            category=FindingCategory.AUTH_WEAKNESS,
            title=MiddlewareAnalyzerConfig.TITLE_UNCOVERED_ROUTE,
            description=MiddlewareAnalyzerConfig.DESC_UNCOVERED_ROUTE.format(
                route=route.route_pattern, file=route.file_path,
            ),
            file_path=middleware_path,
            confidence=MiddlewareAnalyzerConfig.CONFIDENCE_UNCOVERED_ROUTE,
        )

    def _make_weak_auth_finding(self, middleware_path: str) -> CodeFinding:
        return CodeFinding(
            scanner_name=self.scanner_name,
            severity=SeverityLevel.MEDIUM,
            category=FindingCategory.AUTH_WEAKNESS,
            title=MiddlewareAnalyzerConfig.TITLE_WEAK_AUTH,
            description=MiddlewareAnalyzerConfig.DESC_WEAK_AUTH,
            file_path=middleware_path,
            confidence=MiddlewareAnalyzerConfig.CONFIDENCE_WEAK_AUTH,
        )

    def _make_bypass_finding(
        self, matcher: str, file_path: str, bypass_detail: str,
    ) -> CodeFinding:
        return CodeFinding(
            scanner_name=self.scanner_name,
            severity=SeverityLevel.LOW,
            category=FindingCategory.AUTH_WEAKNESS,
            title=MiddlewareAnalyzerConfig.TITLE_BYPASS_POSSIBLE,
            description=MiddlewareAnalyzerConfig.DESC_BYPASS_POSSIBLE.format(
                matcher=matcher, bypass_detail=bypass_detail,
            ),
            file_path=file_path,
            confidence=MiddlewareAnalyzerConfig.CONFIDENCE_BYPASS_POSSIBLE,
        )
