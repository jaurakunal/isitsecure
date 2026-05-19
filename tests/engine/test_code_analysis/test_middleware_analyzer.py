"""Tests for MiddlewareAnalyzer."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.middleware_analyzer import (
    MiddlewareAnalyzer,
)
from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)
from isitsecure.engine.constants import MiddlewareAnalyzerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel

# ---------------------------------------------------------------------------
# Middleware content fixtures
# ---------------------------------------------------------------------------

MIDDLEWARE_WITH_MATCHER = """\
import { NextResponse } from 'next/server'
import { createMiddlewareClient } from '@supabase/auth-helpers-nextjs'

export async function middleware(request) {
    const supabase = createMiddlewareClient({ req: request })
    const { data: { session } } = await supabase.auth.getSession()

    if (!session) {
        return NextResponse.redirect(new URL('/login', request.url))
    }
    return NextResponse.next()
}

export const config = {
    matcher: ['/dashboard/:path*', '/api/protected/:path*']
}
"""

WEAK_MIDDLEWARE = """\
import { NextResponse } from 'next/server'

export async function middleware(request) {
    const token = request.cookies.has('auth_token')
    if (!token) {
        return NextResponse.redirect(new URL('/login', request.url))
    }
    return NextResponse.next()
}

export const config = {
    matcher: ['/dashboard/:path*']
}
"""

STRONG_MIDDLEWARE = """\
import { createMiddlewareClient } from '@supabase/auth-helpers-nextjs'
import { NextResponse } from 'next/server'

export async function middleware(request) {
    const supabase = createMiddlewareClient({ req: request })
    const { data: { user } } = await supabase.auth.getUser()
    if (!user) {
        return NextResponse.redirect(new URL('/login', request.url))
    }
    return NextResponse.next()
}

export const config = {
    matcher: ['/api/:path*', '/dashboard/:path*']
}
"""

SINGLE_STRING_MATCHER_MIDDLEWARE = """\
import { NextResponse } from 'next/server'

export async function middleware(request) {
    const { data: { user } } = await supabase.auth.getUser()
    if (!user) {
        return NextResponse.redirect(new URL('/login', request.url))
    }
    return NextResponse.next()
}

export const config = {
    matcher: '/api/:path*'
}
"""

MIDDLEWARE_WITH_LITERAL_MATCHER = """\
import { NextResponse } from 'next/server'

export async function middleware(request) {
    const { data: { user } } = await supabase.auth.getUser()
    if (!user) {
        return NextResponse.redirect(new URL('/login', request.url))
    }
    return NextResponse.next()
}

export const config = {
    matcher: ['/dashboard']
}
"""

SRC_MIDDLEWARE = """\
import { NextResponse } from 'next/server'
import { createServerClient } from '@supabase/ssr'

export async function middleware(request) {
    const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY, { cookies: {} })
    const { data: { user } } = await supabase.auth.getUser()
    if (!user) {
        return NextResponse.redirect(new URL('/login', request.url))
    }
    return NextResponse.next()
}

export const config = {
    matcher: ['/api/:path*']
}
"""


# ---------------------------------------------------------------------------
# Helper to build RepoSnapshot fixtures
# ---------------------------------------------------------------------------

def _make_repo(
    file_index: dict[str, str] | None = None,
    routes: list[RouteEntry] | None = None,
) -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        file_index=file_index or {},
        route_map=routes or [],
    )


def _make_route(pattern: str, file_path: str = "app/api/route.ts") -> RouteEntry:
    return RouteEntry(
        file_path=file_path,
        http_methods=["GET"],
        route_pattern=pattern,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMiddlewareAnalyzerScannerName:
    def test_scanner_name(self) -> None:
        analyzer = MiddlewareAnalyzer()
        assert analyzer.scanner_name == MiddlewareAnalyzerConfig.SCANNER_NAME


class TestNoMiddleware:
    @pytest.mark.asyncio
    async def test_no_middleware_with_routes_produces_finding(self) -> None:
        """No middleware file + existing routes -> HIGH finding."""
        repo = _make_repo(
            file_index={"app/api/users/route.ts": "export async function GET() {}"},
            routes=[_make_route("/api/users")],
        )
        analyzer = MiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == SeverityLevel.HIGH
        assert finding.category == FindingCategory.AUTH_WEAKNESS
        assert finding.title == MiddlewareAnalyzerConfig.TITLE_NO_MIDDLEWARE
        assert finding.confidence == MiddlewareAnalyzerConfig.CONFIDENCE_NO_MIDDLEWARE

    @pytest.mark.asyncio
    async def test_no_middleware_no_routes_no_finding(self) -> None:
        """No middleware and no routes -> don't flag."""
        repo = _make_repo(file_index={"package.json": "{}"})
        analyzer = MiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        assert len(findings) == 0


class TestUncoveredRoutes:
    @pytest.mark.asyncio
    async def test_detects_uncovered_route(self) -> None:
        """Route /api/users not in matcher -> MEDIUM finding."""
        repo = _make_repo(
            file_index={"middleware.ts": MIDDLEWARE_WITH_MATCHER},
            routes=[
                _make_route("/api/users", "app/api/users/route.ts"),
                _make_route("/api/protected/data", "app/api/protected/data/route.ts"),
            ],
        )
        analyzer = MiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        uncovered = [
            f for f in findings
            if f.title == MiddlewareAnalyzerConfig.TITLE_UNCOVERED_ROUTE
        ]
        assert len(uncovered) == 1
        assert "/api/users" in uncovered[0].description

    @pytest.mark.asyncio
    async def test_covered_route_no_finding(self) -> None:
        """Route /api/protected/data covered by /api/protected/:path* -> no uncovered finding."""
        repo = _make_repo(
            file_index={"middleware.ts": MIDDLEWARE_WITH_MATCHER},
            routes=[
                _make_route("/api/protected/data", "app/api/protected/data/route.ts"),
                _make_route("/dashboard/settings", "app/dashboard/settings/page.ts"),
            ],
        )
        analyzer = MiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        uncovered = [
            f for f in findings
            if f.title == MiddlewareAnalyzerConfig.TITLE_UNCOVERED_ROUTE
        ]
        assert len(uncovered) == 0


class TestWeakAuth:
    @pytest.mark.asyncio
    async def test_detects_weak_auth(self) -> None:
        """Middleware only checks cookie.has() -> weak auth finding."""
        repo = _make_repo(
            file_index={"middleware.ts": WEAK_MIDDLEWARE},
            routes=[_make_route("/dashboard/home")],
        )
        analyzer = MiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        weak = [
            f for f in findings
            if f.title == MiddlewareAnalyzerConfig.TITLE_WEAK_AUTH
        ]
        assert len(weak) == 1
        assert weak[0].severity == SeverityLevel.MEDIUM
        assert weak[0].confidence == MiddlewareAnalyzerConfig.CONFIDENCE_WEAK_AUTH

    @pytest.mark.asyncio
    async def test_no_weak_auth_for_strong_middleware(self) -> None:
        """Middleware with createMiddlewareClient/getUser -> no weak auth finding."""
        repo = _make_repo(
            file_index={"middleware.ts": STRONG_MIDDLEWARE},
            routes=[_make_route("/api/data")],
        )
        analyzer = MiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        weak = [
            f for f in findings
            if f.title == MiddlewareAnalyzerConfig.TITLE_WEAK_AUTH
        ]
        assert len(weak) == 0


class TestMatcherExtraction:
    def test_extract_matcher_patterns_array(self) -> None:
        """Should extract matcher array from config."""
        analyzer = MiddlewareAnalyzer()
        patterns = analyzer._extract_matcher_patterns(MIDDLEWARE_WITH_MATCHER)
        assert "/dashboard/:path*" in patterns
        assert "/api/protected/:path*" in patterns

    def test_extract_matcher_patterns_string(self) -> None:
        """Should handle single matcher string."""
        analyzer = MiddlewareAnalyzer()
        patterns = analyzer._extract_matcher_patterns(SINGLE_STRING_MATCHER_MIDDLEWARE)
        assert "/api/:path*" in patterns

    def test_extract_matcher_no_config(self) -> None:
        """Content without config export returns empty list."""
        analyzer = MiddlewareAnalyzer()
        patterns = analyzer._extract_matcher_patterns("export function middleware() {}")
        assert patterns == []


class TestRouteMatching:
    def test_route_matches_wildcard(self) -> None:
        """/api/anything should match /api/:path*."""
        analyzer = MiddlewareAnalyzer()
        assert analyzer._matches_pattern("/api/users", "/api/:path*") is True
        assert analyzer._matches_pattern("/api/users/123", "/api/:path*") is True

    def test_route_does_not_match(self) -> None:
        """/public should NOT match /api/:path*."""
        analyzer = MiddlewareAnalyzer()
        assert analyzer._matches_pattern("/public", "/api/:path*") is False

    def test_exact_match(self) -> None:
        """/dashboard should match /dashboard exactly."""
        analyzer = MiddlewareAnalyzer()
        assert analyzer._matches_pattern("/dashboard", "/dashboard") is True
        assert analyzer._matches_pattern("/dashboard/sub", "/dashboard") is False

    def test_wildcard_root_match(self) -> None:
        """/api base without sub-path should match /api/:path*."""
        analyzer = MiddlewareAnalyzer()
        # /api itself (no sub-path) should match /api/:path* because :path* is optional
        assert analyzer._matches_pattern("/api", "/api/:path*") is True

    def test_regex_style_matcher(self) -> None:
        """Regex-style matchers should be evaluated as regex."""
        analyzer = MiddlewareAnalyzer()
        # This regex matcher excludes api and _next paths
        assert analyzer._matches_pattern(
            "/api/test", "/((?!api|_next).*)",
        ) is False
        assert analyzer._matches_pattern(
            "/about", "/((?!api|_next).*)",
        ) is True


class TestMiddlewareInSrc:
    @pytest.mark.asyncio
    async def test_find_middleware_in_src(self) -> None:
        """Should find middleware at src/middleware.ts."""
        repo = _make_repo(
            file_index={"src/middleware.ts": SRC_MIDDLEWARE},
            routes=[_make_route("/api/data")],
        )
        analyzer = MiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        # Should NOT produce a "no middleware" finding
        no_mw = [
            f for f in findings
            if f.title == MiddlewareAnalyzerConfig.TITLE_NO_MIDDLEWARE
        ]
        assert len(no_mw) == 0


class TestBypassDetection:
    @pytest.mark.asyncio
    async def test_literal_matcher_trailing_slash_bypass(self) -> None:
        """Literal matcher '/dashboard' (no wildcard, no trailing /) -> bypass finding."""
        repo = _make_repo(
            file_index={"middleware.ts": MIDDLEWARE_WITH_LITERAL_MATCHER},
            routes=[_make_route("/dashboard")],
        )
        analyzer = MiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        bypass = [
            f for f in findings
            if f.title == MiddlewareAnalyzerConfig.TITLE_BYPASS_POSSIBLE
        ]
        assert len(bypass) >= 1
        assert any("trailing slash" in f.description.lower() for f in bypass)

    @pytest.mark.asyncio
    async def test_wildcard_matcher_no_trailing_slash_bypass(self) -> None:
        """Wildcard matcher '/api/:path*' should NOT trigger trailing-slash bypass."""
        repo = _make_repo(
            file_index={"middleware.ts": STRONG_MIDDLEWARE},
            routes=[_make_route("/api/data")],
        )
        analyzer = MiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        bypass = [
            f for f in findings
            if f.title == MiddlewareAnalyzerConfig.TITLE_BYPASS_POSSIBLE
        ]
        assert len(bypass) == 0


class TestMatcherToRegex:
    def test_simple_path(self) -> None:
        assert MiddlewareAnalyzer._matcher_to_regex("/api") == r"^/api$"

    def test_wildcard_path(self) -> None:
        regex = MiddlewareAnalyzer._matcher_to_regex("/api/:path*")
        assert regex == r"^/api(/.*)?$"
        # Verify it actually matches routes
        import re as _re
        assert _re.match(regex, "/api/users")
        assert _re.match(regex, "/api")

    def test_nested_wildcard(self) -> None:
        regex = MiddlewareAnalyzer._matcher_to_regex("/api/protected/:path*")
        assert regex == r"^/api/protected(/.*)?$"
        import re as _re
        assert _re.match(regex, "/api/protected/data")
