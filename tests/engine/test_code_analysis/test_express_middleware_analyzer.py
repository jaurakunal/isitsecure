"""Tests for ExpressMiddlewareAnalyzer."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.express_middleware_analyzer import (
    ExpressMiddlewareAnalyzer,
)
from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)
from isitsecure.engine.constants import ExpressMiddlewareAnalyzerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Content fixtures
# ---------------------------------------------------------------------------

EXPRESS_APP_BASIC = """\
const express = require('express');
const app = express();

app.get('/api/users', (req, res) => {
    res.json({ users: [] });
});

app.listen(3000);
"""

STRONG_AUTH_MIDDLEWARE = """\
const { createClient } = require('@supabase/supabase-js');

module.exports = async function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split('Bearer ')[1];
    const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
    const { data: { user } } = await supabase.auth.getUser(token);
    if (!user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    req.user = user;
    next();
};
"""

WEAK_AUTH_MIDDLEWARE = """\
module.exports = function authMiddleware(req, res, next) {
    if (!req.cookies.auth_token) {
        return res.status(401).json({ error: 'No token' });
    }
    next();
};
"""

IN_MEMORY_RATE_LIMIT_MIDDLEWARE = """\
const rateLimits = new Map();

function rateLimit(req, res, next) {
    const ip = req.ip;
    const now = Date.now();
    const count = rateLimits.get(ip) || 0;
    if (count > 100) {
        return res.status(429).json({ error: 'Too many requests' });
    }
    rateLimits.set(ip, count + 1);
    next();
}

module.exports = rateLimit;
"""

HELMET_MIDDLEWARE = """\
const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(helmet());
app.listen(3000);
"""

CORS_WILDCARD_WITH_CREDENTIALS = """\
const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors({
    origin: '*',
    credentials: true
}));

app.listen(3000);
"""

MULTI_TENANT_APP_NO_MIDDLEWARE = """\
const express = require('express');
const app = express();

// tenant tables and IDs used throughout
const tenants = db.query('SELECT * FROM tenants');
const tenant_id = req.params.tenantId;

app.listen(3000);
"""

MULTI_TENANT_APP_WITH_MIDDLEWARE = """\
const express = require('express');
const app = express();

// tenant tables and IDs used throughout
const tenants = db.query('SELECT * FROM tenants');
const tenant_id = req.params.tenantId;

function requireTenant(req, res, next) {
    if (!req.tenantId) {
        return res.status(403).json({ error: 'No tenant' });
    }
    next();
}

app.listen(3000);
"""


# ---------------------------------------------------------------------------
# Helper to build RepoSnapshot fixtures
# ---------------------------------------------------------------------------

def _make_repo(
    file_index: dict[str, str] | None = None,
    routes: list[RouteEntry] | None = None,
    package_json: dict | None = None,
) -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        file_index=file_index or {},
        route_map=routes or [],
        package_json=package_json or {},
    )


def _make_route(
    pattern: str,
    file_path: str = "src/routes/users.js",
    has_auth_check: bool | None = None,
    http_methods: list[str] | None = None,
) -> RouteEntry:
    return RouteEntry(
        file_path=file_path,
        http_methods=http_methods or ["GET"],
        route_pattern=pattern,
        has_auth_check=has_auth_check,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScannerName:
    def test_scanner_name(self) -> None:
        analyzer = ExpressMiddlewareAnalyzer()
        assert analyzer.scanner_name == ExpressMiddlewareAnalyzerConfig.SCANNER_NAME


class TestNonExpressCodebase:
    @pytest.mark.asyncio
    async def test_returns_empty_for_non_express_code(self) -> None:
        """Non-Express codebase should produce no findings."""
        repo = _make_repo(
            file_index={
                "src/index.ts": "console.log('hello world');",
                "package.json": '{"name": "my-app"}',
            }
        )
        analyzer = ExpressMiddlewareAnalyzer()
        findings = await analyzer.scan(repo)
        assert len(findings) == 0


class TestNoAuthMiddleware:
    @pytest.mark.asyncio
    async def test_flags_when_no_auth_verification_found(self) -> None:
        """Express app with routes but no auth middleware -> finding."""
        repo = _make_repo(
            file_index={
                "src/app.js": EXPRESS_APP_BASIC,
            },
            routes=[
                _make_route("/api/users", "src/routes/users.js"),
            ],
        )
        analyzer = ExpressMiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        no_auth = [
            f for f in findings
            if f.title == ExpressMiddlewareAnalyzerConfig.TITLE_NO_AUTH_MIDDLEWARE
        ]
        assert len(no_auth) == 1
        assert no_auth[0].severity == SeverityLevel.HIGH
        assert no_auth[0].category == FindingCategory.AUTH_WEAKNESS
        assert no_auth[0].confidence == ExpressMiddlewareAnalyzerConfig.CONFIDENCE_NO_AUTH_MIDDLEWARE


class TestStrongAuth:
    @pytest.mark.asyncio
    async def test_no_finding_when_supabase_get_user_present(self) -> None:
        """supabase.auth.getUser() is strong auth -> no auth weakness finding."""
        repo = _make_repo(
            file_index={
                "src/app.js": EXPRESS_APP_BASIC,
                "src/middleware/auth.js": STRONG_AUTH_MIDDLEWARE,
            },
            routes=[
                _make_route("/api/users", "src/routes/users.js"),
            ],
        )
        analyzer = ExpressMiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        no_auth = [
            f for f in findings
            if f.title == ExpressMiddlewareAnalyzerConfig.TITLE_NO_AUTH_MIDDLEWARE
        ]
        assert len(no_auth) == 0

        weak_auth = [
            f for f in findings
            if f.title == ExpressMiddlewareAnalyzerConfig.TITLE_WEAK_AUTH
        ]
        assert len(weak_auth) == 0


class TestWeakAuth:
    @pytest.mark.asyncio
    async def test_flags_when_only_cookie_existence_checked(self) -> None:
        """Middleware checking cookie presence only -> weak auth finding."""
        repo = _make_repo(
            file_index={
                "src/app.js": EXPRESS_APP_BASIC,
                "src/middleware/auth.js": WEAK_AUTH_MIDDLEWARE,
            },
            routes=[
                _make_route("/api/users", "src/routes/users.js"),
            ],
        )
        analyzer = ExpressMiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        weak = [
            f for f in findings
            if f.title == ExpressMiddlewareAnalyzerConfig.TITLE_WEAK_AUTH
        ]
        assert len(weak) == 1
        assert weak[0].severity == SeverityLevel.HIGH
        assert weak[0].confidence == ExpressMiddlewareAnalyzerConfig.CONFIDENCE_WEAK_AUTH


class TestRouteWithoutAuth:
    @pytest.mark.asyncio
    async def test_flags_sensitive_route_without_auth(self) -> None:
        """Sensitive Express route without has_auth_check -> finding."""
        repo = _make_repo(
            file_index={
                "src/app.js": EXPRESS_APP_BASIC,
                "src/middleware/auth.js": STRONG_AUTH_MIDDLEWARE,
            },
            routes=[
                _make_route(
                    "/api/users",
                    "src/routes/users.js",
                    has_auth_check=False,
                ),
            ],
        )
        analyzer = ExpressMiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        route_no_auth = [
            f for f in findings
            if "has no auth middleware" in f.title
        ]
        assert len(route_no_auth) >= 1
        assert route_no_auth[0].severity == SeverityLevel.MEDIUM
        assert route_no_auth[0].confidence == ExpressMiddlewareAnalyzerConfig.CONFIDENCE_ROUTE_UNPROTECTED


class TestRouteWithAuth:
    @pytest.mark.asyncio
    async def test_no_finding_when_route_has_auth_check(self) -> None:
        """Route with has_auth_check=True -> no finding."""
        repo = _make_repo(
            file_index={
                "src/app.js": EXPRESS_APP_BASIC,
                "src/middleware/auth.js": STRONG_AUTH_MIDDLEWARE,
            },
            routes=[
                _make_route(
                    "/api/users",
                    "src/routes/users.js",
                    has_auth_check=True,
                ),
            ],
        )
        analyzer = ExpressMiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        route_no_auth = [
            f for f in findings
            if "has no auth middleware" in f.title
        ]
        assert len(route_no_auth) == 0


class TestPublicRoute:
    @pytest.mark.asyncio
    async def test_skips_health_ping_status_routes(self) -> None:
        """Public routes (/health, /ping, /status) should not be flagged."""
        repo = _make_repo(
            file_index={
                "src/app.js": EXPRESS_APP_BASIC,
                "src/middleware/auth.js": STRONG_AUTH_MIDDLEWARE,
            },
            routes=[
                _make_route("/health", "src/routes/health.js", has_auth_check=False),
                _make_route("/ping", "src/routes/ping.js", has_auth_check=False),
                _make_route("/status", "src/routes/status.js", has_auth_check=False),
            ],
        )
        analyzer = ExpressMiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        route_no_auth = [
            f for f in findings
            if "has no auth middleware" in f.title
        ]
        assert len(route_no_auth) == 0


class TestInMemoryRateLimit:
    @pytest.mark.asyncio
    async def test_flags_map_based_rate_limiter(self) -> None:
        """Rate limiter using new Map() -> in-memory rate limit finding."""
        repo = _make_repo(
            file_index={
                "src/app.js": EXPRESS_APP_BASIC,
                "src/middleware/rateLimit.js": IN_MEMORY_RATE_LIMIT_MIDDLEWARE,
            },
        )
        analyzer = ExpressMiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        in_mem = [
            f for f in findings
            if f.title == ExpressMiddlewareAnalyzerConfig.TITLE_IN_MEMORY_RATE_LIMIT
        ]
        assert len(in_mem) == 1
        assert in_mem[0].severity == SeverityLevel.MEDIUM
        assert in_mem[0].confidence == ExpressMiddlewareAnalyzerConfig.CONFIDENCE_IN_MEMORY_RATE_LIMIT


class TestNoRateLimit:
    @pytest.mark.asyncio
    async def test_flags_when_no_rate_limiting_found(self) -> None:
        """Express app with no rate limiting patterns -> finding."""
        repo = _make_repo(
            file_index={
                "src/app.js": EXPRESS_APP_BASIC,
            },
        )
        analyzer = ExpressMiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        no_rl = [
            f for f in findings
            if f.title == ExpressMiddlewareAnalyzerConfig.TITLE_NO_RATE_LIMIT
        ]
        assert len(no_rl) == 1
        assert no_rl[0].severity == SeverityLevel.MEDIUM
        assert no_rl[0].confidence == ExpressMiddlewareAnalyzerConfig.CONFIDENCE_NO_RATE_LIMIT


class TestMissingSecurityHeaders:
    @pytest.mark.asyncio
    async def test_flags_missing_hsts_when_no_helmet(self) -> None:
        """No helmet and no manual headers -> missing header findings."""
        repo = _make_repo(
            file_index={
                "src/app.js": EXPRESS_APP_BASIC,
            },
        )
        analyzer = ExpressMiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        header_findings = [
            f for f in findings
            if f.category == FindingCategory.MISSING_HEADERS
        ]
        assert len(header_findings) >= 1
        assert header_findings[0].severity == SeverityLevel.LOW
        assert header_findings[0].confidence == ExpressMiddlewareAnalyzerConfig.CONFIDENCE_MISSING_SECURITY_HEADERS

        # Should flag all recommended headers
        header_titles = {f.title for f in header_findings}
        for header in ExpressMiddlewareAnalyzerConfig.RECOMMENDED_SECURITY_HEADERS:
            expected_title = ExpressMiddlewareAnalyzerConfig.TITLE_MISSING_SECURITY_HEADERS.format(
                header=header
            )
            assert expected_title in header_titles


class TestHelmetPresent:
    @pytest.mark.asyncio
    async def test_no_finding_when_helmet_imported(self) -> None:
        """helmet present -> no missing header findings."""
        repo = _make_repo(
            file_index={
                "src/app.js": HELMET_MIDDLEWARE,
            },
        )
        analyzer = ExpressMiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        header_findings = [
            f for f in findings
            if f.category == FindingCategory.MISSING_HEADERS
        ]
        assert len(header_findings) == 0


class TestCorsWildcard:
    @pytest.mark.asyncio
    async def test_flags_wildcard_origin_with_credentials(self) -> None:
        """origin: '*' with credentials: true -> CORS finding."""
        repo = _make_repo(
            file_index={
                "src/app.js": CORS_WILDCARD_WITH_CREDENTIALS,
            },
        )
        analyzer = ExpressMiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        cors = [
            f for f in findings
            if f.title == ExpressMiddlewareAnalyzerConfig.TITLE_CORS_WILDCARD
        ]
        assert len(cors) == 1
        assert cors[0].severity == SeverityLevel.HIGH
        assert cors[0].category == FindingCategory.CORS_MISCONFIGURATION
        assert cors[0].confidence == ExpressMiddlewareAnalyzerConfig.CONFIDENCE_CORS_WILDCARD


class TestTenantIsolation:
    @pytest.mark.asyncio
    async def test_flags_multi_tenant_without_tenant_middleware(self) -> None:
        """Multi-tenant app without tenant isolation middleware -> finding."""
        repo = _make_repo(
            file_index={
                "src/app.js": MULTI_TENANT_APP_NO_MIDDLEWARE,
            },
        )
        analyzer = ExpressMiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        tenant = [
            f for f in findings
            if f.title == ExpressMiddlewareAnalyzerConfig.TITLE_NO_TENANT_ISOLATION
        ]
        assert len(tenant) == 1
        assert tenant[0].severity == SeverityLevel.HIGH
        assert tenant[0].confidence == ExpressMiddlewareAnalyzerConfig.CONFIDENCE_NO_TENANT_ISOLATION

    @pytest.mark.asyncio
    async def test_no_finding_when_tenant_middleware_present(self) -> None:
        """Multi-tenant app with requireTenant -> no finding."""
        repo = _make_repo(
            file_index={
                "src/app.js": MULTI_TENANT_APP_WITH_MIDDLEWARE,
            },
        )
        analyzer = ExpressMiddlewareAnalyzer()
        findings = await analyzer.scan(repo)

        tenant = [
            f for f in findings
            if f.title == ExpressMiddlewareAnalyzerConfig.TITLE_NO_TENANT_ISOLATION
        ]
        assert len(tenant) == 0
