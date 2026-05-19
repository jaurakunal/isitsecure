"""Tests for AuthFlowTracer — LSP-powered auth flow tracing.

Uses a mocked ``LSPClientProtocol`` to verify that the tracer correctly
identifies tRPC, Express, and inline auth patterns, and degrades
gracefully when the LSP client is unavailable.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, PropertyMock

import pytest

from isitsecure.engine.code_analysis.lsp.auth_flow_tracer import (
    AuthFlowTracer,
)
from isitsecure.engine.code_analysis.lsp.protocols import (
    LSPLocation,
)
from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_repo(
    file_index: dict[str, str] | None = None,
    route_map: list[RouteEntry] | None = None,
) -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="test",
        branch="main",
        clone_path="/tmp/test",
        file_index=file_index or {},
        route_map=route_map or [],
    )


def _make_route(file_path: str, pattern: str = "/api/test") -> RouteEntry:
    return RouteEntry(
        file_path=file_path,
        http_methods=["GET"],
        route_pattern=pattern,
    )


def _make_lsp(*, available: bool = True) -> AsyncMock:
    """Create a mock LSP client conforming to LSPClientProtocol."""
    lsp = AsyncMock()
    type(lsp).is_available = PropertyMock(return_value=available)
    lsp.initialize.return_value = available
    lsp.get_definition.return_value = None
    lsp.get_references.return_value = None
    lsp.get_hover.return_value = None
    return lsp


# ===========================================================================
# TestAuthFlowTracerBasic
# ===========================================================================


class TestAuthFlowTracerBasic:
    """Basic trace_routes behavior."""

    @pytest.mark.asyncio
    async def test_empty_routes_returns_empty(self) -> None:
        lsp = _make_lsp()
        repo = _make_repo()
        tracer = AuthFlowTracer(lsp, repo)

        results = await tracer.trace_routes([])
        assert results == {}

    @pytest.mark.asyncio
    async def test_deduplicates_by_file(self) -> None:
        """Two routes from the same file should produce one trace call."""
        file_content = "export const handler = () => {};"
        repo = _make_repo(file_index={"src/routes/api.ts": file_content})
        lsp = _make_lsp()
        tracer = AuthFlowTracer(lsp, repo)

        routes = [
            _make_route("src/routes/api.ts", "/api/users"),
            _make_route("src/routes/api.ts", "/api/posts"),
        ]

        results = await tracer.trace_routes(routes)

        # Both routes should have results (mapped from the single file trace)
        assert len(results) == 2
        assert "src/routes/api.ts:/api/users" in results
        assert "src/routes/api.ts:/api/posts" in results

        # Both should share the same result (same file traced once)
        r1 = results["src/routes/api.ts:/api/users"]
        r2 = results["src/routes/api.ts:/api/posts"]
        assert r1.confidence == r2.confidence


# ===========================================================================
# TestTRPCTracing
# ===========================================================================


class TestTRPCTracing:
    """tRPC procedure base detection (Strategy 1)."""

    @pytest.mark.asyncio
    async def test_detects_protected_procedure(self) -> None:
        """File containing protectedProcedure with LSP returning a definition
        that contains enforcement patterns should yield has_verified_auth=True."""
        trpc_router = (
            "import { protectedProcedure } from '../trpc';\n"
            "export const userRouter = router({\n"
            "  getProfile: protectedProcedure.query(async ({ ctx }) => {\n"
            "    return ctx.db.user.findUnique({ where: { id: ctx.user.id } });\n"
            "  }),\n"
            "});\n"
        )
        # The definition that LSP would trace to
        trpc_middleware = (
            "export const protectedProcedure = t.procedure.use(async ({ ctx, next }) => {\n"
            "  if (!ctx.session?.user) {\n"
            "    throw new TRPCError({ code: 'UNAUTHORIZED' });\n"
            "  }\n"
            "  return next({ ctx: { user: ctx.session.user } });\n"
            "});\n"
        )

        repo = _make_repo(
            file_index={
                "src/server/routers/user.ts": trpc_router,
                "src/server/trpc.ts": trpc_middleware,
            }
        )
        lsp = _make_lsp()
        # LSP traces protectedProcedure to the middleware definition file
        lsp.get_definition.return_value = [
            LSPLocation(file_path="/tmp/test/src/server/trpc.ts", line=0, character=0)
        ]

        tracer = AuthFlowTracer(lsp, repo)
        routes = [_make_route("src/server/routers/user.ts", "/api/user.getProfile")]

        results = await tracer.trace_routes(routes)
        result = results["src/server/routers/user.ts:/api/user.getProfile"]

        assert result.has_verified_auth is True
        assert result.confidence == 0.95
        assert "protectedProcedure" in result.middleware_chain

    @pytest.mark.asyncio
    async def test_detects_public_procedure(self) -> None:
        """File containing only publicProcedure (no auth) falls through to
        the fallback result because _trace_file only returns strategy results
        when has_verified_auth is True."""
        trpc_public = (
            "import { publicProcedure } from '../trpc';\n"
            "export const healthRouter = router({\n"
            "  check: publicProcedure.query(() => 'ok'),\n"
            "});\n"
        )

        repo = _make_repo(
            file_index={"src/server/routers/health.ts": trpc_public}
        )
        lsp = _make_lsp()
        tracer = AuthFlowTracer(lsp, repo)

        routes = [_make_route("src/server/routers/health.ts", "/api/health.check")]
        results = await tracer.trace_routes(routes)
        result = results["src/server/routers/health.ts:/api/health.check"]

        # Public procedures have no verified auth -- the tracer's _trace_file
        # only keeps results where has_verified_auth is True, so this falls
        # through to the default fallback with confidence 0.5.
        assert result.has_verified_auth is False
        assert result.confidence == 0.5

    @pytest.mark.asyncio
    async def test_traces_procedure_definition(self) -> None:
        """When LSP returns a definition location, the tracer reads that file
        and checks for auth terminal patterns."""
        router_content = (
            "const getUser = protectedProcedure.query(async ({ ctx }) => {\n"
            "  return ctx.user;\n"
            "});\n"
        )
        definition_content = (
            "export const protectedProcedure = t.procedure.use(async ({ ctx, next }) => {\n"
            "  const { data: { user } } = await supabase.auth.getUser();\n"
            "  if (!user) throw new TRPCError({ code: 'UNAUTHORIZED' });\n"
            "  return next({ ctx: { user } });\n"
            "});\n"
        )

        repo = _make_repo(
            file_index={
                "src/router.ts": router_content,
                "src/trpc.ts": definition_content,
            }
        )
        lsp = _make_lsp()
        lsp.get_definition.return_value = [
            LSPLocation(file_path="/tmp/test/src/trpc.ts", line=0, character=0)
        ]

        tracer = AuthFlowTracer(lsp, repo)
        routes = [_make_route("src/router.ts")]
        results = await tracer.trace_routes(routes)
        result = results["src/router.ts:/api/test"]

        assert result.has_verified_auth is True
        assert "getUser" in result.auth_method


# ===========================================================================
# TestExpressTracing
# ===========================================================================


class TestExpressTracing:
    """Express middleware detection (Strategy 2)."""

    @pytest.mark.asyncio
    async def test_detects_require_auth(self) -> None:
        """File with requireAuth middleware traced to a getUser call."""
        express_route = (
            "import { requireAuth } from '../middleware/auth';\n"
            "router.get('/profile', requireAuth, handler);\n"
        )
        auth_middleware = (
            "export async function requireAuth(req, res, next) {\n"
            "  const { data: { user } } = await supabase.auth.getUser();\n"
            "  if (!user) return res.status(401).json({ error: 'Unauthorized' });\n"
            "  req.user = user;\n"
            "  next();\n"
            "}\n"
        )

        repo = _make_repo(
            file_index={
                "src/routes/profile.ts": express_route,
                "src/middleware/auth.ts": auth_middleware,
            }
        )
        lsp = _make_lsp()
        lsp.get_definition.return_value = [
            LSPLocation(
                file_path="/tmp/test/src/middleware/auth.ts", line=0, character=0
            )
        ]

        tracer = AuthFlowTracer(lsp, repo)
        routes = [_make_route("src/routes/profile.ts", "/profile")]
        results = await tracer.trace_routes(routes)
        result = results["src/routes/profile.ts:/profile"]

        assert result.has_verified_auth is True
        assert "requireAuth" in result.middleware_chain

    @pytest.mark.asyncio
    async def test_detects_verify_auth(self) -> None:
        """File with verifyAuth middleware and enforcement pattern."""
        express_route = (
            "import { verifyAuth } from '../middleware';\n"
            "router.post('/data', verifyAuth, createData);\n"
        )
        auth_middleware = (
            "export function verifyAuth(req, res, next) {\n"
            "  const token = req.headers.authorization;\n"
            "  if (!token) return res.status(401).json({ error: 'No token' });\n"
            "  jwt.verify(token, SECRET, (err, decoded) => {\n"
            "    if (err) return res.status(401).json({ error: 'Invalid' });\n"
            "    req.user = decoded;\n"
            "    next();\n"
            "  });\n"
            "}\n"
        )

        repo = _make_repo(
            file_index={
                "src/routes/data.ts": express_route,
                "src/middleware.ts": auth_middleware,
            }
        )
        lsp = _make_lsp()
        lsp.get_definition.return_value = [
            LSPLocation(
                file_path="/tmp/test/src/middleware.ts", line=0, character=0
            )
        ]

        tracer = AuthFlowTracer(lsp, repo)
        routes = [_make_route("src/routes/data.ts", "/data")]
        results = await tracer.trace_routes(routes)
        result = results["src/routes/data.ts:/data"]

        assert result.has_verified_auth is True
        assert "verifyAuth" in result.middleware_chain

    @pytest.mark.asyncio
    async def test_no_auth_middleware(self) -> None:
        """File with no auth patterns yields no verified auth."""
        plain_route = (
            "router.get('/health', (req, res) => {\n"
            "  res.json({ status: 'ok' });\n"
            "});\n"
        )

        repo = _make_repo(file_index={"src/routes/health.ts": plain_route})
        lsp = _make_lsp()
        tracer = AuthFlowTracer(lsp, repo)

        routes = [_make_route("src/routes/health.ts", "/health")]
        results = await tracer.trace_routes(routes)
        result = results["src/routes/health.ts:/health"]

        assert result.has_verified_auth is False
        assert result.confidence == 0.5  # fallback confidence


# ===========================================================================
# TestInlineTracing
# ===========================================================================


class TestDecoratorTracing:
    """Auth decorator detection (Strategy 3)."""

    @pytest.mark.asyncio
    async def test_detects_nestjs_use_guards(self) -> None:
        """File with @UseGuards(AuthGuard) should be detected."""
        nestjs_controller = (
            "import { Controller, Get, UseGuards } from '@nestjs/common';\n"
            "import { AuthGuard } from '../guards/auth.guard';\n"
            "\n"
            "@Controller('users')\n"
            "export class UsersController {\n"
            "  @Get()\n"
            "  @UseGuards(AuthGuard)\n"
            "  findAll() { return this.usersService.findAll(); }\n"
            "}\n"
        )

        repo = _make_repo(
            file_index={"src/users/users.controller.ts": nestjs_controller}
        )
        lsp = _make_lsp()
        tracer = AuthFlowTracer(lsp, repo)

        routes = [_make_route("src/users/users.controller.ts", "/users")]
        results = await tracer.trace_routes(routes)
        result = results["src/users/users.controller.ts:/users"]

        assert result.has_verified_auth is True
        assert "UseGuards" in result.auth_method
        assert "decorator" in result.middleware_chain

    @pytest.mark.asyncio
    async def test_detects_python_login_required(self) -> None:
        """File with @login_required should be detected."""
        django_view = (
            "from django.contrib.auth.decorators import login_required\n"
            "\n"
            "@login_required\n"
            "def profile(request):\n"
            "    return render(request, 'profile.html')\n"
        )

        repo = _make_repo(
            file_index={"views/profile.py": django_view}
        )
        lsp = _make_lsp()
        tracer = AuthFlowTracer(lsp, repo)

        routes = [_make_route("views/profile.py", "/profile")]
        results = await tracer.trace_routes(routes)
        result = results["views/profile.py:/profile"]

        assert result.has_verified_auth is True
        assert "login_required" in result.auth_method

    @pytest.mark.asyncio
    async def test_detects_spring_pre_authorize(self) -> None:
        """File with @PreAuthorize should be detected."""
        spring_controller = (
            "@RestController\n"
            "public class UserController {\n"
            "    @GetMapping(\"/admin\")\n"
            "    @PreAuthorize(\"hasRole('ADMIN')\")\n"
            "    public ResponseEntity<List<User>> getAll() {\n"
            "        return ResponseEntity.ok(userService.findAll());\n"
            "    }\n"
            "}\n"
        )

        repo = _make_repo(
            file_index={"src/controllers/UserController.java": spring_controller}
        )
        lsp = _make_lsp()
        tracer = AuthFlowTracer(lsp, repo)

        routes = [_make_route("src/controllers/UserController.java", "/admin")]
        results = await tracer.trace_routes(routes)
        result = results["src/controllers/UserController.java:/admin"]

        assert result.has_verified_auth is True
        assert "PreAuthorize" in result.auth_method

    @pytest.mark.asyncio
    async def test_no_decorator_falls_through(self) -> None:
        """File without decorators should not match this strategy."""
        plain_handler = (
            "export async function handler(req, res) {\n"
            "  res.json({ status: 'ok' });\n"
            "}\n"
        )

        repo = _make_repo(
            file_index={"src/handlers/health.ts": plain_handler}
        )
        lsp = _make_lsp()
        tracer = AuthFlowTracer(lsp, repo)

        routes = [_make_route("src/handlers/health.ts", "/health")]
        results = await tracer.trace_routes(routes)
        result = results["src/handlers/health.ts:/health"]

        assert result.has_verified_auth is False
        assert result.confidence == 0.5


class TestCJSImportFallback:
    """CJS require() fallback for procedure base detection."""

    @pytest.mark.asyncio
    async def test_detects_cjs_require_protected_procedure(self) -> None:
        """File using require() to import protectedProcedure should be detected."""
        cjs_router = (
            "const { protectedProcedure, router } = require('../trpc');\n"
            "module.exports = router({\n"
            "  getProfile: protectedProcedure.query(async ({ ctx }) => {\n"
            "    return ctx.user;\n"
            "  }),\n"
            "});\n"
        )

        repo = _make_repo(
            file_index={"src/routers/user.js": cjs_router}
        )
        lsp = _make_lsp()
        # LSP can't trace, so fallback to import detection
        lsp.get_definition.return_value = None
        tracer = AuthFlowTracer(lsp, repo)

        routes = [_make_route("src/routers/user.js", "/api/user.getProfile")]
        results = await tracer.trace_routes(routes)
        result = results["src/routers/user.js:/api/user.getProfile"]

        assert result.has_verified_auth is True
        assert "protectedProcedure" in result.auth_method
        assert result.confidence == 0.85




    @pytest.mark.asyncio
    async def test_detects_inline_get_user(self) -> None:
        """File with supabase.auth.getUser() inline should be detected."""
        nextjs_route = (
            "export async function GET(req: Request) {\n"
            "  const supabase = createServerClient();\n"
            "  const { data: { user } } = await supabase.auth.getUser();\n"
            "  if (!user) return NextResponse.json({}, { status: 401 });\n"
            "  return NextResponse.json({ user });\n"
            "}\n"
        )

        repo = _make_repo(file_index={"src/app/api/me/route.ts": nextjs_route})
        lsp = _make_lsp()
        tracer = AuthFlowTracer(lsp, repo)

        routes = [_make_route("src/app/api/me/route.ts", "/api/me")]
        results = await tracer.trace_routes(routes)
        result = results["src/app/api/me/route.ts:/api/me"]

        assert result.has_verified_auth is True
        assert "getUser" in result.auth_method
        assert "inline" in result.middleware_chain

    @pytest.mark.asyncio
    async def test_no_inline_auth(self) -> None:
        """File without any auth patterns falls through all strategies."""
        plain_handler = (
            "export async function GET() {\n"
            "  const data = await db.query('SELECT * FROM public_items');\n"
            "  return NextResponse.json(data);\n"
            "}\n"
        )

        repo = _make_repo(
            file_index={"src/app/api/items/route.ts": plain_handler}
        )
        lsp = _make_lsp()
        tracer = AuthFlowTracer(lsp, repo)

        routes = [_make_route("src/app/api/items/route.ts", "/api/items")]
        results = await tracer.trace_routes(routes)
        result = results["src/app/api/items/route.ts:/api/items"]

        assert result.has_verified_auth is False
        assert result.confidence == 0.5


# ===========================================================================
# TestTraceFallback
# ===========================================================================


class TestTraceFallback:
    """Graceful degradation when LSP is unavailable or returns nothing."""

    @pytest.mark.asyncio
    async def test_lsp_unavailable_returns_low_confidence(self) -> None:
        """When LSP is unavailable and file has no inline auth, confidence
        should be the fallback value (0.5)."""
        route_content = (
            "import { requireAuth } from '../auth';\n"
            "router.get('/secret', requireAuth, handler);\n"
        )

        repo = _make_repo(file_index={"src/routes/secret.ts": route_content})
        lsp = _make_lsp(available=False)
        # LSP returns None for all definitions (unavailable)
        lsp.get_definition.return_value = None

        tracer = AuthFlowTracer(lsp, repo)
        routes = [_make_route("src/routes/secret.ts", "/secret")]
        results = await tracer.trace_routes(routes)
        result = results["src/routes/secret.ts:/secret"]

        # Without LSP tracing the definition, requireAuth can't be confirmed
        # unless the definition is in the file_index. Since we didn't include
        # the auth middleware file, it falls through to the fallback.
        assert result.confidence < 0.95

    @pytest.mark.asyncio
    async def test_lsp_returns_none_for_definition(self) -> None:
        """When LSP get_definition returns None, tracer falls back to
        content-based detection and returns fallback confidence."""
        route_content = (
            "import { authenticate } from '../middleware';\n"
            "router.post('/items', authenticate, createItem);\n"
        )

        repo = _make_repo(file_index={"src/routes/items.ts": route_content})
        lsp = _make_lsp()
        lsp.get_definition.return_value = None

        tracer = AuthFlowTracer(lsp, repo)
        routes = [_make_route("src/routes/items.ts", "/items")]
        results = await tracer.trace_routes(routes)
        result = results["src/routes/items.ts:/items"]

        # authenticate is detected as an auth pattern, but LSP can't
        # trace it, so the tracer can't confirm it — falls to fallback
        assert result.has_verified_auth is False
        assert result.confidence == 0.5
