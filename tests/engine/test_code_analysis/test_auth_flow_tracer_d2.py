"""D2 regression tests for the LSP auth tracer.

The tracer's "verified auth" verdict suppresses the "API route missing
authentication check" finding, so every test here pairs a negative case (an
unguarded route must still be reported, i.e. NOT verified) with a positive
control (a genuinely guarded route must still be verified).
"""

from __future__ import annotations

import os
import tempfile

import pytest

from isitsecure.engine.code_analysis.lsp.auth_flow_tracer import AuthFlowTracer
from isitsecure.engine.code_analysis.lsp.protocols import LSPLocation
from isitsecure.engine.code_analysis.protocols import RepoSnapshot, RouteEntry


class _NoLSP:
    async def get_definition(self, f, line, col):
        return []


def _route(path, method, pattern, content=""):
    return RouteEntry(
        file_path=path, http_methods=[method], route_pattern=pattern, content=content
    )


async def _verdicts(src, routes, path="app/api/x/route.ts", lsp=None, clone=None):
    repo = RepoSnapshot(
        repo_url="x", branch="m", clone_path=clone or "/tmp/nonexistent-d2",
        file_index={path: src},
    )
    out = await AuthFlowTracer(lsp or _NoLSP(), repo).trace_routes(routes)
    return {
        k.split(":", 1)[1]: v.has_verified_auth for k, v in out.items()
    }


async def _one(src, path="app/api/x/route.ts", method="POST", pattern="/api/x"):
    v = await _verdicts(src, [_route(path, method, pattern)], path)
    return v[f"{method} {pattern}"]


# --- B6 #1: non-auth calls and comments must not vouch ---------------------


@pytest.mark.asyncio
async def test_bcrypt_compare_is_login_not_authorization() -> None:
    src = (
        "import bcrypt from 'bcrypt'\n"
        "export async function POST(req){ const ok = await bcrypt.compare(pw, hash);"
        " await db.wipeAllUsers(); return Response.json({ok}) }\n"
    )
    assert await _one(src) is False


@pytest.mark.asyncio
async def test_argon2_verify_is_not_authorization() -> None:
    src = "export async function POST(req){ await argon2.verify(h, p); await db.wipe() }\n"
    assert await _one(src) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("call", ["getToken()", "authenticate()", "getUser(req)", "getSession()"])
async def test_bare_lookup_without_rejection_is_not_auth(call: str) -> None:
    src = (
        f"export async function POST(req){{ const t = await {call};"
        " return Response.json(await db.deleteAll(t)) }\n"
    )
    assert await _one(src) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("call", ["getToken()", "authenticate()", "getUser(req)", "getSession()"])
async def test_lookup_that_rejects_is_still_verified(call: str) -> None:  # positive control
    src = (
        f"export async function POST(req){{ const u = await {call};\n"
        "  if (!u) return Response.json({e:'no'}, { status: 401 });\n"
        "  return Response.json(await db.deleteAll(u)) }\n"
    )
    assert await _one(src) is True


@pytest.mark.asyncio
async def test_jwt_verify_still_verified() -> None:  # positive control
    src = "export async function POST(req){ jwt.verify(req.headers.token, KEY); await db.wipe() }\n"
    assert await _one(src) is True


@pytest.mark.asyncio
async def test_comment_mentioning_jwt_verify_is_not_auth() -> None:
    src = (
        "// TODO: add jwt.verify( here\n"
        "/* getServerSession( later */\n"
        "export async function POST(req){ await db.wipe(); return Response.json({}) }\n"
    )
    assert await _one(src) is False


@pytest.mark.asyncio
async def test_real_call_after_a_comment_is_still_verified() -> None:  # positive control
    src = (
        "// guard below\n"
        "export async function POST(req){ jwt.verify(req.headers.token, KEY); await db.wipe() }\n"
    )
    assert await _one(src) is True


@pytest.mark.asyncio
async def test_python_comment_is_not_auth() -> None:
    src = "# jwt.verify( is not called here\ndef handler(request):\n    return wipe()\n"
    assert await _one(src, path="views.py", method="POST", pattern="/wipe") is False


# --- B6 #2: one guarded symbol must not vouch for every route -------------


NEST = (
    "@Controller()\n"
    "class A {\n"
    "  @UseGuards(AuthGuard('jwt'))\n"
    "  @Get('a')\n"
    "  a(){ return 1 }\n"
    "\n"
    "  @Post('b')\n"
    "  b(){ return db.wipe() }\n"
    "}\n"
)


@pytest.mark.asyncio
async def test_decorator_guard_applies_only_to_its_own_route() -> None:
    v = await _verdicts(
        NEST,
        [_route("a.controller.ts", "GET", "/a"), _route("a.controller.ts", "POST", "/b")],
        "a.controller.ts",
    )
    assert v["GET /a"] is True  # positive control
    assert v["POST /b"] is False


@pytest.mark.asyncio
async def test_class_level_guard_covers_every_route() -> None:  # positive control
    src = (
        "@UseGuards(AuthGuard('jwt'))\n"
        "@Controller()\n"
        "class A {\n"
        "  @Get('a') a(){}\n"
        "  @Post('b') b(){}\n"
        "}\n"
    )
    v = await _verdicts(
        src,
        [_route("a.controller.ts", "GET", "/a"), _route("a.controller.ts", "POST", "/b")],
        "a.controller.ts",
    )
    assert v == {"GET /a": True, "POST /b": True}


@pytest.mark.asyncio
async def test_login_required_on_another_function_does_not_vouch() -> None:
    src = (
        "@login_required\n"
        "def a(): pass\n"
        "\n"
        "@app.route('/b', methods=['POST'])\n"
        "def b(): return wipe()\n"
    )
    assert await _one(src, path="views.py", method="POST", pattern="/b") is False


@pytest.mark.asyncio
async def test_login_required_on_its_own_route_still_vouches() -> None:  # positive control
    src = (
        "@app.route('/b', methods=['POST'])\n"
        "@login_required\n"
        "def b(): return wipe()\n"
        "\n"
        "@app.route('/c', methods=['POST'])\n"
        "def c(): return wipe()\n"
    )
    v = await _verdicts(
        src,
        [_route("views.py", "POST", "/b"), _route("views.py", "POST", "/c")],
        "views.py",
    )
    assert v == {"POST /b": True, "POST /c": False}


TRPC = (
    "import { protectedProcedure } from '../trpc'\n"
    "export const r = router({\n"
    "  pub: publicProcedure.query(() => 1),\n"
    "  wipe: publicProcedure.mutation(() => db.wipe()),\n"
    "  mine: protectedProcedure.query(() => 2),\n"
    "})\n"
)


@pytest.mark.asyncio
async def test_trpc_public_procedure_not_vouched_by_protected_neighbour() -> None:
    v = await _verdicts(
        TRPC,
        [_route("r.ts", "GET", "/trpc/wipe"), _route("r.ts", "GET", "/trpc/mine")],
        "r.ts",
    )
    assert v["GET /trpc/wipe"] is False
    assert v["GET /trpc/mine"] is True  # positive control (imported-base fallback)


@pytest.mark.asyncio
async def test_trpc_namespaced_route_name_is_attributed() -> None:
    v = await _verdicts(
        TRPC,
        [_route("r.ts", "GET", "/trpc/user.wipe")],
        "r.ts",
    )
    assert v["GET /trpc/user.wipe"] is False


NEXT_SPACES = (
    "export async function GET(req: Request) {\n"
    "  const s = await getServerSession();\n"
    "  if (!s) return Response.json({}, { status: 401 });\n"
    "  return Response.json(await db.mine(s));\n"
    "}\n"
    "\n"
    "export async function POST(req: Request) {\n"
    "  return Response.json(await db.wipe());\n"
    "}\n"
)


@pytest.mark.asyncio
@pytest.mark.parametrize("indent", ["  ", "\t"])
async def test_next_handler_guard_is_per_method(indent: str) -> None:
    src = NEXT_SPACES.replace("  ", indent)
    path = "app/api/x/route.ts"
    repo_routes = [
        RouteEntry(file_path=path, http_methods=["GET", "POST"], route_pattern="/api/x")
    ]
    v = await _verdicts(src, repo_routes, path)
    assert v["GET /api/x"] is True  # positive control
    assert v["POST /api/x"] is False


@pytest.mark.asyncio
async def test_helper_guard_called_by_handler_still_vouches() -> None:  # positive control
    src = (
        "async function requireUser(req) {\n"
        "  const s = await getServerSession();\n"
        "  if (!s) throw new UnauthorizedException();\n"
        "  return s;\n"
        "}\n"
        "export async function POST(req) { const u = await requireUser(req); return db.wipe(u) }\n"
        "export async function GET(req) { return db.list() }\n"
    )
    path = "app/api/x/route.ts"
    routes = [RouteEntry(file_path=path, http_methods=["GET", "POST"], route_pattern="/api/x")]
    v = await _verdicts(src, routes, path)
    assert v["POST /api/x"] is True
    assert v["GET /api/x"] is False


# --- B6 #3: tab-indented definitions ----------------------------------------


@pytest.mark.parametrize("indent", ["  ", "\t"])
def test_enclosing_block_stops_at_own_closing_brace(indent: str) -> None:
    src = (
        "class Guards {\n"
        f"{indent}noop(req,res,next) {{\n"
        f"{indent}{indent}next()\n"
        f"{indent}}}\n"
        f"{indent}verify(req) {{ return jwt.verify(req.token, KEY) }}\n"
        "}\n"
    )
    block = AuthFlowTracer._enclosing_block(src, 1)
    assert "next()" in block
    assert "jwt.verify" not in block


def _tab_guard_source(indent: str, body: str) -> str:
    return (
        "class Guards {\n"
        f"{indent}guard(req,res,next) {{\n"
        f"{indent}{indent}{body}\n"
        f"{indent}}}\n"
        f"{indent}verify(req) {{ return jwt.verify(req.token, KEY) }}\n"
        "}\n"
        "app.get('/api/secret', guards.guard, handler)\n"
    )


class _LocLSP:
    def __init__(self, path, line, col):
        self.loc = [LSPLocation(file_path=path, line=line, character=col)]

    async def get_definition(self, f, line, col):
        return self.loc


@pytest.mark.asyncio
@pytest.mark.parametrize("indent", ["  ", "\t"])
async def test_unguarded_middleware_not_vouched_by_sibling(indent: str) -> None:
    src = _tab_guard_source(indent, "next()")
    with tempfile.TemporaryDirectory() as d:
        path = "server.ts"
        with open(os.path.join(d, path), "w") as fh:
            fh.write(src)
        lsp = _LocLSP(os.path.join(d, path), 1, len(indent))
        v = await _verdicts(
            src, [_route(path, "GET", "/api/secret")], path, lsp=lsp, clone=d
        )
    assert v["GET /api/secret"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("indent", ["  ", "\t"])
async def test_guarding_middleware_is_still_vouched(indent: str) -> None:  # positive control
    src = _tab_guard_source(indent, "jwt.verify(req.token, KEY); next()")
    with tempfile.TemporaryDirectory() as d:
        path = "server.ts"
        with open(os.path.join(d, path), "w") as fh:
            fh.write(src)
        lsp = _LocLSP(os.path.join(d, path), 1, len(indent))
        v = await _verdicts(
            src, [_route(path, "GET", "/api/secret")], path, lsp=lsp, clone=d
        )
    assert v["GET /api/secret"] is True
