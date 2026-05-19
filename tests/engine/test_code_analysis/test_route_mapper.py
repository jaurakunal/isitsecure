"""Tests for NextJSRouteMapper."""

from __future__ import annotations

from pathlib import Path

from isitsecure.engine.code_analysis.route_mapper import NextJSRouteMapper


class TestNextJSRouteMapper:
    """Tests for Next.js route mapping from file system."""

    def setup_method(self) -> None:
        self.mapper = NextJSRouteMapper()

    # --- App Router ---

    def test_app_router_simple_route(self, tmp_path: Path) -> None:
        """app/api/users/route.ts -> /api/users with GET,POST."""
        route_file = tmp_path / "app" / "api" / "users" / "route.ts"
        route_file.parent.mkdir(parents=True)
        route_file.write_text(
            'export async function GET(req: Request) { return Response.json([]); }\n'
            'export async function POST(req: Request) { return Response.json({}); }\n'
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].route_pattern == "/api/users"
        assert "GET" in routes[0].http_methods
        assert "POST" in routes[0].http_methods

    def test_app_router_dynamic_segment(self, tmp_path: Path) -> None:
        """app/api/users/[id]/route.ts -> /api/users/:id."""
        route_file = tmp_path / "app" / "api" / "users" / "[id]" / "route.ts"
        route_file.parent.mkdir(parents=True)
        route_file.write_text(
            'export async function GET(req: Request) { return Response.json({}); }\n'
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].route_pattern == "/api/users/:id"
        assert routes[0].http_methods == ["GET"]

    def test_app_router_catch_all(self, tmp_path: Path) -> None:
        """app/api/[...slug]/route.ts -> /api/*slug."""
        route_file = tmp_path / "app" / "api" / "[...slug]" / "route.ts"
        route_file.parent.mkdir(parents=True)
        route_file.write_text(
            'export async function GET(req: Request) { return Response.json({}); }\n'
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].route_pattern == "/api/*slug"

    def test_app_router_nested_dynamic(self, tmp_path: Path) -> None:
        """app/api/orgs/[orgId]/members/[memberId]/route.ts -> /api/orgs/:orgId/members/:memberId."""
        route_file = (
            tmp_path
            / "app"
            / "api"
            / "orgs"
            / "[orgId]"
            / "members"
            / "[memberId]"
            / "route.ts"
        )
        route_file.parent.mkdir(parents=True)
        route_file.write_text(
            'export async function DELETE(req: Request) { return Response.json({}); }\n'
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].route_pattern == "/api/orgs/:orgId/members/:memberId"
        assert routes[0].http_methods == ["DELETE"]

    def test_app_router_const_export(self, tmp_path: Path) -> None:
        """Should detect 'export const POST = ...' style exports."""
        route_file = tmp_path / "app" / "api" / "webhooks" / "route.ts"
        route_file.parent.mkdir(parents=True)
        route_file.write_text(
            'export const POST = async (req: Request) => { return Response.json({}); };\n'
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].http_methods == ["POST"]

    # --- Pages Router ---

    def test_pages_router_simple(self, tmp_path: Path) -> None:
        """pages/api/users.ts -> /api/users."""
        api_file = tmp_path / "pages" / "api" / "users.ts"
        api_file.parent.mkdir(parents=True)
        api_file.write_text(
            'if (req.method === "GET") { res.json([]); }\n'
            'if (req.method === "POST") { res.json({}); }\n'
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].route_pattern == "/api/users"
        assert "GET" in routes[0].http_methods
        assert "POST" in routes[0].http_methods

    def test_pages_router_dynamic(self, tmp_path: Path) -> None:
        """pages/api/users/[id].ts -> /api/users/:id."""
        api_file = tmp_path / "pages" / "api" / "users" / "[id].ts"
        api_file.parent.mkdir(parents=True)
        api_file.write_text(
            'if (req.method === "GET") { res.json({}); }\n'
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].route_pattern == "/api/users/:id"

    def test_pages_router_index(self, tmp_path: Path) -> None:
        """pages/api/users/index.ts -> /api/users."""
        api_file = tmp_path / "pages" / "api" / "users" / "index.ts"
        api_file.parent.mkdir(parents=True)
        api_file.write_text(
            'export default function handler(req, res) { res.json({}); }\n'
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].route_pattern == "/api/users"

    def test_pages_router_switch_case(self, tmp_path: Path) -> None:
        """Should detect methods from switch/case statements."""
        api_file = tmp_path / "pages" / "api" / "items.ts"
        api_file.parent.mkdir(parents=True)
        api_file.write_text(
            'switch (req.method) {\n'
            '  case "GET": return res.json([]);\n'
            '  case "PUT": return res.json({});\n'
            '}\n'
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert "GET" in routes[0].http_methods
        assert "PUT" in routes[0].http_methods

    # --- src/ prefix ---

    def test_src_app_directory(self, tmp_path: Path) -> None:
        """Should find routes under src/app/."""
        route_file = tmp_path / "src" / "app" / "api" / "health" / "route.ts"
        route_file.parent.mkdir(parents=True)
        route_file.write_text(
            'export async function GET() { return Response.json({ ok: true }); }\n'
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].route_pattern == "/api/health"

    def test_src_pages_directory(self, tmp_path: Path) -> None:
        """Should find routes under src/pages/api/."""
        api_file = tmp_path / "src" / "pages" / "api" / "status.ts"
        api_file.parent.mkdir(parents=True)
        api_file.write_text(
            'if (req.method === "GET") { res.json({ ok: true }); }\n'
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].route_pattern == "/api/status"

    # --- Combined ---

    def test_both_routers_coexist(self, tmp_path: Path) -> None:
        """Should map routes from both App Router and Pages Router."""
        # App Router route
        app_route = tmp_path / "app" / "api" / "v2" / "users" / "route.ts"
        app_route.parent.mkdir(parents=True)
        app_route.write_text(
            'export async function GET() { return Response.json([]); }\n'
        )
        # Pages Router route
        pages_route = tmp_path / "pages" / "api" / "v1" / "users.ts"
        pages_route.parent.mkdir(parents=True)
        pages_route.write_text(
            'if (req.method === "GET") { res.json([]); }\n'
        )
        routes = self.mapper.map_routes(str(tmp_path))
        patterns = {r.route_pattern for r in routes}
        assert "/api/v2/users" in patterns
        assert "/api/v1/users" in patterns

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Should return empty list when no routes exist."""
        routes = self.mapper.map_routes(str(tmp_path))
        assert routes == []

    def test_route_content_is_captured(self, tmp_path: Path) -> None:
        """Should capture file content in RouteEntry."""
        content = 'export async function GET() { return Response.json([]); }\n'
        route_file = tmp_path / "app" / "api" / "test" / "route.ts"
        route_file.parent.mkdir(parents=True)
        route_file.write_text(content)
        routes = self.mapper.map_routes(str(tmp_path))
        assert routes[0].content == content
