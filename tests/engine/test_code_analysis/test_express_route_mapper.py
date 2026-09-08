"""Tests for ExpressRouteMapper."""

from __future__ import annotations

from pathlib import Path

from isitsecure.engine.code_analysis.express_route_mapper import (
    ExpressRouteMapper,
)
from isitsecure.engine.constants import ExpressRouteMapperConfig


class TestExpressRouteMapperBasic:
    """Basic tests — empty or non-Express codebases."""

    def setup_method(self) -> None:
        self.mapper = ExpressRouteMapper()

    def test_returns_empty_list_for_empty_directory(self, tmp_path: Path) -> None:
        """Scanner returns empty list when no files exist."""
        routes = self.mapper.map_routes(str(tmp_path))
        assert routes == []

    def test_returns_empty_list_for_non_express_codebase(
        self, tmp_path: Path
    ) -> None:
        """Scanner returns empty list when JS files contain no Express patterns."""
        src_dir = tmp_path / "src"
        src_dir.mkdir(parents=True)
        plain_file = src_dir / "utils.js"
        plain_file.write_text(
            "function add(a, b) { return a + b; }\n"
            "module.exports = { add };\n"
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert routes == []


class TestDirectRoutes:
    """Tests for app.get / app.post style route detection."""

    def setup_method(self) -> None:
        self.mapper = ExpressRouteMapper()

    def test_detects_app_get(self, tmp_path: Path) -> None:
        """Detects app.get('/users', handler) route."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        app_file = src_dir / "app.js"
        app_file.write_text(
            "const express = require('express');\n"
            "const app = express();\n"
            "app.get('/users', (req, res) => { res.json([]); });\n"
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].route_pattern == "/users"
        assert routes[0].http_methods == ["GET"]

    def test_detects_app_post(self, tmp_path: Path) -> None:
        """Detects app.post('/users', handler) route."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        app_file = src_dir / "server.js"
        app_file.write_text(
            "const express = require('express');\n"
            "const app = express();\n"
            "app.post('/users', (req, res) => { res.status(201).json({}); });\n"
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].route_pattern == "/users"
        assert routes[0].http_methods == ["POST"]

    def test_detects_multiple_routes_in_one_file(self, tmp_path: Path) -> None:
        """Detects multiple route definitions in the same file."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        app_file = src_dir / "app.js"
        app_file.write_text(
            "const express = require('express');\n"
            "const app = express();\n"
            "app.get('/users', listUsers);\n"
            "app.post('/users', createUser);\n"
            "app.delete('/users/:id', deleteUser);\n"
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 3
        patterns = {r.route_pattern for r in routes}
        assert "/users" in patterns
        assert "/users/:id" in patterns


class TestRouterRoutes:
    """Tests for router.get / router.post style route detection."""

    def setup_method(self) -> None:
        self.mapper = ExpressRouteMapper()

    def test_detects_router_get(self, tmp_path: Path) -> None:
        """Detects router.get('/items', handler) route."""
        routes_dir = tmp_path / "routes"
        routes_dir.mkdir()
        route_file = routes_dir / "items.js"
        route_file.write_text(
            "const express = require('express');\n"
            "const router = express.Router();\n"
            "router.get('/items', (req, res) => { res.json([]); });\n"
            "module.exports = router;\n"
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].route_pattern == "/items"
        assert routes[0].http_methods == ["GET"]

    def test_detects_router_put_and_patch(self, tmp_path: Path) -> None:
        """Detects router.put and router.patch routes."""
        routes_dir = tmp_path / "routes"
        routes_dir.mkdir(parents=True)
        route_file = routes_dir / "items.ts"
        route_file.write_text(
            "import { Router } from 'express';\n"
            "const router = Router();\n"
            "router.put('/items/:id', updateItem);\n"
            "router.patch('/items/:id', patchItem);\n"
            "export default router;\n"
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 2
        methods = {r.http_methods[0] for r in routes}
        assert "PUT" in methods
        assert "PATCH" in methods


class TestAuthDetection:
    """Tests for auth middleware detection in route chains."""

    def setup_method(self) -> None:
        self.mapper = ExpressRouteMapper()

    def test_detects_require_auth_middleware(self, tmp_path: Path) -> None:
        """Detects requireAuth middleware indicator in route definition."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        app_file = src_dir / "app.js"
        app_file.write_text(
            "const express = require('express');\n"
            "const app = express();\n"
            "app.get('/admin', requireAuth, adminHandler);\n"
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].has_auth_check is True

    def test_no_auth_when_absent(self, tmp_path: Path) -> None:
        """Reports no auth when no auth middleware indicator is present."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        app_file = src_dir / "app.js"
        app_file.write_text(
            "const express = require('express');\n"
            "const app = express();\n"
            "app.get('/public', publicHandler);\n"
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].has_auth_check is False

    def test_detects_passport_authenticate(self, tmp_path: Path) -> None:
        """Detects passport.authenticate middleware in route chain."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        app_file = src_dir / "app.js"
        app_file.write_text(
            "const express = require('express');\n"
            "const app = express();\n"
            "app.post('/login', passport.authenticate('local'), loginHandler);\n"
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].has_auth_check is True


class TestAllMethod:
    """Tests for app.all / router.all detection."""

    def setup_method(self) -> None:
        self.mapper = ExpressRouteMapper()

    def test_all_maps_to_all_http_methods(self, tmp_path: Path) -> None:
        """app.all('/health', handler) maps to all HTTP methods."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        app_file = src_dir / "app.js"
        app_file.write_text(
            "const express = require('express');\n"
            "const app = express();\n"
            "app.get('/status', statusHandler);\n"
            "app.all('/health', healthHandler);\n"
        )
        routes = self.mapper.map_routes(str(tmp_path))
        all_routes = [r for r in routes if r.route_pattern == "/health"]
        assert len(all_routes) == 1
        for method in ExpressRouteMapperConfig.HTTP_METHODS:
            assert method in all_routes[0].http_methods


class TestMountPoints:
    """Tests for app.use('/prefix', router) mount point detection."""

    def setup_method(self) -> None:
        self.mapper = ExpressRouteMapper()

    def test_detects_mount_point(self, tmp_path: Path) -> None:
        """Detects app.use('/api/v1', router) mount point in entry file."""
        entry_file = tmp_path / "app.js"
        entry_file.write_text(
            "const express = require('express');\n"
            "const app = express();\n"
            "const userRouter = require('./routes/users');\n"
            "app.use('/api/v1', userRouter);\n"
            "app.get('/health', healthCheck);\n"
        )
        routes = self.mapper.map_routes(str(tmp_path))
        # Should at least detect the /health direct route
        health_routes = [r for r in routes if r.route_pattern == "/health"]
        assert len(health_routes) == 1

    def test_content_is_captured(self, tmp_path: Path) -> None:
        """RouteEntry captures file content for downstream analysis."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        content = (
            "const express = require('express');\n"
            "const app = express();\n"
            "app.get('/test', testHandler);\n"
        )
        app_file = src_dir / "app.js"
        app_file.write_text(content)
        routes = self.mapper.map_routes(str(tmp_path))
        assert len(routes) == 1
        assert routes[0].content == content


class TestRouteFileDiscovery:
    """Which files the mapper treats as this application's routes.

    Two questions, both of which used to be answered wrong. Where to look:
    a fixed list of directory names — src, routes, api — reported zero routes
    for any project that names its own, and "zero routes" is indistinguishable
    from "no Express here" for every stage downstream. And what counts: a repo
    also holds route-shaped code that never runs, and reporting missing auth
    on a fixture is a finding about nothing.
    """

    def setup_method(self) -> None:
        self.mapper = ExpressRouteMapper()

    ROUTE = (
        "const express = require('express');\n"
        "const router = express.Router();\n"
        "router.get('/widgets', (req, res) => res.json([]));\n"
        "module.exports = router;\n"
    )

    def _write(self, root: Path, rel: str, body: str) -> None:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)

    def _app(self, root: Path, *requires: str) -> None:
        """A root entry point that requires the given route modules."""
        body = "const express = require('express');\nconst app = express();\n"
        body += "".join(f"app.use(require('./{r}'));\n" for r in requires)
        self._write(root, "server.js", body)

    def _patterns(self, root: Path) -> list[str]:
        return [r.route_pattern for r in self.mapper.map_routes(str(root))]

    def test_finds_routes_outside_the_conventional_directories(
        self, tmp_path: Path
    ) -> None:
        """NodeGoat's shape: routes under app/routes, which no list reached."""
        self._write(tmp_path, "app/routes/widgets.js", self.ROUTE)
        self._app(tmp_path, "app/routes/widgets")
        assert "/widgets" in self._patterns(tmp_path)

    def test_finds_routes_at_any_depth(self, tmp_path: Path) -> None:
        self._write(tmp_path, "services/billing/http/v2/handlers.js", self.ROUTE)
        self._app(tmp_path, "services/billing/http/v2/handlers")
        assert "/widgets" in self._patterns(tmp_path)

    def test_still_finds_routes_in_the_conventional_directories(
        self, tmp_path: Path
    ) -> None:
        """Widening the search must not lose what the old list did find."""
        self._write(tmp_path, "src/routes/widgets.js", self.ROUTE)
        self._app(tmp_path, "src/routes/widgets")
        assert "/widgets" in self._patterns(tmp_path)

    def test_vendored_code_is_not_scanned(self, tmp_path: Path) -> None:
        """A dependency's routes are not this project's attack surface, and
        node_modules is where a whole-tree walk would otherwise drown."""
        self._write(tmp_path, "node_modules/express-thing/lib/routes.js", self.ROUTE)
        assert self.mapper.map_routes(str(tmp_path)) == []

    def test_hidden_directories_are_not_scanned(self, tmp_path: Path) -> None:
        self._write(tmp_path, ".git/hooks/routes.js", self.ROUTE)
        assert self.mapper.map_routes(str(tmp_path)) == []

    def test_build_output_is_not_scanned(self, tmp_path: Path) -> None:
        """dist/ is a copy of src/, so scanning it doubles every finding."""
        self._write(tmp_path, "dist/routes.js", self.ROUTE)
        assert self.mapper.map_routes(str(tmp_path)) == []

    def test_non_code_files_are_ignored(self, tmp_path: Path) -> None:
        self._write(tmp_path, "app/routes/widgets.md", self.ROUTE)
        assert self.mapper.map_routes(str(tmp_path)) == []

    def test_the_walk_is_bounded(self, tmp_path: Path, monkeypatch) -> None:
        """A pathological tree must not make the scan unbounded."""
        from isitsecure.engine.constants import ExpressRouteMapperConfig

        monkeypatch.setattr(ExpressRouteMapperConfig, "MAX_FILES_SCANNED", 2)
        for i in range(50):
            self._write(tmp_path, f"pkg{i}/routes.js", self.ROUTE)
        assert len(self.mapper.map_routes(str(tmp_path))) < 50


class TestUnreachableRouteFiles:
    """Route-shaped code that the application never loads.

    Juice Shop ships 135 of these under data/static/codefixes — fixtures for
    its own coding challenges. Mapping them produced 84 findings about
    missing auth on code that does not run.
    """

    def setup_method(self) -> None:
        self.mapper = ExpressRouteMapper()

    ROUTE = TestRouteFileDiscovery.ROUTE
    _write = TestRouteFileDiscovery._write
    _app = TestRouteFileDiscovery._app
    _patterns = TestRouteFileDiscovery._patterns

    def _snippet(self, root: Path, rel: str) -> None:
        self._write(
            root,
            rel,
            "const router = require('express').Router();\n"
            "router.get('/snippet', (req, res) => res.json([]));\n",
        )

    def test_a_file_nothing_imports_is_not_a_route(self, tmp_path: Path) -> None:
        self._write(tmp_path, "src/routes/widgets.js", self.ROUTE)
        self._app(tmp_path, "src/routes/widgets")
        self._snippet(tmp_path, "data/static/codefixes/challenge_1.js")
        patterns = self._patterns(tmp_path)
        assert "/widgets" in patterns
        assert "/snippet" not in patterns

    def test_a_neighbour_of_a_reachable_route_is_kept(
        self, tmp_path: Path
    ) -> None:
        """Route files are often loaded by globbing a directory, which leaves
        no import to find. Missing a real route is the worse mistake, so one
        reachable file vouches for its directory."""
        self._write(tmp_path, "src/routes/widgets.js", self.ROUTE)
        self._app(tmp_path, "src/routes/widgets")
        self._snippet(tmp_path, "src/routes/gadgets.js")
        assert "/snippet" in self._patterns(tmp_path)

    def test_an_entry_point_needs_no_importer(self, tmp_path: Path) -> None:
        """Nothing imports the file the process starts from."""
        self._write(tmp_path, "server.js", self.ROUTE)
        assert "/widgets" in self._patterns(tmp_path)

    def test_a_conventional_entry_name_needs_no_importer(
        self, tmp_path: Path
    ) -> None:
        self._write(tmp_path, "app/routes/index.js", self.ROUTE)
        assert "/widgets" in self._patterns(tmp_path)

    def test_nothing_reachable_keeps_everything(self, tmp_path: Path) -> None:
        """When no candidate looks wired the graph is uninformative — the
        entry point may be a .jsx or a compiled artefact this walk never
        read — and pruning on no evidence would drop the whole project."""
        self._write(tmp_path, "src/http/widgets.js", self.ROUTE)
        assert "/widgets" in self._patterns(tmp_path)
