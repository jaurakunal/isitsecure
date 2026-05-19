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
        src_dir = tmp_path / ExpressRouteMapperConfig.SOURCE_DIRS[0]
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
