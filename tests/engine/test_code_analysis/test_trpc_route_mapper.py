"""Tests for TRPCRouteMapper."""

from __future__ import annotations

from pathlib import Path

from isitsecure.engine.code_analysis.trpc_route_mapper import TRPCRouteMapper
from isitsecure.engine.constants import TRPCRouteMapperConfig


# ---------------------------------------------------------------------------
# Helpers — create realistic tRPC file layouts inside tmp_path
# ---------------------------------------------------------------------------

def _create_root_router(base: Path, dirname: str = "src/trpc") -> Path:
    """Create a root router that maps userRouter -> 'user'."""
    root_file = base / dirname / "root.ts"
    root_file.parent.mkdir(parents=True, exist_ok=True)
    root_file.write_text(
        "import { router } from './trpc.js';\n"
        "import { userRouter } from './routers/user.router.js';\n"
        "import { adminRouter } from './routers/admin.router.js';\n"
        "export const appRouter = router({\n"
        "  user: userRouter,\n"
        "  admin: adminRouter,\n"
        "});\n"
    )
    return root_file


def _create_user_router(base: Path, dirname: str = "src/trpc") -> Path:
    """Create a user router with public and protected procedures."""
    router_file = base / dirname / "routers" / "user.router.ts"
    router_file.parent.mkdir(parents=True, exist_ok=True)
    router_file.write_text(
        "import { router, publicProcedure, protectedProcedure } from '../trpc.js';\n"
        "import { z } from 'zod';\n"
        "\n"
        "export const userRouter = router({\n"
        "  getAll: publicProcedure.query(async () => {\n"
        "    return db.user.findMany();\n"
        "  }),\n"
        "  update: protectedProcedure\n"
        "    .input(z.object({ name: z.string() }))\n"
        "    .mutation(async ({ input }) => {\n"
        "      return db.user.update({ data: input });\n"
        "    }),\n"
        "});\n"
    )
    return router_file


def _create_admin_router(base: Path, dirname: str = "src/trpc") -> Path:
    """Create an admin router with a tenant procedure."""
    router_file = base / dirname / "routers" / "admin.router.ts"
    router_file.parent.mkdir(parents=True, exist_ok=True)
    router_file.write_text(
        "import { router, tenantProcedure } from '../trpc.js';\n"
        "\n"
        "export const adminRouter = router({\n"
        "  listUsers: tenantProcedure.query(async () => {\n"
        "    return db.admin.findMany();\n"
        "  }),\n"
        "});\n"
    )
    return router_file


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class TestTRPCRouteMapperBasic:
    """Returns empty results for non-tRPC codebases."""

    def setup_method(self) -> None:
        self.mapper = TRPCRouteMapper()

    def test_empty_directory_returns_no_routes(self, tmp_path: Path) -> None:
        """An empty directory has no tRPC routers."""
        routes = self.mapper.map_routes(str(tmp_path))
        assert routes == []

    def test_non_trpc_files_return_no_routes(self, tmp_path: Path) -> None:
        """Directories with plain JS files but no tRPC patterns yield nothing."""
        src_dir = tmp_path / "src" / "trpc"
        src_dir.mkdir(parents=True)
        (src_dir / "utils.ts").write_text(
            "export function add(a: number, b: number) { return a + b; }\n"
        )
        routes = self.mapper.map_routes(str(tmp_path))
        assert routes == []


class TestProcedureExtraction:
    """Detects procedureName: protectedProcedure.query(...) patterns."""

    def setup_method(self) -> None:
        self.mapper = TRPCRouteMapper()

    def test_extracts_simple_query_procedure(self, tmp_path: Path) -> None:
        """Detects a simple publicProcedure.query(...)."""
        _create_root_router(tmp_path)
        _create_user_router(tmp_path)
        _create_admin_router(tmp_path)

        routes = self.mapper.map_routes(str(tmp_path))
        procedure_names = [r.route_pattern.split(".")[-1] for r in routes]
        assert "getAll" in procedure_names

    def test_extracts_mutation_procedure(self, tmp_path: Path) -> None:
        """Detects protectedProcedure.input(...).mutation(...)."""
        _create_root_router(tmp_path)
        _create_user_router(tmp_path)
        _create_admin_router(tmp_path)

        routes = self.mapper.map_routes(str(tmp_path))
        procedure_names = [r.route_pattern.split(".")[-1] for r in routes]
        assert "update" in procedure_names

    def test_extracts_all_procedures_from_router(self, tmp_path: Path) -> None:
        """Both getAll and update should be found from the user router."""
        _create_root_router(tmp_path)
        _create_user_router(tmp_path)
        _create_admin_router(tmp_path)

        routes = self.mapper.map_routes(str(tmp_path))
        # Deduplicate by route_pattern — overlapping SOURCE_DIRS may
        # discover the same file more than once.
        user_patterns = {
            r.route_pattern for r in routes if "/trpc/user." in r.route_pattern
        }
        assert user_patterns == {"/trpc/user.getAll", "/trpc/user.update"}


class TestAuthLevel:
    """Correctly classifies publicProcedure as PUBLIC, protectedProcedure as AUTH."""

    def setup_method(self) -> None:
        self.mapper = TRPCRouteMapper()

    def test_public_procedure_has_no_auth(self, tmp_path: Path) -> None:
        """publicProcedure should have has_auth_check=False."""
        _create_root_router(tmp_path)
        _create_user_router(tmp_path)
        _create_admin_router(tmp_path)

        routes = self.mapper.map_routes(str(tmp_path))
        get_all = next(r for r in routes if r.route_pattern.endswith("getAll"))
        assert get_all.has_auth_check is False

    def test_protected_procedure_has_auth(self, tmp_path: Path) -> None:
        """protectedProcedure should have has_auth_check=True."""
        _create_root_router(tmp_path)
        _create_user_router(tmp_path)
        _create_admin_router(tmp_path)

        routes = self.mapper.map_routes(str(tmp_path))
        update = next(r for r in routes if r.route_pattern.endswith("update"))
        assert update.has_auth_check is True

    def test_tenant_procedure_has_auth(self, tmp_path: Path) -> None:
        """tenantProcedure should have has_auth_check=True."""
        _create_root_router(tmp_path)
        _create_user_router(tmp_path)
        _create_admin_router(tmp_path)

        routes = self.mapper.map_routes(str(tmp_path))
        list_users = next(
            r for r in routes if r.route_pattern.endswith("listUsers")
        )
        assert list_users.has_auth_check is True

    def test_auth_level_values_match_config(self) -> None:
        """Auth level constants should match the config values."""
        assert TRPCRouteMapperConfig.AUTH_LEVEL_PUBLIC == "public"
        assert TRPCRouteMapperConfig.AUTH_LEVEL_PROTECTED == "protected"
        assert TRPCRouteMapperConfig.AUTH_LEVEL_TENANT == "tenant"


class TestMethodMapping:
    """Maps .query() to GET, .mutation() to POST."""

    def setup_method(self) -> None:
        self.mapper = TRPCRouteMapper()

    def test_query_maps_to_get(self, tmp_path: Path) -> None:
        """.query() procedures should produce GET method."""
        _create_root_router(tmp_path)
        _create_user_router(tmp_path)
        _create_admin_router(tmp_path)

        routes = self.mapper.map_routes(str(tmp_path))
        get_all = next(r for r in routes if r.route_pattern.endswith("getAll"))
        assert get_all.http_methods == [
            TRPCRouteMapperConfig.PROCEDURE_TYPE_TO_METHOD["query"]
        ]

    def test_mutation_maps_to_post(self, tmp_path: Path) -> None:
        """.mutation() procedures should produce POST method."""
        _create_root_router(tmp_path)
        _create_user_router(tmp_path)
        _create_admin_router(tmp_path)

        routes = self.mapper.map_routes(str(tmp_path))
        update = next(r for r in routes if r.route_pattern.endswith("update"))
        assert update.http_methods == [
            TRPCRouteMapperConfig.PROCEDURE_TYPE_TO_METHOD["mutation"]
        ]

    def test_subscription_maps_to_get(self) -> None:
        """subscription type should map to GET per config."""
        assert TRPCRouteMapperConfig.PROCEDURE_TYPE_TO_METHOD["subscription"] == "GET"


class TestNamespaceResolution:
    """Resolves router name from root router mapping."""

    def setup_method(self) -> None:
        self.mapper = TRPCRouteMapper()

    def test_namespace_from_root_router(self, tmp_path: Path) -> None:
        """adminRouter should resolve to 'admin' namespace via root mapping."""
        _create_root_router(tmp_path)
        _create_user_router(tmp_path)
        _create_admin_router(tmp_path)

        routes = self.mapper.map_routes(str(tmp_path))
        admin_routes = [r for r in routes if "/trpc/admin." in r.route_pattern]
        assert len(admin_routes) >= 1
        assert admin_routes[0].route_pattern.startswith("/trpc/admin.")

    def test_fallback_strips_router_suffix(self) -> None:
        """Without root mapping, 'adminRouter' falls back to 'admin'."""
        namespace = TRPCRouteMapper._resolve_namespace("adminRouter", {})
        assert namespace == "admin"

    def test_exact_match_preferred_over_fallback(self) -> None:
        """Root mapping takes precedence over fallback stripping."""
        namespace_map = {"adminRouter": "mgmt"}
        namespace = TRPCRouteMapper._resolve_namespace(
            "adminRouter", namespace_map
        )
        assert namespace == "mgmt"


class TestMultiLineInput:
    """Handles procedures with multi-line .input(z.object({...})) blocks."""

    def setup_method(self) -> None:
        self.mapper = TRPCRouteMapper()

    def test_multiline_input_mutation_detected(self, tmp_path: Path) -> None:
        """Procedure with multi-line .input() then .mutation() is extracted."""
        router_dir = tmp_path / "src" / "trpc" / "routers"
        router_dir.mkdir(parents=True)

        # Root router referencing orderRouter
        root_file = tmp_path / "src" / "trpc" / "root.ts"
        root_file.write_text(
            "import { router } from './trpc.js';\n"
            "import { orderRouter } from './routers/order.router.js';\n"
            "import { userRouter } from './routers/user.router.js';\n"
            "export const appRouter = router({\n"
            "  order: orderRouter,\n"
            "  user: userRouter,\n"
            "});\n"
        )

        # Minimal user router so root counts as root (needs >=2 router imports)
        user_file = router_dir / "user.router.ts"
        user_file.write_text(
            "import { router, publicProcedure } from '../trpc.js';\n"
            "export const userRouter = router({\n"
            "  me: publicProcedure.query(async () => {}),\n"
            "});\n"
        )

        # Order router with multi-line input
        order_file = router_dir / "order.router.ts"
        order_file.write_text(
            "import { router, protectedProcedure } from '../trpc.js';\n"
            "import { z } from 'zod';\n"
            "\n"
            "export const orderRouter = router({\n"
            "  create: protectedProcedure\n"
            "    .input(\n"
            "      z.object({\n"
            "        productId: z.string(),\n"
            "        quantity: z.number().min(1),\n"
            "        shippingAddress: z.object({\n"
            "          street: z.string(),\n"
            "          city: z.string(),\n"
            "          zip: z.string(),\n"
            "        }),\n"
            "      })\n"
            "    )\n"
            "    .mutation(async ({ input }) => {\n"
            "      return db.order.create({ data: input });\n"
            "    }),\n"
            "});\n"
        )

        routes = self.mapper.map_routes(str(tmp_path))
        order_routes = [r for r in routes if "/trpc/order." in r.route_pattern]
        # At least one match (overlapping SOURCE_DIRS may yield duplicates)
        assert len(order_routes) >= 1
        assert order_routes[0].route_pattern == "/trpc/order.create"
        assert order_routes[0].http_methods == ["POST"]
        assert order_routes[0].has_auth_check is True


class TestRoutePattern:
    """Generates correct /trpc/namespace.procedureName patterns."""

    def setup_method(self) -> None:
        self.mapper = TRPCRouteMapper()

    def test_full_route_pattern_format(self, tmp_path: Path) -> None:
        """Route pattern follows /trpc/<namespace>.<procedure> convention."""
        _create_root_router(tmp_path)
        _create_user_router(tmp_path)
        _create_admin_router(tmp_path)

        routes = self.mapper.map_routes(str(tmp_path))
        patterns = {r.route_pattern for r in routes}
        assert "/trpc/user.getAll" in patterns
        assert "/trpc/user.update" in patterns
        assert "/trpc/admin.listUsers" in patterns

    def test_route_without_namespace(self) -> None:
        """Procedures with empty namespace omit the dot prefix."""
        mapper = TRPCRouteMapper()
        procedures = mapper._extract_procedures(
            "  health: publicProcedure.query(async () => {}),\n",
            "src/trpc/root.ts",
            "",
        )
        assert len(procedures) == 1
        assert procedures[0].route_pattern == "/trpc/health"

    def test_content_is_captured_in_route_entry(self, tmp_path: Path) -> None:
        """RouteEntry.content should contain the full file content."""
        _create_root_router(tmp_path)
        _create_user_router(tmp_path)
        _create_admin_router(tmp_path)

        routes = self.mapper.map_routes(str(tmp_path))
        user_route = next(
            r for r in routes if r.route_pattern == "/trpc/user.getAll"
        )
        assert "publicProcedure" in user_route.content
        assert "userRouter" in user_route.content
