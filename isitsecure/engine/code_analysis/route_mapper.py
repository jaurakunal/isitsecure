"""Maps Next.js file structure to API routes."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from isitsecure.engine.code_analysis.protocols import RouteEntry
from isitsecure.engine.constants import (
    RepoIngestionConfig,
    RouteMapperConfig,
)

logger = logging.getLogger(__name__)


class NextJSRouteMapper:
    """Maps Next.js file structure to API routes.

    Handles both App Router (app/api/**/route.ts) and
    Pages Router (pages/api/**/*.ts).
    """

    def map_routes(self, clone_path: str) -> list[RouteEntry]:
        """Map all API routes from the file system."""
        routes: list[RouteEntry] = []
        routes.extend(self._map_app_router(clone_path))
        routes.extend(self._map_pages_router(clone_path))
        return routes

    def _map_app_router(self, clone_path: str) -> list[RouteEntry]:
        """Find app/**/route.ts files and extract route patterns + HTTP methods."""
        routes: list[RouteEntry] = []
        root = Path(clone_path)

        for source_dir_name in RouteMapperConfig.SOURCE_DIRS:
            # Only look in app-style directories
            if "pages" in source_dir_name:
                continue
            source_dir = root / source_dir_name
            if not source_dir.is_dir():
                continue

            for route_file_name in RouteMapperConfig.APP_ROUTER_ROUTE_FILES:
                for route_file in source_dir.rglob(route_file_name):
                    relative = route_file.relative_to(source_dir)
                    route_pattern = self._path_to_route_pattern(
                        str(relative), route_file_name
                    )
                    content = self._safe_read(route_file)
                    methods = self._detect_exported_methods(content)
                    routes.append(
                        RouteEntry(
                            file_path=str(route_file.relative_to(root)),
                            http_methods=methods,
                            route_pattern=route_pattern,
                            content=content,
                        )
                    )
        return routes

    def _map_pages_router(self, clone_path: str) -> list[RouteEntry]:
        """Find pages/api/**/*.ts files and extract route patterns."""
        routes: list[RouteEntry] = []
        root = Path(clone_path)

        for source_dir_name in RouteMapperConfig.SOURCE_DIRS:
            # Only look in pages-style directories
            if "app" in source_dir_name:
                continue
            source_dir = root / source_dir_name
            api_dir = source_dir / "api" if "pages" in source_dir_name else None
            if api_dir is None:
                continue
            if not api_dir.is_dir():
                continue

            for ext in RepoIngestionConfig.CODE_EXTENSIONS:
                for api_file in api_dir.rglob(f"*{ext}"):
                    relative = api_file.relative_to(source_dir)
                    route_pattern = self._path_to_route_pattern(
                        str(relative), api_file.name
                    )
                    content = self._safe_read(api_file)
                    methods = self._detect_pages_methods(content)
                    routes.append(
                        RouteEntry(
                            file_path=str(api_file.relative_to(root)),
                            http_methods=methods,
                            route_pattern=route_pattern,
                            content=content,
                        )
                    )
        return routes

    def _path_to_route_pattern(self, relative_path: str, file_name: str) -> str:
        """Convert file system path to URL route pattern.

        Examples:
            api/users/[id]/route.ts  -> /api/users/:id
            api/users/route.ts       -> /api/users
            api/[...slug]/route.ts   -> /api/*slug
            api/users/[id].ts        -> /api/users/:id
            api/users/index.ts       -> /api/users
        """
        # Normalise separators
        route = relative_path.replace("\\", "/")

        # Strip the file name (route.ts, index.ts, or specific .ts)
        suffixes_to_strip = (
            *RouteMapperConfig.APP_ROUTER_ROUTE_FILES,
            *RouteMapperConfig.INDEX_FILE_NAMES,
        )
        for suffix in suffixes_to_strip:
            if route.endswith(suffix):
                route = route[: -len(suffix)]
                break
        else:
            # Remove the extension from the leaf file (pages router style)
            for ext in RepoIngestionConfig.CODE_EXTENSIONS:
                if route.endswith(ext):
                    route = route[: -len(ext)]
                    break

        # Clean up trailing slashes
        route = route.rstrip("/")

        # Convert catch-all segments [...param] -> *param
        route = re.sub(
            RouteMapperConfig.CATCH_ALL_PATTERN, r"*\1", route
        )

        # Convert dynamic segments [param] -> :param
        route = re.sub(
            RouteMapperConfig.DYNAMIC_SEGMENT_PATTERN, r":\1", route
        )

        # Ensure leading slash
        if not route.startswith("/"):
            route = "/" + route

        return route

    def _detect_exported_methods(self, content: str) -> list[str]:
        """Detect which HTTP methods are exported from an App Router route file.

        Looks for patterns like:
            export async function GET(...)
            export const POST = ...
            export function DELETE(...)
        """
        methods: list[str] = []
        for method in RouteMapperConfig.EXPORTED_HTTP_METHODS:
            # Match: export [async] function METHOD  or  export const METHOD
            pattern = (
                rf"export\s+(?:async\s+)?(?:function|const)\s+{method}\b"
            )
            if re.search(pattern, content):
                methods.append(method)
        return methods

    def _detect_pages_methods(self, content: str) -> list[str]:
        """Detect HTTP methods handled in a Pages Router API file.

        Looks for patterns like:
            req.method === "POST"
            case "GET":
            method === 'PUT'
        """
        methods: list[str] = []
        for method in RouteMapperConfig.EXPORTED_HTTP_METHODS:
            pattern = rf"""(?:req\.method\s*===?\s*['"]|case\s*['"]){method}['"]"""
            if re.search(pattern, content):
                methods.append(method)
        # If no specific methods detected, default to all (handler style)
        if not methods and content.strip():
            methods = list(RouteMapperConfig.DEFAULT_PAGES_METHODS)
        return methods

    @staticmethod
    def _safe_read(path: Path) -> str:
        """Read file content, returning empty string on failure."""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            logger.warning("Failed to read file: %s", path)
            return ""
