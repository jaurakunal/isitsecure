"""Maps Express.js route definitions to API routes.

SRP: This class is responsible ONLY for detecting Express.js route
     definitions from source files.  It does not perform security
     analysis — that is the job of downstream scanners.

OCP: Implements ``RouteMapperProtocol`` so it can be added to the
     route mapper list without modifying ``RepoIngestionService``.

DIP: Depends on ``RouteMapperProtocol`` (abstraction), not on any
     concrete scanner or ingestion class.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from isitsecure.engine.code_analysis.protocols import RouteEntry
from isitsecure.engine.constants import ExpressRouteMapperConfig

logger = logging.getLogger(__name__)


class ExpressRouteMapper:
    """Detects Express.js route definitions from source files.

    Handles:
    - Direct routes: ``app.get('/path', handler)``
    - Router routes: ``router.post('/path', handler)``
    - Mount points: ``app.use('/api/webhooks', webhookRouter)``
    - Auth middleware detection in route chains

    Conforms to ``RouteMapperProtocol``.
    """

    def map_routes(self, clone_path: str) -> list[RouteEntry]:
        """Scan for Express route definitions in the codebase.

        Args:
            clone_path: Absolute path to the repo (or workspace) root.

        Returns:
            List of ``RouteEntry`` for each discovered Express route.
        """
        root = Path(clone_path)
        routes: list[RouteEntry] = []
        mount_points: dict[str, str] = {}  # prefix -> router variable

        # First pass: find all route files and mount points
        route_files = self._find_route_files(root)

        for file_path in route_files:
            try:
                content = self._safe_read(file_path)
                if not content:
                    continue

                relative = str(file_path.relative_to(root))

                # Extract mount points from main entry files
                file_mounts = self._extract_mount_points(content)
                mount_points.update(file_mounts)

                # Extract direct routes
                file_routes = self._extract_routes(content, relative)
                routes.extend(file_routes)

            except Exception as e:
                logger.warning(
                    ExpressRouteMapperConfig.ERROR_ROUTE_DETECTION_FAILED.format(
                        file=file_path, error=e
                    )
                )

        # Second pass: resolve mounted router routes with their prefix
        routes = self._resolve_mount_prefixes(routes, mount_points)

        return routes

    # ------------------------------------------------------------------
    # File discovery
    # ------------------------------------------------------------------

    def _find_route_files(self, root: Path) -> list[Path]:
        """Find files that contain Express route definitions."""
        candidates: list[Path] = []

        # Search in standard source directories
        for source_dir_name in ExpressRouteMapperConfig.SOURCE_DIRS:
            source_dir = root / source_dir_name
            if not source_dir.is_dir():
                continue

            for ext in ExpressRouteMapperConfig.CODE_EXTENSIONS:
                for file_path in source_dir.rglob(f"*{ext}"):
                    candidates.append(file_path)

        # Also check root-level entry files (main.js, app.js, server.js, index.js)
        for name in ("main", "app", "server", "index"):
            for ext in ExpressRouteMapperConfig.CODE_EXTENSIONS:
                entry = root / f"{name}{ext}"
                if entry.is_file() and entry not in candidates:
                    candidates.append(entry)

        # Filter to only files that actually contain Express patterns
        route_files: list[Path] = []
        for file_path in candidates:
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                if self._is_express_file(content):
                    route_files.append(file_path)
            except OSError:
                continue

        return route_files

    @staticmethod
    def _is_express_file(content: str) -> bool:
        """Check if file content contains Express route patterns."""
        return any(
            indicator in content
            for indicator in ExpressRouteMapperConfig.ROUTER_FILE_INDICATORS
        )

    # ------------------------------------------------------------------
    # Route extraction
    # ------------------------------------------------------------------

    def _extract_routes(
        self, content: str, file_path: str
    ) -> list[RouteEntry]:
        """Extract Express route definitions from file content."""
        routes: list[RouteEntry] = []

        for match in re.finditer(
            ExpressRouteMapperConfig.ROUTE_DEFINITION_PATTERN, content
        ):
            method = match.group(1).upper()
            path = match.group(2)

            # Get the full line context for auth detection
            line_start = content.rfind("\n", 0, match.start()) + 1
            line_end = content.find("\n", match.end())
            if line_end == -1:
                line_end = len(content)
            line_context = content[line_start:line_end]

            has_auth = self._detect_auth_middleware(line_context)

            routes.append(
                RouteEntry(
                    file_path=file_path,
                    http_methods=[method] if method != "ALL" else list(
                        ExpressRouteMapperConfig.HTTP_METHODS
                    ),
                    route_pattern=path,
                    has_auth_check=has_auth,
                    content=content,
                )
            )

        return routes

    def _extract_mount_points(self, content: str) -> dict[str, str]:
        """Extract app.use mount points mapping prefix to router variable.

        Parses patterns like:
            app.use('/api/webhooks', webhookRouter)
            app.use('/trpc', verifyAuth, tenantContext, trpcMiddleware)
        """
        mounts: dict[str, str] = {}

        for match in re.finditer(
            ExpressRouteMapperConfig.MOUNT_PATTERN, content
        ):
            mount_path = match.group(1)
            # Extract the last argument (typically the router)
            rest_of_line = content[match.end():content.find("\n", match.end())]
            mounts[mount_path] = rest_of_line.strip()

        return mounts

    # ------------------------------------------------------------------
    # Auth middleware detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_auth_middleware(line_context: str) -> bool:
        """Detect if auth middleware is present in the route definition line."""
        return any(
            indicator in line_context
            for indicator in ExpressRouteMapperConfig.AUTH_MIDDLEWARE_INDICATORS
        )

    # ------------------------------------------------------------------
    # Mount prefix resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_mount_prefixes(
        routes: list[RouteEntry],
        mount_points: dict[str, str],
    ) -> list[RouteEntry]:
        """Resolve route paths with their mount prefixes.

        For now, routes already have their full paths from direct
        extraction.  Mount points are tracked for future cross-referencing
        with router modules.
        """
        # Mount points are useful metadata but routes extracted from
        # router.post('/stripe', ...) inside webhooks.js need the mount
        # prefix.  Since we can't always trace the import chain, we
        # keep routes as-is — the file path provides enough context
        # for downstream scanners.
        return routes

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_read(path: Path) -> str:
        """Read file content, returning empty string on failure."""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            logger.warning("Failed to read file: %s", path)
            return ""
