"""Maps tRPC router definitions to API routes.

SRP: This class is responsible ONLY for detecting tRPC procedure
     definitions from source files.  Security analysis of these
     procedures is handled by downstream scanners.

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
from isitsecure.engine.constants import TRPCRouteMapperConfig

logger = logging.getLogger(__name__)


class TRPCRouteMapper:
    """Detects tRPC procedure definitions from source files.

    Handles:
    - Router definitions: ``export const userRouter = router({...})``
    - Root router namespace mapping: ``user: userRouter``
    - Procedure extraction: ``getAll: protectedProcedure.query(...)``
    - Auth level detection: public vs protected vs tenant procedures

    Conforms to ``RouteMapperProtocol``.
    """

    def map_routes(self, clone_path: str) -> list[RouteEntry]:
        """Scan for tRPC procedure definitions in the codebase.

        Args:
            clone_path: Absolute path to the repo (or workspace) root.

        Returns:
            List of ``RouteEntry`` for each discovered tRPC procedure.
        """
        root = Path(clone_path)
        routes: list[RouteEntry] = []

        # Step 1: Find and parse the root router to get namespace mappings
        namespace_map = self._find_root_router_mappings(root)

        # Step 2: Find and parse all router definition files
        router_files = self._find_router_files(root)

        for file_path in router_files:
            try:
                content = self._safe_read(file_path)
                if not content:
                    continue

                relative = str(file_path.relative_to(root))

                # Extract router name from export
                router_name = self._extract_router_name(content)

                # Resolve namespace from root router mapping
                namespace = self._resolve_namespace(
                    router_name, namespace_map
                )

                # Extract procedures
                procedures = self._extract_procedures(
                    content, relative, namespace
                )
                routes.extend(procedures)

            except Exception as e:
                logger.warning(
                    TRPCRouteMapperConfig.ERROR_ROUTE_DETECTION_FAILED.format(
                        file=file_path, error=e
                    )
                )

        return routes

    # ------------------------------------------------------------------
    # Root router discovery
    # ------------------------------------------------------------------

    def _find_root_router_mappings(
        self, root: Path
    ) -> dict[str, str]:
        """Find the root tRPC router and extract namespace mappings.

        Parses patterns like:
            export const appRouter = router({
                tenant: tenantRouter,
                user: userRouter,
                admin: adminRouter,
            });

        Returns:
            Mapping of router variable name → namespace prefix.
            e.g. {"tenantRouter": "tenant", "userRouter": "user"}
        """
        namespace_map: dict[str, str] = {}

        # Search common root router locations
        root_router_candidates = [
            "root.js", "root.ts", "index.js", "index.ts",
            "_app.js", "_app.ts", "router.js", "router.ts",
        ]

        for source_dir_name in TRPCRouteMapperConfig.SOURCE_DIRS:
            source_dir = root / source_dir_name
            if not source_dir.is_dir():
                continue

            for candidate in root_router_candidates:
                file_path = source_dir / candidate
                if not file_path.is_file():
                    continue

                content = self._safe_read(file_path)
                if not content:
                    continue

                # Check if this is a root router file
                if not self._is_root_router(content):
                    continue

                # Extract namespace mappings
                for match in re.finditer(
                    TRPCRouteMapperConfig.ROOT_ROUTER_MAPPING_PATTERN,
                    content,
                ):
                    namespace = match.group(1)
                    router_var = match.group(2)
                    namespace_map[router_var] = namespace

        return namespace_map

    @staticmethod
    def _is_root_router(content: str) -> bool:
        """Check if file defines a root tRPC router (combines sub-routers)."""
        # Root router typically imports multiple routers and combines them
        router_import_count = len(
            re.findall(r'import\s+.*Router', content)
        )
        has_router_call = bool(
            re.search(r'(?:router|createTRPCRouter)\s*\(\s*\{', content)
        )
        return router_import_count >= 2 and has_router_call

    # ------------------------------------------------------------------
    # Router file discovery
    # ------------------------------------------------------------------

    def _find_router_files(self, root: Path) -> list[Path]:
        """Find files that contain tRPC router definitions."""
        router_files: list[Path] = []

        for source_dir_name in TRPCRouteMapperConfig.SOURCE_DIRS:
            source_dir = root / source_dir_name
            if not source_dir.is_dir():
                continue

            for ext in TRPCRouteMapperConfig.CODE_EXTENSIONS:
                for file_path in source_dir.rglob(f"*{ext}"):
                    try:
                        content = file_path.read_text(
                            encoding="utf-8", errors="replace"
                        )
                        if self._is_router_file(content):
                            router_files.append(file_path)
                    except OSError:
                        continue

        return router_files

    @staticmethod
    def _is_router_file(content: str) -> bool:
        """Check if file defines a tRPC router with procedures."""
        return any(
            re.search(pattern, content)
            for pattern in TRPCRouteMapperConfig.ROUTER_DEFINITION_PATTERNS
        ) and bool(re.search(r'\.(query|mutation|subscription)\s*\(', content))

    # ------------------------------------------------------------------
    # Procedure extraction
    # ------------------------------------------------------------------

    def _extract_procedures(
        self,
        content: str,
        file_path: str,
        namespace: str,
    ) -> list[RouteEntry]:
        """Extract tRPC procedure definitions from router file content.

        Args:
            content: File content.
            file_path: Relative file path.
            namespace: Router namespace prefix (e.g. "admin", "purchase").

        Returns:
            List of RouteEntry for each procedure.
        """
        procedures: list[RouteEntry] = []

        for match in re.finditer(
            TRPCRouteMapperConfig.PROCEDURE_PATTERN, content
        ):
            procedure_name = match.group(1)
            procedure_base = match.group(2)
            procedure_type = match.group(3)

            # Build the full route pattern: /trpc/namespace.procedureName
            if namespace:
                route_pattern = f"/trpc/{namespace}.{procedure_name}"
            else:
                route_pattern = f"/trpc/{procedure_name}"

            # Map procedure type to HTTP method
            http_method = TRPCRouteMapperConfig.PROCEDURE_TYPE_TO_METHOD.get(
                procedure_type, "GET"
            )

            # Determine auth level
            auth_level = TRPCRouteMapperConfig.PROCEDURE_AUTH_MAP.get(
                procedure_base,
                TRPCRouteMapperConfig.AUTH_LEVEL_PUBLIC,
            )
            has_auth = auth_level != TRPCRouteMapperConfig.AUTH_LEVEL_PUBLIC

            procedures.append(
                RouteEntry(
                    file_path=file_path,
                    http_methods=[http_method],
                    route_pattern=route_pattern,
                    has_auth_check=has_auth,
                    content=content,
                )
            )

        return procedures

    # ------------------------------------------------------------------
    # Name resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_router_name(content: str) -> str:
        """Extract the router variable name from the file export.

        Matches: ``export const adminRouter = router({...})``
        Returns: ``adminRouter`` or empty string.
        """
        match = re.search(
            TRPCRouteMapperConfig.ROUTER_NAME_PATTERN, content
        )
        return match.group(1) if match else ""

    @staticmethod
    def _resolve_namespace(
        router_name: str,
        namespace_map: dict[str, str],
    ) -> str:
        """Resolve the namespace prefix for a router.

        Uses the root router mapping (e.g. adminRouter → "admin").
        Falls back to stripping "Router" suffix from the variable name.
        """
        if router_name in namespace_map:
            return namespace_map[router_name]

        # Fallback: strip "Router" suffix
        if router_name.endswith("Router"):
            return router_name[: -len("Router")]

        return router_name

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
