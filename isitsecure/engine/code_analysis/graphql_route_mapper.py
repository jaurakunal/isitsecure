"""Maps GraphQL schema definitions and resolvers to API routes.

SRP: This class is responsible ONLY for detecting GraphQL Query and
     Mutation fields from SDL files and code-first resolver patterns.
     It does not perform security analysis -- that is the job of
     downstream scanners.

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
from isitsecure.engine.constants import GraphQLRouteMapperConfig

logger = logging.getLogger(__name__)


class GraphQLRouteMapper:
    """Detects GraphQL Query and Mutation fields from source files.

    Handles:
    - SDL files (``.graphql``/``.gql``): ``type Query { ... }``
    - Extended types: ``extend type Mutation { ... }``
    - Code-first resolvers (Pothos, TypeGraphQL, Nexus, graphql-js)
    - Auth pattern detection in resolver files

    Conforms to ``RouteMapperProtocol``.
    """

    def map_routes(self, clone_path: str) -> list[RouteEntry]:
        """Scan for GraphQL field definitions in the codebase.

        Args:
            clone_path: Absolute path to the repo (or workspace) root.

        Returns:
            List of ``RouteEntry`` for each discovered GraphQL field.
        """
        root = Path(clone_path)
        routes: list[RouteEntry] = []

        # Phase 1: SDL files (.graphql / .gql)
        sdl_files = self._find_sdl_files(root)
        for file_path in sdl_files:
            try:
                content = self._safe_read(file_path)
                if not content:
                    continue
                relative = str(file_path.relative_to(root))
                sdl_routes = self._extract_sdl_fields(content, relative)
                routes.extend(sdl_routes)
            except Exception as e:
                logger.warning(
                    GraphQLRouteMapperConfig.ERROR_ROUTE_DETECTION_FAILED.format(
                        file=file_path, error=e
                    )
                )

        # Phase 2: Code-first resolver files (.ts / .js)
        resolver_files = self._find_resolver_files(root)
        for file_path in resolver_files:
            try:
                content = self._safe_read(file_path)
                if not content:
                    continue
                relative = str(file_path.relative_to(root))
                resolver_routes = self._extract_code_first_fields(
                    content, relative
                )
                routes.extend(resolver_routes)
            except Exception as e:
                logger.warning(
                    GraphQLRouteMapperConfig.ERROR_ROUTE_DETECTION_FAILED.format(
                        file=file_path, error=e
                    )
                )

        return routes

    # ------------------------------------------------------------------
    # File discovery
    # ------------------------------------------------------------------

    def _find_sdl_files(self, root: Path) -> list[Path]:
        """Find .graphql and .gql files containing type definitions."""
        candidates: list[Path] = []

        for source_dir_name in GraphQLRouteMapperConfig.SOURCE_DIRS:
            source_dir = root / source_dir_name
            if not source_dir.is_dir():
                continue
            for ext in GraphQLRouteMapperConfig.SDL_EXTENSIONS:
                for file_path in source_dir.rglob(f"*{ext}"):
                    candidates.append(file_path)

        # Also check root-level schema files
        for ext in GraphQLRouteMapperConfig.SDL_EXTENSIONS:
            for file_path in root.glob(f"*{ext}"):
                if file_path not in candidates:
                    candidates.append(file_path)

        return candidates

    def _find_resolver_files(self, root: Path) -> list[Path]:
        """Find JS/TS files containing code-first resolver patterns."""
        resolver_files: list[Path] = []

        for source_dir_name in GraphQLRouteMapperConfig.SOURCE_DIRS:
            source_dir = root / source_dir_name
            if not source_dir.is_dir():
                continue
            for ext in GraphQLRouteMapperConfig.CODE_EXTENSIONS:
                for file_path in source_dir.rglob(f"*{ext}"):
                    try:
                        content = file_path.read_text(
                            encoding="utf-8", errors="replace"
                        )
                        if self._is_resolver_file(content):
                            resolver_files.append(file_path)
                    except OSError:
                        continue

        return resolver_files

    @staticmethod
    def _is_resolver_file(content: str) -> bool:
        """Check if file content contains code-first GraphQL resolver patterns."""
        return any(
            re.search(pattern, content)
            for pattern in GraphQLRouteMapperConfig.RESOLVER_FILE_INDICATORS
        )

    # ------------------------------------------------------------------
    # SDL field extraction
    # ------------------------------------------------------------------

    def _extract_sdl_fields(
        self, content: str, file_path: str
    ) -> list[RouteEntry]:
        """Extract Query and Mutation fields from SDL type definitions.

        Handles both ``type Query { ... }`` and ``extend type Query { ... }``.
        """
        routes: list[RouteEntry] = []

        for match in re.finditer(
            GraphQLRouteMapperConfig.SDL_TYPE_BLOCK_PATTERN,
            content,
            re.DOTALL,
        ):
            type_name = match.group(1)  # "Query" or "Mutation"
            block_body = match.group(2)

            if type_name not in GraphQLRouteMapperConfig.OPERATION_TYPES:
                continue

            http_method = GraphQLRouteMapperConfig.OPERATION_TYPE_TO_METHOD[
                type_name
            ]

            # Extract individual field names from block body
            for field_match in re.finditer(
                GraphQLRouteMapperConfig.SDL_FIELD_NAME_PATTERN, block_body
            ):
                field_name = field_match.group(1)

                if self._is_introspection_or_federation_field(field_name):
                    continue

                route_pattern = (
                    GraphQLRouteMapperConfig.ROUTE_PREFIX_TEMPLATE.format(
                        type_name=type_name, field_name=field_name
                    )
                )

                routes.append(
                    RouteEntry(
                        file_path=file_path,
                        http_methods=[http_method],
                        route_pattern=route_pattern,
                        has_auth_check=None,
                        content=content,
                    )
                )

        return routes

    # ------------------------------------------------------------------
    # Code-first resolver extraction
    # ------------------------------------------------------------------

    def _extract_code_first_fields(
        self, content: str, file_path: str
    ) -> list[RouteEntry]:
        """Extract GraphQL fields from code-first resolver patterns.

        Supports Pothos, TypeGraphQL, Nexus, and raw graphql-js.
        """
        routes: list[RouteEntry] = []
        has_auth = self._detect_auth_pattern(content)

        # TypeGraphQL decorators: @Query() / @Mutation()
        for match in re.finditer(
            GraphQLRouteMapperConfig.TYPEGRAPHQL_DECORATOR_PATTERN, content
        ):
            operation_type = match.group(1)  # "Query" or "Mutation"
            # The method name follows on the next line
            method_match = re.search(
                GraphQLRouteMapperConfig.DECORATOR_METHOD_NAME_PATTERN,
                content[match.end():],
            )
            if not method_match:
                continue

            field_name = method_match.group(1)
            if self._is_introspection_or_federation_field(field_name):
                continue

            http_method = GraphQLRouteMapperConfig.OPERATION_TYPE_TO_METHOD.get(
                operation_type, "GET"
            )
            route_pattern = (
                GraphQLRouteMapperConfig.ROUTE_PREFIX_TEMPLATE.format(
                    type_name=operation_type, field_name=field_name
                )
            )

            routes.append(
                RouteEntry(
                    file_path=file_path,
                    http_methods=[http_method],
                    route_pattern=route_pattern,
                    has_auth_check=has_auth,
                    content=content,
                )
            )

        # Pothos / Nexus: t.field('fieldName', ...) or t.queryField / t.mutationField
        for match in re.finditer(
            GraphQLRouteMapperConfig.POTHOS_FIELD_PATTERN, content
        ):
            field_name = match.group(1)
            if self._is_introspection_or_federation_field(field_name):
                continue

            # Determine operation type from surrounding context
            operation_type = self._infer_operation_type_from_context(
                content, match.start()
            )
            http_method = GraphQLRouteMapperConfig.OPERATION_TYPE_TO_METHOD.get(
                operation_type, "GET"
            )
            route_pattern = (
                GraphQLRouteMapperConfig.ROUTE_PREFIX_TEMPLATE.format(
                    type_name=operation_type, field_name=field_name
                )
            )

            routes.append(
                RouteEntry(
                    file_path=file_path,
                    http_methods=[http_method],
                    route_pattern=route_pattern,
                    has_auth_check=has_auth,
                    content=content,
                )
            )

        # Nexus: queryField / mutationField top-level calls
        for match in re.finditer(
            GraphQLRouteMapperConfig.NEXUS_TOP_LEVEL_PATTERN, content
        ):
            operation_prefix = match.group(1)  # "query" or "mutation"
            field_name = match.group(2)

            if self._is_introspection_or_federation_field(field_name):
                continue

            operation_type = (
                "Query" if operation_prefix == "query" else "Mutation"
            )
            http_method = GraphQLRouteMapperConfig.OPERATION_TYPE_TO_METHOD[
                operation_type
            ]
            route_pattern = (
                GraphQLRouteMapperConfig.ROUTE_PREFIX_TEMPLATE.format(
                    type_name=operation_type, field_name=field_name
                )
            )

            routes.append(
                RouteEntry(
                    file_path=file_path,
                    http_methods=[http_method],
                    route_pattern=route_pattern,
                    has_auth_check=has_auth,
                    content=content,
                )
            )

        return routes

    # ------------------------------------------------------------------
    # Auth detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_auth_pattern(content: str) -> bool:
        """Detect if auth patterns are present in resolver content."""
        return any(
            indicator in content
            for indicator in GraphQLRouteMapperConfig.AUTH_INDICATORS
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_introspection_or_federation_field(field_name: str) -> bool:
        """Check if a field is a GraphQL introspection or federation field."""
        return field_name in GraphQLRouteMapperConfig.SKIP_FIELDS

    def _infer_operation_type_from_context(
        self, content: str, position: int
    ) -> str:
        """Infer whether a field belongs to Query or Mutation from context.

        Looks backward from the field position for type builder context
        like ``queryType``, ``mutationType``, ``queryField``.
        """
        # Look at the preceding 500 characters for context clues
        context_start = max(0, position - GraphQLRouteMapperConfig.CONTEXT_LOOKBACK_CHARS)
        preceding = content[context_start:position].lower()

        for mutation_indicator in GraphQLRouteMapperConfig.MUTATION_CONTEXT_INDICATORS:
            if mutation_indicator in preceding:
                return "Mutation"

        return "Query"

    @staticmethod
    def _safe_read(path: Path) -> str:
        """Read file content, returning empty string on failure."""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            logger.warning("Failed to read file: %s", path)
            return ""
