"""Import-graph centrality review trigger.

SRP: Selects non-route files with high fan-in from trigger-selected
     routes for LLM review.  Does NOT parse imports itself (delegated
     to ``ImportGraphBuilder``) or review code (delegated to the LLM
     reviewer).

DIP: Depends on ``ImportGraphBuilder`` (abstraction-level peer) and
     ``RepoSnapshot`` / ``RouteEntry`` data models, not on concrete
     scanners or LLM clients.

This trigger is invoked separately from the standard
``ReviewTriggerProtocol`` triggers because it requires knowledge of
which routes were already selected (the ``selected_route_paths`` set).
"""

from __future__ import annotations

import logging

from isitsecure.engine.code_analysis.import_graph import (
    ImportGraphBuilder,
)
from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)
from isitsecure.engine.constants import (
    CrossScannerIntelligenceConfig,
    ImportGraphCentralityConfig,
)
from isitsecure.engine.enums import ReviewTriggerType

logger = logging.getLogger(__name__)


class ImportGraphCentralityTrigger:
    """Select non-route files with high fan-in from trigger-selected routes.

    A file that is imported by many high-risk route files is
    security-relevant regardless of its content, because a bug there
    has high blast radius.  This catches shared helpers, middleware,
    DB layers, and utility modules that content heuristics would miss.
    """

    @property
    def trigger_type(self) -> ReviewTriggerType:
        return ReviewTriggerType.IMPORT_GRAPH_CENTRALITY

    @property
    def priority(self) -> int:
        return CrossScannerIntelligenceConfig.PRIORITY_IMPORT_CENTRALITY

    def select_files(
        self,
        repo: RepoSnapshot,
        selected_route_paths: set[str],
    ) -> list[RouteEntry]:
        """Select non-route files imported by many already-selected routes.

        Args:
            repo: The repository snapshot with file_index and route_map.
            selected_route_paths: File paths already selected by other
                review triggers (financial, cross-scanner, mutation, risk).

        Returns:
            Synthetic ``RouteEntry`` objects for non-route files to review,
            ordered by risk-importer count (descending).
        """
        if not repo.file_index or not selected_route_paths:
            return []

        # Build the import graph once
        builder = ImportGraphBuilder()
        fan_in_map = builder.build_fan_in_map(repo.file_index)

        # Route mappers produce workspace-relative paths (e.g., "src/routes/webhooks.js")
        # but file_index keys are clone-root-relative (e.g., "backend/src/routes/webhooks.js").
        # Build a suffix-match lookup so we can match across path conventions.
        file_index_keys = set(repo.file_index.keys())

        def _normalize_to_file_index(paths: set[str]) -> set[str]:
            """Map workspace-relative paths to file_index keys via suffix matching."""
            normalized: set[str] = set()
            for p in paths:
                if p in file_index_keys:
                    normalized.add(p)
                else:
                    # Suffix match: "src/routes/webhooks.js" → "backend/src/routes/webhooks.js"
                    for fi_key in file_index_keys:
                        if fi_key.endswith("/" + p) or fi_key == p:
                            normalized.add(fi_key)
                            break
            return normalized

        selected_normalized = _normalize_to_file_index(selected_route_paths)
        route_paths = _normalize_to_file_index(
            {r.file_path for r in repo.route_map}
        )

        # Score each non-route file by how many trigger-selected routes import it
        candidates: list[tuple[str, set[str]]] = []

        for imported_file, importers in fan_in_map.items():
            # Skip files that ARE routes (already handled by standard triggers)
            if imported_file in route_paths:
                continue

            # Skip files not in file_index (shouldn't happen, but safety check)
            if imported_file not in repo.file_index:
                continue

            # Count importers that are trigger-selected high-risk routes
            risk_importers = importers & selected_normalized
            if len(risk_importers) >= ImportGraphCentralityConfig.MIN_RISK_IMPORTER_COUNT:
                candidates.append((imported_file, risk_importers))

        # Sort by risk-importer count (highest blast radius first)
        candidates.sort(key=lambda c: len(c[1]), reverse=True)

        # Take top N and wrap as synthetic RouteEntry
        selected = candidates[: ImportGraphCentralityConfig.MAX_CENTRALITY_FILES]

        results: list[RouteEntry] = []
        for file_path, risk_importers in selected:
            content = repo.file_index.get(file_path, "")
            if not content:
                continue

            # Encode importer context into route_pattern for the LLM prompt
            importer_names = sorted(risk_importers)[:5]
            route_pattern = (
                f"{ImportGraphCentralityConfig.SYNTHETIC_ROUTE_PREFIX}"
                f"{file_path} (imported by {len(risk_importers)} risk "
                f"routes: {', '.join(importer_names)})"
            )

            results.append(
                RouteEntry(
                    file_path=file_path,
                    content=content,
                    route_pattern=route_pattern,
                    http_methods=[],
                    has_auth_check=None,
                )
            )

        logger.info(
            "Import-graph centrality: %d candidates, selected %d files "
            "(threshold: imported by >= %d risk routes)",
            len(candidates),
            len(results),
            ImportGraphCentralityConfig.MIN_RISK_IMPORTER_COUNT,
        )
        return results
