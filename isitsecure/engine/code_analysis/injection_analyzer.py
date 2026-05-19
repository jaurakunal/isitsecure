"""Injection pattern file selector for LLM review.

Uses regex patterns to FLAG files containing potential injection vectors
(SQL injection, XSS, command injection, path traversal), then delegates
those files to the LLM code reviewer for human-quality analysis.

This is a review trigger, not a finding-producing scanner.  Regex cannot
reliably distinguish ``db.query(`SELECT * FROM ${userInput}`)`` (dangerous)
from ``db.query(sql`SELECT * FROM ${safeConstant}`)`` (safe tagged template).
The LLM can, because it understands data flow and variable origins.

SRP: This class selects files.  The LLM reviewer produces findings.
OCP: New injection patterns are added to config, not to this class.
DIP: Depends on ``RepoSnapshot`` (abstraction), not concrete repo types.
"""

from __future__ import annotations

import logging
import re

from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)
from isitsecure.engine.constants import (
    CrossScannerIntelligenceConfig,
    StaticInjectionConfig,
)
from isitsecure.engine.enums import ReviewTriggerType

logger = logging.getLogger(__name__)


class InjectionPatternTrigger:
    """Select files containing injection-relevant patterns for LLM review.

    Files with SQL template literals, innerHTML assignments, exec/spawn
    calls, or fs operations with variable paths are flagged and sent to
    the LLM reviewer with a specialized injection-focused prompt.

    Unlike the old ``StaticInjectionAnalyzer``, this class does NOT
    produce findings.  It produces a list of ``RouteEntry`` objects
    (synthetic wrappers for non-route files) that the LLM reviewer
    will analyze.
    """

    @property
    def trigger_type(self) -> ReviewTriggerType:
        return ReviewTriggerType.INJECTION_PATTERN_FLAG

    @property
    def priority(self) -> int:
        return CrossScannerIntelligenceConfig.PRIORITY_INJECTION_PATTERN

    def select_files(
        self,
        repo: RepoSnapshot,
        selected_route_paths: set[str],
    ) -> list[RouteEntry]:
        """Select files with injection patterns that aren't already selected.

        Args:
            repo: Repository snapshot with file_index.
            selected_route_paths: Paths already selected by other triggers
                (these files will already get LLM review).

        Returns:
            Synthetic ``RouteEntry`` objects for flagged files.
        """
        if not repo.file_index:
            return []

        candidates: list[tuple[str, list[str]]] = []

        for file_path, content in repo.file_index.items():
            if not self._should_scan(file_path):
                continue

            # Skip files already selected by other triggers
            if file_path in selected_route_paths:
                continue

            # Check for injection patterns
            matched_types = self._detect_patterns(content)
            if matched_types:
                candidates.append((file_path, matched_types))

        # Sort by number of pattern types matched (more = higher risk)
        candidates.sort(key=lambda c: len(c[1]), reverse=True)

        # Cap to avoid token explosion
        selected = candidates[: StaticInjectionConfig.MAX_FILES_TO_FLAG]

        results: list[RouteEntry] = []
        for file_path, matched_types in selected:
            content = repo.file_index.get(file_path, "")
            if not content:
                continue

            types_str = ", ".join(matched_types)
            results.append(
                RouteEntry(
                    file_path=file_path,
                    content=content,
                    route_pattern=(
                        f"{StaticInjectionConfig.SYNTHETIC_ROUTE_PREFIX}"
                        f"{file_path} (injection patterns: {types_str})"
                    ),
                    http_methods=[],
                    has_auth_check=None,
                )
            )

        logger.info(
            "InjectionPatternTrigger: %d files flagged for LLM review "
            "(from %d scanned, %d already selected by other triggers)",
            len(results),
            sum(1 for fp in repo.file_index if self._should_scan(fp)),
            len(selected_route_paths),
        )
        return results

    @staticmethod
    def _should_scan(file_path: str) -> bool:
        """Check if a file should be scanned based on extension."""
        if not any(
            file_path.endswith(ext)
            for ext in StaticInjectionConfig.CODE_EXTENSIONS
        ):
            return False
        for skip in StaticInjectionConfig.SKIP_FILE_PATTERNS:
            if re.search(skip, file_path):
                return False
        return True

    @staticmethod
    def _detect_patterns(content: str) -> list[str]:
        """Detect which injection pattern types are present in the file.

        Returns a list of matched type names (e.g., ["SQL injection", "XSS"]).
        """
        matched: list[str] = []

        for label, patterns in StaticInjectionConfig.INJECTION_FLAG_PATTERNS:
            for pattern in patterns:
                if re.search(pattern, content):
                    matched.append(label)
                    break  # One match per type is enough

        return matched
