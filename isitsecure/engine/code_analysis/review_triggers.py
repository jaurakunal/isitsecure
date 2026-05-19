"""Review trigger strategies for LLM code review prioritization.

SRP: Each trigger strategy has ONE responsibility — deciding whether a
     route should be reviewed, based on a specific criterion.

OCP: New triggers are added as new classes implementing
     ``ReviewTriggerProtocol``, then appended to the trigger list in
     ``PrioritizedRouteSelector`` — no existing code changes.

DIP: All triggers depend on ``ReviewTriggerProtocol`` (abstraction).
     The ``PrioritizedRouteSelector`` depends on the protocol, not
     on any concrete trigger class.

LSP: Every trigger is substitutable — the selector iterates them
     uniformly regardless of their internal logic.
"""

from __future__ import annotations

import re
from typing import Protocol, runtime_checkable

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)
from isitsecure.engine.constants import (
    CrossScannerIntelligenceConfig,
    LLMCodeReviewConfig,
    RouteAuthAnalyzerConfig,
)
from isitsecure.engine.enums import ReviewTriggerType


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ReviewTriggerProtocol(Protocol):
    """Protocol for LLM review trigger strategies."""

    @property
    def trigger_type(self) -> ReviewTriggerType: ...

    @property
    def priority(self) -> int: ...

    def select_routes(
        self,
        repo: RepoSnapshot,
        sast_findings: list[CodeFinding],
    ) -> list[RouteEntry]: ...


# ---------------------------------------------------------------------------
# Trigger 1: Financial operations (Priority 0 — always reviewed)
# ---------------------------------------------------------------------------


class FinancialOperationTrigger:
    """Select routes containing payment/financial operations.

    These are ALWAYS sent to the LLM regardless of other risk
    indicators, because business logic flaws in payment flows are
    critical and undetectable by regex (race conditions, double-spend,
    price manipulation).

    Uses BOTH route pattern and content to avoid false positives: a
    ``/health`` route should not be flagged just because the file also
    contains a comment mentioning "payout".
    """

    # Route patterns that strongly indicate financial operations
    _FINANCIAL_ROUTE_INDICATORS = (
        "payment", "checkout", "purchase", "subscribe", "subscription",
        "billing", "invoice", "refund", "payout", "charge", "stripe",
        "order", "cart", "wallet", "transfer", "credit",
    )

    @property
    def trigger_type(self) -> ReviewTriggerType:
        return ReviewTriggerType.FINANCIAL_OPERATION

    @property
    def priority(self) -> int:
        return CrossScannerIntelligenceConfig.PRIORITY_FINANCIAL

    def select_routes(
        self,
        repo: RepoSnapshot,
        sast_findings: list[CodeFinding],
    ) -> list[RouteEntry]:
        return [
            route
            for route in repo.route_map
            if route.content and self._is_financial_route(route)
        ]

    @classmethod
    def _is_financial_route(cls, route: RouteEntry) -> bool:
        """Check if a route is financial using both pattern and content.

        A route is considered financial if:
        1. Its route pattern contains a financial keyword (strong signal), OR
        2. Its file content has multiple financial patterns AND is a
           mutation (POST/PUT/PATCH/DELETE) — not just a file that
           mentions "payout" in a comment.
        """
        pattern_lower = route.route_pattern.lower()

        # Strong signal: route pattern itself is financial
        if any(
            ind in pattern_lower for ind in cls._FINANCIAL_ROUTE_INDICATORS
        ):
            return True

        # Weaker signal: content has financial patterns — require mutation method
        # AND at least 2 distinct financial pattern matches (not just a comment)
        is_mutation = any(
            m in route.http_methods for m in ("POST", "PUT", "PATCH", "DELETE")
        )
        if not is_mutation:
            return False

        content_lower = route.content.lower()
        match_count = sum(
            1
            for pattern in CrossScannerIntelligenceConfig.FINANCIAL_PATTERNS
            if re.search(pattern, content_lower)
        )
        return match_count >= 2


# ---------------------------------------------------------------------------
# Trigger 2: Cross-scanner flagged entities (Priority 1)
# ---------------------------------------------------------------------------


class CrossScannerFlaggedTrigger:
    """Select routes that interact with entities flagged by SAST scanners.

    When a SAST scanner flags a table or endpoint, this trigger finds
    routes that reference that entity so the LLM can analyze how the
    route interacts with the flagged resource.
    """

    @property
    def trigger_type(self) -> ReviewTriggerType:
        return ReviewTriggerType.CROSS_SCANNER_FLAGGED

    @property
    def priority(self) -> int:
        return CrossScannerIntelligenceConfig.PRIORITY_CROSS_SCANNER

    def select_routes(
        self,
        repo: RepoSnapshot,
        sast_findings: list[CodeFinding],
    ) -> list[RouteEntry]:
        if not sast_findings:
            return []

        flagged_tables = self._extract_flagged_tables(sast_findings)
        flagged_routes = self._extract_flagged_routes(sast_findings)

        if not flagged_tables and not flagged_routes:
            return []

        selected: list[RouteEntry] = []
        for route in repo.route_map:
            if not route.content:
                continue

            # Check if route references a flagged table
            route_tables = self._extract_tables_from_code(route.content)
            if route_tables & flagged_tables:
                selected.append(route)
                continue

            # Check if route matches a flagged route pattern
            if any(
                flagged in route.route_pattern
                for flagged in flagged_routes
            ):
                selected.append(route)

        return selected

    @staticmethod
    def _extract_flagged_tables(
        findings: list[CodeFinding],
    ) -> set[str]:
        """Extract table names from SAST finding titles and descriptions."""
        tables: set[str] = set()
        for finding in findings:
            text = f"{finding.title} {finding.description}"
            for match in re.finditer(
                CrossScannerIntelligenceConfig.TABLE_NAME_FROM_FINDING_PATTERN,
                text,
                re.IGNORECASE,
            ):
                tables.add(match.group(1).lower())
        return tables

    @staticmethod
    def _extract_flagged_routes(
        findings: list[CodeFinding],
    ) -> set[str]:
        """Extract route patterns from SAST finding titles and descriptions."""
        routes: set[str] = set()
        for finding in findings:
            text = f"{finding.title} {finding.description}"
            for match in re.finditer(
                CrossScannerIntelligenceConfig.ROUTE_FROM_FINDING_PATTERN,
                text,
                re.IGNORECASE,
            ):
                routes.add(match.group(1))
        return routes

    @staticmethod
    def _extract_tables_from_code(content: str) -> set[str]:
        """Extract table names referenced in route code."""
        tables: set[str] = set()
        for pattern in (
            CrossScannerIntelligenceConfig.TABLE_REFERENCE_IN_CODE_PATTERNS
        ):
            for match in re.finditer(pattern, content):
                tables.add(match.group(1).lower())
        return tables


# ---------------------------------------------------------------------------
# Trigger 3: State mutations with conditional logic (Priority 2)
# ---------------------------------------------------------------------------


class StateMutationTrigger:
    """Select routes with database mutations AND conditional logic.

    Files that both mutate state and have conditional branching are
    prone to TOCTOU race conditions and authorization bypass through
    alternative code paths.
    """

    @property
    def trigger_type(self) -> ReviewTriggerType:
        return ReviewTriggerType.STATE_MUTATION

    @property
    def priority(self) -> int:
        return CrossScannerIntelligenceConfig.PRIORITY_MUTATION

    def select_routes(
        self,
        repo: RepoSnapshot,
        sast_findings: list[CodeFinding],
    ) -> list[RouteEntry]:
        return [
            route
            for route in repo.route_map
            if route.content
            and self._has_mutations(route.content)
            and self._has_conditionals(route.content)
        ]

    @staticmethod
    def _has_mutations(content: str) -> bool:
        """Check if content has database mutation patterns."""
        return any(
            re.search(pattern, content)
            for pattern in CrossScannerIntelligenceConfig.MUTATION_PATTERNS
        )

    @staticmethod
    def _has_conditionals(content: str) -> bool:
        """Check if content has conditional logic patterns."""
        return any(
            re.search(pattern, content)
            for pattern in CrossScannerIntelligenceConfig.CONDITIONAL_PATTERNS
        )


# ---------------------------------------------------------------------------
# Trigger 4: Existing risk indicators (Priority 3 — backward compat)
# ---------------------------------------------------------------------------


class RiskIndicatorTrigger:
    """Select routes with static risk indicators.

    Preserves the original LLMCodeReviewer risk selection logic:
    no auth check, user-supplied IDs without ownership, service_role.
    """

    @property
    def trigger_type(self) -> ReviewTriggerType:
        return ReviewTriggerType.RISK_INDICATOR

    @property
    def priority(self) -> int:
        return CrossScannerIntelligenceConfig.PRIORITY_RISK_INDICATOR

    def select_routes(
        self,
        repo: RepoSnapshot,
        sast_findings: list[CodeFinding],
    ) -> list[RouteEntry]:
        return [
            route
            for route in repo.route_map
            if route.content and self._has_risk_indicators(route.content)
        ]

    @staticmethod
    def _has_risk_indicators(content: str) -> bool:
        """Check for risk indicators (original LLMCodeReviewer logic)."""
        has_auth = any(
            re.search(p, content)
            for p in RouteAuthAnalyzerConfig.AUTH_CHECK_PATTERNS
        )
        if not has_auth:
            return True

        has_user_id = any(
            re.search(p, content)
            for p in RouteAuthAnalyzerConfig.USER_SUPPLIED_ID_PATTERNS
        )
        has_ownership = any(
            re.search(p, content)
            for p in RouteAuthAnalyzerConfig.OWNERSHIP_CHECK_PATTERNS
        )
        if has_user_id and not has_ownership:
            return True

        if any(
            re.search(p, content)
            for p in RouteAuthAnalyzerConfig.SERVICE_ROLE_PATTERNS
        ):
            return True

        return False


# ---------------------------------------------------------------------------
# Compositor: PrioritizedRouteSelector
# ---------------------------------------------------------------------------


class PrioritizedRouteSelector:
    """Composes multiple review triggers with priority-based deduplication.

    Runs triggers in priority order, collects routes, deduplicates
    (higher-priority trigger wins), and respects the file review budget.

    OCP: New triggers are added to the constructor list — no changes
    to this class.
    """

    def __init__(
        self,
        triggers: list[ReviewTriggerProtocol] | None = None,
    ) -> None:
        self._triggers = sorted(
            triggers or self._default_triggers(),
            key=lambda t: t.priority,
        )

    @staticmethod
    def _default_triggers() -> list[ReviewTriggerProtocol]:
        """Create the default set of review triggers."""
        return [
            FinancialOperationTrigger(),
            CrossScannerFlaggedTrigger(),
            StateMutationTrigger(),
            RiskIndicatorTrigger(),
        ]

    def select_routes(
        self,
        repo: RepoSnapshot,
        sast_findings: list[CodeFinding],
        max_files: int = LLMCodeReviewConfig.MAX_FILES_TO_REVIEW,
        max_file_size: int = LLMCodeReviewConfig.MAX_FILE_SIZE_CHARS,
    ) -> list[tuple[RouteEntry, ReviewTriggerType]]:
        """Select routes for LLM review with priority-based deduplication.

        Runs standard triggers first (financial, cross-scanner, mutation,
        risk), then a second pass for import-graph centrality (shared
        helpers imported by the already-selected high-risk routes).

        Returns:
            List of ``(route, trigger_type)`` tuples, ordered by trigger
            priority.  Higher-priority triggers are listed first; if the
            token budget runs out, lower-priority routes are dropped.
        """
        seen_paths: set[str] = set()
        result: list[tuple[RouteEntry, ReviewTriggerType]] = []

        # Phase 1: Standard route-based triggers
        for trigger in self._triggers:
            if len(result) >= max_files:
                break

            routes = trigger.select_routes(repo, sast_findings)

            for route in routes:
                if len(result) >= max_files:
                    break

                # Skip already-selected routes (higher-priority trigger won)
                if route.file_path in seen_paths:
                    continue

                # Skip oversized files
                if len(route.content) > max_file_size:
                    continue

                # Skip empty content
                if not route.content:
                    continue

                seen_paths.add(route.file_path)
                result.append((route, trigger.trigger_type))

        # Phase 2+3: File-based triggers (import centrality, injection).
        # These select non-route files and need the already-selected set.
        if len(result) < max_files and repo.file_index:
            from isitsecure.engine.code_analysis.import_centrality_trigger import (
                ImportGraphCentralityTrigger,
            )
            from isitsecure.engine.code_analysis.injection_analyzer import (
                InjectionPatternTrigger,
            )

            file_triggers = [
                ImportGraphCentralityTrigger(),
                InjectionPatternTrigger(),
            ]

            for trigger in file_triggers:
                if len(result) >= max_files:
                    break
                self._collect_file_trigger_results(
                    trigger, repo, seen_paths, result,
                    max_files, max_file_size,
                )

        return result

    @staticmethod
    def _collect_file_trigger_results(
        trigger,
        repo: RepoSnapshot,
        seen_paths: set[str],
        result: list,
        max_files: int,
        max_file_size: int,
    ) -> None:
        """Run a file-based trigger and append results.

        Shared logic for import-centrality and injection triggers
        (DRY — avoids duplicating the filter/dedup/cap loop).
        """
        files = trigger.select_files(repo, set(seen_paths))
        for route in files:
            if len(result) >= max_files:
                break
            if route.file_path in seen_paths:
                continue
            if len(route.content) > max_file_size:
                continue
            if not route.content:
                continue
            seen_paths.add(route.file_path)
            result.append((route, trigger.trigger_type))
