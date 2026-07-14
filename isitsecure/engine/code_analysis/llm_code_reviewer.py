"""LLM-powered security code reviewer with cross-scanner intelligence.

Uses Claude to analyze code for business logic vulnerabilities that
pattern matchers can't find:
- Missing ownership checks (authn != authz)
- Business logic flaws (any user can change any price)
- Race conditions in payment flows
- Incorrect RLS policy logic
- Auth bypass through alternative code paths

Cross-scanner intelligence: SAST findings from rule-based scanners
are used to prioritize which routes get LLM review and to provide
targeted context in the LLM prompt.

SRP: This class handles LLM interaction and response parsing.  Route
     selection is delegated to ``PrioritizedRouteSelector`` (DIP).

OCP: New review triggers are added via ``review_triggers.py`` without
     modifying this class.

Parallelized: routes are reviewed in batches of MAX_CONCURRENT_REVIEWS
to maximize throughput while respecting API rate limits.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)
from isitsecure.engine.code_analysis.review_triggers import (
    PrioritizedRouteSelector,
)
from isitsecure.engine.constants import (
    CrossScannerIntelligenceConfig,
    ImportGraphCentralityConfig,
    LLMCodeReviewConfig,
    RLSPolicyAnalyzerConfig,
    StaticInjectionConfig,
)
from isitsecure.engine.enums import ReviewTriggerType
from isitsecure.llm.protocol import LLMClientProtocol
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.code_analysis.category_classifier import (
    classify_finding_category,
)

logger = logging.getLogger(__name__)


class LLMCodeReviewer:
    """LLM-powered security code reviewer with cross-scanner intelligence.

    Implements CodeScannerProtocol.
    Depends on LLMClientProtocol and PrioritizedRouteSelector (DIP).
    """

    SEVERITY_MAP = {
        "CRITICAL": SeverityLevel.CRITICAL,
        "HIGH": SeverityLevel.HIGH,
        "MEDIUM": SeverityLevel.MEDIUM,
        "LOW": SeverityLevel.LOW,
    }

    # Map trigger types to specialized system prompts
    _TRIGGER_SYSTEM_PROMPTS = {
        ReviewTriggerType.FINANCIAL_OPERATION: (
            CrossScannerIntelligenceConfig.FINANCIAL_REVIEW_SYSTEM_PROMPT
        ),
        ReviewTriggerType.STATE_MUTATION: (
            CrossScannerIntelligenceConfig.MUTATION_REVIEW_SYSTEM_PROMPT
        ),
        ReviewTriggerType.IMPORT_GRAPH_CENTRALITY: (
            ImportGraphCentralityConfig.SHARED_HELPER_REVIEW_SYSTEM_PROMPT
        ),
        ReviewTriggerType.INJECTION_PATTERN_FLAG: (
            StaticInjectionConfig.INJECTION_REVIEW_SYSTEM_PROMPT
        ),
    }

    def __init__(
        self,
        llm_client: LLMClientProtocol,
        route_selector: PrioritizedRouteSelector | None = None,
    ) -> None:
        self._llm = llm_client
        self._route_selector = route_selector or PrioritizedRouteSelector()
        self._total_tokens_used = 0
        self._sast_findings: list[CodeFinding] = []
        self._auth_flows: dict[str, object] = {}

    @property
    def scanner_name(self) -> str:
        return LLMCodeReviewConfig.SCANNER_NAME

    # ------------------------------------------------------------------
    # Cross-scanner context (called by agent between Phase 7 and 8)
    # ------------------------------------------------------------------

    def set_sast_context(self, findings: list[CodeFinding]) -> None:
        """Provide SAST findings from rule-based scanners for context.

        Called by the agent orchestrator after Phase 7 (SAST) and
        before Phase 8 (LLM review).  The findings are used to:
        1. Prioritize which routes get reviewed (CrossScannerFlaggedTrigger)
        2. Enrich the LLM prompt with targeted context
        """
        self._sast_findings = findings

    def set_lsp_context(
        self, auth_flows: dict[str, object]
    ) -> None:
        """Provide LSP-resolved auth flow data for prompt enrichment.

        Called by the agent orchestrator after Phase 7.5 (LSP validation).
        When present, the LLM prompt includes resolved middleware chains
        and type info instead of relying on the LLM to infer them.
        """
        self._auth_flows = auth_flows

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Review prioritized routes and RLS policies with LLM.

        Routes are reviewed in parallel batches of MAX_CONCURRENT_REVIEWS
        for throughput. RLS review runs after all route reviews complete.
        """
        findings: list[CodeFinding] = []

        # Phase 1: Select routes using cross-scanner intelligence
        selected = self._route_selector.select_routes(
            repo, self._sast_findings
        )

        # Phase 2: Review routes in parallel batches
        batch_size = LLMCodeReviewConfig.MAX_CONCURRENT_REVIEWS
        for batch_start in range(0, len(selected), batch_size):
            batch = selected[batch_start : batch_start + batch_size]

            tasks = [
                self._review_route(route, repo, trigger_type)
                for route, trigger_type in batch
            ]

            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in batch_results:
                if isinstance(result, Exception):
                    logger.warning("LLM review failed: %s", result)
                else:
                    findings.extend(result)

        # Phase 3: Review RLS policies
        migration_sql = self._collect_migration_sql(repo)
        if migration_sql:
            rls_findings = await self._review_rls_policies(migration_sql, repo)
            findings.extend(rls_findings)

        logger.info(
            "LLMCodeReviewer: %d findings, ~%d tokens used, "
            "%d routes reviewed (%d from SAST context)",
            len(findings),
            self._total_tokens_used,
            len(selected),
            sum(
                1
                for _, t in selected
                if t == ReviewTriggerType.CROSS_SCANNER_FLAGGED
            ),
        )
        return findings

    # ------------------------------------------------------------------
    # LLM review: API routes (with trigger-specific prompts)
    # ------------------------------------------------------------------

    async def _review_route(
        self,
        route: RouteEntry,
        repo: RepoSnapshot,
        trigger_type: ReviewTriggerType,
    ) -> list[CodeFinding]:
        """Send a single route to LLM for review with context."""
        tables = self._extract_table_names(route.content)

        # Detect framework and language from the route's workspace context
        framework = self._detect_route_framework(route, repo)
        language = self._detect_language(route.file_path)

        # Build DB context (generalized — not Supabase-specific)
        db_context = (
            f"Database tables referenced: {', '.join(tables)}\n"
            if tables
            else ""
        )

        # Add line numbers to code so the LLM can reference exact lines
        numbered_code = self._add_line_numbers(
            route.content[: LLMCodeReviewConfig.MAX_FILE_SIZE_CHARS]
        )

        # Build the user prompt — use specialized prompt for non-route triggers
        if trigger_type == ReviewTriggerType.IMPORT_GRAPH_CENTRALITY:
            # Extract importer info from the synthetic route_pattern
            # Format: "[shared] path (imported by N risk routes: a, b, c)"
            importer_info = route.route_pattern.replace(
                ImportGraphCentralityConfig.SYNTHETIC_ROUTE_PREFIX, ""
            )
            user_prompt = ImportGraphCentralityConfig.SHARED_HELPER_USER_PROMPT.format(
                file_path=route.file_path,
                importer_count=importer_info.split("imported by ")[-1].split(" risk")[0] if "imported by" in importer_info else "multiple",
                importers=importer_info.split("routes: ")[-1].rstrip(")") if "routes: " in importer_info else "multiple route files",
                language=language,
                code=numbered_code,
                db_context=db_context,
            )
        elif trigger_type == ReviewTriggerType.INJECTION_PATTERN_FLAG:
            # Extract flagged patterns from synthetic route_pattern
            # Format: "[injection-check] path (injection patterns: SQL, XSS)"
            flagged = route.route_pattern.split("injection patterns: ")[-1].rstrip(")") if "injection patterns:" in route.route_pattern else "potential injection"
            user_prompt = StaticInjectionConfig.INJECTION_REVIEW_USER_PROMPT.format(
                file_path=route.file_path,
                flagged_patterns=flagged,
                language=language,
                code=numbered_code,
                db_context=db_context,
            )
        else:
            user_prompt = LLMCodeReviewConfig.ROUTE_REVIEW_USER_PROMPT.format(
                framework=framework,
                route_pattern=route.route_pattern,
                http_methods=", ".join(route.http_methods),
                file_path=route.file_path,
                language=language,
                code=numbered_code,
                db_context=db_context,
            )

        # Append SAST context for cross-scanner flagged routes
        if (
            trigger_type == ReviewTriggerType.CROSS_SCANNER_FLAGGED
            and self._sast_findings
        ):
            sast_context = self._build_sast_context(route, tables)
            if sast_context:
                user_prompt += (
                    CrossScannerIntelligenceConfig.SAST_CONTEXT_SECTION.format(
                        sast_context=sast_context
                    )
                )

        # Append LSP-resolved auth flow context when available
        lsp_context = self._build_lsp_context(route)
        if lsp_context:
            user_prompt += lsp_context

        # Select system prompt based on trigger type
        system_prompt = self._TRIGGER_SYSTEM_PROMPTS.get(
            trigger_type,
            LLMCodeReviewConfig.ROUTE_REVIEW_SYSTEM_PROMPT,
        )

        # Rough token estimate
        self._total_tokens_used += (
            len(user_prompt) // LLMCodeReviewConfig.CHARS_PER_TOKEN_ESTIMATE
        )

        try:
            response = await self._llm.generate_with_system(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=LLMCodeReviewConfig.MAX_TOKENS_PER_REVIEW,
            )

            self._total_tokens_used += (
                len(response) // LLMCodeReviewConfig.CHARS_PER_TOKEN_ESTIMATE
            )
            # Injection-triggered reviews default to INJECTION_RISK; general
            # route reviews default to AUTH_WEAKNESS. Per-finding keyword
            # classification refines both.
            default_category = (
                FindingCategory.INJECTION_RISK
                if trigger_type == ReviewTriggerType.INJECTION_PATTERN_FLAG
                else FindingCategory.AUTH_WEAKNESS
            )
            return self._parse_llm_findings(
                response, route.file_path, route.content, default_category
            )

        except Exception as e:
            logger.warning(
                LLMCodeReviewConfig.ERROR_LLM_REVIEW_FAILED.format(
                    file=route.file_path, error=str(e)
                )
            )
            return []

    # ------------------------------------------------------------------
    # LSP context builder
    # ------------------------------------------------------------------

    def _build_lsp_context(self, route: RouteEntry) -> str:
        """Build LSP-resolved auth flow context for the LLM prompt.

        When LSP data is available, provides the LLM with resolved
        middleware chains and auth methods instead of requiring it
        to infer them from raw code.
        """
        if not self._auth_flows:
            return ""

        key = f"{route.file_path}:{route.route_pattern}"
        flow = self._auth_flows.get(key)
        if flow is None:
            # Try file-only match
            for k, v in self._auth_flows.items():
                if k.startswith(route.file_path + ":"):
                    flow = v
                    break

        if flow is None:
            return ""

        # Build context string from AuthFlowResult
        from isitsecure.engine.code_analysis.lsp.protocols import (
            AuthFlowResult,
        )

        if not isinstance(flow, AuthFlowResult):
            return ""

        parts: list[str] = [
            "\n\nLSP Analysis (resolved via TypeScript Language Server):"
        ]

        if flow.has_verified_auth:
            chain = " → ".join(flow.middleware_chain) if flow.middleware_chain else "unknown"
            parts.append(
                f"- Auth: VERIFIED via {flow.auth_method} "
                f"(chain: {chain})"
            )
        else:
            parts.append("- Auth: NOT VERIFIED by LSP analysis")

        if flow.has_ownership_check:
            parts.append(
                f"- Ownership: VERIFIED via {flow.ownership_method}"
            )

        if flow.type_info:
            type_lines = [
                f"  {name}: {type_str}"
                for name, type_str in flow.type_info.items()
            ]
            parts.append("- Types:\n" + "\n".join(type_lines))

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # SAST context builder
    # ------------------------------------------------------------------

    def _build_sast_context(
        self,
        route: RouteEntry,
        route_tables: list[str],
    ) -> str:
        """Build SAST context string for routes flagged by cross-scanner.

        Finds SAST findings that are relevant to the entities (tables,
        endpoints) referenced by this route.
        """
        relevant: list[str] = []
        route_tables_lower = {t.lower() for t in route_tables}

        for finding in self._sast_findings:
            finding_text = f"{finding.title} {finding.description}".lower()

            # Check if finding mentions any table this route uses
            is_relevant = any(
                table in finding_text for table in route_tables_lower
            )

            # Check if finding mentions this route's pattern
            if not is_relevant and route.route_pattern:
                is_relevant = route.route_pattern.lower() in finding_text

            # Check if finding is from the same file
            if not is_relevant and finding.file_path:
                is_relevant = finding.file_path == route.file_path

            if is_relevant:
                relevant.append(
                    f"- [{finding.scanner_name}] {finding.severity.value.upper()}: "
                    f"{finding.title}"
                )

            if len(relevant) >= (
                CrossScannerIntelligenceConfig.MAX_SAST_CONTEXT_FINDINGS
            ):
                break

        return "\n".join(relevant)

    # ------------------------------------------------------------------
    # LLM review: RLS policies (unchanged)
    # ------------------------------------------------------------------

    async def _review_rls_policies(
        self, sql: str, repo: RepoSnapshot
    ) -> list[CodeFinding]:
        """Send RLS policies to LLM for review."""
        user_prompt = LLMCodeReviewConfig.RLS_REVIEW_USER_PROMPT.format(
            migration_sql=sql[: LLMCodeReviewConfig.MAX_FILE_SIZE_CHARS],
            known_tables=(
                ", ".join(r.route_pattern for r in repo.route_map[:20])
                if repo.route_map
                else "unknown"
            ),
        )

        self._total_tokens_used += (
            len(user_prompt) // LLMCodeReviewConfig.CHARS_PER_TOKEN_ESTIMATE
        )

        try:
            response = await self._llm.generate_with_system(
                system_prompt=LLMCodeReviewConfig.RLS_REVIEW_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                max_tokens=LLMCodeReviewConfig.MAX_TOKENS_PER_REVIEW,
            )

            self._total_tokens_used += (
                len(response) // LLMCodeReviewConfig.CHARS_PER_TOKEN_ESTIMATE
            )
            return self._parse_llm_findings(
                response,
                RLSPolicyAnalyzerConfig.DEFAULT_MIGRATION_DIR,
                default_category=FindingCategory.RLS_MISCONFIGURATION,
            )

        except Exception as e:
            logger.warning(
                LLMCodeReviewConfig.ERROR_LLM_REVIEW_FAILED.format(
                    file="rls_policies", error=str(e)
                )
            )
            return []

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_llm_findings(
        self,
        response: str,
        file_path: str,
        content: str = "",
        default_category: FindingCategory = FindingCategory.AUTH_WEAKNESS,
    ) -> list[CodeFinding]:
        """Parse LLM JSON response into CodeFinding objects.

        Each finding's category is inferred from its title/description via
        :func:`classify_finding_category`, falling back to ``default_category``
        (chosen by the review trigger) when no keyword rule matches. This keeps
        SQLi/XSS/IDOR/etc. out of the ``AUTH_WEAKNESS`` catch-all so
        category-based PR grouping stays meaningful.
        """
        from isitsecure.engine.shared.code_context import (
            CodeContextExtractor,
        )

        findings: list[CodeFinding] = []

        # Extract JSON array from response (may be wrapped in code block)
        json_match = re.search(r"\[.*\]", response, re.DOTALL)
        if not json_match:
            return findings

        try:
            items = json.loads(json_match.group(0))
        except json.JSONDecodeError as e:
            logger.debug(
                LLMCodeReviewConfig.ERROR_PARSE_RESPONSE.format(
                    error=str(e)
                )
            )
            return findings

        for item in items[: LLMCodeReviewConfig.MAX_FINDINGS_PER_FILE]:
            if not isinstance(item, dict):
                continue

            severity_str = item.get("severity", "MEDIUM").upper()
            severity = self.SEVERITY_MAP.get(
                severity_str, SeverityLevel.MEDIUM
            )

            line_number = item.get("line_number")

            # Validate and correct LLM-reported line number.
            # LLMs sometimes hallucinate line numbers. If the LLM
            # quoted a code pattern, search for it near the reported
            # line to find the true location.
            line_number = self._validate_line_number(
                content, line_number, item.get("description", "")
            )

            title = item.get(
                "title",
                LLMCodeReviewConfig.FALLBACK_FINDING_TITLE,
            )
            description = item.get("description", "")
            category = classify_finding_category(
                f"{title} {description}", default=default_category
            )

            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=severity,
                    category=category,
                    title=title,
                    description=description,
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=CodeContextExtractor.extract(
                        content, line_number
                    ) if content else "",
                    confidence=LLMCodeReviewConfig.CONFIDENCE_LLM_FINDING,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_route_framework(
        route: RouteEntry, repo: RepoSnapshot
    ) -> str:
        """Detect the framework for a specific route.

        In monorepos, the route's file path determines which workspace
        it belongs to, and thus which framework applies.
        """
        if repo.workspaces:
            for ws in repo.workspaces:
                if route.file_path.startswith(ws.path + "/") or route.file_path.startswith(ws.path + "\\"):
                    return ws.framework.value if hasattr(ws.framework, "value") else str(ws.framework)

        # tRPC routes
        if "/trpc/" in route.route_pattern:
            return "trpc"

        # Fallback to repo-level framework
        return repo.framework.value if hasattr(repo.framework, "value") else str(repo.framework)

    @staticmethod
    def _validate_line_number(
        content: str,
        reported_line: int | None,
        description: str,
    ) -> int | None:
        """Validate and correct an LLM-reported line number.

        LLMs sometimes hallucinate line numbers. This method extracts
        code identifiers from the title and description, then searches
        the file in expanding rings around the reported line.

        Returns the corrected line number, or the original if no
        better match is found.
        """
        if not content or not reported_line or reported_line < 1:
            return reported_line

        lines = content.splitlines()
        total = len(lines)

        if reported_line > total:
            reported_line = total

        # Extract identifiers from title + description
        text = description
        keywords: list[str] = []

        # Backtick-quoted code, single-quoted, method calls, camelCase ids
        for match in re.finditer(
            r'`([^`]{3,60})`|'
            r"'([^']{3,60})'|"
            r'\.(\w{3,40})\s*\(|'
            r'\b([a-z][a-zA-Z]{5,30})\b',
            text,
        ):
            kw = match.group(1) or match.group(2) or match.group(3) or match.group(4)
            if kw and len(kw) >= 4 and kw not in (
                "this", "that", "with", "from", "into", "which",
                "could", "should", "would", "because", "through",
                "between", "without", "before", "after",
            ):
                keywords.append(kw)

        if not keywords:
            return reported_line

        # Search in expanding rings: ±20, then full file
        unique_kws = list(dict.fromkeys(keywords))[:5]
        for search_radius in (20, total):
            start = max(0, reported_line - 1 - search_radius)
            end = min(total, reported_line + search_radius)
            for kw in unique_kws:
                for i in range(start, end):
                    if kw in lines[i]:
                        return i + 1

        return reported_line

    @staticmethod
    def _add_line_numbers(code: str) -> str:
        """Prepend line numbers to each line of code.

        This gives the LLM visible line references so it can report
        accurate line_number values instead of hallucinating them.
        """
        lines = code.splitlines()
        width = len(str(len(lines)))
        return "\n".join(
            f"{str(i + 1).rjust(width)} | {line}"
            for i, line in enumerate(lines)
        )

    @staticmethod
    def _detect_language(file_path: str) -> str:
        """Detect the code fence language from the file extension."""
        ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
        return {
            "ts": "typescript",
            "tsx": "typescript",
            "js": "javascript",
            "jsx": "javascript",
            "mjs": "javascript",
            "py": "python",
            "java": "java",
            "go": "go",
            "rb": "ruby",
            "rs": "rust",
            "sql": "sql",
        }.get(ext, "typescript")

    @staticmethod
    def _extract_table_names(content: str) -> list[str]:
        """Extract table names from code content.

        Handles multiple ORM patterns:
        - Supabase: .from("table_name")
        - Drizzle: .from(tableName) — imported schema objects
        - Supabase RPC: .rpc("function_name")
        - Drizzle insert/update/delete: .insert(table), .update(table)
        """
        tables: set[str] = set()
        # .from("string") — Supabase/Knex
        for match in re.finditer(
            r'\.from\s*\(\s*["\'](\w+)["\']', content
        ):
            tables.add(match.group(1))
        # .from(identifier) — Drizzle ORM
        for match in re.finditer(
            r'\.from\s*\(\s*([a-zA-Z]\w*)\s*\)', content
        ):
            tables.add(match.group(1))
        # .insert(table) / .update(table) / .delete(table) — Drizzle
        for match in re.finditer(
            r'\.(insert|update|delete)\s*\(\s*([a-zA-Z]\w*)\s*\)', content
        ):
            tables.add(match.group(2))
        # .rpc("function")
        for match in re.finditer(
            r'\.rpc\s*\(\s*["\'](\w+)["\']', content
        ):
            tables.add(f"rpc:{match.group(1)}")
        return sorted(tables)

    def _collect_migration_sql(self, repo: RepoSnapshot) -> str:
        """Collect all migration SQL content from the repo file index."""
        sql_parts: list[str] = []
        for file_path, content in repo.file_index.items():
            if file_path.endswith(".sql") and "migration" in file_path.lower():
                sql_parts.append(f"-- File: {file_path}\n{content}")
        return "\n\n".join(sql_parts)
