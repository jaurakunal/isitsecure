"""Supabase RLS policy analyzer.

Parses SQL migration files to analyze Row Level Security coverage:
1. Which tables have RLS enabled
2. Which tables have no policies defined
3. Which policies are overly permissive (USING (true))
4. Which policies don't use auth.uid()
"""

from __future__ import annotations

import logging
import re
from typing import Any

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import RLSPolicyAnalyzerConfig
from isitsecure.engine.enums import BackendType, FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class RLSPolicyAnalyzer:
    """Analyzes Supabase migration files for RLS policy coverage.

    Implements CodeScannerProtocol.
    """

    # Internal tables managed by Supabase/PostgREST that don't need user RLS
    SYSTEM_TABLES = frozenset({
        "schema_migrations", "migrations", "seed",
    })

    @property
    def scanner_name(self) -> str:
        return RLSPolicyAnalyzerConfig.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Analyze all migration files for RLS issues.

        Args:
            repo: Repository snapshot with file_index and migration_files.

        Returns:
            List of code findings for RLS misconfigurations.
        """
        findings: list[CodeFinding] = []

        migration_content = self._collect_migrations(repo)
        if not migration_content:
            return findings

        tables = self._extract_tables(migration_content)
        rls_enabled = self._extract_rls_enabled(migration_content)
        policies = self._extract_policies(migration_content)

        for table in sorted(tables):
            if table in self.SYSTEM_TABLES:
                continue

            try:
                table_findings = self._analyze_table(
                    table, rls_enabled, policies, migration_content
                )
                findings.extend(table_findings)
            except Exception as exc:
                logger.debug(
                    RLSPolicyAnalyzerConfig.ERROR_ANALYSIS_FAILED.format(
                        file=table, error=str(exc)
                    )
                )

        logger.info(
            "RLSPolicyAnalyzer: %d tables, %d findings",
            len(tables), len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # Migration collection
    # ------------------------------------------------------------------

    def _collect_migrations(
        self, repo: RepoSnapshot
    ) -> dict[str, str]:
        """Collect Supabase migration file contents (sorted by path = apply order).

        Returns:
            Mapping of file path to SQL content.
        """
        migrations: dict[str, str] = {}

        for file_path, content in repo.file_index.items():
            if file_path.endswith(".sql") and "migration" in file_path.lower():
                migrations[file_path] = content

        # Include explicitly listed migration files
        for mf in repo.migration_files:
            if mf not in migrations and mf in repo.file_index:
                migrations[mf] = repo.file_index[mf]

        supabase_repo = repo.backend == BackendType.SUPABASE
        return {
            path: migrations[path]
            for path in sorted(migrations)
            if supabase_repo or self._is_supabase_sql(path, migrations[path])
        }

    @staticmethod
    def _is_supabase_sql(path: str, content: str) -> bool:
        """True for SQL under supabase/ or using Supabase-specific constructs."""
        if RLSPolicyAnalyzerConfig.SUPABASE_PATH_MARKER in path.lower():
            return True
        return any(
            re.search(p, content, re.IGNORECASE)
            for p in RLSPolicyAnalyzerConfig.SUPABASE_SQL_MARKERS
        )

    # ------------------------------------------------------------------
    # SQL parsing
    # ------------------------------------------------------------------

    def _extract_tables(self, migrations: dict[str, str]) -> set[str]:
        """Tables that exist after replaying all migrations in order."""
        return self._replay(migrations)[0]

    def _extract_rls_enabled(self, migrations: dict[str, str]) -> set[str]:
        """Tables that have RLS enabled after replaying all migrations."""
        return self._replay(migrations)[1]

    def _extract_policies(
        self, migrations: dict[str, str]
    ) -> dict[str, list[dict[str, Any]]]:
        """Extract the surviving policies per table.

        Returns:
            Mapping of table name to list of policy dicts with keys:
            name, for_operation, using, with_check, roles.
        """
        return self._replay(migrations)[2]

    @staticmethod
    def _statements(content: str) -> list[str]:
        """Split SQL into statements with comments removed."""
        content = re.sub(r"/\*.*?\*/", " ", content, flags=re.DOTALL)
        content = re.sub(r"--[^\n]*", " ", content)
        # An unterminated "/*" comments out the rest of the file: earlier
        # statements stay analysed, nothing after it is executed.
        content = content.split("/*", 1)[0]
        return [stmt.strip() for stmt in content.split(";") if stmt.strip()]

    @staticmethod
    def _first_group(match: re.Match[str], count: int) -> str:
        """First non-empty group among the leading ``count`` name alternatives."""
        return next((g for g in match.groups()[:count] if g), "")

    def _replay(
        self, migrations: dict[str, str]
    ) -> tuple[set[str], set[str], dict[str, list[dict[str, Any]]]]:
        """Apply statements in file order so DISABLE/DROP undo earlier state."""
        cfg = RLSPolicyAnalyzerConfig
        tables: set[str] = set()
        rls_enabled: set[str] = set()
        policies: dict[str, list[dict[str, Any]]] = {}
        flags = re.IGNORECASE | re.DOTALL

        for content in migrations.values():
            for stmt in self._statements(content):
                if m := re.match(cfg.CREATE_TABLE_PATTERN, stmt, flags):
                    tables.add(m.group(1))
                elif m := re.match(cfg.DROP_TABLE_PATTERN, stmt, flags):
                    for raw in m.group(1).split(","):
                        name = re.sub(r"(?i)\s+(cascade|restrict)\s*$", "", raw.strip())
                        name = name.split(".")[-1].strip("\"' ")
                        tables.discard(name)
                        rls_enabled.discard(name)
                        policies.pop(name, None)
                elif m := re.match(cfg.ENABLE_RLS_PATTERN, stmt, flags):
                    rls_enabled.add(m.group(1))
                elif m := re.match(cfg.DISABLE_RLS_PATTERN, stmt, flags):
                    rls_enabled.discard(m.group(1))
                elif m := re.match(cfg.DROP_POLICY_PATTERN, stmt, flags):
                    name, table = self._first_group(m, 3), m.group(4)
                    policies[table] = [
                        p for p in policies.get(table, []) if p["name"] != name
                    ]
                elif m := re.match(cfg.CREATE_POLICY_PATTERN, stmt, flags):
                    name, table = self._first_group(m, 3), m.group(4)
                    policies.setdefault(table, []).append(
                        self._parse_policy(name, stmt[m.end():])
                    )
        return tables, rls_enabled, policies

    def _parse_policy(self, name: str, rest: str) -> dict[str, Any]:
        """Build a policy dict from the text following ``CREATE POLICY n ON t``."""
        for_match = re.search(
            RLSPolicyAnalyzerConfig.POLICY_FOR_PATTERN, rest, re.IGNORECASE
        )
        roles_match = re.search(
            RLSPolicyAnalyzerConfig.POLICY_ROLES_PATTERN, rest, re.IGNORECASE
        )
        roles = (
            [r.strip().strip('"').lower() for r in roles_match.group(1).split(",")]
            if roles_match
            else []
        )
        return {
            "name": name,
            "for_operation": for_match.group(1).upper() if for_match else "ALL",
            "using": self._extract_clause(rest, "USING"),
            "with_check": self._extract_clause(rest, "WITH\\s+CHECK"),
            "roles": roles,
        }

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def _analyze_table(
        self,
        table: str,
        rls_enabled: set[str],
        policies: dict[str, list[dict[str, Any]]],
        migrations: dict[str, str],
    ) -> list[CodeFinding]:
        """Analyze a single table for RLS issues."""
        findings: list[CodeFinding] = []
        file_path = self._find_table_file(table, migrations)

        # Check 1: RLS not enabled
        if table not in rls_enabled:
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.CRITICAL,
                    category=FindingCategory.RLS_MISCONFIGURATION,
                    title=RLSPolicyAnalyzerConfig.TITLE_NO_RLS.format(
                        table=table
                    ),
                    description=RLSPolicyAnalyzerConfig.DESC_NO_RLS.format(
                        table=table, file=file_path
                    ),
                    file_path=file_path,
                    confidence=RLSPolicyAnalyzerConfig.CONFIDENCE_NO_RLS,
                )
            )
            return findings  # No point checking policies if RLS is off

        # Check 2: RLS enabled but no policies
        table_policies = policies.get(table, [])
        if not table_policies:
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.HIGH,
                    category=FindingCategory.RLS_MISCONFIGURATION,
                    title=RLSPolicyAnalyzerConfig.TITLE_NO_POLICIES.format(
                        table=table
                    ),
                    description=RLSPolicyAnalyzerConfig.DESC_NO_POLICIES.format(
                        table=table
                    ),
                    file_path=file_path,
                    confidence=RLSPolicyAnalyzerConfig.CONFIDENCE_NO_POLICIES,
                )
            )
            return findings

        # Check 3 & 4: Analyze individual policies
        for policy in table_policies:
            policy_findings = self._analyze_policy(table, policy, file_path)
            findings.extend(policy_findings)

        return findings

    def _analyze_policy(
        self,
        table: str,
        policy: dict[str, Any],
        file_path: str,
    ) -> list[CodeFinding]:
        """Analyze a single RLS policy for weaknesses."""
        findings: list[CodeFinding] = []
        using_expr = policy.get("using", "")
        with_check = policy.get("with_check", "")
        policy_name = policy["name"]
        operation = policy.get("for_operation", "ALL")

        roles = policy.get("roles") or []
        if roles and all(
            r in RLSPolicyAnalyzerConfig.PRIVILEGED_POLICY_ROLES for r in roles
        ):
            return findings  # only reachable with a server-side key

        # Check 3: Overly permissive USING expression
        if using_expr:
            for permissive_pattern in RLSPolicyAnalyzerConfig.PERMISSIVE_EXPRESSIONS:
                if re.match(permissive_pattern, using_expr, re.IGNORECASE):
                    findings.append(
                        CodeFinding(
                            scanner_name=self.scanner_name,
                            severity=SeverityLevel.HIGH,
                            category=FindingCategory.RLS_MISCONFIGURATION,
                            title=RLSPolicyAnalyzerConfig.TITLE_PERMISSIVE_POLICY.format(
                                table=table
                            ),
                            description=RLSPolicyAnalyzerConfig.DESC_PERMISSIVE_POLICY.format(
                                policy=policy_name,
                                table=table,
                                expression=using_expr,
                                operation=operation.lower(),
                            ),
                            file_path=file_path,
                            confidence=RLSPolicyAnalyzerConfig.CONFIDENCE_PERMISSIVE,
                        )
                    )
                    break

        # Check 4: Missing auth.uid() in USING or WITH CHECK
        all_expressions = " ".join(
            expr for expr in (using_expr, with_check) if expr
        )
        if all_expressions and not re.search(
            RLSPolicyAnalyzerConfig.AUTH_UID_PATTERN, all_expressions
        ):
            # Only flag if the policy isn't already flagged as permissive
            already_permissive = any(
                f.title
                == RLSPolicyAnalyzerConfig.TITLE_PERMISSIVE_POLICY.format(
                    table=table
                )
                for f in findings
            )
            if not already_permissive:
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.MEDIUM,
                        category=FindingCategory.RLS_MISCONFIGURATION,
                        title=RLSPolicyAnalyzerConfig.TITLE_MISSING_AUTH_UID.format(
                            table=table
                        ),
                        description=RLSPolicyAnalyzerConfig.DESC_MISSING_AUTH_UID.format(
                            operation=operation.lower(),
                            policy=policy_name,
                            table=table,
                        ),
                        file_path=file_path,
                        confidence=RLSPolicyAnalyzerConfig.CONFIDENCE_MISSING_AUTH_UID,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_clause(block: str, keyword: str) -> str:
        """Extract the parenthesized expression after a SQL keyword.

        Handles one level of nested parens so ``auth.uid()`` is captured
        in full rather than being cut short by a non-greedy ``(.*?)``.
        """
        pattern = keyword + r'\s*' + RLSPolicyAnalyzerConfig.PAREN_CONTENT_PATTERN
        match = re.search(pattern, block, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""

    def _find_table_file(
        self, table: str, migrations: dict[str, str]
    ) -> str:
        """Find which migration file defines a given table."""
        for file_path, content in migrations.items():
            if re.search(
                rf'CREATE\s+TABLE.*\b{re.escape(table)}\b',
                content,
                re.IGNORECASE,
            ):
                return file_path
        return RLSPolicyAnalyzerConfig.DEFAULT_MIGRATION_DIR
