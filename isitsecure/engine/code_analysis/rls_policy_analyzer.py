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
from isitsecure.engine.enums import FindingCategory, SeverityLevel

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
        """Collect migration file contents.

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

        return migrations

    # ------------------------------------------------------------------
    # SQL parsing
    # ------------------------------------------------------------------

    def _extract_tables(self, migrations: dict[str, str]) -> set[str]:
        """Extract table names from CREATE TABLE statements."""
        tables: set[str] = set()
        for content in migrations.values():
            for match in re.finditer(
                RLSPolicyAnalyzerConfig.CREATE_TABLE_PATTERN,
                content,
                re.IGNORECASE,
            ):
                tables.add(match.group(1))
        return tables

    def _extract_rls_enabled(self, migrations: dict[str, str]) -> set[str]:
        """Extract tables that have RLS enabled."""
        enabled: set[str] = set()
        for content in migrations.values():
            for match in re.finditer(
                RLSPolicyAnalyzerConfig.ENABLE_RLS_PATTERN,
                content,
                re.IGNORECASE,
            ):
                enabled.add(match.group(1))
        return enabled

    def _extract_policies(
        self, migrations: dict[str, str]
    ) -> dict[str, list[dict[str, Any]]]:
        """Extract policies per table.

        Returns:
            Mapping of table name to list of policy dicts with keys:
            name, for_operation, using, with_check.
        """
        policies: dict[str, list[dict[str, Any]]] = {}

        for content in migrations.values():
            # Split by CREATE POLICY to handle multi-line statements
            policy_blocks = re.split(
                r'(?=CREATE\s+POLICY)', content, flags=re.IGNORECASE
            )

            for block in policy_blocks:
                policy_match = re.search(
                    RLSPolicyAnalyzerConfig.CREATE_POLICY_PATTERN,
                    block,
                    re.IGNORECASE,
                )
                if not policy_match:
                    continue

                policy_name = policy_match.group(1)
                table_name = policy_match.group(2)

                # Extract FOR clause
                for_match = re.search(
                    RLSPolicyAnalyzerConfig.POLICY_FOR_PATTERN,
                    block,
                    re.IGNORECASE,
                )
                for_operation = for_match.group(1).upper() if for_match else "ALL"

                # Extract USING expression (with balanced parens)
                using_expr = self._extract_clause(block, "USING")

                # Extract WITH CHECK expression (with balanced parens)
                with_check = self._extract_clause(block, "WITH\\s+CHECK")

                policy_entry: dict[str, Any] = {
                    "name": policy_name,
                    "for_operation": for_operation,
                    "using": using_expr,
                    "with_check": with_check,
                }

                if table_name not in policies:
                    policies[table_name] = []
                policies[table_name].append(policy_entry)

        return policies

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
