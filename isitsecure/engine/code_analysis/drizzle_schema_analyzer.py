"""Drizzle ORM schema security analyzer.

SRP: This scanner is responsible ONLY for analyzing Drizzle ORM schema
     definitions for security issues.  It does not analyze SQL migrations
     (that's RLSPolicyAnalyzer) or runtime query patterns (that's
     RouteAuthAnalyzer).

OCP: Implements ``CodeScannerProtocol`` — added to sast_scanners list
     without modifying the agent or factory.

DIP: Depends on ``RepoSnapshot`` and ``CodeScannerProtocol``
     (abstractions), never on concrete implementations.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import (
    DrizzleSchemaAnalyzerConfig,
    SchemaAnalyzerSharedConfig,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal models (SRP: schema parsing is separate from security analysis)
# ---------------------------------------------------------------------------


@dataclass
class ParsedColumn:
    """A single column extracted from a Drizzle table definition."""

    property_name: str  # JS property name (e.g., "email_encrypted")
    db_name: str  # Database column name
    column_type: str  # Drizzle type (text, uuid, etc.)


@dataclass
class ParsedTable:
    """A parsed Drizzle table definition."""

    name: str
    file_path: str
    columns: list[ParsedColumn] = field(default_factory=list)
    has_tenant_id: bool = False


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class DrizzleSchemaAnalyzer:
    """Analyzes Drizzle ORM schema files for security issues.

    Checks performed:
    1. Secrets stored in plaintext (API keys, tokens, etc.)
    2. PII columns without encryption counterparts
    3. Missing tenant scoping in multi-tenant apps
    4. Payment provider IDs stored in plaintext

    Implements ``CodeScannerProtocol``.
    """

    @property
    def scanner_name(self) -> str:
        return DrizzleSchemaAnalyzerConfig.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Analyze Drizzle schema files for security issues."""
        findings: list[CodeFinding] = []

        # Find and parse all Drizzle schema files
        tables = self._find_and_parse_schemas(repo)

        if not tables:
            return findings

        is_multi_tenant = self._detect_multi_tenant(tables)

        for table in tables:
            # 1. Check for secrets in plaintext
            findings.extend(self._check_secret_columns(table))

            # 2. Check for PII without encryption
            findings.extend(self._check_pii_columns(table))

            # 3. Check tenant scoping
            if is_multi_tenant:
                findings.extend(self._check_tenant_scoping(table))

            # 4. Check payment data exposure
            findings.extend(self._check_payment_columns(table))

        logger.info(
            "DrizzleSchemaAnalyzer: %d tables parsed, %d findings",
            len(tables),
            len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # Schema parsing (SRP: separate from security checks)
    # ------------------------------------------------------------------

    def _find_and_parse_schemas(
        self, repo: RepoSnapshot
    ) -> list[ParsedTable]:
        """Find Drizzle schema files and parse table definitions."""
        tables: list[ParsedTable] = []

        for file_path, content in repo.file_index.items():
            # Only process files with Drizzle table definitions
            if not re.search(
                DrizzleSchemaAnalyzerConfig.TABLE_DEFINITION_PATTERN, content
            ):
                continue

            try:
                file_tables = self._parse_schema_file(content, file_path)
                tables.extend(file_tables)
            except Exception as e:
                logger.warning(
                    DrizzleSchemaAnalyzerConfig.ERROR_ANALYSIS_FAILED.format(
                        file=file_path, error=e
                    )
                )

        return tables

    def _parse_schema_file(
        self, content: str, file_path: str
    ) -> list[ParsedTable]:
        """Parse all table definitions from a single schema file."""
        tables: list[ParsedTable] = []

        # Find each table definition and its content block
        # We split on pgTable/mysqlTable/sqliteTable calls
        table_pattern = (
            r'(?:export\s+const\s+\w+\s*=\s*)?'
            r'(?:pgTable|mysqlTable|sqliteTable)\s*\(\s*'
            r"""['"]([\w]+)['"]\s*,\s*\{"""
        )

        for match in re.finditer(table_pattern, content):
            table_name = match.group(1)

            # Extract the column definition block (between { and })
            block_start = match.end() - 1  # Start at the opening {
            block = self._extract_balanced_block(content, block_start)

            if not block:
                continue

            # Parse columns from the block
            columns = self._parse_columns(block)
            has_tenant_id = any(
                c.db_name in DrizzleSchemaAnalyzerConfig.TENANT_COLUMN_NAMES
                for c in columns
            )

            tables.append(
                ParsedTable(
                    name=table_name,
                    file_path=file_path,
                    columns=columns,
                    has_tenant_id=has_tenant_id,
                )
            )

        return tables

    @staticmethod
    def _parse_columns(block: str) -> list[ParsedColumn]:
        """Extract column definitions from a table definition block."""
        columns: list[ParsedColumn] = []

        for match in re.finditer(
            DrizzleSchemaAnalyzerConfig.COLUMN_PATTERN, block
        ):
            columns.append(
                ParsedColumn(
                    property_name=match.group(1),
                    db_name=match.group(3),
                    column_type=match.group(2),
                )
            )

        return columns

    @staticmethod
    def _extract_balanced_block(content: str, start: int) -> str:
        """Extract content between balanced braces starting at position."""
        if start >= len(content) or content[start] != "{":
            return ""

        depth = 0
        for i in range(start, len(content)):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    return content[start : i + 1]

        return ""

    # ------------------------------------------------------------------
    # Multi-tenant detection
    # ------------------------------------------------------------------

    @classmethod
    def _detect_multi_tenant(cls, tables: list[ParsedTable]) -> bool:
        """Detect if the schema is multi-tenant."""
        return any(
            t.name in SchemaAnalyzerSharedConfig.MULTI_TENANT_INDICATORS for t in tables
        )

    # ------------------------------------------------------------------
    # 1. Secret columns check
    # ------------------------------------------------------------------

    def _check_secret_columns(
        self, table: ParsedTable
    ) -> list[CodeFinding]:
        """Find columns that store secrets in plaintext."""
        findings: list[CodeFinding] = []
        column_names = {c.db_name for c in table.columns}

        for col in table.columns:
            if not self._is_secret_column(col.db_name):
                continue

            # Check if there's an encrypted counterpart
            has_encrypted = any(
                col.db_name + suffix in column_names
                for suffix in DrizzleSchemaAnalyzerConfig.ENCRYPTION_SUFFIX_PATTERNS
            )

            if not has_encrypted:
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.HIGH,
                        category=FindingCategory.EXPOSED_SECRETS,
                        title=DrizzleSchemaAnalyzerConfig.TITLE_SECRET_PLAINTEXT.format(
                            column=col.db_name, table=table.name
                        ),
                        description=DrizzleSchemaAnalyzerConfig.DESC_SECRET_PLAINTEXT.format(
                            column=col.db_name,
                            table=table.name,
                            file=table.file_path,
                        ),
                        file_path=table.file_path,
                        confidence=DrizzleSchemaAnalyzerConfig.CONFIDENCE_SECRET_PLAINTEXT,
                    )
                )

        return findings

    @staticmethod
    def _is_secret_column(column_name: str) -> bool:
        """Check if a column name indicates it stores a secret."""
        name_lower = column_name.lower()
        return any(
            indicator in name_lower
            for indicator in DrizzleSchemaAnalyzerConfig.SECRET_COLUMN_INDICATORS
        )

    # ------------------------------------------------------------------
    # 2. PII columns check
    # ------------------------------------------------------------------

    def _check_pii_columns(
        self, table: ParsedTable
    ) -> list[CodeFinding]:
        """Find PII columns without encryption counterparts."""
        findings: list[CodeFinding] = []
        column_names = {c.db_name for c in table.columns}

        for col in table.columns:
            if not self._is_pii_column(col.db_name):
                continue

            # Skip if this IS the encrypted/hashed version
            if any(
                col.db_name.endswith(suffix)
                for suffix in DrizzleSchemaAnalyzerConfig.ENCRYPTION_SUFFIX_PATTERNS
            ):
                continue

            # Check if there's an encrypted counterpart
            has_encrypted = any(
                col.db_name + suffix in column_names
                for suffix in DrizzleSchemaAnalyzerConfig.ENCRYPTION_SUFFIX_PATTERNS
            )

            if not has_encrypted:
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.MEDIUM,
                        category=FindingCategory.UNENCRYPTED_PII,
                        title=DrizzleSchemaAnalyzerConfig.TITLE_PII_NO_ENCRYPTION.format(
                            column=col.db_name, table=table.name
                        ),
                        description=DrizzleSchemaAnalyzerConfig.DESC_PII_NO_ENCRYPTION.format(
                            column=col.db_name,
                            table=table.name,
                            file=table.file_path,
                        ),
                        file_path=table.file_path,
                        confidence=DrizzleSchemaAnalyzerConfig.CONFIDENCE_PII_NO_ENCRYPTION,
                    )
                )

        return findings

    @staticmethod
    def _is_pii_column(column_name: str) -> bool:
        """Check if a column name indicates PII data."""
        name_lower = column_name.lower()

        # Exact match on core PII columns, substring match on others
        for indicator in DrizzleSchemaAnalyzerConfig.PII_COLUMN_INDICATORS:
            # Use word-boundary-style matching: "email" matches "email"
            # and "buyer_email" but not "email_encrypted"
            if indicator == name_lower or name_lower.endswith(f"_{indicator}"):
                return True
            if name_lower.startswith(f"{indicator}_") and not any(
                name_lower.endswith(suffix)
                for suffix in DrizzleSchemaAnalyzerConfig.ENCRYPTION_SUFFIX_PATTERNS
            ):
                return True

        return False

    # ------------------------------------------------------------------
    # 3. Tenant scoping check
    # ------------------------------------------------------------------

    def _check_tenant_scoping(
        self, table: ParsedTable
    ) -> list[CodeFinding]:
        """Check if tenant-specific tables have tenant_id."""
        findings: list[CodeFinding] = []

        # Skip global tables
        if table.name in DrizzleSchemaAnalyzerConfig.GLOBAL_TABLE_INDICATORS:
            return findings

        # Skip if table already has tenant_id
        if table.has_tenant_id:
            return findings

        # Only flag tables that typically need tenant scoping
        if not any(
            indicator in table.name.lower()
            for indicator in DrizzleSchemaAnalyzerConfig.TENANT_SCOPED_TABLE_INDICATORS
        ):
            return findings

        findings.append(
            CodeFinding(
                scanner_name=self.scanner_name,
                severity=SeverityLevel.MEDIUM,
                category=FindingCategory.AUTH_WEAKNESS,
                title=DrizzleSchemaAnalyzerConfig.TITLE_MISSING_TENANT_SCOPE.format(
                    table=table.name
                ),
                description=DrizzleSchemaAnalyzerConfig.DESC_MISSING_TENANT_SCOPE.format(
                    table=table.name, file=table.file_path
                ),
                file_path=table.file_path,
                confidence=DrizzleSchemaAnalyzerConfig.CONFIDENCE_MISSING_TENANT_SCOPE,
            )
        )

        return findings

    # ------------------------------------------------------------------
    # 4. Payment data check
    # ------------------------------------------------------------------

    def _check_payment_columns(
        self, table: ParsedTable
    ) -> list[CodeFinding]:
        """Check for payment provider IDs stored in plaintext."""
        findings: list[CodeFinding] = []

        for col in table.columns:
            if not self._is_payment_column(col.db_name):
                continue

            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.LOW,
                    category=FindingCategory.INFO_DISCLOSURE,
                    title=DrizzleSchemaAnalyzerConfig.TITLE_PAYMENT_DATA_STORED.format(
                        column=col.db_name, table=table.name
                    ),
                    description=DrizzleSchemaAnalyzerConfig.DESC_PAYMENT_DATA_STORED.format(
                        column=col.db_name,
                        table=table.name,
                        file=table.file_path,
                    ),
                    file_path=table.file_path,
                    confidence=DrizzleSchemaAnalyzerConfig.CONFIDENCE_PAYMENT_DATA_EXPOSURE,
                )
            )

        return findings

    @staticmethod
    def _is_payment_column(column_name: str) -> bool:
        """Check if a column stores payment provider data.

        Matches if the column has a known payment provider prefix AND
        contains an ID-like suffix, OR has a known provider prefix with
        any identifying suffix (covers cases like ``stripe_customer``).
        """
        name_lower = column_name.lower()

        # Must have a payment provider prefix
        has_provider_prefix = any(
            name_lower.startswith(prefix)
            for prefix in DrizzleSchemaAnalyzerConfig.PAYMENT_COLUMN_PREFIXES
        )

        if not has_provider_prefix:
            return False

        # Check for payment-specific suffixes
        has_payment_suffix = any(
            name_lower.endswith(suffix)
            for suffix in DrizzleSchemaAnalyzerConfig.PAYMENT_COLUMN_SUFFIXES
        )

        if has_payment_suffix:
            return True

        # Also match provider-prefixed columns that look like identifiers
        # e.g., stripe_customer, paypal_merchant, but NOT stripe_webhook_secret
        # (secrets are handled by _is_secret_column)
        name_after_prefix = name_lower
        for prefix in DrizzleSchemaAnalyzerConfig.PAYMENT_COLUMN_PREFIXES:
            if name_lower.startswith(prefix):
                name_after_prefix = name_lower[len(prefix):]
                break

        # Skip if it's a secret/key/token (handled by secret check)
        if any(
            ind in name_after_prefix
            for ind in SchemaAnalyzerSharedConfig.PAYMENT_FIELD_SECRET_INDICATORS
        ):
            return False

        return False
