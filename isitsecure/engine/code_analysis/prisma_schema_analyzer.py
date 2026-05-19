"""Prisma schema security analyzer.

SRP: This scanner is responsible ONLY for analyzing Prisma schema
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
    PrismaSchemaAnalyzerConfig,
    SchemaAnalyzerSharedConfig,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal models (SRP: schema parsing is separate from security analysis)
# ---------------------------------------------------------------------------


@dataclass
class ParsedField:
    """A single field extracted from a Prisma model definition."""

    name: str  # Field name (e.g., "email")
    field_type: str  # Prisma type (String, Int, etc.)


@dataclass
class ParsedModel:
    """A parsed Prisma model definition."""

    name: str
    file_path: str
    fields: list[ParsedField] = field(default_factory=list)
    has_tenant_id: bool = False


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class PrismaSchemaAnalyzer:
    """Analyzes Prisma schema files for security issues.

    Checks performed:
    1. Secrets stored in plaintext (API keys, tokens, etc.)
    2. PII columns without encryption counterparts
    3. Missing tenant scoping in multi-tenant apps
    4. Payment provider IDs stored in plaintext

    Implements ``CodeScannerProtocol``.
    """

    @property
    def scanner_name(self) -> str:
        return PrismaSchemaAnalyzerConfig.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Analyze Prisma schema files for security issues."""
        findings: list[CodeFinding] = []

        # Find and parse all Prisma schema files
        models = self._find_and_parse_schemas(repo)

        if not models:
            return findings

        is_multi_tenant = self._detect_multi_tenant(models)

        for model in models:
            # 1. Check for secrets in plaintext
            findings.extend(self._check_secret_fields(model))

            # 2. Check for PII without encryption
            findings.extend(self._check_pii_fields(model))

            # 3. Check tenant scoping
            if is_multi_tenant:
                findings.extend(self._check_tenant_scoping(model))

            # 4. Check payment data exposure
            findings.extend(self._check_payment_fields(model))

        logger.info(
            "PrismaSchemaAnalyzer: %d models parsed, %d findings",
            len(models),
            len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # Schema parsing (SRP: separate from security checks)
    # ------------------------------------------------------------------

    def _find_and_parse_schemas(
        self, repo: RepoSnapshot
    ) -> list[ParsedModel]:
        """Find Prisma schema files and parse model definitions."""
        models: list[ParsedModel] = []

        for file_path, content in repo.file_index.items():
            # Only process files with Prisma model definitions
            if not re.search(
                PrismaSchemaAnalyzerConfig.MODEL_PATTERN, content
            ):
                continue

            try:
                file_models = self._parse_schema_file(content, file_path)
                models.extend(file_models)
            except Exception as e:
                logger.warning(
                    PrismaSchemaAnalyzerConfig.ERROR_ANALYSIS_FAILED.format(
                        file=file_path, error=e
                    )
                )

        return models

    def _parse_schema_file(
        self, content: str, file_path: str
    ) -> list[ParsedModel]:
        """Parse all model definitions from a single Prisma schema file."""
        models: list[ParsedModel] = []

        for match in re.finditer(
            PrismaSchemaAnalyzerConfig.MODEL_PATTERN, content
        ):
            model_name = match.group(1)

            # Skip system models
            if model_name in PrismaSchemaAnalyzerConfig.SYSTEM_MODELS:
                continue

            # Extract the model body (between { and })
            block_start = match.end() - 1  # Start at the opening {
            block = self._extract_balanced_block(content, block_start)

            if not block:
                continue

            # Parse fields from the block
            fields = self._parse_fields(block)
            has_tenant_id = any(
                f.name in PrismaSchemaAnalyzerConfig.TENANT_COLUMN_NAMES
                for f in fields
            )

            models.append(
                ParsedModel(
                    name=model_name,
                    file_path=file_path,
                    fields=fields,
                    has_tenant_id=has_tenant_id,
                )
            )

        return models

    @staticmethod
    def _parse_fields(block: str) -> list[ParsedField]:
        """Extract field definitions from a Prisma model block.

        Skips relation fields (annotated with @relation) and lines that
        are comments or blank.
        """
        fields: list[ParsedField] = []

        for line in block.splitlines():
            stripped = line.strip()

            # Skip empty lines, comments, and closing brace
            if not stripped or stripped.startswith("//") or stripped == "}":
                continue

            # Skip lines with @relation (virtual relation fields)
            if re.search(PrismaSchemaAnalyzerConfig.RELATION_PATTERN, stripped):
                continue

            # Skip block-level attributes like @@map, @@unique, @@index
            if stripped.startswith("@@"):
                continue

            # Match field definitions: fieldName FieldType ...
            field_match = re.match(
                PrismaSchemaAnalyzerConfig.FIELD_PATTERN, stripped
            )
            if field_match:
                fields.append(
                    ParsedField(
                        name=field_match.group(1),
                        field_type=field_match.group(2),
                    )
                )

        return fields

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
    def _detect_multi_tenant(cls, models: list[ParsedModel]) -> bool:
        """Detect if the schema is multi-tenant."""
        return any(
            m.name in SchemaAnalyzerSharedConfig.MULTI_TENANT_INDICATORS
            for m in models
        )

    # ------------------------------------------------------------------
    # 1. Secret fields check
    # ------------------------------------------------------------------

    def _check_secret_fields(
        self, model: ParsedModel
    ) -> list[CodeFinding]:
        """Find fields that store secrets in plaintext."""
        findings: list[CodeFinding] = []
        field_names = {f.name for f in model.fields}

        for fld in model.fields:
            if not self._is_secret_field(fld.name):
                continue

            # Check if there's an encrypted counterpart
            has_encrypted = any(
                fld.name + suffix in field_names
                for suffix in PrismaSchemaAnalyzerConfig.ENCRYPTION_SUFFIX_PATTERNS
            )

            if not has_encrypted:
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.HIGH,
                        category=FindingCategory.EXPOSED_SECRETS,
                        title=PrismaSchemaAnalyzerConfig.TITLE_SECRET_PLAINTEXT.format(
                            column=fld.name, table=model.name
                        ),
                        description=PrismaSchemaAnalyzerConfig.DESC_SECRET_PLAINTEXT.format(
                            column=fld.name,
                            table=model.name,
                            file=model.file_path,
                        ),
                        file_path=model.file_path,
                        confidence=PrismaSchemaAnalyzerConfig.CONFIDENCE_SECRET_PLAINTEXT,
                    )
                )

        return findings

    @staticmethod
    def _is_secret_field(field_name: str) -> bool:
        """Check if a field name indicates it stores a secret."""
        name_lower = field_name.lower()
        return any(
            indicator in name_lower
            for indicator in PrismaSchemaAnalyzerConfig.SECRET_COLUMN_INDICATORS
        )

    # ------------------------------------------------------------------
    # 2. PII fields check
    # ------------------------------------------------------------------

    def _check_pii_fields(
        self, model: ParsedModel
    ) -> list[CodeFinding]:
        """Find PII fields without encryption counterparts."""
        findings: list[CodeFinding] = []
        field_names = {f.name for f in model.fields}

        for fld in model.fields:
            if not self._is_pii_field(fld.name):
                continue

            # Skip if this IS the encrypted/hashed version
            if any(
                fld.name.endswith(suffix)
                for suffix in PrismaSchemaAnalyzerConfig.ENCRYPTION_SUFFIX_PATTERNS
            ):
                continue

            # Check if there's an encrypted counterpart
            has_encrypted = any(
                fld.name + suffix in field_names
                for suffix in PrismaSchemaAnalyzerConfig.ENCRYPTION_SUFFIX_PATTERNS
            )

            if not has_encrypted:
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.MEDIUM,
                        category=FindingCategory.UNENCRYPTED_PII,
                        title=PrismaSchemaAnalyzerConfig.TITLE_PII_NO_ENCRYPTION.format(
                            column=fld.name, table=model.name
                        ),
                        description=PrismaSchemaAnalyzerConfig.DESC_PII_NO_ENCRYPTION.format(
                            column=fld.name,
                            table=model.name,
                            file=model.file_path,
                        ),
                        file_path=model.file_path,
                        confidence=PrismaSchemaAnalyzerConfig.CONFIDENCE_PII_NO_ENCRYPTION,
                    )
                )

        return findings

    @staticmethod
    def _is_pii_field(field_name: str) -> bool:
        """Check if a field name indicates PII data."""
        name_lower = field_name.lower()

        for indicator in PrismaSchemaAnalyzerConfig.PII_COLUMN_INDICATORS:
            if indicator == name_lower or name_lower.endswith(f"_{indicator}"):
                return True
            if name_lower.startswith(f"{indicator}_") and not any(
                name_lower.endswith(suffix)
                for suffix in PrismaSchemaAnalyzerConfig.ENCRYPTION_SUFFIX_PATTERNS
            ):
                return True

        return False

    # ------------------------------------------------------------------
    # 3. Tenant scoping check
    # ------------------------------------------------------------------

    def _check_tenant_scoping(
        self, model: ParsedModel
    ) -> list[CodeFinding]:
        """Check if tenant-specific models have tenant_id."""
        findings: list[CodeFinding] = []

        # Skip global models
        if model.name in PrismaSchemaAnalyzerConfig.GLOBAL_TABLE_INDICATORS:
            return findings

        # Skip if model already has tenant_id
        if model.has_tenant_id:
            return findings

        # Only flag models that typically need tenant scoping
        if not any(
            indicator in model.name.lower()
            for indicator in PrismaSchemaAnalyzerConfig.TENANT_SCOPED_TABLE_INDICATORS
        ):
            return findings

        findings.append(
            CodeFinding(
                scanner_name=self.scanner_name,
                severity=SeverityLevel.MEDIUM,
                category=FindingCategory.AUTH_WEAKNESS,
                title=PrismaSchemaAnalyzerConfig.TITLE_MISSING_TENANT_SCOPE.format(
                    table=model.name
                ),
                description=PrismaSchemaAnalyzerConfig.DESC_MISSING_TENANT_SCOPE.format(
                    table=model.name, file=model.file_path
                ),
                file_path=model.file_path,
                confidence=PrismaSchemaAnalyzerConfig.CONFIDENCE_MISSING_TENANT_SCOPE,
            )
        )

        return findings

    # ------------------------------------------------------------------
    # 4. Payment data check
    # ------------------------------------------------------------------

    def _check_payment_fields(
        self, model: ParsedModel
    ) -> list[CodeFinding]:
        """Check for payment provider IDs stored in plaintext."""
        findings: list[CodeFinding] = []

        for fld in model.fields:
            if not self._is_payment_field(fld.name):
                continue

            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.LOW,
                    category=FindingCategory.INFO_DISCLOSURE,
                    title=PrismaSchemaAnalyzerConfig.TITLE_PAYMENT_DATA_STORED.format(
                        column=fld.name, table=model.name
                    ),
                    description=PrismaSchemaAnalyzerConfig.DESC_PAYMENT_DATA_STORED.format(
                        column=fld.name,
                        table=model.name,
                        file=model.file_path,
                    ),
                    file_path=model.file_path,
                    confidence=PrismaSchemaAnalyzerConfig.CONFIDENCE_PAYMENT_DATA_EXPOSURE,
                )
            )

        return findings

    @staticmethod
    def _is_payment_field(field_name: str) -> bool:
        """Check if a field stores payment provider data."""
        name_lower = field_name.lower()

        # Must have a payment provider prefix
        has_provider_prefix = any(
            name_lower.startswith(prefix)
            for prefix in PrismaSchemaAnalyzerConfig.PAYMENT_COLUMN_PREFIXES
        )

        if not has_provider_prefix:
            return False

        # Check for payment-specific suffixes
        has_payment_suffix = any(
            name_lower.endswith(suffix)
            for suffix in PrismaSchemaAnalyzerConfig.PAYMENT_COLUMN_SUFFIXES
        )

        if has_payment_suffix:
            return True

        # Skip if it's a secret/key/token (handled by secret check)
        name_after_prefix = name_lower
        for prefix in PrismaSchemaAnalyzerConfig.PAYMENT_COLUMN_PREFIXES:
            if name_lower.startswith(prefix):
                name_after_prefix = name_lower[len(prefix):]
                break

        if any(
            ind in name_after_prefix
            for ind in SchemaAnalyzerSharedConfig.PAYMENT_FIELD_SECRET_INDICATORS
        ):
            return False

        return False
