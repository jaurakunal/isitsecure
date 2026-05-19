"""Tests for PrismaSchemaAnalyzer."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.prisma_schema_analyzer import (
    PrismaSchemaAnalyzer,
)
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import PrismaSchemaAnalyzerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Content fixtures
# ---------------------------------------------------------------------------

SCHEMA_WITH_SECRET_PLAINTEXT = """\
model Integration {
    id              String @id @default(cuid())
    name            String
    embed_secret    String
    api_key         String
}
"""

SCHEMA_WITH_SECRET_ENCRYPTED = """\
model Integration {
    id                      String @id @default(cuid())
    name                    String
    embed_secret            String
    embed_secret_encrypted  String
    api_key                 String
    api_key_encrypted       String
}
"""

SCHEMA_WITH_PII_NO_ENCRYPTION = """\
model User {
    id    String @id @default(cuid())
    email String @unique
    phone String?
}
"""

SCHEMA_WITH_PII_ENCRYPTED = """\
model User {
    id               String @id @default(cuid())
    email            String @unique
    email_encrypted  String
    phone            String?
    phone_encrypted  String?
}
"""

SCHEMA_MULTI_TENANT_NO_SCOPE = """\
model Tenant {
    id   String @id @default(cuid())
    name String
}

model Users {
    id   String @id @default(cuid())
    name String
}
"""

SCHEMA_MULTI_TENANT_WITH_SCOPE = """\
model Tenant {
    id        String @id @default(cuid())
    name      String
}

model Users {
    id        String @id @default(cuid())
    name      String
    tenant_id String
}
"""

SCHEMA_WITH_PAYMENT_COLUMNS = """\
model Customer {
    id                  String @id @default(cuid())
    name                String
    stripe_customer_id  String
}
"""

SCHEMA_WITH_PLAIN_IDS = """\
model Customer {
    id          String @id @default(cuid())
    user_id     String
    customer_id String
}
"""

SCHEMA_GLOBAL_TABLES = """\
model Tenant {
    id   String @id @default(cuid())
    name String
}

model AuditLog {
    id        String   @id @default(cuid())
    action    String
    createdAt DateTime @default(now())
}
"""

SCHEMA_WITH_RELATION = """\
model Post {
    id       String @id @default(cuid())
    title    String
    author   User   @relation(fields: [authorId], references: [id])
    authorId String
}
"""

SCHEMA_PRISMA_MIGRATIONS = """\
model _prisma_migrations {
    id          String @id
    checksum    String
    finished_at DateTime?
}
"""

NO_PRISMA_CODE = """\
const express = require('express');
const app = express();
app.listen(3000);
"""


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_repo(
    file_index: dict[str, str] | None = None,
) -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        file_index=file_index or {},
        route_map=[],
        package_json={},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScannerName:
    def test_scanner_name(self) -> None:
        analyzer = PrismaSchemaAnalyzer()
        assert analyzer.scanner_name == PrismaSchemaAnalyzerConfig.SCANNER_NAME


class TestNoPrismaFiles:
    @pytest.mark.asyncio
    async def test_returns_empty_when_no_model_keyword(self) -> None:
        """No Prisma model definitions -> no findings."""
        repo = _make_repo(file_index={"src/app.ts": NO_PRISMA_CODE})
        analyzer = PrismaSchemaAnalyzer()
        findings = await analyzer.scan(repo)
        assert len(findings) == 0


class TestSecretInPlaintext:
    @pytest.mark.asyncio
    async def test_flags_apikey_and_token(self) -> None:
        """Columns like apiKey, token without encrypted counterpart -> finding."""
        repo = _make_repo(
            file_index={"prisma/schema.prisma": SCHEMA_WITH_SECRET_PLAINTEXT}
        )
        analyzer = PrismaSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        secret_findings = [
            f for f in findings
            if f.category == FindingCategory.EXPOSED_SECRETS
        ]
        assert len(secret_findings) >= 2
        assert all(
            f.severity == SeverityLevel.HIGH for f in secret_findings
        )
        assert all(
            f.confidence == PrismaSchemaAnalyzerConfig.CONFIDENCE_SECRET_PLAINTEXT
            for f in secret_findings
        )


class TestSecretWithEncryption:
    @pytest.mark.asyncio
    async def test_no_finding_for_original_when_encrypted_counterpart_exists(self) -> None:
        """Secret columns with _encrypted counterpart -> original column not flagged."""
        repo = _make_repo(
            file_index={"prisma/schema.prisma": SCHEMA_WITH_SECRET_ENCRYPTED}
        )
        analyzer = PrismaSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        # Original columns should NOT be flagged (they have _encrypted counterparts)
        original_secret_findings = [
            f for f in findings
            if f.category == FindingCategory.EXPOSED_SECRETS
            and ("'embed_secret'" in f.title or "'api_key'" in f.title)
        ]
        assert len(original_secret_findings) == 0


class TestPIIWithoutEncryption:
    @pytest.mark.asyncio
    async def test_flags_email_without_encrypted(self) -> None:
        """PII column 'email' without email_encrypted -> finding."""
        repo = _make_repo(
            file_index={"prisma/schema.prisma": SCHEMA_WITH_PII_NO_ENCRYPTION}
        )
        analyzer = PrismaSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        pii_findings = [
            f for f in findings
            if f.category == FindingCategory.UNENCRYPTED_PII
        ]
        assert len(pii_findings) >= 1
        assert pii_findings[0].severity == SeverityLevel.MEDIUM
        assert pii_findings[0].confidence == PrismaSchemaAnalyzerConfig.CONFIDENCE_PII_NO_ENCRYPTION


class TestPIIWithEncryption:
    @pytest.mark.asyncio
    async def test_no_finding_when_encrypted_counterpart_exists(self) -> None:
        """PII columns with _encrypted counterparts -> no finding."""
        repo = _make_repo(
            file_index={"prisma/schema.prisma": SCHEMA_WITH_PII_ENCRYPTED}
        )
        analyzer = PrismaSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        pii_findings = [
            f for f in findings
            if f.category == FindingCategory.UNENCRYPTED_PII
        ]
        assert len(pii_findings) == 0


class TestMissingTenantScope:
    @pytest.mark.asyncio
    async def test_flags_users_model_without_tenant_id(self) -> None:
        """Multi-tenant schema with Users model missing tenant_id -> finding."""
        repo = _make_repo(
            file_index={"prisma/schema.prisma": SCHEMA_MULTI_TENANT_NO_SCOPE}
        )
        analyzer = PrismaSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        tenant_findings = [
            f for f in findings
            if f.category == FindingCategory.AUTH_WEAKNESS
            and "tenantId" in f.title
        ]
        assert len(tenant_findings) == 1
        assert tenant_findings[0].severity == SeverityLevel.MEDIUM
        assert tenant_findings[0].confidence == PrismaSchemaAnalyzerConfig.CONFIDENCE_MISSING_TENANT_SCOPE

    @pytest.mark.asyncio
    async def test_no_finding_when_tenant_id_present(self) -> None:
        """Multi-tenant schema with tenantId on User -> no finding."""
        repo = _make_repo(
            file_index={"prisma/schema.prisma": SCHEMA_MULTI_TENANT_WITH_SCOPE}
        )
        analyzer = PrismaSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        tenant_findings = [
            f for f in findings
            if f.category == FindingCategory.AUTH_WEAKNESS
            and "tenantId" in f.title
        ]
        assert len(tenant_findings) == 0


class TestGlobalTableSkipped:
    @pytest.mark.asyncio
    async def test_does_not_flag_tenant_or_audit_log(self) -> None:
        """Global tables (Tenant, AuditLog) should not be flagged for missing tenantId."""
        repo = _make_repo(
            file_index={"prisma/schema.prisma": SCHEMA_GLOBAL_TABLES}
        )
        analyzer = PrismaSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        tenant_findings = [
            f for f in findings
            if "tenantId" in f.title
        ]
        assert len(tenant_findings) == 0


class TestPaymentColumns:
    @pytest.mark.asyncio
    async def test_flags_stripe_customer_id(self) -> None:
        """stripeCustomerId matches prefix+suffix -> finding."""
        repo = _make_repo(
            file_index={"prisma/schema.prisma": SCHEMA_WITH_PAYMENT_COLUMNS}
        )
        analyzer = PrismaSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        payment_findings = [
            f for f in findings
            if f.category == FindingCategory.INFO_DISCLOSURE
            and "stripe_customer_id" in f.title
        ]
        assert len(payment_findings) == 1
        assert payment_findings[0].severity == SeverityLevel.LOW
        assert payment_findings[0].confidence == PrismaSchemaAnalyzerConfig.CONFIDENCE_PAYMENT_DATA_EXPOSURE


class TestNonPaymentColumn:
    @pytest.mark.asyncio
    async def test_does_not_flag_user_id_or_plain_customer_id(self) -> None:
        """userId and customerId (no payment prefix) should not be flagged."""
        repo = _make_repo(
            file_index={"prisma/schema.prisma": SCHEMA_WITH_PLAIN_IDS}
        )
        analyzer = PrismaSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        payment_findings = [
            f for f in findings
            if f.category == FindingCategory.INFO_DISCLOSURE
        ]
        assert len(payment_findings) == 0


class TestSystemModelsSkipped:
    @pytest.mark.asyncio
    async def test_skips_prisma_migrations(self) -> None:
        """_prisma_migrations system model should be skipped entirely."""
        repo = _make_repo(
            file_index={"prisma/schema.prisma": SCHEMA_PRISMA_MIGRATIONS}
        )
        analyzer = PrismaSchemaAnalyzer()
        findings = await analyzer.scan(repo)
        assert len(findings) == 0


class TestRelationFieldsSkipped:
    @pytest.mark.asyncio
    async def test_relation_fields_not_flagged(self) -> None:
        """Fields with @relation decorator are virtual and should be skipped."""
        repo = _make_repo(
            file_index={"prisma/schema.prisma": SCHEMA_WITH_RELATION}
        )
        analyzer = PrismaSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        # The relation field 'author' should not produce findings
        author_findings = [
            f for f in findings
            if "author" in f.title.lower()
        ]
        assert len(author_findings) == 0
