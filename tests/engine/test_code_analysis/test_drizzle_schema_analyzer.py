"""Tests for DrizzleSchemaAnalyzer."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.drizzle_schema_analyzer import (
    DrizzleSchemaAnalyzer,
)
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import DrizzleSchemaAnalyzerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Content fixtures
# ---------------------------------------------------------------------------

SCHEMA_WITH_SECRET_PLAINTEXT = """\
import { pgTable, uuid, text } from 'drizzle-orm/pg-core';

export const integrations = pgTable('integrations', {
    id: uuid('id').primaryKey(),
    name: text('name').notNull(),
    embed_secret: text('embed_secret'),
    api_key: text('api_key'),
});
"""

SCHEMA_WITH_SECRET_ENCRYPTED = """\
import { pgTable, uuid, text } from 'drizzle-orm/pg-core';

export const integrations = pgTable('integrations', {
    id: uuid('id').primaryKey(),
    name: text('name').notNull(),
    embed_secret: text('embed_secret'),
    embed_secret_encrypted: text('embed_secret_encrypted'),
    api_key: text('api_key'),
    api_key_encrypted: text('api_key_encrypted'),
});
"""

SCHEMA_WITH_PII_NO_ENCRYPTION = """\
import { pgTable, uuid, text } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
    id: uuid('id').primaryKey(),
    email: text('email').notNull(),
    phone: text('phone'),
});
"""

SCHEMA_WITH_PII_ENCRYPTED = """\
import { pgTable, uuid, text } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
    id: uuid('id').primaryKey(),
    email: text('email').notNull(),
    email_encrypted: text('email_encrypted'),
    phone: text('phone'),
    phone_encrypted: text('phone_encrypted'),
});
"""

SCHEMA_MULTI_TENANT_NO_SCOPE = """\
import { pgTable, uuid, text } from 'drizzle-orm/pg-core';

export const tenants = pgTable('tenants', {
    id: uuid('id').primaryKey(),
    name: text('name').notNull(),
});

export const users = pgTable('users', {
    id: uuid('id').primaryKey(),
    name: text('name').notNull(),
});
"""

SCHEMA_MULTI_TENANT_WITH_SCOPE = """\
import { pgTable, uuid, text } from 'drizzle-orm/pg-core';

export const tenants = pgTable('tenants', {
    id: uuid('id').primaryKey(),
    name: text('name').notNull(),
});

export const users = pgTable('users', {
    id: uuid('id').primaryKey(),
    name: text('name').notNull(),
    tenant_id: uuid('tenant_id').notNull(),
});
"""

SCHEMA_WITH_PAYMENT_COLUMNS = """\
import { pgTable, uuid, text } from 'drizzle-orm/pg-core';

export const customers = pgTable('customers', {
    id: uuid('id').primaryKey(),
    name: text('name').notNull(),
    stripe_customer_id: text('stripe_customer_id'),
});
"""

SCHEMA_WITH_PLAIN_IDS = """\
import { pgTable, uuid, text } from 'drizzle-orm/pg-core';

export const customers = pgTable('customers', {
    id: uuid('id').primaryKey(),
    user_id: uuid('user_id'),
    customer_id: uuid('customer_id'),
});
"""

SCHEMA_GLOBAL_TABLES = """\
import { pgTable, uuid, text, timestamp } from 'drizzle-orm/pg-core';

export const tenants = pgTable('tenants', {
    id: uuid('id').primaryKey(),
    name: text('name').notNull(),
});

export const audit_logs = pgTable('audit_logs', {
    id: uuid('id').primaryKey(),
    action: text('action').notNull(),
    created_at: timestamp('created_at'),
});
"""

NO_DRIZZLE_CODE = """\
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
        analyzer = DrizzleSchemaAnalyzer()
        assert analyzer.scanner_name == DrizzleSchemaAnalyzerConfig.SCANNER_NAME


class TestNoDrizzleFiles:
    @pytest.mark.asyncio
    async def test_returns_empty_when_no_pg_table(self) -> None:
        """No Drizzle table definitions -> no findings."""
        repo = _make_repo(file_index={"src/app.ts": NO_DRIZZLE_CODE})
        analyzer = DrizzleSchemaAnalyzer()
        findings = await analyzer.scan(repo)
        assert len(findings) == 0


class TestSecretInPlaintext:
    @pytest.mark.asyncio
    async def test_flags_embed_secret_and_api_key(self) -> None:
        """Columns like embed_secret, api_key without encrypted counterpart -> finding."""
        repo = _make_repo(
            file_index={"db/schema.ts": SCHEMA_WITH_SECRET_PLAINTEXT}
        )
        analyzer = DrizzleSchemaAnalyzer()
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
            f.confidence == DrizzleSchemaAnalyzerConfig.CONFIDENCE_SECRET_PLAINTEXT
            for f in secret_findings
        )


class TestSecretWithEncryption:
    @pytest.mark.asyncio
    async def test_no_finding_for_original_when_encrypted_counterpart_exists(self) -> None:
        """Secret columns with _encrypted counterpart -> original column not flagged.

        Note: the _encrypted columns themselves may still be flagged because
        their names contain secret indicators (e.g., "embed_secret_encrypted"
        contains "secret").  This test verifies only that the *original*
        plaintext columns are suppressed.
        """
        repo = _make_repo(
            file_index={"db/schema.ts": SCHEMA_WITH_SECRET_ENCRYPTED}
        )
        analyzer = DrizzleSchemaAnalyzer()
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
            file_index={"db/schema.ts": SCHEMA_WITH_PII_NO_ENCRYPTION}
        )
        analyzer = DrizzleSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        pii_findings = [
            f for f in findings
            if f.category == FindingCategory.UNENCRYPTED_PII
        ]
        assert len(pii_findings) >= 1
        assert pii_findings[0].severity == SeverityLevel.MEDIUM
        assert pii_findings[0].confidence == DrizzleSchemaAnalyzerConfig.CONFIDENCE_PII_NO_ENCRYPTION


class TestPIIWithEncryption:
    @pytest.mark.asyncio
    async def test_no_finding_when_encrypted_counterpart_exists(self) -> None:
        """PII columns with _encrypted counterparts -> no finding."""
        repo = _make_repo(
            file_index={"db/schema.ts": SCHEMA_WITH_PII_ENCRYPTED}
        )
        analyzer = DrizzleSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        pii_findings = [
            f for f in findings
            if f.category == FindingCategory.UNENCRYPTED_PII
        ]
        assert len(pii_findings) == 0


class TestMissingTenantScope:
    @pytest.mark.asyncio
    async def test_flags_users_table_without_tenant_id(self) -> None:
        """Multi-tenant schema with users table missing tenant_id -> finding."""
        repo = _make_repo(
            file_index={"db/schema.ts": SCHEMA_MULTI_TENANT_NO_SCOPE}
        )
        analyzer = DrizzleSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        tenant_findings = [
            f for f in findings
            if f.category == FindingCategory.AUTH_WEAKNESS
            and "tenant_id" in f.title
        ]
        assert len(tenant_findings) == 1
        assert tenant_findings[0].severity == SeverityLevel.MEDIUM
        assert tenant_findings[0].confidence == DrizzleSchemaAnalyzerConfig.CONFIDENCE_MISSING_TENANT_SCOPE

    @pytest.mark.asyncio
    async def test_no_finding_when_tenant_id_present(self) -> None:
        """Multi-tenant schema with tenant_id on users -> no finding."""
        repo = _make_repo(
            file_index={"db/schema.ts": SCHEMA_MULTI_TENANT_WITH_SCOPE}
        )
        analyzer = DrizzleSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        tenant_findings = [
            f for f in findings
            if f.category == FindingCategory.AUTH_WEAKNESS
            and "tenant_id" in f.title
        ]
        assert len(tenant_findings) == 0


class TestGlobalTableSkipped:
    @pytest.mark.asyncio
    async def test_does_not_flag_tenants_or_audit_logs(self) -> None:
        """Global tables (tenants, audit_logs) should not be flagged for missing tenant_id."""
        repo = _make_repo(
            file_index={"db/schema.ts": SCHEMA_GLOBAL_TABLES}
        )
        analyzer = DrizzleSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        tenant_findings = [
            f for f in findings
            if "tenant_id" in f.title
        ]
        assert len(tenant_findings) == 0


class TestPaymentColumns:
    @pytest.mark.asyncio
    async def test_flags_stripe_customer_id(self) -> None:
        """stripe_customer_id matches prefix+suffix -> finding."""
        repo = _make_repo(
            file_index={"db/schema.ts": SCHEMA_WITH_PAYMENT_COLUMNS}
        )
        analyzer = DrizzleSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        payment_findings = [
            f for f in findings
            if f.category == FindingCategory.INFO_DISCLOSURE
            and "stripe_customer_id" in f.title
        ]
        assert len(payment_findings) == 1
        assert payment_findings[0].severity == SeverityLevel.LOW
        assert payment_findings[0].confidence == DrizzleSchemaAnalyzerConfig.CONFIDENCE_PAYMENT_DATA_EXPOSURE


class TestNonPaymentColumn:
    @pytest.mark.asyncio
    async def test_does_not_flag_user_id_or_plain_customer_id(self) -> None:
        """user_id and customer_id (no payment prefix) should not be flagged."""
        repo = _make_repo(
            file_index={"db/schema.ts": SCHEMA_WITH_PLAIN_IDS}
        )
        analyzer = DrizzleSchemaAnalyzer()
        findings = await analyzer.scan(repo)

        payment_findings = [
            f for f in findings
            if f.category == FindingCategory.INFO_DISCLOSURE
        ]
        assert len(payment_findings) == 0
