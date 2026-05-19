"""Tests for RLSPolicyAnalyzer."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.code_analysis.rls_policy_analyzer import (
    RLSPolicyAnalyzer,
)
from isitsecure.engine.constants import RLSPolicyAnalyzerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# --- SQL Fixtures ---

NO_RLS_SQL = """
CREATE TABLE public.deals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title text NOT NULL,
    user_id uuid REFERENCES auth.users(id)
);
"""

RLS_NO_POLICIES_SQL = """
CREATE TABLE public.deals (id uuid PRIMARY KEY, user_id uuid);
ALTER TABLE public.deals ENABLE ROW LEVEL SECURITY;
"""

PERMISSIVE_RLS_SQL = """
CREATE TABLE public.deals (id uuid PRIMARY KEY, user_id uuid);
ALTER TABLE public.deals ENABLE ROW LEVEL SECURITY;
CREATE POLICY "allow_all" ON public.deals FOR SELECT USING (true);
"""

PERMISSIVE_1_EQUALS_1_SQL = """
CREATE TABLE public.reports (id uuid PRIMARY KEY, user_id uuid);
ALTER TABLE public.reports ENABLE ROW LEVEL SECURITY;
CREATE POLICY "open_access" ON public.reports FOR SELECT USING (1 = 1);
"""

PROPER_RLS_SQL = """
CREATE TABLE public.deals (id uuid PRIMARY KEY, user_id uuid);
ALTER TABLE public.deals ENABLE ROW LEVEL SECURITY;
CREATE POLICY "users_own_deals" ON public.deals FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "users_insert_own" ON public.deals FOR INSERT WITH CHECK (auth.uid() = user_id);
"""

NO_AUTH_UID_POLICY_SQL = """
CREATE TABLE public.public_posts (id uuid PRIMARY KEY, status text);
ALTER TABLE public.public_posts ENABLE ROW LEVEL SECURITY;
CREATE POLICY "by_status" ON public.public_posts FOR SELECT USING (status = 'published');
"""

MULTIPLE_TABLES_SQL = """
CREATE TABLE public.users (id uuid PRIMARY KEY, name text);
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "self_read" ON public.users FOR SELECT USING (auth.uid() = id);

CREATE TABLE public.orders (id uuid PRIMARY KEY, user_id uuid);
-- orders has no RLS enabled!
"""

QUOTED_TABLE_NAME_SQL = """
CREATE TABLE IF NOT EXISTS public."user_profiles" (
    id uuid PRIMARY KEY,
    user_id uuid
);
ALTER TABLE public."user_profiles" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own_profile" ON public."user_profiles" FOR SELECT USING (auth.uid() = user_id);
"""


# --- Helpers ---


def _make_repo(
    file_index: dict[str, str] | None = None,
    migration_files: list[str] | None = None,
) -> RepoSnapshot:
    """Create a minimal RepoSnapshot for testing."""
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/test-repo",
        file_index=file_index or {},
        migration_files=migration_files or [],
    )


class TestRLSPolicyAnalyzer:
    """Tests for the RLSPolicyAnalyzer scanner."""

    def setup_method(self) -> None:
        self.analyzer = RLSPolicyAnalyzer()

    # --- Basic Properties ---

    def test_scanner_name(self) -> None:
        assert self.analyzer.scanner_name == RLSPolicyAnalyzerConfig.SCANNER_NAME

    # --- Table Without RLS ---

    @pytest.mark.asyncio
    async def test_detects_table_without_rls(self) -> None:
        """CREATE TABLE without ALTER TABLE ENABLE RLS -> CRITICAL."""
        repo = _make_repo(
            file_index={"supabase/migrations/001_init.sql": NO_RLS_SQL}
        )

        findings = await self.analyzer.scan(repo)

        no_rls = [
            f for f in findings
            if RLSPolicyAnalyzerConfig.TITLE_NO_RLS.format(table="deals")
            == f.title
        ]
        assert len(no_rls) == 1
        assert no_rls[0].severity == SeverityLevel.CRITICAL
        assert no_rls[0].category == FindingCategory.RLS_MISCONFIGURATION
        assert no_rls[0].confidence == RLSPolicyAnalyzerConfig.CONFIDENCE_NO_RLS

    # --- RLS Without Policies ---

    @pytest.mark.asyncio
    async def test_detects_rls_without_policies(self) -> None:
        """RLS enabled but no CREATE POLICY -> HIGH."""
        repo = _make_repo(
            file_index={
                "supabase/migrations/001_init.sql": RLS_NO_POLICIES_SQL,
            }
        )

        findings = await self.analyzer.scan(repo)

        no_policy = [
            f for f in findings
            if RLSPolicyAnalyzerConfig.TITLE_NO_POLICIES.format(table="deals")
            == f.title
        ]
        assert len(no_policy) == 1
        assert no_policy[0].severity == SeverityLevel.HIGH
        assert no_policy[0].confidence == RLSPolicyAnalyzerConfig.CONFIDENCE_NO_POLICIES

    # --- Permissive Policies ---

    @pytest.mark.asyncio
    async def test_detects_permissive_using_true(self) -> None:
        """Policy with USING (true) -> permissive finding."""
        repo = _make_repo(
            file_index={
                "supabase/migrations/001_init.sql": PERMISSIVE_RLS_SQL,
            }
        )

        findings = await self.analyzer.scan(repo)

        permissive = [
            f for f in findings
            if RLSPolicyAnalyzerConfig.TITLE_PERMISSIVE_POLICY.format(
                table="deals"
            )
            == f.title
        ]
        assert len(permissive) == 1
        assert permissive[0].severity == SeverityLevel.HIGH
        assert "allow_all" in permissive[0].description
        assert "true" in permissive[0].description

    @pytest.mark.asyncio
    async def test_detects_permissive_1_equals_1(self) -> None:
        """Policy with USING (1 = 1) -> permissive finding."""
        repo = _make_repo(
            file_index={
                "supabase/migrations/001_init.sql": PERMISSIVE_1_EQUALS_1_SQL,
            }
        )

        findings = await self.analyzer.scan(repo)

        permissive = [
            f for f in findings
            if RLSPolicyAnalyzerConfig.TITLE_PERMISSIVE_POLICY.format(
                table="reports"
            )
            == f.title
        ]
        assert len(permissive) == 1

    # --- Missing auth.uid() ---

    @pytest.mark.asyncio
    async def test_detects_missing_auth_uid(self) -> None:
        """Policy without auth.uid() -> finding."""
        repo = _make_repo(
            file_index={
                "supabase/migrations/001_init.sql": NO_AUTH_UID_POLICY_SQL,
            }
        )

        findings = await self.analyzer.scan(repo)

        missing_uid = [
            f for f in findings
            if RLSPolicyAnalyzerConfig.TITLE_MISSING_AUTH_UID.format(
                table="public_posts"
            )
            == f.title
        ]
        assert len(missing_uid) == 1
        assert missing_uid[0].severity == SeverityLevel.MEDIUM
        assert missing_uid[0].confidence == RLSPolicyAnalyzerConfig.CONFIDENCE_MISSING_AUTH_UID

    # --- Proper RLS (No Findings) ---

    @pytest.mark.asyncio
    async def test_proper_rls_no_findings(self) -> None:
        """Proper RLS with auth.uid() -> 0 findings."""
        repo = _make_repo(
            file_index={
                "supabase/migrations/001_init.sql": PROPER_RLS_SQL,
            }
        )

        findings = await self.analyzer.scan(repo)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_no_finding_with_rls_and_policies(self) -> None:
        """Table with RLS + proper policies -> safe."""
        repo = _make_repo(
            file_index={
                "supabase/migrations/001_init.sql": PROPER_RLS_SQL,
            }
        )

        findings = await self.analyzer.scan(repo)

        assert len(findings) == 0

    # --- Multiple Tables ---

    @pytest.mark.asyncio
    async def test_multiple_tables_mixed_findings(self) -> None:
        """Multiple tables: one with RLS, one without -> only unsafe flagged."""
        repo = _make_repo(
            file_index={
                "supabase/migrations/001_init.sql": MULTIPLE_TABLES_SQL,
            }
        )

        findings = await self.analyzer.scan(repo)

        # orders has no RLS -> CRITICAL
        orders_findings = [f for f in findings if "orders" in f.title]
        assert len(orders_findings) == 1
        assert orders_findings[0].severity == SeverityLevel.CRITICAL

        # users has proper RLS -> no findings
        users_findings = [
            f for f in findings
            if "users" in f.title
            and f.title != RLSPolicyAnalyzerConfig.TITLE_NO_RLS.format(
                table="orders"
            )
        ]
        assert len(users_findings) == 0

    # --- Edge Cases ---

    @pytest.mark.asyncio
    async def test_empty_repo_no_findings(self) -> None:
        """Empty file_index -> 0 findings, no crash."""
        repo = _make_repo(file_index={})

        findings = await self.analyzer.scan(repo)

        assert findings == []

    @pytest.mark.asyncio
    async def test_no_migration_files(self) -> None:
        """Non-migration SQL files should be skipped."""
        repo = _make_repo(
            file_index={"src/schema.sql": NO_RLS_SQL}
        )

        findings = await self.analyzer.scan(repo)

        assert findings == []

    @pytest.mark.asyncio
    async def test_migration_files_list_used(self) -> None:
        """Files in migration_files list are picked up even without
        'migration' in the path."""
        repo = _make_repo(
            file_index={"supabase/seed.sql": NO_RLS_SQL},
            migration_files=["supabase/seed.sql"],
        )

        findings = await self.analyzer.scan(repo)

        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_quoted_table_names(self) -> None:
        """Quoted table names should be handled properly."""
        repo = _make_repo(
            file_index={
                "supabase/migrations/001_init.sql": QUOTED_TABLE_NAME_SQL,
            }
        )

        findings = await self.analyzer.scan(repo)

        # Proper RLS with auth.uid() -> no findings
        assert len(findings) == 0

    # --- SQL Parsing Unit Tests ---

    def test_extract_tables(self) -> None:
        migrations = {"test.sql": NO_RLS_SQL}
        tables = self.analyzer._extract_tables(migrations)
        assert "deals" in tables

    def test_extract_tables_multiple(self) -> None:
        migrations = {"test.sql": MULTIPLE_TABLES_SQL}
        tables = self.analyzer._extract_tables(migrations)
        assert "users" in tables
        assert "orders" in tables

    def test_extract_rls_enabled(self) -> None:
        migrations = {"test.sql": RLS_NO_POLICIES_SQL}
        enabled = self.analyzer._extract_rls_enabled(migrations)
        assert "deals" in enabled

    def test_extract_rls_enabled_empty(self) -> None:
        migrations = {"test.sql": NO_RLS_SQL}
        enabled = self.analyzer._extract_rls_enabled(migrations)
        assert "deals" not in enabled

    def test_extract_policies(self) -> None:
        migrations = {"test.sql": PROPER_RLS_SQL}
        policies = self.analyzer._extract_policies(migrations)
        assert "deals" in policies
        assert len(policies["deals"]) == 2

        policy_names = {p["name"] for p in policies["deals"]}
        assert "users_own_deals" in policy_names
        assert "users_insert_own" in policy_names

    def test_extract_policies_with_using(self) -> None:
        migrations = {"test.sql": PERMISSIVE_RLS_SQL}
        policies = self.analyzer._extract_policies(migrations)
        assert "deals" in policies
        assert policies["deals"][0]["using"] == "true"

    def test_extract_policies_with_check(self) -> None:
        migrations = {"test.sql": PROPER_RLS_SQL}
        policies = self.analyzer._extract_policies(migrations)
        insert_policies = [
            p for p in policies["deals"]
            if p["for_operation"] == "INSERT"
        ]
        assert len(insert_policies) == 1
        assert "auth.uid()" in insert_policies[0]["with_check"]

    def test_extract_policies_for_operation(self) -> None:
        migrations = {"test.sql": PROPER_RLS_SQL}
        policies = self.analyzer._extract_policies(migrations)
        ops = {p["for_operation"] for p in policies["deals"]}
        assert "SELECT" in ops
        assert "INSERT" in ops

    def test_extract_policies_empty(self) -> None:
        migrations = {"test.sql": RLS_NO_POLICIES_SQL}
        policies = self.analyzer._extract_policies(migrations)
        assert policies.get("deals", []) == []

    def test_find_table_file(self) -> None:
        migrations = {
            "supabase/migrations/001_users.sql": "CREATE TABLE users (id uuid);",
            "supabase/migrations/002_deals.sql": NO_RLS_SQL,
        }
        result = self.analyzer._find_table_file("deals", migrations)
        assert result == "supabase/migrations/002_deals.sql"

    def test_find_table_file_fallback(self) -> None:
        migrations = {"test.sql": "SELECT 1;"}
        result = self.analyzer._find_table_file("nonexistent", migrations)
        assert result == "supabase/migrations/"
