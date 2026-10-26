"""D2 regression tests for the RLS analyzer (spaced names, DISABLE/DROP, TO roles, gating)."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.code_analysis.rls_policy_analyzer import RLSPolicyAnalyzer
from isitsecure.engine.enums import BackendType, SeverityLevel


async def _scan(sql: str, path: str = "supabase/migrations/001_init.sql", **kw):
    repo = RepoSnapshot(
        repo_url="x", branch="main", clone_path="/tmp/x", file_index={path: sql}, **kw
    )
    return await RLSPolicyAnalyzer().scan(repo)


def _titles(findings) -> list[str]:
    return [f.title for f in findings]


SPACED = """
CREATE TABLE public.notes (id uuid PRIMARY KEY, user_id uuid);
ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Enable read access for all users" ON public.notes FOR SELECT USING (true);
CREATE POLICY "Users can insert their own notes" ON public.notes FOR INSERT WITH CHECK (auth.uid() = user_id);
"""


@pytest.mark.asyncio
async def test_spaced_policy_name_is_parsed_and_permissive_reported() -> None:
    findings = await _scan(SPACED)
    titles = _titles(findings)
    assert not any("no policies" in t for t in titles)
    perm = [f for f in findings if "permissive" in f.title.lower()]
    assert len(perm) == 1
    assert "Enable read access for all users" in perm[0].description


@pytest.mark.asyncio
async def test_disable_rls_after_enable_is_critical() -> None:
    sql = """
CREATE TABLE public.deals (id uuid PRIMARY KEY, user_id uuid);
ALTER TABLE public.deals ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON public.deals USING (auth.uid() = user_id);
ALTER TABLE public.deals DISABLE ROW LEVEL SECURITY;
"""
    findings = await _scan(sql)
    assert any(
        f.severity == SeverityLevel.CRITICAL and "does not have Row Level Security" in f.title
        for f in findings
    )


@pytest.mark.asyncio
async def test_re_enable_after_disable_is_clean() -> None:
    sql = """
CREATE TABLE public.deals (id uuid PRIMARY KEY, user_id uuid);
ALTER TABLE public.deals DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.deals ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON public.deals USING (auth.uid() = user_id);
"""
    assert await _scan(sql) == []


@pytest.mark.asyncio
async def test_dropped_permissive_policy_not_reported() -> None:
    sql = """
CREATE TABLE public.deals (id uuid PRIMARY KEY, user_id uuid);
ALTER TABLE public.deals ENABLE ROW LEVEL SECURITY;
CREATE POLICY "open" ON public.deals FOR SELECT USING (true);
CREATE POLICY "own" ON public.deals FOR SELECT USING (auth.uid() = user_id);
DROP POLICY "open" ON public.deals;
"""
    assert await _scan(sql) == []


@pytest.mark.asyncio
async def test_permissive_policy_still_reported_when_other_policy_dropped() -> None:
    sql = """
CREATE TABLE public.deals (id uuid PRIMARY KEY, user_id uuid);
ALTER TABLE public.deals ENABLE ROW LEVEL SECURITY;
CREATE POLICY "open" ON public.deals FOR SELECT USING (true);
CREATE POLICY "own" ON public.deals FOR SELECT USING (auth.uid() = user_id);
DROP POLICY IF EXISTS "own" ON public.deals;
"""
    assert any("permissive" in t.lower() for t in _titles(await _scan(sql)))


@pytest.mark.asyncio
async def test_dropped_table_not_reported() -> None:
    sql = """
CREATE TABLE public.tmp (id uuid);
DROP TABLE IF EXISTS public.tmp;
"""
    assert await _scan(sql) == []


@pytest.mark.asyncio
async def test_service_role_only_policy_not_permissive() -> None:
    sql = """
CREATE TABLE public.audit (id uuid PRIMARY KEY);
ALTER TABLE public.audit ENABLE ROW LEVEL SECURITY;
CREATE POLICY "svc" ON public.audit TO service_role USING (true) WITH CHECK (true);
"""
    findings = await _scan(sql)
    assert findings == []


@pytest.mark.asyncio
async def test_authenticated_using_true_still_reported() -> None:  # positive control
    sql = """
CREATE TABLE public.audit (id uuid PRIMARY KEY);
ALTER TABLE public.audit ENABLE ROW LEVEL SECURITY;
CREATE POLICY "svc" ON public.audit TO service_role USING (true);
CREATE POLICY "read" ON public.audit FOR SELECT TO authenticated USING (true);
"""
    assert any("permissive" in t.lower() for t in _titles(await _scan(sql)))


PRISMA_SQL = "CREATE TABLE \"User\" (id SERIAL PRIMARY KEY, email TEXT);\n"


@pytest.mark.asyncio
async def test_prisma_migration_not_flagged_as_missing_rls() -> None:
    findings = await _scan(
        PRISMA_SQL,
        path="prisma/migrations/20240101_init/migration.sql",
        backend=BackendType.PRISMA,
    )
    assert findings == []


@pytest.mark.asyncio
async def test_non_conventional_path_with_supabase_markers_still_analyzed() -> None:
    sql = (
        "CREATE TABLE public.deals (id uuid PRIMARY KEY, user_id uuid REFERENCES auth.users(id));\n"
    )
    findings = await _scan(sql, path="db/migrations/001.sql")
    assert any(f.severity == SeverityLevel.CRITICAL for f in findings)


@pytest.mark.asyncio
async def test_supabase_backend_plain_sql_still_analyzed() -> None:
    findings = await _scan(
        "CREATE TABLE public.deals (id uuid PRIMARY KEY);\n",
        path="db/migrations/001.sql",
        backend=BackendType.SUPABASE,
    )
    assert any(f.severity == SeverityLevel.CRITICAL for f in findings)
