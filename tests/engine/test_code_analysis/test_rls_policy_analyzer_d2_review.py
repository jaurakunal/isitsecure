"""RLS analyzer: ALTER TABLE ONLY ... ENABLE, and unterminated block comments."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.code_analysis.rls_policy_analyzer import RLSPolicyAnalyzer


async def _titles(sql: str) -> list[str]:
    repo = RepoSnapshot(
        repo_url="x", branch="main", clone_path="/tmp/x",
        file_index={"supabase/migrations/001.sql": sql},
    )
    return [f.title for f in await RLSPolicyAnalyzer().scan(repo)]


@pytest.mark.asyncio
@pytest.mark.parametrize("alter", [
    "ALTER TABLE ONLY public.notes ENABLE ROW LEVEL SECURITY;",
    "ALTER TABLE IF EXISTS public.notes ENABLE ROW LEVEL SECURITY;",
])
async def test_alter_table_only_enable_rls_is_recognised(alter: str) -> None:
    sql = f"CREATE TABLE public.notes (id uuid, user_id uuid);\n{alter}\n"
    titles = await _titles(sql)
    assert not any("does not have Row Level Security" in t for t in titles)


@pytest.mark.asyncio
async def test_positive_control_table_without_rls_still_reported() -> None:
    titles = await _titles("CREATE TABLE public.notes (id uuid, user_id uuid);\n")
    assert any("does not have Row Level Security" in t for t in titles)


@pytest.mark.asyncio
async def test_unterminated_comment_is_comment_to_end_of_file() -> None:
    sql = (
        "CREATE TABLE public.a (id uuid);\n"
        "ALTER TABLE public.a ENABLE ROW LEVEL SECURITY;\n"
        "/* trailing note that never closes\n"
        "SELECT 1;\n"
        "ALTER TABLE public.a DISABLE ROW LEVEL SECURITY;\n"
    )
    titles = await _titles(sql)
    # earlier statements are still analysed ...
    assert titles == ["Table 'a' has RLS enabled but no policies defined"]
    # ... and nothing after the unterminated "/*" is executed
    assert not any("does not have Row Level Security" in t for t in titles)
