"""Tests for InjectionPatternTrigger."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.injection_analyzer import (
    InjectionPatternTrigger,
)
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import StaticInjectionConfig
from isitsecure.engine.enums import ReviewTriggerType


# ---------------------------------------------------------------------------
# Content fixtures
# ---------------------------------------------------------------------------

SQL_INJECTION_CODE = """\
import { db } from './db';

export async function getUser(userId: string) {
  const result = await db.raw(`SELECT * FROM users WHERE id = ${userId}`);
  return result;
}
"""

XSS_CODE = """\
function renderContent(userHtml: string) {
  const el = document.getElementById('content');
  el.innerHTML = userHtml;
}
"""

COMMAND_INJECTION_CODE = """\
import { exec } from 'child_process';

export function runCommand(userInput: string) {
  exec(`ls -la ${userInput}`);
}
"""

MULTIPLE_PATTERNS_CODE = """\
import { db } from './db';
import { exec } from 'child_process';

export async function handler(req) {
  const result = await db.raw(`SELECT * FROM users WHERE id = ${req.params.id}`);
  const el = document.getElementById('output');
  el.innerHTML = result.html;
  exec(`echo ${req.query.cmd}`);
  return result;
}
"""

SAFE_CODE = """\
import { db } from './db';

export async function getUser(userId: string) {
  const result = await db.select().from('users').where({ id: userId });
  return result;
}
"""

TEST_FILE_CODE = """\
import { db } from './db';

describe('getUser', () => {
  it('should query', async () => {
    const result = await db.raw(`SELECT * FROM users WHERE id = ${testId}`);
    expect(result).toBeDefined();
  });
});
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


class TestTriggerType:
    def test_trigger_type(self) -> None:
        trigger = InjectionPatternTrigger()
        assert trigger.trigger_type == ReviewTriggerType.INJECTION_PATTERN_FLAG


class TestNoInjectionPatterns:
    def test_returns_empty_for_safe_code(self) -> None:
        """No injection patterns -> 0 files flagged."""
        repo = _make_repo(file_index={"src/db/users.ts": SAFE_CODE})
        trigger = InjectionPatternTrigger()
        results = trigger.select_files(repo, selected_route_paths=set())
        assert len(results) == 0


class TestSQLInjectionPattern:
    def test_flags_sql_injection(self) -> None:
        """SQL injection pattern -> file flagged with 'SQL injection' label."""
        repo = _make_repo(file_index={"src/db/users.ts": SQL_INJECTION_CODE})
        trigger = InjectionPatternTrigger()
        results = trigger.select_files(repo, selected_route_paths=set())

        assert len(results) == 1
        assert results[0].file_path == "src/db/users.ts"
        assert "SQL injection" in results[0].route_pattern


class TestXSSPattern:
    def test_flags_xss(self) -> None:
        """XSS pattern -> file flagged with 'XSS' label."""
        repo = _make_repo(file_index={"src/utils/render.ts": XSS_CODE})
        trigger = InjectionPatternTrigger()
        results = trigger.select_files(repo, selected_route_paths=set())

        assert len(results) == 1
        assert results[0].file_path == "src/utils/render.ts"
        assert "XSS" in results[0].route_pattern


class TestCommandInjectionPattern:
    def test_flags_command_injection(self) -> None:
        """Command injection pattern -> file flagged."""
        repo = _make_repo(file_index={"src/utils/cmd.ts": COMMAND_INJECTION_CODE})
        trigger = InjectionPatternTrigger()
        results = trigger.select_files(repo, selected_route_paths=set())

        assert len(results) == 1
        assert results[0].file_path == "src/utils/cmd.ts"
        assert "Command injection" in results[0].route_pattern


class TestMultiplePatternTypes:
    def test_flags_with_all_types(self) -> None:
        """Multiple pattern types in one file -> file flagged with all types."""
        repo = _make_repo(file_index={"src/handler.ts": MULTIPLE_PATTERNS_CODE})
        trigger = InjectionPatternTrigger()
        results = trigger.select_files(repo, selected_route_paths=set())

        assert len(results) == 1
        route_pattern = results[0].route_pattern
        assert "SQL injection" in route_pattern
        assert "XSS" in route_pattern
        assert "Command injection" in route_pattern


class TestAlreadySelectedSkipped:
    def test_skips_already_selected_routes(self) -> None:
        """Files already in selected_route_paths -> skipped."""
        repo = _make_repo(
            file_index={"src/db/users.ts": SQL_INJECTION_CODE}
        )
        trigger = InjectionPatternTrigger()
        results = trigger.select_files(
            repo,
            selected_route_paths={"src/db/users.ts"},
        )
        assert len(results) == 0


class TestTestFilesSkipped:
    def test_skips_test_files(self) -> None:
        """.test.ts and .spec.ts files should be skipped."""
        repo = _make_repo(
            file_index={
                "src/db/users.test.ts": TEST_FILE_CODE,
                "src/db/users.spec.ts": TEST_FILE_CODE,
            }
        )
        trigger = InjectionPatternTrigger()
        results = trigger.select_files(repo, selected_route_paths=set())
        assert len(results) == 0


class TestSyntheticRouteEntry:
    def test_returns_route_entry_with_synthetic_pattern(self) -> None:
        """Results should be RouteEntry with synthetic route_pattern containing labels."""
        repo = _make_repo(file_index={"src/api/query.ts": SQL_INJECTION_CODE})
        trigger = InjectionPatternTrigger()
        results = trigger.select_files(repo, selected_route_paths=set())

        assert len(results) == 1
        entry = results[0]
        assert entry.file_path == "src/api/query.ts"
        assert entry.route_pattern.startswith(
            StaticInjectionConfig.SYNTHETIC_ROUTE_PREFIX
        )
        assert entry.http_methods == []
        assert entry.has_auth_check is None
        assert entry.content == SQL_INJECTION_CODE


class TestMaxFilesToFlag:
    def test_respects_max_files_cap(self) -> None:
        """MAX_FILES_TO_FLAG cap is respected."""
        # Create more files than MAX_FILES_TO_FLAG
        file_index = {}
        for i in range(StaticInjectionConfig.MAX_FILES_TO_FLAG + 5):
            file_index[f"src/route{i}.ts"] = SQL_INJECTION_CODE

        repo = _make_repo(file_index=file_index)
        trigger = InjectionPatternTrigger()
        results = trigger.select_files(repo, selected_route_paths=set())

        assert len(results) <= StaticInjectionConfig.MAX_FILES_TO_FLAG
