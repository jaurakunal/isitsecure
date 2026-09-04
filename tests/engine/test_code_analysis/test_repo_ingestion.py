"""Tests for RepoIngestionService."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from isitsecure.engine.code_analysis.framework_detector import (
    FrameworkDetector,
)
from isitsecure.engine.code_analysis.repo_ingestion import (
    RepoIngestionService,
)
from isitsecure.engine.code_analysis.route_mapper import NextJSRouteMapper
from isitsecure.engine.constants import RepoIngestionConfig


class TestRepoIngestionService:
    """Tests for repository ingestion."""

    def setup_method(self) -> None:
        self.detector = FrameworkDetector()
        self.mapper = NextJSRouteMapper()
        self.service = RepoIngestionService(
            framework_detector=self.detector,
            route_mappers=[self.mapper],
        )

    @pytest.mark.asyncio
    async def test_ingest_creates_snapshot(self, tmp_path: Path) -> None:
        """Mock git clone and verify RepoSnapshot is built."""
        # Set up a fake repo directory
        pkg = {"dependencies": {"next": "14.0.0", "@supabase/supabase-js": "2.0.0"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        route_dir = tmp_path / "app" / "api" / "users" / "route.ts"
        route_dir.parent.mkdir(parents=True)
        route_dir.write_text(
            'export async function GET() { return Response.json([]); }\n'
        )

        with patch.object(
            self.service, "_clone_repo", new_callable=AsyncMock
        ) as mock_clone:
            # Make clone a no-op (directory already exists)
            mock_clone.return_value = None

            # Patch tempfile to use our tmp_path
            with patch("isitsecure.engine.code_analysis.repo_ingestion.tempfile") as mock_tmp:
                mock_tmp.mkdtemp.return_value = str(tmp_path)

                snapshot = await self.service.ingest(
                    repo_url="https://github.com/test/repo",
                    branch="main",
                )

        assert snapshot.repo_url == "https://github.com/test/repo"
        assert snapshot.branch == "main"
        assert snapshot.framework.value == "nextjs"
        assert snapshot.backend.value == "supabase"
        assert len(snapshot.route_map) == 1
        assert snapshot.route_map[0].route_pattern == "/api/users"
        assert snapshot.total_files > 0

    def test_read_package_json(self, tmp_path: Path) -> None:
        """Should parse package.json correctly."""
        pkg = {"name": "test-app", "version": "1.0.0"}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        result = self.service._read_package_json(str(tmp_path))
        assert result == pkg

    def test_read_package_json_missing(self, tmp_path: Path) -> None:
        """Should return empty dict when package.json is missing."""
        result = self.service._read_package_json(str(tmp_path))
        assert result == {}

    def test_read_package_json_invalid(self, tmp_path: Path) -> None:
        """Should return empty dict when package.json is invalid JSON."""
        (tmp_path / "package.json").write_text("not valid json {{{")
        result = self.service._read_package_json(str(tmp_path))
        assert result == {}

    def test_index_key_files_skips_node_modules(self, tmp_path: Path) -> None:
        """Should not index files in node_modules."""
        # Key file in root
        (tmp_path / "package.json").write_text('{"name": "app"}')
        # File in node_modules
        nm_dir = tmp_path / "node_modules" / "react"
        nm_dir.mkdir(parents=True)
        (nm_dir / "index.js").write_text("module.exports = {};")

        file_index, _, _ = self.service._index_key_files(str(tmp_path))
        assert "package.json" in file_index
        assert not any("node_modules" in k for k in file_index)

    def test_index_key_files_skips_large_files(self, tmp_path: Path) -> None:
        """Should skip files exceeding MAX_FILE_SIZE_BYTES."""
        small_file = tmp_path / "small.ts"
        small_file.write_text("const x = 1;")

        large_file = tmp_path / "large.ts"
        large_file.write_text("x" * (RepoIngestionConfig.MAX_FILE_SIZE_BYTES + 1))

        file_index, total_files, _ = self.service._index_key_files(str(tmp_path))
        assert "small.ts" in file_index
        assert "large.ts" not in file_index
        assert total_files == 2  # Both counted, but large one not indexed

    def test_index_key_files_includes_code_extensions(self, tmp_path: Path) -> None:
        """Should index .ts, .tsx, .js, .jsx, .mjs, .sql files."""
        for ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".sql"):
            (tmp_path / f"file{ext}").write_text(f"// {ext} file")
        (tmp_path / "readme.md").write_text("# Readme")

        file_index, _, _ = self.service._index_key_files(str(tmp_path))
        for ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".sql"):
            assert f"file{ext}" in file_index
        assert "readme.md" not in file_index

    def test_index_key_files_includes_key_files(self, tmp_path: Path) -> None:
        """Should index key files like middleware.ts, .env."""
        (tmp_path / "middleware.ts").write_text("export function middleware() {}")
        (tmp_path / ".env").write_text("SECRET=value")

        file_index, _, _ = self.service._index_key_files(str(tmp_path))
        assert "middleware.ts" in file_index
        assert ".env" in file_index

    def test_index_skips_git_directory(self, tmp_path: Path) -> None:
        """Should skip .git directory."""
        git_dir = tmp_path / ".git" / "objects"
        git_dir.mkdir(parents=True)
        (git_dir / "pack.js").write_text("git internal")
        (tmp_path / "app.ts").write_text("const app = 1;")

        file_index, _, _ = self.service._index_key_files(str(tmp_path))
        assert "app.ts" in file_index
        assert not any(".git" in k for k in file_index)

    def test_find_migration_files(self, tmp_path: Path) -> None:
        """Should find .sql files in supabase/migrations/."""
        migrations_dir = tmp_path / "supabase" / "migrations"
        migrations_dir.mkdir(parents=True)
        (migrations_dir / "001_create_users.sql").write_text("CREATE TABLE users();")
        (migrations_dir / "002_add_posts.sql").write_text("CREATE TABLE posts();")

        result = self.service._find_all_migration_files(str(tmp_path), [])
        assert len(result) == 2
        assert any("001_create_users.sql" in f for f in result)
        assert any("002_add_posts.sql" in f for f in result)

    def test_find_migration_files_no_dir(self, tmp_path: Path) -> None:
        """Should return empty list when supabase/migrations/ doesn't exist."""
        result = self.service._find_all_migration_files(str(tmp_path), [])
        assert result == []

    def test_find_env_files(self, tmp_path: Path) -> None:
        """Should find .env, .env.local, .env.production."""
        (tmp_path / ".env").write_text("SECRET=1")
        (tmp_path / ".env.local").write_text("LOCAL=2")
        (tmp_path / ".env.production").write_text("PROD=3")
        (tmp_path / "package.json").write_text("{}")

        result = self.service._find_env_files(str(tmp_path))
        assert ".env" in result
        assert ".env.local" in result
        assert ".env.production" in result
        assert "package.json" not in result

    def test_find_env_files_empty(self, tmp_path: Path) -> None:
        """Should return empty list when no .env files exist."""
        result = self.service._find_env_files(str(tmp_path))
        assert result == []


# ---------------------------------------------------------------------------
# #147 — branch selection
# ---------------------------------------------------------------------------


class _FakeProcess:
    """Stand-in for the git subprocess, with a scripted result."""

    def __init__(self, returncode: int = 0, stderr: bytes = b"") -> None:
        self.returncode = returncode
        self._stderr = stderr

    async def communicate(self):
        return b"", self._stderr


class TestBranchSelection:
    """The branch a scan reads must be the one the caller asked for — and,
    when they asked for nothing, the repository's own default rather than an
    assumed ``main`` (issue #147)."""

    def setup_method(self) -> None:
        self.service = RepoIngestionService(
            framework_detector=FrameworkDetector(), route_mappers=[],
        )

    async def _clone_argv(self, monkeypatch, branch, returncode=0, stderr=b""):
        """Run _clone_repo against a stubbed git and return its argv."""
        captured: list[str] = []

        async def fake_exec(*cmd, **_kwargs):
            captured.extend(cmd)
            return _FakeProcess(returncode, stderr)

        monkeypatch.setattr(
            "isitsecure.engine.code_analysis.repo_ingestion."
            "asyncio.create_subprocess_exec",
            fake_exec,
        )
        await self.service._clone_repo(
            "https://github.com/org/repo", branch, "/tmp/clone", None, False
        )
        return captured

    @pytest.mark.asyncio
    async def test_no_branch_lets_git_pick_the_default(self, monkeypatch) -> None:
        """Without --branch, git clones the remote's own default branch."""
        argv = await self._clone_argv(monkeypatch, None)
        assert "--branch" not in argv
        assert "main" not in argv

    @pytest.mark.asyncio
    async def test_explicit_branch_is_passed_to_git(self, monkeypatch) -> None:
        argv = await self._clone_argv(monkeypatch, "master")
        assert argv[argv.index("--branch") + 1] == "master"

    @pytest.mark.asyncio
    async def test_url_still_terminated_by_double_dash(self, monkeypatch) -> None:
        """The arg-injection guard survives the branch becoming optional."""
        argv = await self._clone_argv(monkeypatch, None)
        assert argv[argv.index("--") + 1] == "https://github.com/org/repo"

    @pytest.mark.asyncio
    async def test_missing_branch_is_reported_as_a_branch_problem(
        self, monkeypatch
    ) -> None:
        with pytest.raises(RuntimeError, match="Branch 'nope' not found"):
            await self._clone_argv(
                monkeypatch, "nope", returncode=1, stderr=b"remote branch not found",
            )

    @pytest.mark.asyncio
    async def test_missing_repo_is_not_blamed_on_a_branch(
        self, monkeypatch
    ) -> None:
        """We asked git for no branch, so 'not found' is about the repo —
        blaming a branch nobody requested is what sent people astray."""
        with pytest.raises(RuntimeError) as exc:
            await self._clone_argv(
                monkeypatch, None, returncode=1, stderr=b"repository not found",
            )
        assert "Branch" not in str(exc.value)
        assert "https://github.com/org/repo" in str(exc.value)

    @pytest.mark.asyncio
    async def test_snapshot_records_the_branch_actually_checked_out(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """`branch=None` must not leave the snapshot claiming 'main'."""
        (tmp_path / "package.json").write_text("{}")
        monkeypatch.setattr(
            RepoIngestionService, "_get_branch_name",
            AsyncMock(return_value="develop"),
        )
        with patch.object(self.service, "_clone_repo", new_callable=AsyncMock):
            with patch(
                "isitsecure.engine.code_analysis.repo_ingestion.tempfile"
            ) as mock_tmp:
                mock_tmp.mkdtemp.return_value = str(tmp_path)
                snapshot = await self.service.ingest(
                    repo_url="https://github.com/org/repo",
                )
        assert snapshot.branch == "develop"

    @pytest.mark.asyncio
    async def test_requested_branch_is_the_fallback_when_git_cannot_answer(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        (tmp_path / "package.json").write_text("{}")
        monkeypatch.setattr(
            RepoIngestionService, "_get_branch_name", AsyncMock(return_value=""),
        )
        with patch.object(self.service, "_clone_repo", new_callable=AsyncMock):
            with patch(
                "isitsecure.engine.code_analysis.repo_ingestion.tempfile"
            ) as mock_tmp:
                mock_tmp.mkdtemp.return_value = str(tmp_path)
                snapshot = await self.service.ingest(
                    repo_url="https://github.com/org/repo", branch="release",
                )
        assert snapshot.branch == "release"

    def test_validate_remote_still_rejects_option_like_branches(self) -> None:
        with pytest.raises(RuntimeError, match="branch"):
            RepoIngestionService._validate_remote(
                "https://github.com/org/repo", "--upload-pack=evil",
            )

    def test_validate_remote_accepts_no_branch(self) -> None:
        RepoIngestionService._validate_remote(
            "https://github.com/org/repo", None,
        )  # must not raise

    def test_validate_remote_still_rejects_unsafe_transports(self) -> None:
        with pytest.raises(RuntimeError):
            RepoIngestionService._validate_remote("ext::sh -c evil", None)
