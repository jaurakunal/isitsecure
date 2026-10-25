"""Containment of repo ingestion: workspaces, symlinks, scan-root-relative
skips, GitHub URL/token handling and subprocess timeouts."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from isitsecure.engine.code_analysis.fastapi_route_mapper import (
    FastAPIRouteMapper,
)
from isitsecure.engine.code_analysis.framework_detector import FrameworkDetector
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.code_analysis.repo_ingestion import RepoIngestionService
from isitsecure.engine.code_analysis.secret_scanner import GitSecretScanner
from isitsecure.engine.code_analysis.shared_utils import should_skip_path
from isitsecure.engine.code_analysis.workspace_detector import WorkspaceDetector
from isitsecure.engine.constants import RepoIngestionConfig, SecretScannerConfig
from isitsecure.engine.fixes.pr_flow import parse_github_url

MOD = "isitsecure.engine.code_analysis.repo_ingestion"


# ---------------------------------------------------------------- workspaces
class TestWorkspaceGlobContainment:
    def _repo(self, tmp_path: Path, patterns: list[str]) -> tuple[Path, Path]:
        root = tmp_path / "clone"
        root.mkdir()
        (root / "package.json").write_text(json.dumps({"workspaces": patterns}))
        (root / "packages" / "ok").mkdir(parents=True)
        (root / "packages" / "ok" / "package.json").write_text("{}")
        outside = tmp_path / "outside"
        (outside / "secretpkg").mkdir(parents=True)
        (outside / "secretpkg" / "package.json").write_text('{"name":"leak"}')
        return root, outside

    def _detect(self, root: Path):
        return WorkspaceDetector(FrameworkDetector()).detect(str(root))

    def test_dotdot_pattern_ignored(self, tmp_path: Path) -> None:
        root, _ = self._repo(tmp_path, ["../outside/*", "packages/*"])
        assert [w.path for w in self._detect(root)] == ["packages/ok"]

    def test_absolute_pattern_ignored_without_crash(self, tmp_path: Path) -> None:
        root, outside = self._repo(tmp_path, ["packages/*"])
        (root / "package.json").write_text(
            json.dumps({"workspaces": [str(outside / "*"), "packages/*"]})
        )
        assert [w.path for w in self._detect(root)] == ["packages/ok"]

    def test_symlinked_workspace_dir_outside_ignored(self, tmp_path: Path) -> None:
        root, outside = self._repo(tmp_path, ["packages/*"])
        os.symlink(outside / "secretpkg", root / "packages" / "evil")
        assert [w.path for w in self._detect(root)] == ["packages/ok"]


# ------------------------------------------------------------------ symlinks
class TestIndexSymlinks:
    def test_outside_symlinks_not_indexed(self, tmp_path: Path) -> None:
        service = RepoIngestionService(
            framework_detector=FrameworkDetector(), route_mappers=[]
        )
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "host.py").write_text("SECRET_FROM_HOST = 1\n")
        root = tmp_path / "clone"
        root.mkdir()
        (root / "app.py").write_text("x = 1\n")
        os.symlink(outside / "host.py", root / "link.py")
        os.symlink(outside, root / "linkdir")
        index, _, _ = service._index_key_files(str(root))
        assert "app.py" in index
        assert not any("SECRET_FROM_HOST" in v for v in index.values())
        assert "link.py" not in index
        assert not any(k.startswith("linkdir") for k in index)


# --------------------------------------------------------- scan-root relative
FASTAPI_SRC = (
    "from fastapi import APIRouter\n"
    "router = APIRouter()\n"
    "@router.get('/items')\n"
    "def items(): return []\n"
)


class TestSkipPathRelativeToRoot:
    @pytest.mark.parametrize(
        "parent", ["work", "build", "env", "dist", "node_modules"]
    )
    def test_routes_independent_of_parent_dir_name(
        self, tmp_path: Path, parent: str
    ) -> None:
        root = tmp_path / parent / "proj"
        root.mkdir(parents=True)
        (root / "main.py").write_text(FASTAPI_SRC)
        routes = FastAPIRouteMapper().map_routes(str(root))
        assert [r.route_pattern for r in routes] == ["/items"]

    def test_should_skip_path_uses_relative_parts(self) -> None:
        root = Path("/x/build/proj")
        assert not should_skip_path(root / "app" / "main.py", root=root)
        assert should_skip_path(root / "node_modules" / "a.py", root=root)

    def test_mapper_does_not_follow_outside_symlink(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "r.py").write_text(FASTAPI_SRC)
        root = tmp_path / "clone"
        root.mkdir()
        os.symlink(outside / "r.py", root / "r.py")
        assert FastAPIRouteMapper().map_routes(str(root)) == []


# ------------------------------------------------------------------ URL/token
class TestGithubUrlStrict:
    @pytest.mark.parametrize("bad", [
        "https://evil.com#@github.com/o/r",
        "https://evil.com?@github.com/o/r",
        "https://github.com.evil.com/o/r",
        "https://x@github.com/o/r",
        "https://x-access-token:tok@github.com/o/r",
        "https://github.com@evil.com/o/r",
        "https://github.com/o/r/extra",
        "https://github.com/o/r?x=1",
        "https://github.com/o/r#frag",
    ])
    def test_rejected_as_github(self, bad: str) -> None:
        try:
            ref = parse_github_url(bad)
        except ValueError:
            return
        assert not ref.is_github

    @pytest.mark.parametrize("good", [
        "https://github.com/o/r", "https://GitHub.com/o/r.git",
        "git@github.com:o/r.git", "ssh://git@github.com/o/r",
    ])
    def test_accepted(self, good: str) -> None:
        ref = parse_github_url(good)
        assert (ref.host.lower(), ref.owner, ref.repo) == ("github.com", "o", "r")
        assert ref.is_github


class _FakeProc:
    returncode = 0

    async def communicate(self):
        return b"", b""


class TestTokenInjection:
    async def _argv(self, monkeypatch, url: str) -> list[str]:
        captured: list[str] = []

        async def fake_exec(*cmd, **_kw):
            captured.extend(cmd)
            return _FakeProc()

        monkeypatch.setattr(f"{MOD}.asyncio.create_subprocess_exec", fake_exec)
        svc = RepoIngestionService(FrameworkDetector(), [])
        await svc._clone_repo(url, None, "/tmp/c", "TOKEN123", False)
        return captured

    async def test_token_injected_for_github(self, monkeypatch) -> None:
        argv = await self._argv(monkeypatch, "https://github.com/o/r")
        assert "https://x-access-token:TOKEN123@github.com/o/r" in argv

    @pytest.mark.parametrize("url", [
        "https://evil.com#@github.com/o/r",
        "https://github.com.evil.com/o/r",
        "https://gitlab.com/o/r",
        "https://x@github.com/o/r",
    ])
    async def test_token_never_sent_elsewhere(self, monkeypatch, url) -> None:
        argv = await self._argv(monkeypatch, url)
        assert not any("TOKEN123" in a for a in argv)


# ------------------------------------------------------------- git timeouts
class _HangProc:
    returncode = None

    def __init__(self) -> None:
        self.killed = False
        self.reaped = False

    async def communicate(self):
        await asyncio.sleep(3600)

    def kill(self) -> None:
        self.killed = True

    async def wait(self):
        self.reaped = True
        return -9


class TestTimeoutKillsChild:
    async def test_clone_timeout_kills_and_reaps(self, monkeypatch) -> None:
        proc = _HangProc()

        async def fake_exec(*_a, **_k):
            return proc

        monkeypatch.setattr(f"{MOD}.asyncio.create_subprocess_exec", fake_exec)
        monkeypatch.setattr(RepoIngestionConfig, "CLONE_TIMEOUT_SECONDS", 0.05)
        svc = RepoIngestionService(FrameworkDetector(), [])
        with pytest.raises(RuntimeError, match="timed out"):
            await svc._clone_repo(
                "https://github.com/o/r", None, "/tmp/c", None, False
            )
        assert proc.killed and proc.reaped

    @pytest.mark.parametrize(
        "method", ["_scan_git_history", "_scan_sensitive_files"]
    )
    async def test_secret_scanner_timeout_kills_and_reaps(
        self, monkeypatch, method
    ) -> None:
        proc = _HangProc()

        async def fake_exec(*_a, **_k):
            return proc

        monkeypatch.setattr(
            "isitsecure.engine.code_analysis.secret_scanner.asyncio."
            "create_subprocess_exec",
            fake_exec,
        )
        monkeypatch.setattr(SecretScannerConfig, "GIT_LOG_TIMEOUT_SECONDS", 0.05)
        repo = RepoSnapshot(repo_url="x", branch="main", clone_path="/tmp/none")
        await getattr(GitSecretScanner(), method)(repo)
        assert proc.killed and proc.reaped
