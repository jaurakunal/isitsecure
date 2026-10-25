"""Symlink containment for every walk/read of a scanned clone (round 2, R4).

A scanned repo can plant a symlink pointing outside the clone. No mapper or
scanner may follow it (file or directory, directly or through a chain), and
a clone whose own parent path contains symlinks must keep working.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from isitsecure.engine.code_analysis.django_route_mapper import DjangoRouteMapper
from isitsecure.engine.code_analysis.express_route_mapper import ExpressRouteMapper
from isitsecure.engine.code_analysis.fastapi_route_mapper import FastAPIRouteMapper
from isitsecure.engine.code_analysis.go_route_mapper import GoRouteMapper
from isitsecure.engine.code_analysis.graphql_route_mapper import GraphQLRouteMapper
from isitsecure.engine.code_analysis.k8s_scanner import K8sScanner
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.code_analysis.route_mapper import NextJSRouteMapper
from isitsecure.engine.code_analysis.semgrep_analyzer import SemgrepAnalyzer
from isitsecure.engine.code_analysis.shared_utils import (
    is_plain_in_root,
    iter_repo_files,
    read_repo_file,
)
from isitsecure.engine.code_analysis.spring_route_mapper import SpringRouteMapper
from isitsecure.engine.code_analysis.trpc_route_mapper import TRPCRouteMapper

MARKER = "SECRET_MARKER"

# name -> (mapper class, repo-relative path of the route file, payload).
# Every payload defines a route containing "leak" (or, for Next.js, whose
# content carries MARKER) so a followed symlink is visible in the output.
CASES = {
    "nextjs": (
        NextJSRouteMapper,
        "app/api/x/route.ts",
        f"// {MARKER}\nexport async function GET() {{ return 1 }}\n",
    ),
    "express": (
        ExpressRouteMapper,
        "src/leaky.js",
        f"// {MARKER}\nconst app = require('express')();\n"
        "app.get('/leak', (req, res) => res.send('x'));\n",
    ),
    "trpc": (
        TRPCRouteMapper,
        "src/trpc/routers/leaky.router.ts",
        f"// {MARKER}\nexport const leakRouter = router({{\n"
        "  leak: publicProcedure.query(() => 'x'),\n});\n",
    ),
    "graphql": (
        GraphQLRouteMapper,
        "src/schema.graphql",
        f"# {MARKER}\ntype Query {{\n  leak: String\n}}\n",
    ),
    "django": (
        DjangoRouteMapper,
        "api/urls.py",
        f"# {MARKER}\nfrom django.urls import path\n"
        "urlpatterns = [path('leak/', views.leak)]\n",
    ),
    "fastapi": (
        FastAPIRouteMapper,
        "app/main.py",
        f"# {MARKER}\nfrom fastapi import FastAPI\napp = FastAPI()\n"
        "@app.get('/leak')\ndef leak():\n    return 1\n",
    ),
    "spring": (
        SpringRouteMapper,
        "src/main/java/LeakController.java",
        f"// {MARKER}\n@RestController\npublic class LeakController {{\n"
        '  @GetMapping("/leak")\n  public String leak() {{ return ""; }}\n}}\n',
    ),
    "go": (
        GoRouteMapper,
        "cmd/main.go",
        f"// {MARKER}\npackage main\nfunc main() {{\n"
        '  r := gin.Default()\n  r.GET("/leak", leak)\n}}\n',
    ),
}


# Real (non-link) files some mappers need next to the payload to resolve it.
EXTRAS = {
    "trpc": {
        "src/trpc/root.ts": "import { leakRouter } from './routers/leaky.router.js';\n"
        "export const appRouter = router({ leak: leakRouter });\n",
    },
}


def _leaked(routes) -> bool:
    return any(
        "leak" in r.route_pattern.lower() or MARKER in repr(r) for r in routes
    ) or any(MARKER in r.content for r in routes)


def _extras(repo: Path, name: str) -> None:
    for rel, text in EXTRAS.get(name, {}).items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)


def _mk(tmp_path: Path, payload: str) -> tuple[Path, Path]:
    """repo/ and outside/secret (holding the payload)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "outside"
    out.mkdir()
    (out / "secret").write_text(payload)
    return repo, out


@pytest.mark.parametrize("name", CASES)
class TestMapperSymlinks:
    def test_control_real_file_is_mapped(self, tmp_path: Path, name: str) -> None:
        cls, rel, payload = CASES[name]
        repo, _ = _mk(tmp_path, payload)
        _extras(repo, name)
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(payload)
        assert _leaked(cls().map_routes(str(repo)))  # the payload is detectable

    def test_symlinked_file_outside_repo_is_ignored(
        self, tmp_path: Path, name: str
    ) -> None:
        cls, rel, payload = CASES[name]
        repo, out = _mk(tmp_path, payload)
        _extras(repo, name)
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).symlink_to(out / "secret")
        # also give the extensioned name an outside file with the right suffix
        assert not _leaked(cls().map_routes(str(repo)))

    def test_nested_symlink_chain_is_ignored(self, tmp_path: Path, name: str) -> None:
        cls, rel, payload = CASES[name]
        repo, out = _mk(tmp_path, payload)
        _extras(repo, name)
        (repo / "hop2").symlink_to(out / "secret")
        (repo / "hop1").symlink_to(repo / "hop2")
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).symlink_to(repo / "hop1")
        assert not _leaked(cls().map_routes(str(repo)))

    def test_symlinked_directory_is_ignored(self, tmp_path: Path, name: str) -> None:
        cls, rel, payload = CASES[name]
        repo, out = _mk(tmp_path, payload)
        _extras(repo, name)
        outdir = out / "dir"
        outdir.mkdir()
        (outdir / Path(rel).name).write_text(payload)
        parent = (repo / rel).parent
        parent.parent.mkdir(parents=True, exist_ok=True)
        parent.symlink_to(outdir, target_is_directory=True)
        assert not _leaked(cls().map_routes(str(repo)))

    def test_clone_root_under_symlinked_parent_still_works(
        self, tmp_path: Path, name: str
    ) -> None:
        cls, rel, payload = CASES[name]
        real = tmp_path / "real"
        repo = real / "repo"
        repo.mkdir(parents=True)
        _extras(repo, name)
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(payload)
        (tmp_path / "via").symlink_to(real, target_is_directory=True)
        assert _leaked(cls().map_routes(str(tmp_path / "via" / "repo")))

    def test_symlinked_parent_still_rejects_outside_links(
        self, tmp_path: Path, name: str
    ) -> None:
        cls, rel, payload = CASES[name]
        real = tmp_path / "real"
        repo = real / "repo"
        repo.mkdir(parents=True)
        out = tmp_path / "outside"
        out.mkdir()
        (out / "secret").write_text(payload)
        _extras(repo, name)
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).symlink_to(out / "secret")
        (tmp_path / "via").symlink_to(real, target_is_directory=True)
        assert not _leaked(cls().map_routes(str(tmp_path / "via" / "repo")))


def test_in_repo_symlink_is_skipped_by_design(tmp_path: Path) -> None:
    """Even a link to another file inside the clone is skipped: telling a
    benign link from an escape is the repo's call, so none are followed."""
    cls, rel, payload = CASES["fastapi"]
    repo, _ = _mk(tmp_path, payload)
    (repo / "app").mkdir()
    (repo / "app" / "real_impl.txt").write_text(payload)
    (repo / rel).symlink_to(repo / "app" / "real_impl.txt")
    assert not _leaked(cls().map_routes(str(repo)))


class TestSharedHelpers:
    def test_iter_skips_links_and_counts_them(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        repo, out = _mk(tmp_path, "x")
        (repo / "a.py").write_text("a")
        (repo / "l.py").symlink_to(out / "secret")
        (repo / "d").symlink_to(out, target_is_directory=True)
        with caplog.at_level("DEBUG", logger="isitsecure.engine.code_analysis.shared_utils"):
            found = list(iter_repo_files(repo, ["*.py"]))
        assert [p.name for p in found] == ["a.py"]
        msgs = [r.getMessage() for r in caplog.records if "skipped" in r.getMessage()]
        assert len(msgs) == 1 and "2 symlinked" in msgs[0]

    def test_iter_with_symlinked_base_yields_nothing(self, tmp_path: Path) -> None:
        repo, out = _mk(tmp_path, "x")
        (out / "n.py").write_text("n")
        (repo / "src").symlink_to(out, target_is_directory=True)
        assert list(iter_repo_files(repo, ["*.py"], base=repo / "src")) == []

    def test_iter_prunes_skip_dirs_and_hidden(self, tmp_path: Path) -> None:
        repo, _ = _mk(tmp_path, "x")
        for d in ("node_modules", ".hid", "ok"):
            (repo / d).mkdir()
            (repo / d / "f.js").write_text("f")
        names = {
            p.parent.name
            for p in iter_repo_files(
                repo, ["*.js"], skip_dirs=frozenset({"node_modules"}), skip_hidden=True
            )
        }
        assert names == {"ok"}

    def test_read_repo_file(self, tmp_path: Path) -> None:
        repo, out = _mk(tmp_path, "payload")
        (repo / "ok.txt").write_text("fine")
        (repo / "l.txt").symlink_to(out / "secret")
        assert read_repo_file(repo, repo / "ok.txt") == "fine"
        assert read_repo_file(repo, repo / "l.txt") is None
        assert read_repo_file(repo, out / "secret") is None
        assert read_repo_file(repo, repo / "missing.txt") is None

    def test_is_plain_in_root_accepts_root_itself_under_symlinked_parent(
        self, tmp_path: Path
    ) -> None:
        real = tmp_path / "real"
        (real / "repo").mkdir(parents=True)
        (tmp_path / "via").symlink_to(real, target_is_directory=True)
        root = tmp_path / "via" / "repo"
        assert is_plain_in_root(root, root)


# ------------------------------------------------------------------ k8s
K8S_YAML = (
    f"# {MARKER}\napiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n"
    "  containers:\n  - name: a\n    image: x\n    securityContext:\n"
    "      privileged: true\n"
)


def _k8s_scan(root: Path):
    repo = RepoSnapshot(
        repo_url="https://github.com/test/repo", branch="main",
        clone_path=str(root), file_index={}, route_map=[], package_json={},
    )
    return asyncio.run(K8sScanner().scan(repo))


class TestK8sSymlinks:
    def test_control(self, tmp_path: Path) -> None:
        repo, _ = _mk(tmp_path, K8S_YAML)
        (repo / "k8s").mkdir()
        (repo / "k8s" / "pod.yaml").write_text(K8S_YAML)
        assert _k8s_scan(repo)

    def test_symlinked_manifest_outside_repo_ignored(self, tmp_path: Path) -> None:
        repo, out = _mk(tmp_path, K8S_YAML)
        (repo / "k8s").mkdir()
        (repo / "k8s" / "pod.yaml").symlink_to(out / "secret")
        assert not _k8s_scan(repo)

    def test_symlinked_k8s_directory_ignored(self, tmp_path: Path) -> None:
        repo, out = _mk(tmp_path, K8S_YAML)
        (out / "dir").mkdir()
        (out / "dir" / "pod.yaml").write_text(K8S_YAML)
        (repo / "k8s").symlink_to(out / "dir", target_is_directory=True)
        assert not _k8s_scan(repo)

    def test_symlinked_parent_still_works(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        (real / "repo" / "k8s").mkdir(parents=True)
        (real / "repo" / "k8s" / "pod.yaml").write_text(K8S_YAML)
        (tmp_path / "via").symlink_to(real, target_is_directory=True)
        assert _k8s_scan(tmp_path / "via" / "repo")


# -------------------------------------------------------------- semgrep
SEMGREP = shutil.which("semgrep") or str(
    Path(os.environ.get("VIRTUAL_ENV", "")) / "bin" / "semgrep"
)
needs_semgrep = pytest.mark.skipif(
    not Path(SEMGREP).is_file(), reason="semgrep binary not available"
)


@needs_semgrep
class TestSemgrepSymlinks:
    """Verified against the real binary: semgrep never follows symlinks, in or
    out of a git work tree; these tests pin that so a semgrep change or a
    different invocation cannot silently start reading outside the clone."""

    def _scan(self, repo: Path, rules: Path):
        snap = RepoSnapshot(
            repo_url="https://github.com/test/repo", branch="main",
            clone_path=str(repo), file_index={}, route_map=[], package_json={},
        )
        analyzer = SemgrepAnalyzer(rules_dir=rules)
        analyzer._find_semgrep = staticmethod(lambda: SEMGREP)  # type: ignore[method-assign]
        return asyncio.run(analyzer.scan(snap))

    def _rules(self, tmp_path: Path) -> Path:
        rules = tmp_path / "rules"
        rules.mkdir()
        (rules / "injection-python.yaml").write_text(
            "rules:\n  - id: t-command-injection\n    languages: [python]\n"
            "    message: found\n    severity: ERROR\n    pattern: os.system(...)\n"
        )
        return rules

    @pytest.mark.parametrize("git", [False, True])
    def test_symlinked_source_is_not_scanned(self, tmp_path: Path, git: bool) -> None:
        src = f"import os\n# {MARKER}\nos.system('ls')\n"
        repo, out = _mk(tmp_path, src)
        (out / "dir").mkdir()
        (out / "dir" / "inner.py").write_text(src)
        (repo / "real.py").write_text(src)
        (repo / "link.py").symlink_to(out / "secret")
        (repo / "dirlink").symlink_to(out / "dir", target_is_directory=True)
        if git:
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        findings = self._scan(repo, self._rules(tmp_path))
        assert {f.file_path for f in findings} == {"real.py"}
        assert all(MARKER not in (f.code_snippet or "") or f.file_path == "real.py"
                   for f in findings)
