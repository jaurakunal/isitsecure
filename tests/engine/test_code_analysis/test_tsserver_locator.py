"""Tests for the TypeScript runtime locator (issue #145).

The language server refuses to start without a TypeScript 5.x
``lib/tsserver.js``, and scans always run against a tree with no
``node_modules`` — so these tests pin down where we look for one, in what
order, and that a 7.x install is never mistaken for a usable runtime.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from isitsecure.engine.code_analysis.lsp import tsserver_locator
from isitsecure.engine.code_analysis.lsp.tsserver_locator import (
    ENV_OVERRIDE,
    find_tsserver_js,
    tsserver_js_in,
)


def _make_typescript(root: Path, *, version_5: bool = True) -> Path:
    """Create a fake ``node_modules/typescript`` under ``root``.

    A TypeScript 7.x package (``version_5=False``) is the Go rewrite: it has
    the package directory but no ``lib/tsserver.js``.
    """
    lib = root / "node_modules" / "typescript" / "lib"
    lib.mkdir(parents=True, exist_ok=True)
    tsserver = lib / "tsserver.js"
    if version_5:
        tsserver.write_text("// tsserver")
    return tsserver


@pytest.fixture
def isolated(monkeypatch, tmp_path: Path):
    """Neutralise every ambient source so each test controls exactly one."""
    monkeypatch.delenv(ENV_OVERRIDE, raising=False)
    monkeypatch.setattr(
        tsserver_locator, "PROVISIONED_ROOT", tmp_path / "unused-config"
    )
    monkeypatch.setattr(tsserver_locator.shutil, "which", lambda _name: None)
    return tmp_path


# ------------------------------------------------------------------
# tsserver_js_in
# ------------------------------------------------------------------


class TestTsserverJsIn:
    def test_finds_installed_typescript(self, tmp_path: Path) -> None:
        expected = _make_typescript(tmp_path)
        assert tsserver_js_in(tmp_path) == expected

    def test_returns_none_without_node_modules(self, tmp_path: Path) -> None:
        assert tsserver_js_in(tmp_path) is None

    def test_rejects_typescript_7_without_tsserver_js(self, tmp_path: Path) -> None:
        """TS 7.x ships no lib/tsserver.js — the package alone isn't enough."""
        _make_typescript(tmp_path, version_5=False)
        assert (tmp_path / "node_modules" / "typescript").is_dir()
        assert tsserver_js_in(tmp_path) is None

    def test_accepts_str_path(self, tmp_path: Path) -> None:
        expected = _make_typescript(tmp_path)
        assert tsserver_js_in(str(tmp_path)) == expected


# ------------------------------------------------------------------
# find_tsserver_js — sources
# ------------------------------------------------------------------


class TestFindTsserverJsSources:
    def test_env_override_wins(self, isolated: Path, monkeypatch) -> None:
        override = isolated / "custom-tsserver.js"
        override.write_text("// tsserver")
        project = isolated / "project"
        project.mkdir()
        _make_typescript(project)
        monkeypatch.setenv(ENV_OVERRIDE, str(override))

        assert find_tsserver_js(project) == override

    def test_env_override_ignored_when_not_a_file(
        self, isolated: Path, monkeypatch
    ) -> None:
        monkeypatch.setenv(ENV_OVERRIDE, str(isolated / "does-not-exist.js"))
        project = isolated / "project"
        project.mkdir()
        expected = _make_typescript(project)

        assert find_tsserver_js(project) == expected

    def test_project_install(self, isolated: Path) -> None:
        project = isolated / "project"
        project.mkdir()
        expected = _make_typescript(project)
        assert find_tsserver_js(project) == expected

    def test_monorepo_package_install(self, isolated: Path) -> None:
        """The only install may live in a workspace package, not the root."""
        project = isolated / "project"
        (project / "packages").mkdir(parents=True)
        expected = _make_typescript(project / "packages")
        assert find_tsserver_js(project) == expected

    def test_provisioned_root(self, isolated: Path, monkeypatch) -> None:
        provisioned = isolated / "config" / "lsp"
        provisioned.mkdir(parents=True)
        expected = _make_typescript(provisioned)
        monkeypatch.setattr(
            tsserver_locator, "PROVISIONED_ROOT", provisioned
        )

        project = isolated / "project"
        project.mkdir()  # no node_modules — the repo-clone case

        assert find_tsserver_js(project) == expected

    def test_project_preferred_over_provisioned(
        self, isolated: Path, monkeypatch
    ) -> None:
        provisioned = isolated / "config" / "lsp"
        provisioned.mkdir(parents=True)
        _make_typescript(provisioned)
        monkeypatch.setattr(tsserver_locator, "PROVISIONED_ROOT", provisioned)

        project = isolated / "project"
        project.mkdir()
        expected = _make_typescript(project)

        assert find_tsserver_js(project) == expected

    def test_sibling_of_language_server_binary(
        self, isolated: Path, monkeypatch
    ) -> None:
        """`npm i -g typescript-language-server typescript` puts them as
        siblings in the same global node_modules."""
        node_modules = isolated / "lib" / "node_modules"
        server_bin = node_modules / "typescript-language-server" / "lib" / "cli.mjs"
        server_bin.parent.mkdir(parents=True)
        server_bin.write_text("// server")
        expected = node_modules / "typescript" / "lib" / "tsserver.js"
        expected.parent.mkdir(parents=True)
        expected.write_text("// tsserver")

        monkeypatch.setattr(
            tsserver_locator.shutil, "which", lambda _name: str(server_bin)
        )

        assert find_tsserver_js(isolated / "project") == expected

    def test_nested_install_under_language_server(
        self, isolated: Path, monkeypatch
    ) -> None:
        server_pkg = isolated / "node_modules" / "typescript-language-server"
        server_bin = server_pkg / "lib" / "cli.mjs"
        server_bin.parent.mkdir(parents=True)
        server_bin.write_text("// server")
        expected = _make_typescript(server_pkg)

        monkeypatch.setattr(
            tsserver_locator.shutil, "which", lambda _name: str(server_bin)
        )

        assert find_tsserver_js(isolated / "project") == expected

    def test_npm_global_root_fallback(
        self, isolated: Path, monkeypatch
    ) -> None:
        global_root = isolated / "global" / "node_modules"
        expected = global_root / "typescript" / "lib" / "tsserver.js"
        expected.parent.mkdir(parents=True)
        expected.write_text("// tsserver")

        monkeypatch.setattr(
            tsserver_locator.shutil,
            "which",
            lambda name: "/usr/bin/npm" if name == "npm" else None,
        )
        monkeypatch.setattr(
            tsserver_locator.subprocess,
            "run",
            lambda *a, **k: subprocess.CompletedProcess(
                a[0], 0, stdout=f"{global_root}\n", stderr=""
            ),
        )

        assert find_tsserver_js(isolated / "project") == expected

    def test_returns_none_when_nothing_is_installed(
        self, isolated: Path
    ) -> None:
        assert find_tsserver_js(isolated / "project") is None

    def test_no_project_path_still_searches_other_sources(
        self, isolated: Path, monkeypatch
    ) -> None:
        provisioned = isolated / "config" / "lsp"
        provisioned.mkdir(parents=True)
        expected = _make_typescript(provisioned)
        monkeypatch.setattr(tsserver_locator, "PROVISIONED_ROOT", provisioned)

        assert find_tsserver_js() == expected


# ------------------------------------------------------------------
# find_tsserver_js — robustness
# ------------------------------------------------------------------


class TestFindTsserverJsRobustness:
    def test_a_failing_source_does_not_break_the_search(
        self, isolated: Path, monkeypatch
    ) -> None:
        """One broken lookup must not cost us the runtime a later one finds."""
        provisioned = isolated / "config" / "lsp"
        provisioned.mkdir(parents=True)
        expected = _make_typescript(provisioned)
        monkeypatch.setattr(tsserver_locator, "PROVISIONED_ROOT", provisioned)

        def explode(_project_path):
            raise OSError("permission denied")

        monkeypatch.setattr(tsserver_locator, "_from_project", explode)

        assert find_tsserver_js(isolated / "project") == expected

    def test_npm_failure_is_survivable(self, isolated: Path, monkeypatch) -> None:
        monkeypatch.setattr(
            tsserver_locator.shutil,
            "which",
            lambda name: "/usr/bin/npm" if name == "npm" else None,
        )

        def timeout(*_a, **_k):
            raise subprocess.TimeoutExpired("npm", 15)

        monkeypatch.setattr(tsserver_locator.subprocess, "run", timeout)

        assert find_tsserver_js(isolated / "project") is None

    def test_missing_project_directory_is_survivable(
        self, isolated: Path
    ) -> None:
        assert find_tsserver_js(isolated / "nope" / "gone") is None
