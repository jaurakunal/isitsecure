"""Tests for choosing the language server that matches the project.

The behaviour these pin down: the client used to be chosen when the agent was
built — before ingestion — so it could only go on what was installed. With Node
present that was always TypeScript, and a Python repository was handed tsserver
while a working pyright sat idle.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from isitsecure.engine.code_analysis.lsp.language_router import (
    LanguageRoutingLSPClient,
    detect_project_language,
)


def _tree(root: Path, files: dict[str, int]) -> Path:
    """Create ``{"src/a.ts": 3}`` as three .ts files under src/."""
    for spec, count in files.items():
        directory, _, name = spec.rpartition("/")
        stem, ext = name.rsplit(".", 1)
        target = root / directory if directory else root
        target.mkdir(parents=True, exist_ok=True)
        for i in range(count):
            (target / f"{stem}{i}.{ext}").write_text("x")
    return root


class _StubClient:
    """A concrete client stand-in that records how it was driven."""

    def __init__(self, *, initializes: bool = True) -> None:
        self.initializes = initializes
        self.initialized_with: str | None = None
        self.shutdown_called = False
        self.last_error: str | None = None if initializes else "server said no"

    @property
    def is_available(self) -> bool:
        return self.initialized_with is not None and self.initializes

    async def initialize(self, project_path: str) -> bool:
        self.initialized_with = project_path
        return self.initializes

    async def get_definition(self, *_a):
        return ["definition"]

    async def get_references(self, *_a):
        return ["reference"]

    async def get_hover(self, *_a):
        return "hover"

    async def shutdown(self) -> None:
        self.shutdown_called = True


def _support(installed: dict[str, _StubClient], missing: tuple[str, ...] = ()):
    entries = {
        lang: (lambda: True, lambda c=client: c)
        for lang, client in installed.items()
    }
    for lang in missing:
        entries[lang] = (lambda: False, lambda: _StubClient())
    return entries


# ---------------------------------------------------------------------------
# detect_project_language
# ---------------------------------------------------------------------------


class TestDetectProjectLanguage:
    def test_typescript_project(self, tmp_path: Path) -> None:
        _tree(tmp_path, {"src/app.ts": 5, "src/util.js": 2})
        assert detect_project_language(str(tmp_path)) == "typescript"

    def test_python_project(self, tmp_path: Path) -> None:
        _tree(tmp_path, {"pkg/mod.py": 6})
        assert detect_project_language(str(tmp_path)) == "python"

    def test_java_and_kotlin_count_as_one_language(self, tmp_path: Path) -> None:
        _tree(tmp_path, {"src/A.java": 2, "src/B.kt": 2, "web/app.ts": 3})
        assert detect_project_language(str(tmp_path)) == "java"

    def test_majority_wins_in_a_mixed_repo(self, tmp_path: Path) -> None:
        _tree(tmp_path, {"api/svc.py": 20, "web/app.ts": 3})
        assert detect_project_language(str(tmp_path)) == "python"

    def test_vendored_directories_do_not_decide_the_language(
        self, tmp_path: Path
    ) -> None:
        """A Python app with a bundled JS dependency is still a Python app."""
        _tree(tmp_path, {"app/main.py": 4})
        _tree(tmp_path, {"node_modules/pkg/index.js": 50})
        assert detect_project_language(str(tmp_path)) == "python"

    def test_hidden_directories_are_skipped(self, tmp_path: Path) -> None:
        _tree(tmp_path, {"app/main.py": 3})
        _tree(tmp_path, {".cache/gen/thing.ts": 40})
        assert detect_project_language(str(tmp_path)) == "python"

    def test_no_recognised_source_returns_none(self, tmp_path: Path) -> None:
        _tree(tmp_path, {"docs/readme.md": 3})
        assert detect_project_language(str(tmp_path)) is None

    def test_empty_project_returns_none(self, tmp_path: Path) -> None:
        assert detect_project_language(str(tmp_path)) is None

    def test_tie_is_broken_deterministically(self, tmp_path: Path) -> None:
        """Equal counts must resolve the same way on every scan."""
        _tree(tmp_path, {"a/x.ts": 3, "b/y.py": 3})
        first = detect_project_language(str(tmp_path))
        assert first == detect_project_language(str(tmp_path))
        assert first == "typescript"  # declaration order in LANGUAGE_EXTENSIONS


# ---------------------------------------------------------------------------
# LanguageRoutingLSPClient
# ---------------------------------------------------------------------------


class TestLanguageRouting:
    @pytest.mark.asyncio
    async def test_python_project_gets_the_python_server(
        self, tmp_path: Path
    ) -> None:
        """The whole point: this used to hand a Python repo tsserver."""
        _tree(tmp_path, {"app/main.py": 5})
        py, ts = _StubClient(), _StubClient()
        client = LanguageRoutingLSPClient(
            _support({"python": py, "typescript": ts})
        )

        assert await client.initialize(str(tmp_path)) is True
        assert py.initialized_with == str(tmp_path)
        assert ts.initialized_with is None

    @pytest.mark.asyncio
    async def test_typescript_project_gets_the_typescript_server(
        self, tmp_path: Path
    ) -> None:
        _tree(tmp_path, {"src/app.ts": 5})
        py, ts = _StubClient(), _StubClient()
        client = LanguageRoutingLSPClient(
            _support({"python": py, "typescript": ts})
        )

        assert await client.initialize(str(tmp_path)) is True
        assert ts.initialized_with == str(tmp_path)
        assert py.initialized_with is None

    @pytest.mark.asyncio
    async def test_missing_server_does_not_fall_back_to_another_language(
        self, tmp_path: Path
    ) -> None:
        """A server for the wrong language is a confident silence, not a
        partial answer — which is exactly the bug this replaces."""
        _tree(tmp_path, {"app/main.py": 5})
        ts = _StubClient()
        client = LanguageRoutingLSPClient(
            _support({"typescript": ts}, missing=("python",))
        )

        assert await client.initialize(str(tmp_path)) is False
        assert ts.initialized_with is None
        assert "python" in (client.last_error or "")
        assert "setup --lsp" in (client.last_error or "")

    @pytest.mark.asyncio
    async def test_unrecognised_project_reports_why(self, tmp_path: Path) -> None:
        _tree(tmp_path, {"docs/readme.md": 2})
        client = LanguageRoutingLSPClient(_support({"python": _StubClient()}))

        assert await client.initialize(str(tmp_path)) is False
        assert "No language" in (client.last_error or "")

    @pytest.mark.asyncio
    async def test_delegate_failure_surfaces_its_reason(
        self, tmp_path: Path
    ) -> None:
        _tree(tmp_path, {"app/main.py": 3})
        py = _StubClient(initializes=False)
        client = LanguageRoutingLSPClient(_support({"python": py}))

        assert await client.initialize(str(tmp_path)) is False
        assert client.last_error == "server said no"

    @pytest.mark.asyncio
    async def test_requests_reach_the_chosen_delegate(
        self, tmp_path: Path
    ) -> None:
        _tree(tmp_path, {"app/main.py": 3})
        client = LanguageRoutingLSPClient(_support({"python": _StubClient()}))
        await client.initialize(str(tmp_path))

        assert await client.get_definition("f", 0, 0) == ["definition"]
        assert await client.get_references("f", 0, 0) == ["reference"]
        assert await client.get_hover("f", 0, 0) == "hover"
        assert client.is_available is True

    @pytest.mark.asyncio
    async def test_requests_before_initialize_are_safe(self) -> None:
        client = LanguageRoutingLSPClient(_support({}))
        assert await client.get_definition("f", 0, 0) is None
        assert await client.get_references("f", 0, 0) is None
        assert await client.get_hover("f", 0, 0) is None
        assert client.is_available is False
        await client.shutdown()  # must not raise

    @pytest.mark.asyncio
    async def test_shutdown_closes_the_delegate(self, tmp_path: Path) -> None:
        _tree(tmp_path, {"app/main.py": 3})
        py = _StubClient()
        client = LanguageRoutingLSPClient(_support({"python": py}))
        await client.initialize(str(tmp_path))

        await client.shutdown()

        assert py.shutdown_called is True
        assert client.is_available is False

    @pytest.mark.asyncio
    async def test_reinitialising_reselects(self, tmp_path: Path) -> None:
        """One agent can scan a Python repo and then a TypeScript one."""
        py, ts = _StubClient(), _StubClient()
        client = LanguageRoutingLSPClient(
            _support({"python": py, "typescript": ts})
        )
        python_repo = _tree(tmp_path / "py", {"app/main.py": 3})
        ts_repo = _tree(tmp_path / "ts", {"src/app.ts": 3})

        await client.initialize(str(python_repo))
        await client.initialize(str(ts_repo))

        assert py.initialized_with == str(python_repo)
        assert ts.initialized_with == str(ts_repo)
