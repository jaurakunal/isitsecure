"""Tests for SemgrepAnalyzer (#4).

These tests must NOT depend on the `semgrep` binary being installed — the
subprocess boundary (`_run_semgrep`) and the binary lookup (`_find_semgrep`)
are mocked so the suite is deterministic in CI (no `[taint]` extra required).
"""

import json
import pathlib

import pytest

from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.code_analysis.semgrep_analyzer import SemgrepAnalyzer
from isitsecure.engine.enums import FindingCategory, SeverityLevel

_PACKS = [pathlib.Path("injection-js.yaml")]  # dummy pack arg for _run_semgrep tests


def _snapshot(files: dict[str, str], clone_path: str = "/repo") -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        commit_hash="abc123",
        clone_path=clone_path,
        auth_provider="",
        package_json={},
        file_index=files,
        route_map=[],
        migration_files=[],
        env_files=[],
        total_files=len(files),
        total_size_bytes=0,
    )


def _disk_snapshot(tmp_path, names: list[str]) -> RepoSnapshot:
    """A snapshot whose clone_path is a real dir containing `names` on disk —
    `_select_packs` walks the disk (not file_index), so pack tests need real files."""
    for n in names:
        p = tmp_path / n
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x = 1\n")
    return _snapshot({}, clone_path=str(tmp_path))


def _result(
    *,
    path: str = "/repo/src/app/api/login/route.ts",
    line: int = 11,
    end: int = 11,
    message: str = "User input flows into a raw SQL query — parameterize it.",
    category: str = "injection_risk",
    severity: str = "critical",
    check_id: str = "isitsecure-sqli-taint",
    lines: str = "sql.unsafe(`SELECT * FROM u WHERE id=${id}`)",
) -> dict:
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line},
        "end": {"line": end},
        "extra": {
            "message": message,
            "lines": lines,
            "severity": "ERROR",
            "metadata": {"category": category, "isitsecure-severity": severity},
        },
    }


class TestGracefulNoOp:
    @pytest.mark.asyncio
    async def test_no_semgrep_binary_returns_empty(self, monkeypatch):
        """No semgrep installed → no-op, never raises."""
        monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: None))
        analyzer = SemgrepAnalyzer()
        findings = await analyzer.scan(_snapshot({"src/x.ts": ""}))
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_supported_files_skips_run(self, monkeypatch, tmp_path):
        """A repo with no rule-pack-covered files (no JS/TS/Python) skips semgrep."""
        monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: "/bin/semgrep"))

        async def _boom(*a, **k):  # pragma: no cover - must not be called
            raise AssertionError("_run_semgrep should not run without supported files")

        monkeypatch.setattr(SemgrepAnalyzer, "_run_semgrep", _boom)
        analyzer = SemgrepAnalyzer()
        findings = await analyzer.scan(_disk_snapshot(tmp_path, ["main.go", "README.md"]))
        assert findings == []

    @pytest.mark.asyncio
    async def test_python_files_trigger_run(self, monkeypatch, tmp_path):
        """A Python-only repo runs semgrep with the #93 Python rule pack only."""
        monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: "/bin/semgrep"))
        ran = {}

        async def _fake(self, semgrep, clone_path, packs):
            ran["packs"] = [p.name for p in packs]
            return {"results": []}

        monkeypatch.setattr(SemgrepAnalyzer, "_run_semgrep", _fake)
        await SemgrepAnalyzer().scan(_disk_snapshot(tmp_path, ["app/views.py"]))
        assert ran.get("packs") == ["injection-python.yaml"]  # not the JS pack

    @pytest.mark.asyncio
    async def test_semgrep_crash_returns_empty(self, monkeypatch, tmp_path):
        """_run_semgrep returning None (crash/timeout) degrades to no findings."""
        monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: "/bin/semgrep"))

        async def _none(self, semgrep, clone_path, packs):
            return None

        monkeypatch.setattr(SemgrepAnalyzer, "_run_semgrep", _none)
        findings = await SemgrepAnalyzer().scan(_disk_snapshot(tmp_path, ["src/x.ts"]))
        assert findings == []


class TestPackSelection:
    """#94 — only the packs whose languages appear in the repo are run.

    Selection walks the on-disk tree (what semgrep scans), not the curated
    file_index — so these use real files.
    """

    def test_js_only(self, tmp_path):
        packs = SemgrepAnalyzer()._select_packs(_disk_snapshot(tmp_path, ["src/a.ts", "b.jsx"]))
        assert [p.name for p in packs] == ["injection-js.yaml"]

    def test_python_only(self, tmp_path):
        packs = SemgrepAnalyzer()._select_packs(_disk_snapshot(tmp_path, ["app/x.py"]))
        assert [p.name for p in packs] == ["injection-python.yaml"]

    def test_mixed_repo_gets_both(self, tmp_path):
        packs = SemgrepAnalyzer()._select_packs(_disk_snapshot(tmp_path, ["a.ts", "b.py"]))
        assert {p.name for p in packs} == {"injection-js.yaml", "injection-python.yaml"}

    def test_unsupported_language_gets_nothing(self, tmp_path):
        packs = SemgrepAnalyzer()._select_packs(_disk_snapshot(tmp_path, ["main.go", "README.md"]))
        assert packs == []

    def test_selects_lang_in_dir_dropped_from_file_index(self, tmp_path):
        """Regression guard: a .py only under a build/ dir (excluded from
        file_index but still scanned by semgrep) must still select the Python
        pack — selection reads the disk, not file_index."""
        packs = SemgrepAnalyzer()._select_packs(
            _disk_snapshot(tmp_path, ["a.ts", "build/generated.py"]))
        assert {p.name for p in packs} == {"injection-js.yaml", "injection-python.yaml"}

    def test_skips_node_modules(self, tmp_path):
        """A language present only under node_modules is not selected (semgrep
        skips node_modules too, so this can't lose a real finding)."""
        packs = SemgrepAnalyzer()._select_packs(
            _disk_snapshot(tmp_path, ["a.ts", "node_modules/pkg/x.py"]))
        assert [p.name for p in packs] == ["injection-js.yaml"]

    def test_cjs_is_selected(self, tmp_path):
        """`.cjs` (a real JS extension semgrep scans) selects the JS pack."""
        packs = SemgrepAnalyzer()._select_packs(_disk_snapshot(tmp_path, ["server.cjs"]))
        assert [p.name for p in packs] == ["injection-js.yaml"]

    def test_missing_pack_file_skipped(self, monkeypatch, tmp_path):
        """A stale registry entry (file gone) is skipped, not fatal to the scan."""
        import isitsecure.engine.code_analysis.semgrep_analyzer as mod
        bogus = mod._RulePack("bogus", "does-not-exist.yaml", (".rb",))
        monkeypatch.setattr(mod, "_RULE_PACKS", (*mod._RULE_PACKS, bogus))
        packs = SemgrepAnalyzer()._select_packs(_disk_snapshot(tmp_path, ["a.ts", "x.rb"]))
        assert [p.name for p in packs] == ["injection-js.yaml"]  # bogus dropped


class TestFindSemgrep:
    def test_prefers_venv_binary_over_path(self, monkeypatch, tmp_path):
        """The binary next to the interpreter wins over PATH."""
        import isitsecure.engine.code_analysis.semgrep_analyzer as mod

        venv_bin = tmp_path / "semgrep"
        venv_bin.write_text("#!/bin/sh\n")
        monkeypatch.setattr(mod.sys, "executable", str(tmp_path / "python"))
        monkeypatch.setattr(mod.shutil, "which", lambda _: "/usr/bin/semgrep")
        assert SemgrepAnalyzer._find_semgrep() == str(venv_bin)

    def test_falls_back_to_path(self, monkeypatch, tmp_path):
        import isitsecure.engine.code_analysis.semgrep_analyzer as mod

        monkeypatch.setattr(mod.sys, "executable", str(tmp_path / "python"))  # no sibling semgrep
        monkeypatch.setattr(mod.shutil, "which", lambda _: "/usr/bin/semgrep")
        assert SemgrepAnalyzer._find_semgrep() == "/usr/bin/semgrep"


class TestFindingMapping:
    async def _run(self, monkeypatch, results):
        monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: "/bin/semgrep"))
        # These test result→CodeFinding mapping, not selection — force a pack so
        # scan() proceeds without touching the (fake) clone_path on disk.
        monkeypatch.setattr(SemgrepAnalyzer, "_select_packs",
                            lambda self, repo: [pathlib.Path("injection-js.yaml")])

        async def _fake(self, semgrep, clone_path, packs):
            return {"results": results}

        monkeypatch.setattr(SemgrepAnalyzer, "_run_semgrep", _fake)
        return await SemgrepAnalyzer().scan(_snapshot({"src/x.ts": ""}))

    @pytest.mark.asyncio
    async def test_maps_core_fields(self, monkeypatch):
        findings = await self._run(monkeypatch, [_result()])
        assert len(findings) == 1
        f = findings[0]
        assert f.scanner_name == "semgrep_taint"
        assert f.category == FindingCategory.INJECTION_RISK
        assert f.severity == SeverityLevel.CRITICAL
        assert f.file_path == "src/app/api/login/route.ts"  # made relative to clone_path
        assert f.line_number == 11
        assert f.title == "User input flows into a raw SQL query"  # split on em-dash
        assert f.confidence == 0.85
        assert "sql.unsafe" in f.code_snippet

    @pytest.mark.asyncio
    async def test_severity_falls_back_to_semgrep_level(self, monkeypatch):
        """No explicit isitsecure-severity → map ERROR/WARNING/INFO."""
        r = _result(severity="")
        r["extra"]["metadata"].pop("isitsecure-severity")
        r["extra"]["severity"] = "WARNING"
        findings = await self._run(monkeypatch, [r])
        assert findings[0].severity == SeverityLevel.MEDIUM

    @pytest.mark.asyncio
    async def test_unknown_category_defaults_to_injection(self, monkeypatch):
        findings = await self._run(monkeypatch, [_result(category="not-a-real-category")])
        assert findings[0].category == FindingCategory.INJECTION_RISK

    @pytest.mark.asyncio
    async def test_dedups_same_class_rules_on_same_line(self, monkeypatch):
        """The sqli sink rule and the sqli taint rule on one line collapse to one."""
        a = _result(check_id="isitsecure-sqli-raw-query", message="SQLi via sink rule")
        b = _result(check_id="isitsecure-sqli-taint", message="SQLi via taint rule")
        findings = await self._run(monkeypatch, [a, b])
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_distinct_classes_on_same_line_kept(self, monkeypatch):
        """Genuinely different vuln classes on one line survive (reflected-XSS vs SSRF).

        Both map to FindingCategory.INJECTION_RISK, so keying on category alone would
        wrongly drop one — the dedup keys on the rule's vuln class instead.
        """
        xss = _result(line=21, check_id="isitsecure-reflected-xss", severity="high")
        ssrf = _result(line=21, check_id="isitsecure-ssrf", severity="high")
        findings = await self._run(monkeypatch, [xss, ssrf])
        assert len(findings) == 2

    @pytest.mark.asyncio
    async def test_unknown_rule_ids_are_own_class(self, monkeypatch):
        """Two unrecognised rule ids on one line don't collapse into each other."""
        a = _result(line=5, check_id="some-other-rule-a")
        b = _result(line=5, check_id="some-other-rule-b")
        findings = await self._run(monkeypatch, [a, b])
        assert len(findings) == 2

    @pytest.mark.asyncio
    async def test_path_outside_clone_root_kept_verbatim(self, monkeypatch):
        """A path that isn't under clone_path shouldn't crash the mapping."""
        findings = await self._run(monkeypatch, [_result(path="/elsewhere/x.ts")])
        assert findings[0].file_path == "/elsewhere/x.ts"

    @pytest.mark.asyncio
    async def test_empty_results(self, monkeypatch):
        findings = await self._run(monkeypatch, [])
        assert findings == []

    @pytest.mark.asyncio
    async def test_title_falls_back_when_no_separator(self, monkeypatch):
        findings = await self._run(monkeypatch, [_result(message="Command injection")])
        assert findings[0].title == "Command injection"


class TestRunSemgrepBoundary:
    """Exercise _run_semgrep's parsing/timeout via a fake subprocess (no binary)."""

    @pytest.mark.asyncio
    async def test_builds_one_config_arg_per_pack(self, monkeypatch):
        """Each selected pack becomes its own --config <path> in the argv."""
        captured = {}

        class _Proc:
            returncode = 0

            async def communicate(self):
                return b'{"results": []}', b""

            def kill(self):  # pragma: no cover
                pass

        async def _fake_exec(*cmd, **k):
            captured["cmd"] = cmd
            return _Proc()

        monkeypatch.setattr(
            "isitsecure.engine.code_analysis.semgrep_analyzer.asyncio.create_subprocess_exec",
            _fake_exec,
        )
        packs = [pathlib.Path("injection-js.yaml"), pathlib.Path("injection-python.yaml")]
        await SemgrepAnalyzer()._run_semgrep("/bin/semgrep", "/repo", packs)
        cmd = list(captured["cmd"])
        assert cmd.count("--config") == 2
        assert str(packs[0]) in cmd and str(packs[1]) in cmd
        assert cmd[-1] == "/repo"

    @pytest.mark.asyncio
    async def test_parses_stdout_json(self, monkeypatch):
        payload = json.dumps({"results": [_result()]}).encode()

        class _Proc:
            returncode = 0

            async def communicate(self):
                return payload, b""

            def kill(self):  # pragma: no cover
                pass

        async def _fake_exec(*a, **k):
            return _Proc()

        monkeypatch.setattr(
            "isitsecure.engine.code_analysis.semgrep_analyzer.asyncio.create_subprocess_exec",
            _fake_exec,
        )
        raw = await SemgrepAnalyzer()._run_semgrep("/bin/semgrep", "/repo", _PACKS)
        assert raw is not None and len(raw["results"]) == 1

    @pytest.mark.asyncio
    async def test_empty_stdout_returns_none(self, monkeypatch):
        class _Proc:
            returncode = 0

            async def communicate(self):
                return b"", b"some stderr"

            def kill(self):  # pragma: no cover
                pass

        async def _fake_exec(*a, **k):
            return _Proc()

        monkeypatch.setattr(
            "isitsecure.engine.code_analysis.semgrep_analyzer.asyncio.create_subprocess_exec",
            _fake_exec,
        )
        assert await SemgrepAnalyzer()._run_semgrep("/bin/semgrep", "/repo", _PACKS) is None

    @pytest.mark.asyncio
    async def test_subprocess_exception_returns_none(self, monkeypatch):
        async def _boom(*a, **k):
            raise OSError("no such binary")

        monkeypatch.setattr(
            "isitsecure.engine.code_analysis.semgrep_analyzer.asyncio.create_subprocess_exec",
            _boom,
        )
        assert await SemgrepAnalyzer()._run_semgrep("/bin/semgrep", "/repo", _PACKS) is None

    @pytest.mark.asyncio
    async def test_malformed_json_returns_none(self, monkeypatch):
        class _Proc:
            returncode = 0

            async def communicate(self):
                return b"not json at all", b""

            def kill(self):  # pragma: no cover
                pass

        monkeypatch.setattr(
            "isitsecure.engine.code_analysis.semgrep_analyzer.asyncio.create_subprocess_exec",
            lambda *a, **k: _fake_awaitable(_Proc()),
        )
        assert await SemgrepAnalyzer()._run_semgrep("/bin/semgrep", "/repo", _PACKS) is None

    @pytest.mark.asyncio
    async def test_non_dict_json_returns_none(self, monkeypatch):
        class _Proc:
            returncode = 0

            async def communicate(self):
                return b"[1, 2, 3]", b""  # valid JSON, but not an object

            def kill(self):  # pragma: no cover
                pass

        monkeypatch.setattr(
            "isitsecure.engine.code_analysis.semgrep_analyzer.asyncio.create_subprocess_exec",
            lambda *a, **k: _fake_awaitable(_Proc()),
        )
        assert await SemgrepAnalyzer()._run_semgrep("/bin/semgrep", "/repo", _PACKS) is None

    @pytest.mark.asyncio
    async def test_timeout_kills_and_reaps_child(self, monkeypatch):
        """On the internal timeout the semgrep child must be killed AND reaped."""
        killed = {"kill": False, "wait": False}

        class _Proc:
            returncode = None  # still running

            async def communicate(self):
                import asyncio as _a

                await _a.sleep(999)  # never returns → wait_for times out

            def kill(self):
                killed["kill"] = True
                self.returncode = -9

            async def wait(self):
                killed["wait"] = True
                return -9

        monkeypatch.setattr(
            "isitsecure.engine.code_analysis.semgrep_analyzer._SCAN_TIMEOUT_S", 0.01
        )
        monkeypatch.setattr(
            "isitsecure.engine.code_analysis.semgrep_analyzer.asyncio.create_subprocess_exec",
            lambda *a, **k: _fake_awaitable(_Proc()),
        )
        result = await SemgrepAnalyzer()._run_semgrep("/bin/semgrep", "/repo", _PACKS)
        assert result is None
        assert killed["kill"] and killed["wait"]  # no orphan, no zombie

    @pytest.mark.asyncio
    async def test_cancellation_reaps_child_and_propagates(self, monkeypatch):
        """An outer cancel (scan timeout) must reap the child, then re-raise."""
        import asyncio as _a

        killed = {"kill": False}

        class _Proc:
            returncode = None

            async def communicate(self):
                raise _a.CancelledError()

            def kill(self):
                killed["kill"] = True
                self.returncode = -9

            async def wait(self):
                return -9

        monkeypatch.setattr(
            "isitsecure.engine.code_analysis.semgrep_analyzer.asyncio.create_subprocess_exec",
            lambda *a, **k: _fake_awaitable(_Proc()),
        )
        with pytest.raises(_a.CancelledError):
            await SemgrepAnalyzer()._run_semgrep("/bin/semgrep", "/repo", _PACKS)
        assert killed["kill"]  # child killed even on cancellation


async def _fake_awaitable(value):
    """Wrap a value so `await create_subprocess_exec(...)` yields it."""
    return value
