"""Fixes for the adversarial review of the F1+F2 branch (H1, H2, M1, M2, M3)."""

from __future__ import annotations

import asyncio
import json
import stat
from unittest.mock import AsyncMock

import pytest

from isitsecure import mcp_server
from isitsecure.engine import reverify as R
from isitsecure.engine.code_analysis.semgrep_analyzer import SemgrepAnalyzer, require_semgrep
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.fixes import verifier
from isitsecure.engine.fixes.verifier import classify_against_rescan, finding_as_rescan_dict
from isitsecure.engine.models import CodeLocation, DeepFinding, DeepScanReport, FindingSource
from isitsecure.engine.shared.scanner_runner import reset_failure_log, use_failure_log
from isitsecure.server import app as srv
from isitsecure.server import fix_service
from tests._f2_support import StubLLM, git, make_finding, make_repo, report_for


def _f(path: str, snippet: str = "", scanner: str = "semgrep_taint", title: str = "SQLi",
       line: int = 3, severity=SeverityLevel.HIGH) -> DeepFinding:
    return DeepFinding(
        source=FindingSource.SAST_CODE, category=FindingCategory.EXPOSED_SECRETS,
        severity=severity, title=title, description="d", confidence=0.9,
        scanner_name=scanner,
        code_location=CodeLocation(file_path=path, line_number=line, code_snippet=snippet),
    )


def _snip(code: str) -> str:
    return f"2 |   # above\n3 >>> {code}\n4 |   # below"


# --------------------------------------------------------------------------
# H1: semgrep that skipped / choked on files must not read as "fixed"
# --------------------------------------------------------------------------

class _Repo:
    def __init__(self, path):
        self.clone_path = str(path)
        self.file_index = {}


def _fake_semgrep(tmp_path, body: str, code: int):
    script = tmp_path / "fake-semgrep"
    script.write_text(f"#!/bin/sh\ncat <<'EOF'\n{body}\nEOF\nexit {code}\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


@pytest.fixture
def log():
    entries: list[str] = []
    token = use_failure_log(entries)
    yield entries
    reset_failure_log(token)


@pytest.fixture
def js_repo(tmp_path):
    (tmp_path / "app.js").write_text("const x = 1;\n")
    return _Repo(tmp_path)


async def test_unparseable_file_is_a_failure_during_verification(monkeypatch, tmp_path, js_repo, log):
    body = json.dumps({"results": [], "errors": [
        {"type": "SyntaxError", "level": "error", "path": "app.js"}]})
    sem = _fake_semgrep(tmp_path, body, 0)
    monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: sem))
    with require_semgrep():
        assert await SemgrepAnalyzer().scan(js_repo) == []
    assert any("could not analyse 1 file" in e for e in log)


async def test_unparseable_file_does_not_change_a_normal_scan(monkeypatch, tmp_path, js_repo, log):
    body = json.dumps({"results": [], "errors": [
        {"type": "SyntaxError", "level": "error", "path": "app.js"}]})
    sem = _fake_semgrep(tmp_path, body, 0)
    monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: sem))
    assert await SemgrepAnalyzer().scan(js_repo) == []
    assert log == []


async def test_fatal_exit_code_is_always_a_failure(monkeypatch, tmp_path, js_repo, log):
    sem = _fake_semgrep(tmp_path, json.dumps({"results": [], "errors": []}), 2)
    monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: sem))
    assert await SemgrepAnalyzer().scan(js_repo) == []
    assert any("exited with status 2" in e for e in log)


async def test_findings_exit_code_one_is_not_a_failure(monkeypatch, tmp_path, js_repo, log):
    sem = _fake_semgrep(tmp_path, json.dumps({"results": [], "errors": []}), 1)
    monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: sem))
    await SemgrepAnalyzer().scan(js_repo)
    assert log == []


# --------------------------------------------------------------------------
# M3 / H2: one classifier
# --------------------------------------------------------------------------

def test_unapplied_sibling_does_not_mask_a_fixed_finding():
    a, b, c = (_f("x.py", _snip(f"q{i}(sql)"), line=3 + i) for i in range(3))
    # A and B were fixed; C (not applied) is still there.
    still, moved, gone = classify_against_rescan(
        [a, b], [finding_as_rescan_dict(c)], context=[a, b, c])
    assert still == [] and moved == [] and {id(x) for x in gone} == {id(a), id(b)}


def test_unapplied_sibling_without_discriminator_still_counts_right():
    a, b, c = (_f("x.py") for _ in range(3))  # no '>>>' marker: identical fingerprints
    still, _moved, gone = classify_against_rescan(
        [a, b], [finding_as_rescan_dict(c)], context=[a, b, c])
    assert still == [] and len(gone) == 2


def test_copy_pasted_sink_elsewhere_is_not_a_move():
    sink = _snip("cursor.execute(query)")
    a, b = _f("a.py", sink), _f("b.py", sink)
    # A was fixed; B (same flagged line, other file) is untouched and still reported.
    still, moved, gone = classify_against_rescan(
        [a], [finding_as_rescan_dict(b)], context=[a, b])
    assert still == [] and moved == [] and gone == [a]


def test_real_move_is_still_detected():
    moved_from = _f("old.py", _snip("cursor.execute(query)"))
    new_home = _f("new.py", _snip("cursor.execute(query)"))
    still, moved, gone = classify_against_rescan([moved_from], [finding_as_rescan_dict(new_home)])
    assert moved == [moved_from] and still == [] and gone == []


async def test_reverify_reports_moved_code_as_unverifiable(monkeypatch):
    old = _f("old.py", _snip("cursor.execute(query)"))
    new_home = _f("new.py", _snip("cursor.execute(query)"))
    monkeypatch.setattr(R, "_sast_rescan", AsyncMock(return_value=[finding_as_rescan_dict(new_home)]))
    (v,) = await R.reverify_findings([old], repo_path="repo")
    assert v.status == R.VerifyStatus.UNVERIFIABLE and "moved" in v.detail


def test_mcp_verify_does_not_resolve_moved_code():
    old = DeepScanReport(findings=[_f("old.py", _snip("cursor.execute(query)"))])
    new = DeepScanReport(findings=[_f("new.py", _snip("cursor.execute(query)"))])
    r = mcp_server._verify_result(old, new, "sid")
    assert r["resolved_count"] == 0 and r["possibly_moved_count"] == 1
    assert r["unverifiable_count"] == 1 and r["counts"]["high"] == 1


def test_mcp_verify_edited_flagged_line_is_still_present():
    old = DeepScanReport(findings=[_f("a.py", _snip("run(uid)"))])
    new = DeepScanReport(findings=[_f("a.py", _snip("run(str(uid))"))])
    r = mcp_server._verify_result(old, new, "sid")
    assert r["still_present_count"] == 1 and r["resolved_count"] == 0


# --------------------------------------------------------------------------
# M1: a missing optional semgrep must not turn verify into "incomplete"
# --------------------------------------------------------------------------

def test_mcp_verify_missing_semgrep_is_unverifiable_but_not_incomplete():
    old = DeepScanReport(findings=[_f("a.py", _snip("run(uid)"))])
    new = DeepScanReport(findings=[], scanner_errors=[
        "semgrep_taint: semgrep is not installed (pip install isitsecure[taint])"])
    r = mcp_server._verify_result(old, new, "sid")
    assert r["resolved_count"] == 0 and r["unverifiable_count"] == 1
    assert r["incomplete"] is False
    assert "isitsecure[taint]" in r["summary"]
    assert r["counts"]["high"] == 1  # held constant: not credited as fixed


def test_mcp_verify_other_scanner_failure_still_marks_incomplete():
    old = DeepScanReport(findings=[_f("a.py", _snip("run(uid)"), severity=SeverityLevel.LOW)])
    new = DeepScanReport(findings=[], scanner_errors=["semgrep_taint: semgrep timed out after 120s"])
    r = mcp_server._verify_result(old, new, "sid")
    assert r["incomplete"] is True and r["resolved_count"] == 0


# --------------------------------------------------------------------------
# M2: cancelling during the shielded apply must not strand a commit
# --------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("ISITSECURE_BACKUP_DIR", str(tmp_path / "backups"))
    yield
    srv._fix_jobs.clear()


async def test_cancel_during_apply_still_reports_the_fix_branch(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {"a.py": b"a = BAD\n"})
    monkeypatch.setattr(fix_service, "load_api_key", lambda p: "key")
    monkeypatch.setattr("isitsecure.llm.adapters.create_llm_client", lambda p, k, **kw: StubLLM())
    in_verify = asyncio.Event()

    async def slow_verify(*a, **kw):
        in_verify.set()  # the commit is already on the fix branch
        await asyncio.sleep(0.3)
        return verifier.VerifyResult(resolved=1)

    monkeypatch.setattr(verifier, "verify_findings_resolved", slow_verify)
    srv._fix_jobs["j1"] = {"status": "running", "events": [], "result": None, "error": None}
    task = asyncio.ensure_future(srv._run_fix_all_job(
        "j1", report_for(repo, [make_finding("a.py")]), "anthropic", ("high",)))
    await in_verify.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    job = srv._fix_jobs["j1"]
    assert job["status"] == "cancelled"
    assert job["result"]["branch"] == "isitsecure/fixes"
    assert "isitsecure/fixes" in job["error"]
    assert git(repo, "rev-parse", "--verify", "isitsecure/fixes")  # the branch is real
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"  # user restored


# --------------------------------------------------------------------------
# A file that no longer parses: scanners skip it silently, so it must not read as fixed
# --------------------------------------------------------------------------

def _broken_repo(tmp_path):
    (tmp_path / "a.ts").write_text("function f() { if (x) { run(q);\n")  # truncated reply
    return str(tmp_path)


async def test_verifier_does_not_resolve_findings_of_an_unparseable_file(tmp_path, monkeypatch):
    repo = _broken_repo(tmp_path)
    monkeypatch.setattr(verifier, "_rescan_sast_findings",
                        AsyncMock(return_value=verifier.RescanFindings([], [])))  # scanners see nothing
    res = await verifier.verify_findings_resolved(repo, [_f("a.ts", _snip("run(q)"))])
    assert res.resolved == 0 and res.unverifiable == 1
    assert "a.ts" in res.unparseable_files
    assert res.to_dict()["unparseable_files"]["a.ts"]


async def test_verifier_still_resolves_findings_of_a_parseable_file(tmp_path, monkeypatch):
    (tmp_path / "a.ts").write_text("function f() { run(safe); }\n")
    monkeypatch.setattr(verifier, "_rescan_sast_findings",
                        AsyncMock(return_value=verifier.RescanFindings([], [])))
    res = await verifier.verify_findings_resolved(str(tmp_path), [_f("a.ts", _snip("run(q)"))])
    assert res.resolved == 1 and res.unparseable_files == {}


async def test_reverify_does_not_call_an_unparseable_file_fixed(tmp_path, monkeypatch):
    repo = _broken_repo(tmp_path)
    monkeypatch.setattr(R, "_sast_rescan", AsyncMock(return_value=verifier.RescanFindings([], [])))
    (v,) = await R.reverify_findings([_f("a.ts", _snip("run(q)"))], repo_path=repo)
    assert v.status == R.VerifyStatus.COULD_NOT_VERIFY and "no longer parses" in v.detail


def test_mcp_verify_does_not_resolve_findings_of_an_unparseable_file(tmp_path):
    repo = _broken_repo(tmp_path)
    old = DeepScanReport(findings=[_f("a.ts", _snip("run(q)"))])
    r = mcp_server._verify_result(old, DeepScanReport(findings=[]), "sid", repo)
    assert r["resolved_count"] == 0 and r["unverifiable_count"] == 1
    assert "no longer parses" in r["summary"]
    assert r["counts"]["high"] == 1  # held constant in the grade
