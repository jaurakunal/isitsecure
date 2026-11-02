"""F2: web fix-all must never lose user data (real temp git repo, real generator,
real apply/commit/restore; only the LLM and the post-fix re-scan are stubbed)."""

from __future__ import annotations

import asyncio
import logging
import subprocess
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from isitsecure.engine.fixes import safe_apply, verifier
from isitsecure.server import app as srv
from isitsecure.server import fix_service
from tests._f2_support import StubLLM, git, make_finding, make_repo, report_for


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("ISITSECURE_BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setattr(fix_service, "load_api_key", lambda p: "key")
    monkeypatch.setattr(verifier, "verify_findings_resolved",
                        AsyncMock(return_value=verifier.VerifyResult(resolved=1)))
    yield
    srv._fix_jobs.clear()
    srv._scans.clear()


def _llm(monkeypatch, llm=None):
    llm = llm or StubLLM()
    monkeypatch.setattr("isitsecure.llm.adapters.create_llm_client", lambda p, k, **kw: llm)
    return llm


async def _run(repo, findings, **kw):
    events: list[dict] = []

    async def emit(e):
        events.append(e)

    res = await fix_service.run_fix_all(
        report=report_for(repo, findings), llm_provider="anthropic", emit=emit, **kw)
    return res


# ---------------------------------------------------------------------------
# local apply: checkout / commit / restore
# ---------------------------------------------------------------------------

async def test_apply_commits_on_fix_branch_and_restores_user_branch(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {"a.py": b"a = BAD\r\nb = 1\r\n"})
    _llm(monkeypatch)
    res = await _run(repo, [make_finding("a.py")])
    assert res["applied"] is True and res["restored_base_branch"] is True
    assert res["branch"] == "isitsecure/fixes"
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert (repo / "a.py").read_bytes() == b"a = BAD\r\nb = 1\r\n"  # user's tree untouched
    assert git(repo, "status", "--porcelain") == ""
    blob = subprocess.run(["git", "-C", str(repo), "show", f"{res['branch']}:a.py"],
                          capture_output=True).stdout
    assert blob == b"a = GOOD\r\nb = 1\r\n"  # fixed on the branch, CRLF preserved
    assert git(repo, "log", "--format=%s", "-1", res["branch"]).startswith("isitsecure: fix 1")


async def test_gitignored_file_is_refused_not_written(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {".gitignore": b"secret.py\n", "a.py": b"x = 1\n"})
    (repo / "secret.py").write_bytes(b"k = BAD\n")
    llm = _llm(monkeypatch)
    res = await _run(repo, [make_finding("secret.py")])
    assert res["applied"] is False
    assert any("not tracked by git" in s for s in res["skipped"])
    assert (repo / "secret.py").read_bytes() == b"k = BAD\n"
    assert llm.calls == 0  # no paid call for a file we will not touch
    assert git(repo, "branch", "--list", "isitsecure/*") == ""
    assert git(repo, "status", "--porcelain") == ""


async def test_mixed_tracked_and_ignored_only_tracked_is_fixed(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {".gitignore": b"secret.py\n", "a.py": b"a = BAD\n"})
    (repo / "secret.py").write_bytes(b"k = BAD\n")
    _llm(monkeypatch)
    res = await _run(repo, [make_finding("a.py"), make_finding("secret.py", title="Key")])
    assert res["applied"] is True and res["files_changed"] == ["a.py"]
    assert (repo / "secret.py").read_bytes() == b"k = BAD\n"
    assert res["plain"]["couldnt_fix"] == 1  # the ignored one is reported, not hidden


async def test_user_edit_during_generation_is_never_discarded(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {"a.py": b"a = BAD\n", "other.py": b"o = 1\n"})
    precious = b"o = 1\n# precious uncommitted edit\n"
    _llm(monkeypatch, StubLLM(on_call=lambda n: (repo / "other.py").write_bytes(precious)))
    res = await _run(repo, [make_finding("a.py")])
    assert res["mode"] == "plan"
    assert "changed while fixes were being generated" in res["reason"]
    assert (repo / "other.py").read_bytes() == precious
    assert (repo / "a.py").read_bytes() == b"a = BAD\n"
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert git(repo, "branch", "--list", "isitsecure/*") == ""
    # The plan is built from the fixes we already paid for, from REAL contents.
    assert "-a = BAD" in res["markdown"] and "+a = GOOD" in res["markdown"]


async def test_user_edit_to_the_file_being_fixed_wins(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {"a.py": b"a = BAD\n"})
    edit = b"a = BAD  # mine\n"
    _llm(monkeypatch, StubLLM(on_call=lambda n: (repo / "a.py").write_bytes(edit)))
    res = await _run(repo, [make_finding("a.py")])
    assert res["mode"] == "plan"
    assert (repo / "a.py").read_bytes() == edit


async def test_commit_by_user_during_generation_falls_back_to_plan(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {"a.py": b"a = BAD\n"})

    def commit(n):
        (repo / "new.py").write_text("n = 1\n")
        git(repo, "add", "-A")
        git(repo, "commit", "-qm", "user work")

    _llm(monkeypatch, StubLLM(on_call=commit))
    res = await _run(repo, [make_finding("a.py")])
    assert res["mode"] == "plan"
    assert git(repo, "log", "--format=%s", "-1") == "user work"


async def test_restore_never_forces_over_user_edits(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {"a.py": b"a = BAD\n"})
    _llm(monkeypatch)
    user_edit = b"a = GOOD  # user rewrote the fixed line while verification ran\n"

    async def slow_verify(root, findings, **kw):
        (repo / "a.py").write_bytes(user_edit)  # edit lands on the fix branch checkout
        return verifier.VerifyResult(resolved=1)

    monkeypatch.setattr(verifier, "verify_findings_resolved", slow_verify)
    res = await _run(repo, [make_finding("a.py")])
    assert res["applied"] is True
    assert res["restored_base_branch"] is False
    assert "nothing was overwritten" in res["message"]
    assert res["branch"] in res["plain"]["next_step"] or "switch back" in res["plain"]["next_step"]
    assert (repo / "a.py").read_bytes() == user_edit  # NOT force-checked-out away
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == res["branch"]


async def test_failing_write_rolls_back_leaves_no_branch_and_restores(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {"a.py": b"a = BAD\n", "b.py": b"b = BAD\n"})
    _llm(monkeypatch)
    real = safe_apply.atomic_write_bytes
    n = {"c": 0}

    def flaky(t, d):
        n["c"] += 1
        if n["c"] == 2:
            raise OSError("disk full")
        real(t, d)

    monkeypatch.setattr(safe_apply, "atomic_write_bytes", flaky)
    with pytest.raises(RuntimeError, match="nothing was kept"):
        await _run(repo, [make_finding("a.py"), make_finding("b.py")])
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert git(repo, "branch", "--list", "isitsecure/*") == ""
    assert git(repo, "status", "--porcelain") == ""
    assert (repo / "a.py").read_bytes() == b"a = BAD\n"


async def test_commit_failure_restores_files_and_index(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {"a.py": b"a = BAD\n"})
    _llm(monkeypatch)
    hook = repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho no >&2\nexit 1\n")
    hook.chmod(0o755)
    with pytest.raises(RuntimeError, match="Commit failed"):
        await _run(repo, [make_finding("a.py")])
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert git(repo, "status", "--porcelain") == ""
    assert git(repo, "branch", "--list", "isitsecure/*") == ""


async def test_concurrent_fix_all_on_same_repo_is_serialised(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {"a.py": b"a = BAD\n", "b.py": b"b = BAD\n"})
    _llm(monkeypatch)
    r1, r2 = await asyncio.gather(
        _run(repo, [make_finding("a.py")]), _run(repo, [make_finding("b.py")]))
    assert {r1["branch"], r2["branch"]} == {"isitsecure/fixes", "isitsecure/fixes-2"}
    assert git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert git(repo, "status", "--porcelain") == ""


async def test_dirty_tree_up_front_goes_to_plan_without_touching_anything(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {"a.py": b"a = BAD\n"})
    (repo / "wip.py").write_text("w = 1\n")
    _llm(monkeypatch)
    res = await _run(repo, [make_finding("a.py")])
    assert res["mode"] == "plan" and "uncommitted" in res["reason"]
    assert (repo / "wip.py").read_text() == "w = 1\n"


async def test_llm_call_budget_caps_spend(tmp_path, monkeypatch):
    repo = make_repo(tmp_path, {"a.py": b"a = BAD\nb = BAD\n"})
    llm = _llm(monkeypatch)
    res = await _run(repo, [make_finding("a.py", title="one"), make_finding("a.py", title="two")],
                     max_llm_calls=1)
    assert llm.calls == 1
    assert any("budget" in s for s in res["skipped"])
    assert res["plain"]["couldnt_fix"] == 1  # the unattempted finding is not "fixed"


# ---------------------------------------------------------------------------
# plan mode: real file contents, no marker-annotated snippets
# ---------------------------------------------------------------------------

async def test_plan_for_non_git_folder_uses_real_file_not_snippet(tmp_path, monkeypatch):
    folder = tmp_path / "plain"
    folder.mkdir()
    (folder / "a.py").write_bytes(b"x = 1\nq = BAD\ny = 2\n")
    llm = _llm(monkeypatch)
    snippet = "1 | x = 1\n2 >>> q = BAD\n3 | y = 2"
    res = await _run(folder, [make_finding("a.py", snippet=snippet)])
    assert res["mode"] == "plan" and "git" in res["reason"]
    assert ">>>" not in llm.prompts[0] and "2 | " not in llm.prompts[0]
    assert "+q = GOOD" in res["markdown"] and "-q = BAD" in res["markdown"]
    assert ">>>" not in res["markdown"]


async def test_plan_for_remote_target_never_fabricates_a_diff(monkeypatch):
    llm = _llm(monkeypatch)
    snippet = "10 | foo\n11 >>> BAD()\n12 | bar"
    report = {"repo_url": "https://example.com/o/r",
              "findings": [make_finding("a.py", snippet=snippet).model_dump(mode="json")]}

    async def emit(e):
        pass

    res = await fix_service.run_fix_all(report=report, llm_provider="anthropic", emit=emit)
    assert res["mode"] == "plan" and llm.calls == 0
    assert res["fixed_count"] == 0 and "```diff" not in res["markdown"]
    assert any("source not available locally" in s for s in res["skipped"])


# ---------------------------------------------------------------------------
# validation + secret scrubbing
# ---------------------------------------------------------------------------

def test_validate_fix_options():
    ok = fix_service.validate_fix_options(["Critical", "high"], "single", 3)
    assert ok == (("critical", "high"), "single", 3)
    assert fix_service.validate_fix_options(None, None, None)[1:] == ("per-category", 8)
    for bad in (
        (["crit"], None, None), (["low", "nonsense"], None, None),
        (None, "bogus", None), (None, None, 0), (None, None, -1),
        (None, None, 10 ** 9), (None, None, True),
    ):
        with pytest.raises(ValueError):
            fix_service.validate_fix_options(*bad)


def test_scrub_secrets_removes_explicit_and_shaped_credentials():
    key, tok = "sk-ant-api03-ABCDEFGHIJKLMNOP", "ghp_" + "a" * 36
    text = f"401 for {key}; clone https://x:{tok}@github.com/o/r failed; custom=hunter2hunter2"
    out = fix_service.scrub_secrets(text, "hunter2hunter2")
    assert key not in out and tok not in out and "hunter2hunter2" not in out


async def test_git_stderr_is_scrubbed(tmp_path):
    tok = "ghp_" + "b" * 36
    code, _, err = await fix_service._git(
        str(tmp_path), "clone", f"https://u:{tok}@127.0.0.1:1/x.git", str(tmp_path / "c"))
    assert code != 0 and tok not in err


async def test_job_errors_are_scrubbed_from_log_store_and_stream(monkeypatch, caplog):
    key, tok = "sk-ant-api03-SECRETSECRETSECRET", "ghp_" + "c" * 36

    async def boom(**kw):
        raise RuntimeError(f"provider said bad key {key} and token {tok}")

    monkeypatch.setattr(fix_service, "run_fix_all", boom)
    srv._fix_jobs["j1"] = {"status": "running", "events": [], "result": None, "watchers": 0}
    with caplog.at_level(logging.DEBUG):
        await srv._run_fix_all_job("j1", {}, "anthropic", ("high",), github_token=tok, api_key=key)
    job = srv._fix_jobs["j1"]
    assert job["status"] == "failed"
    assert key not in job["error"] and tok not in job["error"]
    assert key not in caplog.text and tok not in caplog.text


async def test_single_fix_route_scrubs_provider_errors(monkeypatch):
    key = "sk-ant-api03-ROUTEROUTEROUTE"
    srv._scans["s"] = {"status": "complete", "events": [], "report": {
        "findings": [make_finding("a.py").model_dump(mode="json") | {"id": "f1"}]}}

    class Leaky:
        async def generate_with_system(self, **kw):
            raise RuntimeError(f"auth failed for {key}")

    monkeypatch.setattr("isitsecure.llm.adapters.create_llm_client", lambda p, k, **kw: Leaky())
    res = await srv.generate_fix(srv.FixRequest(
        finding_id="f1", file_content="a = BAD\n", api_key=key))
    assert key not in (res["error"] or "") and res["success"] is False


# ---------------------------------------------------------------------------
# job lifecycle: caps, dedupe, cancel, key lifecycle
# ---------------------------------------------------------------------------

def _scan_with_report(scan_id="s1", **kw):
    srv._scans[scan_id] = {"status": "complete", "events": [], "llm_provider": "anthropic",
                           "api_key": kw.pop("api_key", "sk-x"),
                           "report": {"findings": [{"severity": "high"}]}, **kw}


async def test_start_fix_all_validates_before_spawning(monkeypatch):
    _scan_with_report()
    for body in ({"severities": ["crit"]}, {"pr_strategy": "nope"}, {"max_prs": 0},
                 {"max_prs": 10 ** 9}):
        with pytest.raises(HTTPException) as ei:
            await srv.start_fix_all(srv.FixAllRequest(scan_id="s1", **body))
        assert ei.value.status_code == 400
    assert srv._fix_jobs == {}


async def test_duplicate_fix_all_for_same_scan_attaches_to_running_job(monkeypatch):
    gate = asyncio.Event()

    async def slow(job_id, report, provider, severities, **kw):
        await gate.wait()

    monkeypatch.setattr(srv, "_run_fix_all_job", slow)
    _scan_with_report()
    first = await srv.start_fix_all(srv.FixAllRequest(scan_id="s1"))
    second = await srv.start_fix_all(srv.FixAllRequest(scan_id="s1"))
    assert second["job_id"] == first["job_id"] and second["deduplicated"] is True
    assert len(srv._fix_jobs) == 1
    assert first["job_id"] in srv._fix_tasks  # strong ref kept
    gate.set()
    await asyncio.sleep(0.05)
    assert first["job_id"] not in srv._fix_tasks


async def test_concurrent_job_limit_and_finished_job_eviction(monkeypatch):
    gate = asyncio.Event()

    async def slow(job_id, report, provider, severities, **kw):
        await gate.wait()
        srv._fix_jobs[job_id]["status"] = "complete"

    monkeypatch.setattr(srv, "_run_fix_all_job", slow)
    for i in range(srv.MAX_CONCURRENT_FIX_JOBS):
        _scan_with_report(f"s{i}")
        await srv.start_fix_all(srv.FixAllRequest(scan_id=f"s{i}"))
    _scan_with_report("extra")
    with pytest.raises(HTTPException) as ei:
        await srv.start_fix_all(srv.FixAllRequest(scan_id="extra"))
    assert ei.value.status_code == 429
    gate.set()
    await asyncio.sleep(0.05)

    for i in range(srv.MAX_RETAINED_FIX_JOBS + 20):
        srv._fix_jobs[f"old{i}"] = {"status": "complete", "events": [], "result": {}}
    srv._evict_fix_jobs()
    assert len(srv._fix_jobs) <= srv.MAX_RETAINED_FIX_JOBS


async def test_cancel_stops_a_running_job(monkeypatch):
    started = asyncio.Event()

    async def hang(job_id, report, provider, severities, **kw):
        started.set()
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            srv._fix_jobs[job_id]["status"] = "cancelled"
            raise

    monkeypatch.setattr(srv, "_run_fix_all_job", hang)
    _scan_with_report()
    job_id = (await srv.start_fix_all(srv.FixAllRequest(scan_id="s1")))["job_id"]
    await started.wait()
    await srv.cancel_fix_all(job_id)
    await asyncio.sleep(0.05)
    assert srv._fix_jobs[job_id]["status"] == "cancelled"
    assert job_id not in srv._fix_tasks
    with pytest.raises(HTTPException):
        await srv.cancel_fix_all("nope")


async def test_orphaned_job_is_cancelled_after_client_disconnect(monkeypatch):
    monkeypatch.setattr(srv, "FIX_DISCONNECT_GRACE_S", 0.01)
    started = asyncio.Event()

    async def hang(job_id, report, provider, severities, **kw):
        started.set()
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            srv._fix_jobs[job_id]["status"] = "cancelled"
            raise

    monkeypatch.setattr(srv, "_run_fix_all_job", hang)
    _scan_with_report()
    job_id = (await srv.start_fix_all(srv.FixAllRequest(scan_id="s1")))["job_id"]
    await started.wait()
    resp = await srv.stream_fix_all(job_id)
    gen = resp.body_iterator
    task = asyncio.ensure_future(gen.__anext__())
    await asyncio.sleep(0.4)  # watcher attached, nothing to send yet
    task.cancel()  # client goes away
    with pytest.raises(asyncio.CancelledError):
        await task
    await gen.aclose()
    await asyncio.sleep(0.2)
    assert srv._fix_jobs[job_id]["status"] == "cancelled"


async def test_second_job_gets_a_clear_key_message_not_a_misleading_one(monkeypatch):
    monkeypatch.setattr(fix_service, "load_api_key", lambda p: None)
    monkeypatch.setattr(srv, "load_api_key", lambda p: None)

    async def ok(job_id, report, provider, severities, **kw):
        srv._fix_jobs[job_id]["status"] = "complete"
        srv._fix_jobs[job_id]["result"] = {}

    monkeypatch.setattr(srv, "_run_fix_all_job", ok)
    _scan_with_report(api_key="sk-request-key")
    await srv.start_fix_all(srv.FixAllRequest(scan_id="s1"))
    await asyncio.sleep(0.05)
    assert srv._scans["s1"]["api_key"] is None
    with pytest.raises(HTTPException) as ei:
        await srv.start_fix_all(srv.FixAllRequest(scan_id="s1"))
    assert ei.value.status_code == 409 and "discarded" in ei.value.detail


async def test_failed_job_keeps_request_key_so_retry_works(monkeypatch):
    async def fail(job_id, report, provider, severities, **kw):
        srv._fix_jobs[job_id]["status"] = "failed"
        srv._fix_jobs[job_id]["error"] = "x"

    monkeypatch.setattr(srv, "_run_fix_all_job", fail)
    _scan_with_report(api_key="sk-request-key")
    await srv.start_fix_all(srv.FixAllRequest(scan_id="s1"))
    await asyncio.sleep(0.05)
    assert srv._scans["s1"]["api_key"] == "sk-request-key"


async def test_stream_reports_cancelled_job(monkeypatch):
    srv._fix_jobs["j"] = {"status": "cancelled", "events": [], "result": None,
                          "error": "Fix job was cancelled.", "watchers": 0}
    resp = await srv.stream_fix_all("j")
    chunks = [c async for c in resp.body_iterator]
    assert any("cancelled" in c for c in chunks)
