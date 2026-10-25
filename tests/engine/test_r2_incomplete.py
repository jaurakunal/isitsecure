"""R2: incomplete-scan state reaches every consumer; cancellation propagates."""

from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from isitsecure.cli.render import _generate_badge_svg
from isitsecure.engine.agent import DeepScanEvent, DeepScanPhase, DeepSecurityScanAgent, ScanMode
from isitsecure.engine.integrations.cicd_service import CICDIntegrationService
from isitsecure.engine.models import DeepScanReport
from isitsecure.engine.scan_context import ScanContext
from isitsecure.engine.shared import progress
from isitsecure.engine.shared.scanner_runner import (
    record_skipped_work,
    reset_failure_log,
    use_failure_log,
)
from isitsecure import mcp_server


def _agent(**kw):
    return DeepSecurityScanAgent(
        ingestion_service=MagicMock(), endpoint_scanner=MagicMock(), **kw
    )


# ---- #4: MCP / CI / badge -------------------------------------------------

@pytest.mark.parametrize("field", ["scanner_errors", "ingestion_errors"])
def test_mcp_scan_result_incomplete(field):
    report = DeepScanReport(**{field: ["jwt: timed out"]})
    res = mcp_server._trim_report(report, "low", "sid")
    assert res["incomplete"] is True
    assert res["coverage_gaps"] == ["jwt: timed out"]
    assert res["safe_to_launch"] is False
    assert "safe to launch" not in res["verdict"].replace("can't confirm it's safe to launch", "")
    assert "Provisional" in res["grade_label"]
    assert res["grade"] == "A"  # letter unchanged
    md = mcp_server._render_markdown(report)
    assert "Scan incomplete" in md and "jwt: timed out" in md


def test_mcp_scan_result_complete_unchanged():
    res = mcp_server._trim_report(DeepScanReport(), "low", "sid")
    assert res["incomplete"] is False and res["coverage_gaps"] == []
    assert res["safe_to_launch"] is True


async def test_cicd_status_error_when_incomplete():
    svc = CICDIntegrationService.__new__(CICDIntegrationService)
    svc.update_github_commit_status = AsyncMock(return_value=True)
    svc.should_fail_build = lambda r, s: False
    report = DeepScanReport(scanner_errors=["sqli: timed out"])
    await svc.post_scan_status(report, "o", "r", "sha")
    args = svc.update_github_commit_status.await_args.args
    assert args[3] == "error" and "sqli: timed out" in args[4] and len(args[4]) <= 140
    svc.update_github_commit_status.reset_mock()
    await svc.post_scan_status(DeepScanReport(), "o", "r", "sha")
    assert svc.update_github_commit_status.await_args.args[3] == "success"


def test_badge_marks_incomplete():
    assert "incomplete" in _generate_badge_svg("A", 0, 0, 0, incomplete=True)
    assert "incomplete" not in _generate_badge_svg("A", 0, 0, 0)


# ---- #7: skipped work reaches scanner_errors ------------------------------

def test_record_skipped_work_reads_attrs_defensively():
    log: list[str] = []
    tok = use_failure_log(log)
    try:
        sc = SimpleNamespace(
            skipped_files=[("a.py", "llm_error"), ("b.py", "llm_error"), ("c.py", "llm_error")],
            skipped_steps=[("s", "timeout")], unchecked_packages=2,
        )
        record_skipped_work("llm_code_reviewer", sc)
        record_skipped_work("plain", SimpleNamespace())
        record_skipped_work("osv", SimpleNamespace(_unchecked_packages=4))
        record_skipped_work("clean", SimpleNamespace(skipped_files=[], unchecked_packages=0))
    finally:
        reset_failure_log(tok)
    assert "llm_code_reviewer: 3 file(s) not reviewed (llm_error)" in log
    assert "llm_code_reviewer: 1 step(s) skipped (timeout)" in log
    assert "llm_code_reviewer: 2 package(s) not checked" in log
    assert "osv: 4 package(s) not checked" in log
    assert len(log) == 4


async def test_llm_review_phase_reports_skipped_files():
    reviewer = MagicMock()
    reviewer.skipped_files = [("x.py", "llm_error")]
    reviewer.scan = AsyncMock(return_value=[])
    agent = _agent(llm_code_reviewer=reviewer)
    agent._scanner_errors = []
    ctx = ScanContext(
        mode=ScanMode.CODE_ONLY, target_url=None, repo_url="r", repo_branch=None,
        github_token=None, credentials_a=None, credentials_b=None,
    )
    ctx.repo_snapshot = MagicMock()
    tok = use_failure_log(agent._scanner_errors)
    try:
        _ = [e async for e in agent._phase_llm_code_review(ctx)]
    finally:
        reset_failure_log(tok)
    assert "llm_code_reviewer: 1 file(s) not reviewed (llm_error)" in agent._scanner_errors


# ---- #8: cancellation propagates ------------------------------------------

class _Hang:
    scanner_name = "hang"

    def __init__(self):
        self.cancelled = False

    async def scan(self, *a, **k):
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return []


@pytest.mark.parametrize("gen,args,attr", [
    ("_run_dast_scanners_streamed", ([], MagicMock()), "dast_scanners"),
    ("_run_sast_scanners_streamed", (MagicMock(),), "sast_scanners"),
])
async def test_cancelling_consumer_propagates_and_cleans_workers(gen, args, attr):
    hang = _Hang()
    agent = _agent(**{attr: [hang]})
    agent._reporter = progress.ProgressReporter()
    agent._scanner_errors = []
    ptok = progress.use_reporter(agent._reporter)

    async def consume():
        async for _ in getattr(agent, gen)(*args):
            pass

    try:
        task = asyncio.ensure_future(consume())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
        await asyncio.sleep(0.05)
        assert hang.cancelled
    finally:
        progress.reset_reporter(ptok)


# ---- nice-to-haves --------------------------------------------------------

async def test_token_not_in_any_log_record(caplog):
    secret = "SECRETTOKENVALUE1234567890abcdef"
    agent = _agent()
    agent._run_authenticated_crawl = AsyncMock(return_value=SimpleNamespace(
        pages_visited=1, discovered_endpoints=[], tables_discovered=[],
        auth_headers={"Authorization": f"Bearer {secret}"}, errors=[],
    ))
    creds = SimpleNamespace(email="u@example.invalid", provider="token")
    ctx = ScanContext(
        mode=ScanMode.AUTHENTICATED, target_url="http://127.0.0.1:1", repo_url=None,
        repo_branch=None, github_token=None, credentials_a=creds, credentials_b=None,
    )
    with caplog.at_level(logging.DEBUG):
        _ = [e async for e in agent._phase_authenticated_crawl(ctx)]
    assert ctx.session_a is not None and ctx.session_a.access_token == secret
    for rec in caplog.records:
        text = rec.getMessage() + " " + str(rec.args)
        assert secret not in text and secret[:8] not in text


async def test_scan_cleanup_order_with_real_lsp_phase(monkeypatch):
    """Real LSP-init phase + real reporter reset: shutdown runs while the ambient
    reporter is still installed, and the reporter is restored afterwards."""
    order: list[str] = []

    class FakeLSP:
        async def initialize(self, path):
            return True

        async def shutdown(self):
            order.append(f"shutdown(reporter={progress._current.get() is not None})")

    agent = _agent(lsp_client=FakeLSP())

    async def empty(ctx):
        return
        yield  # pragma: no cover

    async def noop(ctx):
        return None

    for name in dir(agent):
        if name.startswith("_phase_") and name != "_phase_lsp_initialization":
            monkeypatch.setattr(
                agent, name,
                noop if name in ("_phase_oob_registration", "_phase_cross_probe_analysis",
                                 "_phase_oob_collection") else empty,
            )

    async def repo(ctx):
        ctx.repo_snapshot = MagicMock(clone_path="/nonexistent", branch="main", commit_hash="abc")
        return
        yield  # pragma: no cover

    async def after_lsp(ctx):
        yield DeepScanEvent(DeepScanPhase.SAST_SCANNING, "after lsp", 1)

    monkeypatch.setattr(agent, "_phase_repo_ingestion", repo)
    monkeypatch.setattr(agent, "_phase_sast_scanners", after_lsp)
    assert progress._current.get() is None
    for break_early in (True, False):
        order.clear()
        gen = agent.scan(repo_url="https://example.invalid/r.git", scan_mode=ScanMode.CODE_ONLY)
        async for ev in gen:
            if break_early and ev.phase == DeepScanPhase.SAST_SCANNING:
                break
        await gen.aclose()
        assert order == ["shutdown(reporter=True)"], order
        assert progress._current.get() is None
