"""Engine-core robustness: runner hangs, scan() cleanup, incomplete verdict."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from isitsecure.engine.agent import (
    DeepScanPhase,
    DeepSecurityScanAgent,
)
from isitsecure.engine.models import DeepScanReport
from isitsecure.engine.reporting import plain_english
from isitsecure.engine.reporting.report_generator import ReportGenerator
from isitsecure.engine.scan_context import ScanContext
from isitsecure.engine.shared import progress
from isitsecure.engine.shared.scanner_runner import (
    reset_failure_log,
    run_scanner_safe,
    use_failure_log,
)


class _Scanner:
    def __init__(self, name, exc=None):
        self.scanner_name = name
        self._exc = exc

    async def scan(self, *a, **k):
        if self._exc:
            raise self._exc
        return []


def _agent(**kw):
    return DeepSecurityScanAgent(
        ingestion_service=MagicMock(), endpoint_scanner=MagicMock(), **kw
    )


async def _drain(agent, gen_name, *args):
    agent._reporter = progress.ProgressReporter()
    tok = progress.use_reporter(agent._reporter)
    agent._scanner_errors = []
    ftok = use_failure_log(agent._scanner_errors)
    try:
        out = []
        async for item in getattr(agent, gen_name)(*args):
            out.append(item)
        return out
    finally:
        reset_failure_log(ftok)
        progress.reset_reporter(tok)


async def test_dast_runner_survives_cancelled_error():
    agent = _agent(dast_scanners=[
        _Scanner("ok"), _Scanner("boom", exc=asyncio.CancelledError()),
    ])
    out = await asyncio.wait_for(
        _drain(agent, "_run_dast_scanners_streamed", [], MagicMock()), 5
    )
    assert out[-1][0] == "result"
    assert "boom: failed" in agent._scanner_errors


async def test_sast_runner_survives_cancelled_error():
    agent = _agent(sast_scanners=[
        _Scanner("ok"), _Scanner("boom", exc=asyncio.CancelledError()),
    ])
    out = await asyncio.wait_for(
        _drain(agent, "_run_sast_scanners_streamed", MagicMock()), 5
    )
    assert out[-1][0] == "result"
    assert "boom: failed" in agent._scanner_errors


async def test_run_scanner_safe_records_timeout_and_failure():
    log: list[str] = []
    tok = use_failure_log(log)
    try:
        async def slow():
            await asyncio.sleep(5)
            return []

        async def bad():
            raise RuntimeError("x")

        assert await run_scanner_safe("slow", slow(), 0.05) == []
        assert await run_scanner_safe("bad", bad(), 1) == []
    finally:
        reset_failure_log(tok)
    assert log == ["slow: timed out", "bad: failed"]


def _stub_phases(agent, monkeypatch, *, raise_in=None):
    async def empty(ctx):
        return
        yield  # pragma: no cover

    async def noop(ctx):
        return None

    for name in dir(agent):
        if not name.startswith("_phase_"):
            continue
        fn = noop if name in (
            "_phase_oob_registration", "_phase_cross_probe_analysis",
            "_phase_oob_collection",
        ) else empty
        monkeypatch.setattr(agent, name, fn)
    if raise_in:
        async def boom(ctx):
            raise RuntimeError("phase blew up")
            yield  # pragma: no cover
        monkeypatch.setattr(agent, raise_in, boom)


def _lsp_agent():
    lsp = MagicMock()
    lsp.shutdown = AsyncMock()
    return _agent(lsp_client=lsp), lsp


async def test_cleanup_after_complete_and_early_break(monkeypatch):
    from isitsecure.engine.agent import DeepScanEvent
    real_reset = progress.reset_reporter
    for break_at_complete in (True, False):
        agent, lsp = _lsp_agent()
        _stub_phases(agent, monkeypatch)

        async def init(ctx, agent=agent):
            agent._lsp_started = True
            yield DeepScanEvent(DeepScanPhase.SAST_SCANNING, "lsp up", 1)

        monkeypatch.setattr(agent, "_phase_lsp_initialization", init)
        resets = []
        monkeypatch.setattr(
            progress, "reset_reporter",
            lambda tok, r=resets: (r.append(1), real_reset(tok))[1],
        )
        gen = agent.scan(target_url="http://127.0.0.1:1")
        async for ev in gen:
            # Either stop after the first event or at COMPLETE.
            if not break_at_complete or ev.phase == DeepScanPhase.COMPLETE:
                break
        await gen.aclose()
        lsp.shutdown.assert_awaited_once()
        assert resets == [1]


async def test_cleanup_when_phase_raises(monkeypatch):
    agent, lsp = _lsp_agent()
    _stub_phases(agent, monkeypatch, raise_in="_phase_sast_scanners")
    agent._lsp_started = False

    async def init(ctx):
        agent._lsp_started = True
        return
        yield  # pragma: no cover

    monkeypatch.setattr(agent, "_phase_lsp_initialization", init)
    seen = {}
    real_reset = progress.reset_reporter

    def spy(tok):
        seen["reset"] = True
        real_reset(tok)

    monkeypatch.setattr(progress, "reset_reporter", spy)
    with pytest.raises(RuntimeError, match="phase blew up"):
        async for _ in agent.scan(target_url="http://127.0.0.1:1"):
            pass
    lsp.shutdown.assert_awaited_once()
    assert seen.get("reset")


async def test_full_mode_missing_repo_emits_not_scanned_event():
    agent = _agent(repo_ingestion_service=None)
    ctx = ScanContext(
        mode=__import__("isitsecure.engine.agent", fromlist=["ScanMode"]).ScanMode.FULL,
        target_url="http://127.0.0.1:1",
        repo_url="https://example.invalid/r.git",
        repo_branch=None, github_token=None,
        credentials_a=None, credentials_b=None,
    )
    agent._ingest_repo = AsyncMock(side_effect=RuntimeError("clone failed"))
    events = [e async for e in agent._phase_repo_ingestion(ctx)]
    errs = [e for e in events if (e.data or {}).get("error")]
    assert errs and "clone failed" in errs[-1].message
    assert not ctx.aborted
    assert ctx.ingestion_errors == ["clone failed"]


async def test_code_only_missing_repo_aborts_once():
    from isitsecure.engine.agent import ScanMode
    agent = _agent()
    ctx = ScanContext(
        mode=ScanMode.CODE_ONLY, target_url=None,
        repo_url="https://example.invalid/r.git", repo_branch=None,
        github_token=None, credentials_a=None, credentials_b=None,
    )
    agent._ingest_repo = AsyncMock(side_effect=RuntimeError("nope"))
    events = [e async for e in agent._phase_repo_ingestion(ctx)]
    assert ctx.aborted
    assert sum(1 for e in events if (e.data or {}).get("error")) == 1


def test_token_not_logged():
    import inspect
    from isitsecure.engine import agent as mod
    assert "token[:20]" not in inspect.getsource(mod)


def test_verdict_incomplete_and_provisional_grade():
    v = plain_english.launch_verdict(0, 0, 0, incomplete=True)
    assert v.incomplete and not v.ready and "safe to launch" not in v.headline.replace("can't confirm it's safe to launch", "")
    assert plain_english.launch_verdict(0, 0, 0).ready
    # Real findings still win
    assert "Not safe" in plain_english.launch_verdict(1, 0, incomplete=True).headline
    g = plain_english.calculate_grade(0, 0, 0, 0, provisional=True)
    assert g.grade == "A" and g.provisional and "Provisional" in g.label
    assert not plain_english.calculate_grade(0, 0, 0, 0).provisional


@pytest.mark.parametrize("field,val", [
    ("ingestion_errors", ["clone failed"]),
    ("scanner_errors", ["jwt: timed out"]),
])
def test_report_generator_marks_incomplete(field, val):
    report = DeepScanReport(**{field: val})
    data = ReportGenerator().generate(report)
    assert data["launch_verdict"]["ready"] is False
    assert data["launch_verdict"]["incomplete"] is True
    assert "Provisional" in data["grade_label"]
    assert data[field] == val
    clean = ReportGenerator().generate(DeepScanReport())
    assert clean["launch_verdict"]["ready"] is True
    assert clean["scanner_errors"] == []
