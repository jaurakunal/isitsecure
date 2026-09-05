"""Characterization tests for the scan phases that had no coverage.

`DeepSecurityScanAgent.scan()` is 871 lines across 19 phases, and roughly 40%
of it was unreachable by the existing tests — the phases needing an LLM client
or authenticated sessions, which no unit test and no `--llm none` live scan
ever executed.

These pin down what those phases *currently do*, so that moving them (into a
ScanContext-based decomposition) has to preserve it. They deliberately assert
observable behaviour — which scanner names land in `scanners_run`, which
findings survive, which collaborators get called with what — rather than
internal structure, so they stay true across the refactor.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from isitsecure.engine.agent import DeepSecurityScanAgent
from isitsecure.engine.enums import (
    DeepScanPhase,
    FindingCategory,
    ScanMode,
    SeverityLevel,
)
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(title: str = "A finding", **kwargs) -> DeepFinding:
    defaults = {
        "source": FindingSource.DAST_URL,
        "category": FindingCategory.IDOR,
        "severity": SeverityLevel.HIGH,
        "title": title,
        "description": "d",
        "confidence": 0.9,
        "scanner_name": "test_scanner",
    }
    defaults.update(kwargs)
    return DeepFinding(**defaults)


def _code_finding(suppressed: bool = False):
    from isitsecure.engine.code_analysis.models import CodeFinding

    return CodeFinding(
        scanner_name="route_auth",
        severity=SeverityLevel.HIGH,
        category=FindingCategory.AUTH_WEAKNESS,
        title="Missing auth",
        description="d",
        file_path="src/api/route.ts",
        line_number=10,
        confidence=0.85,
        lsp_suppressed=suppressed,
    )


def _repo_snapshot():
    return MagicMock(branch="main", commit_hash="abc123", route_map=["/api/a"])


def _agent(**kwargs) -> DeepSecurityScanAgent:
    """An agent whose network-touching collaborators are all inert."""
    ingestion = AsyncMock()
    snapshot = MagicMock()
    snapshot.all_js_content = "js"
    snapshot.html_content = "<html></html>"
    snapshot.assets = []
    ingestion.ingest.return_value = snapshot

    endpoint_scanner = AsyncMock()
    endpoint_scanner.discover.return_value = kwargs.pop("endpoints", [])

    kwargs.setdefault("ingestion_service", ingestion)
    kwargs.setdefault("endpoint_scanner", endpoint_scanner)
    return DeepSecurityScanAgent(**kwargs)


async def _collect(gen) -> list:
    return [e async for e in gen]


def _report(events) -> dict:
    return events[-1].data["report"]


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """Keep every test in this module off the network.

    `scan()` builds the OOB service and the DOM XSS scanner itself; unstubbed
    they reach the live oob.isitsecure.ai and launch a browser.
    """
    class _NoOOB:
        is_registered = False

        async def register(self) -> bool:
            return False

    class _NoDOMXSS:
        SCANNER_NAME = "dom_xss_scanner"

        async def scan(self, **_kwargs) -> list:
            return []

    monkeypatch.setattr(
        "isitsecure.engine.shared.oob_callback.OOBCallbackService", _NoOOB
    )
    monkeypatch.setattr(
        "isitsecure.engine.scanners.dom_xss_scanner.DOMXSSScanner", _NoDOMXSS
    )


# ---------------------------------------------------------------------------
# Phase 5.5 — cross-probe analysis
# ---------------------------------------------------------------------------


class TestCrossProbeAnalysis:
    @pytest.mark.asyncio
    async def test_analyzer_findings_are_added_and_recorded(self) -> None:
        xss = AsyncMock()
        xss.scanner_name = "xss_scanner"
        xss.scan.return_value = [_finding("dast finding")]

        analyzer = MagicMock()
        analyzer.analyze = AsyncMock(return_value=[_finding("correlated")])

        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            dast_scanners=[xss],
        )
        with patch(
            "isitsecure.engine.shared.probe_analyzer.ProbeAnalyzer",
            return_value=analyzer,
        ):
            events = await _collect(agent.scan(target_url="https://example.com"))

        report = _report(events)
        assert "probe_analyzer" in report["scanners_run"]
        assert any(f["title"] == "correlated" for f in report["findings"])

    @pytest.mark.asyncio
    async def test_not_recorded_when_it_finds_nothing(self) -> None:
        xss = AsyncMock()
        xss.scanner_name = "xss_scanner"
        xss.scan.return_value = [_finding()]
        analyzer = MagicMock()
        analyzer.analyze = AsyncMock(return_value=[])

        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            dast_scanners=[xss],
        )
        with patch(
            "isitsecure.engine.shared.probe_analyzer.ProbeAnalyzer",
            return_value=analyzer,
        ):
            events = await _collect(agent.scan(target_url="https://example.com"))

        assert "probe_analyzer" not in _report(events)["scanners_run"]

    @pytest.mark.asyncio
    async def test_a_failing_analyzer_does_not_lose_findings(self) -> None:
        """Fail open — an analysis step must never cost us real findings."""
        xss = AsyncMock()
        xss.scanner_name = "xss_scanner"
        xss.scan.return_value = [_finding("real")]
        analyzer = MagicMock()
        analyzer.analyze = AsyncMock(side_effect=RuntimeError("boom"))

        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            dast_scanners=[xss],
        )
        with patch(
            "isitsecure.engine.shared.probe_analyzer.ProbeAnalyzer",
            return_value=analyzer,
        ):
            events = await _collect(agent.scan(target_url="https://example.com"))

        report = _report(events)
        assert any(f["title"] == "real" for f in report["findings"])
        assert "probe_analyzer" not in report["scanners_run"]


# ---------------------------------------------------------------------------
# Phase 3.5 / 5.6 — OOB callback registration and collection
# ---------------------------------------------------------------------------


class TestOOBCallback:
    @staticmethod
    def _oob(findings, *, registered=True, poll_error=None):
        service = MagicMock()
        service.is_registered = registered
        service.register = AsyncMock(return_value=registered)
        service.poll = AsyncMock(side_effect=poll_error) if poll_error else AsyncMock()
        service.get_findings = MagicMock(return_value=findings)
        return service

    @pytest.mark.asyncio
    async def test_confirmed_callbacks_become_findings(self, monkeypatch) -> None:
        service = self._oob([_finding("blind ssrf confirmed")])
        monkeypatch.setattr(
            "isitsecure.engine.shared.oob_callback.OOBCallbackService",
            lambda: service,
        )
        agent = _agent(endpoints=[DiscoveredEndpoint(url="https://example.com/a")])

        events = await _collect(agent.scan(target_url="https://example.com"))

        report = _report(events)
        assert "oob_callback" in report["scanners_run"]
        assert any(f["title"] == "blind ssrf confirmed" for f in report["findings"])

    @pytest.mark.asyncio
    async def test_no_interactions_is_not_recorded_as_a_scanner(
        self, monkeypatch
    ) -> None:
        service = self._oob([])
        monkeypatch.setattr(
            "isitsecure.engine.shared.oob_callback.OOBCallbackService",
            lambda: service,
        )
        agent = _agent(endpoints=[DiscoveredEndpoint(url="https://example.com/a")])

        events = await _collect(agent.scan(target_url="https://example.com"))

        assert "oob_callback" not in _report(events)["scanners_run"]

    @pytest.mark.asyncio
    async def test_unregistered_service_is_never_polled(self, monkeypatch) -> None:
        service = self._oob([], registered=False)
        monkeypatch.setattr(
            "isitsecure.engine.shared.oob_callback.OOBCallbackService",
            lambda: service,
        )
        agent = _agent(endpoints=[DiscoveredEndpoint(url="https://example.com/a")])

        await _collect(agent.scan(target_url="https://example.com"))

        service.poll.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_failing_poll_does_not_end_the_scan(self, monkeypatch) -> None:
        service = self._oob([], poll_error=RuntimeError("network gone"))
        monkeypatch.setattr(
            "isitsecure.engine.shared.oob_callback.OOBCallbackService",
            lambda: service,
        )
        agent = _agent(endpoints=[DiscoveredEndpoint(url="https://example.com/a")])

        events = await _collect(agent.scan(target_url="https://example.com"))

        assert events[-1].phase == DeepScanPhase.COMPLETE
        assert "report" in events[-1].data


# ---------------------------------------------------------------------------
# Phase 6.5 / 7.5 — LSP initialization and validation
# ---------------------------------------------------------------------------


def _lsp_client(*, initializes=True, error=None):
    client = MagicMock()
    client.is_available = initializes
    client.last_error = error
    client.initialize = AsyncMock(return_value=initializes)
    client.shutdown = AsyncMock()
    client._process = object()  # not the no-op client
    return client


def _sast_scanner(code_findings, *, validate=None):
    scanner = AsyncMock()
    scanner.scanner_name = "route_auth"
    scanner.scan.return_value = code_findings
    if validate is None:
        # A scanner without validate_with_lsp must be skipped, not crashed on.
        del scanner.validate_with_lsp
    else:
        scanner.validate_with_lsp = MagicMock(side_effect=validate)
    return scanner


class TestLSPInitialization:
    @pytest.mark.asyncio
    async def test_client_is_initialized_against_the_ingested_clone(
        self, tmp_path
    ) -> None:
        client = _lsp_client()
        repo = _repo_snapshot()
        repo.clone_path = str(tmp_path)
        ingestion = AsyncMock()
        ingestion.ingest.return_value = repo

        agent = _agent(repo_ingestion_service=ingestion, lsp_client=client)
        await _collect(agent.scan(
            repo_url="https://github.com/o/r", scan_mode=ScanMode.CODE_ONLY
        ))

        client.initialize.assert_awaited_once_with(str(tmp_path))

    @pytest.mark.asyncio
    async def test_failed_initialization_does_not_end_the_scan(self) -> None:
        client = _lsp_client(initializes=False, error="no server installed")
        ingestion = AsyncMock()
        ingestion.ingest.return_value = _repo_snapshot()

        agent = _agent(repo_ingestion_service=ingestion, lsp_client=client)
        events = await _collect(agent.scan(
            repo_url="https://github.com/o/r", scan_mode=ScanMode.CODE_ONLY
        ))

        report = _report(events)
        assert "lsp_validator" not in report["scanners_run"]

    @pytest.mark.asyncio
    async def test_the_noop_client_skips_initialization_entirely(self) -> None:
        from isitsecure.engine.code_analysis.lsp.noop_client import NoOpLSPClient

        ingestion = AsyncMock()
        ingestion.ingest.return_value = _repo_snapshot()
        agent = _agent(repo_ingestion_service=ingestion, lsp_client=NoOpLSPClient())

        events = await _collect(agent.scan(
            repo_url="https://github.com/o/r", scan_mode=ScanMode.CODE_ONLY
        ))

        phases = [e.phase for e in events]
        assert DeepScanPhase.LSP_INITIALIZATION not in phases

    @pytest.mark.asyncio
    async def test_the_client_is_shut_down_when_the_scan_ends(self) -> None:
        client = _lsp_client()
        ingestion = AsyncMock()
        ingestion.ingest.return_value = _repo_snapshot()
        agent = _agent(repo_ingestion_service=ingestion, lsp_client=client)

        await _collect(agent.scan(
            repo_url="https://github.com/o/r", scan_mode=ScanMode.CODE_ONLY
        ))

        client.shutdown.assert_awaited()


class TestLSPValidation:
    @pytest.mark.asyncio
    async def test_a_disproved_finding_is_removed_from_the_report(self) -> None:
        """The whole point of LSP validation.

        `validate_with_lsp` *drops* the findings it disproves rather than
        returning them flagged, so the suppressed set is what left the list.
        """
        kept, disproved = _code_finding(), _code_finding(suppressed=True)
        scanner = _sast_scanner(
            [kept, disproved],
            # Mirrors the real analyzer: suppressed findings do not come back.
            validate=lambda findings, _flows: [
                f for f in findings if not f.lsp_suppressed
            ],
        )
        ingestion = AsyncMock()
        ingestion.ingest.return_value = _repo_snapshot()

        agent = _agent(
            repo_ingestion_service=ingestion,
            lsp_client=_lsp_client(),
            sast_scanners=[scanner],
        )
        with patch(
            "isitsecure.engine.code_analysis.lsp.auth_flow_tracer.AuthFlowTracer"
        ) as tracer_cls:
            tracer_cls.return_value.trace_routes = AsyncMock(return_value={})
            events = await _collect(agent.scan(
                repo_url="https://github.com/o/r", scan_mode=ScanMode.CODE_ONLY
            ))

        report = _report(events)
        assert "lsp_validator" in report["scanners_run"]
        assert len(report["findings"]) == 1
        assert report["findings"][0]["id"] == kept.id

    @pytest.mark.asyncio
    async def test_findings_the_tracer_confirms_are_kept(self) -> None:
        """Suppression must remove only what was disproved, nothing else."""
        a, b = _code_finding(), _code_finding()
        scanner = _sast_scanner([a, b], validate=lambda findings, _fl: findings)
        ingestion = AsyncMock()
        ingestion.ingest.return_value = _repo_snapshot()

        agent = _agent(
            repo_ingestion_service=ingestion,
            lsp_client=_lsp_client(),
            sast_scanners=[scanner],
        )
        with patch(
            "isitsecure.engine.code_analysis.lsp.auth_flow_tracer.AuthFlowTracer"
        ) as tracer_cls:
            tracer_cls.return_value.trace_routes = AsyncMock(return_value={})
            events = await _collect(agent.scan(
                repo_url="https://github.com/o/r", scan_mode=ScanMode.CODE_ONLY
            ))

        assert len(_report(events)["findings"]) == 2

    @pytest.mark.asyncio
    async def test_scanners_without_lsp_validation_are_skipped_not_crashed_on(
        self,
    ) -> None:
        scanner = _sast_scanner([_code_finding()])  # no validate_with_lsp
        ingestion = AsyncMock()
        ingestion.ingest.return_value = _repo_snapshot()

        agent = _agent(
            repo_ingestion_service=ingestion,
            lsp_client=_lsp_client(),
            sast_scanners=[scanner],
        )
        with patch(
            "isitsecure.engine.code_analysis.lsp.auth_flow_tracer.AuthFlowTracer"
        ) as tracer_cls:
            tracer_cls.return_value.trace_routes = AsyncMock(return_value={})
            events = await _collect(agent.scan(
                repo_url="https://github.com/o/r", scan_mode=ScanMode.CODE_ONLY
            ))

        report = _report(events)
        assert "lsp_validator" in report["scanners_run"]
        assert len(report["findings"]) == 1

    @pytest.mark.asyncio
    async def test_a_failing_tracer_keeps_every_finding(self) -> None:
        """Fail open: a broken tracer must not silently drop real findings."""
        scanner = _sast_scanner([_code_finding()], validate=lambda f, _fl: f)
        ingestion = AsyncMock()
        ingestion.ingest.return_value = _repo_snapshot()

        agent = _agent(
            repo_ingestion_service=ingestion,
            lsp_client=_lsp_client(),
            sast_scanners=[scanner],
        )
        with patch(
            "isitsecure.engine.code_analysis.lsp.auth_flow_tracer.AuthFlowTracer"
        ) as tracer_cls:
            tracer_cls.return_value.trace_routes = AsyncMock(
                side_effect=RuntimeError("tracer died")
            )
            events = await _collect(agent.scan(
                repo_url="https://github.com/o/r", scan_mode=ScanMode.CODE_ONLY
            ))

        report = _report(events)
        assert "lsp_validator" not in report["scanners_run"]
        assert len(report["findings"]) == 1

    @pytest.mark.asyncio
    async def test_validation_is_skipped_when_lsp_never_initialized(self) -> None:
        scanner = _sast_scanner([_code_finding()], validate=lambda f, _fl: f)
        ingestion = AsyncMock()
        ingestion.ingest.return_value = _repo_snapshot()

        agent = _agent(
            repo_ingestion_service=ingestion,
            lsp_client=_lsp_client(initializes=False),
            sast_scanners=[scanner],
        )
        events = await _collect(agent.scan(
            repo_url="https://github.com/o/r", scan_mode=ScanMode.CODE_ONLY
        ))

        assert "lsp_validator" not in _report(events)["scanners_run"]
        scanner.validate_with_lsp.assert_not_called()


# ---------------------------------------------------------------------------
# Phase 8 — LLM code review
# ---------------------------------------------------------------------------


def _llm_reviewer(code_findings=None):
    reviewer = AsyncMock()
    reviewer.scan.return_value = code_findings or []
    reviewer.set_sast_context = MagicMock()
    reviewer.set_lsp_context = MagicMock()
    # A real client exposes a dict here or nothing; auto-created mock
    # attributes would make _collect_token_usage add a coroutine to an int and
    # join a MagicMock into the model name.
    reviewer.token_usage = None
    reviewer._llm = None
    return reviewer


class TestLLMCodeReview:
    @pytest.mark.asyncio
    async def test_llm_findings_reach_the_report(self) -> None:
        reviewer = _llm_reviewer([_code_finding()])
        ingestion = AsyncMock()
        ingestion.ingest.return_value = _repo_snapshot()

        agent = _agent(repo_ingestion_service=ingestion, llm_code_reviewer=reviewer)
        events = await _collect(agent.scan(
            repo_url="https://github.com/o/r", scan_mode=ScanMode.CODE_ONLY
        ))

        report = _report(events)
        assert "llm_review" in report["scanners_run"]
        assert len(report["findings"]) == 1

    @pytest.mark.asyncio
    async def test_sast_findings_are_handed_over_as_context(self) -> None:
        """Cross-scanner context: the reviewer is told what SAST already found
        so it doesn't re-report the same things."""
        reviewer = _llm_reviewer()
        scanner = _sast_scanner([_code_finding()])
        ingestion = AsyncMock()
        ingestion.ingest.return_value = _repo_snapshot()

        agent = _agent(
            repo_ingestion_service=ingestion,
            llm_code_reviewer=reviewer,
            sast_scanners=[scanner],
        )
        await _collect(agent.scan(
            repo_url="https://github.com/o/r", scan_mode=ScanMode.CODE_ONLY
        ))

        reviewer.set_sast_context.assert_called_once()
        assert len(reviewer.set_sast_context.call_args[0][0]) == 1

    @pytest.mark.asyncio
    async def test_no_review_without_a_repo(self) -> None:
        reviewer = _llm_reviewer([_code_finding()])
        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            llm_code_reviewer=reviewer,
        )

        events = await _collect(agent.scan(target_url="https://example.com"))

        assert "llm_review" not in _report(events)["scanners_run"]
        reviewer.scan.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_failing_reviewer_does_not_end_the_scan(self) -> None:
        reviewer = _llm_reviewer()
        reviewer.scan.side_effect = RuntimeError("model unavailable")
        ingestion = AsyncMock()
        ingestion.ingest.return_value = _repo_snapshot()

        agent = _agent(repo_ingestion_service=ingestion, llm_code_reviewer=reviewer)
        events = await _collect(agent.scan(
            repo_url="https://github.com/o/r", scan_mode=ScanMode.CODE_ONLY
        ))

        assert "report" in events[-1].data


# ---------------------------------------------------------------------------
# Phase 9.4 — injection false-positive adjudication
# ---------------------------------------------------------------------------


class TestInjectionAdjudication:
    @pytest.mark.asyncio
    async def test_dropped_false_positives_leave_the_report(self) -> None:
        kept = _finding("real sqli")
        xss = AsyncMock()
        xss.scanner_name = "xss_scanner"
        xss.scan.return_value = [kept, _finding("false positive")]

        adjudicator = MagicMock()
        adjudicator.adjudicate = AsyncMock(return_value=[kept])

        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            dast_scanners=[xss],
            injection_adjudicator=adjudicator,
        )
        events = await _collect(agent.scan(target_url="https://example.com"))

        report = _report(events)
        assert len(report["findings"]) == 1
        assert "injection_adjudicator" in report["scanners_run"]

    @pytest.mark.asyncio
    async def test_not_recorded_when_it_drops_nothing(self) -> None:
        found = _finding("real")
        xss = AsyncMock()
        xss.scanner_name = "xss_scanner"
        xss.scan.return_value = [found]
        adjudicator = MagicMock()
        adjudicator.adjudicate = AsyncMock(return_value=[found])

        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            dast_scanners=[xss],
            injection_adjudicator=adjudicator,
        )
        events = await _collect(agent.scan(target_url="https://example.com"))

        assert "injection_adjudicator" not in _report(events)["scanners_run"]

    @pytest.mark.asyncio
    async def test_it_fails_open_and_never_loses_findings(self) -> None:
        """An adjudicator that errors must not delete real findings."""
        xss = AsyncMock()
        xss.scanner_name = "xss_scanner"
        xss.scan.return_value = [_finding("real")]
        adjudicator = MagicMock()
        adjudicator.adjudicate = AsyncMock(side_effect=RuntimeError("boom"))

        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            dast_scanners=[xss],
            injection_adjudicator=adjudicator,
        )
        events = await _collect(agent.scan(target_url="https://example.com"))

        assert len(_report(events)["findings"]) == 1


# ---------------------------------------------------------------------------
# Phase 9.5 — LLM triage
# ---------------------------------------------------------------------------


class TestTriage:
    @staticmethod
    def _triage(findings, *, error=None):
        service = MagicMock()
        service.token_usage = None
        service._llm = None
        if error:
            service.triage = AsyncMock(side_effect=error)
        else:
            from isitsecure.engine.models import OwnerSummary

            result = MagicMock()
            result.triaged_findings = findings
            # A real OwnerSummary — the report model validates this field.
            result.owner_summary = OwnerSummary(risk_summary="all good")
            result.themes = []
            service.triage = AsyncMock(return_value=result)
        return service

    @pytest.mark.asyncio
    async def test_triaged_findings_replace_the_raw_ones(self) -> None:
        raw = _finding("raw")
        triaged = _finding("triaged and enriched")
        xss = AsyncMock()
        xss.scanner_name = "xss_scanner"
        xss.scan.return_value = [raw]

        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            dast_scanners=[xss],
            llm_triage=self._triage([triaged]),
        )
        events = await _collect(agent.scan(target_url="https://example.com"))

        report = _report(events)
        assert [f["title"] for f in report["findings"]] == ["triaged and enriched"]
        assert report["owner_summary"] is not None

    @pytest.mark.asyncio
    async def test_a_failing_triage_keeps_the_untriaged_findings(self) -> None:
        """Triage is enrichment — losing it must not lose the findings."""
        xss = AsyncMock()
        xss.scanner_name = "xss_scanner"
        xss.scan.return_value = [_finding("raw")]

        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            dast_scanners=[xss],
            llm_triage=self._triage([], error=RuntimeError("model down")),
        )
        events = await _collect(agent.scan(target_url="https://example.com"))

        report = _report(events)
        assert [f["title"] for f in report["findings"]] == ["raw"]
        assert report["owner_summary"] is None

    @pytest.mark.asyncio
    async def test_triage_is_skipped_when_there_is_nothing_to_triage(self) -> None:
        triage = self._triage([])
        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            llm_triage=triage,
        )
        await _collect(agent.scan(target_url="https://example.com"))
        triage.triage.assert_not_awaited()


# ---------------------------------------------------------------------------
# Phase 9.1 — SAST-guided DAST
# ---------------------------------------------------------------------------


class TestGuidedDAST:
    @pytest.mark.asyncio
    async def test_runs_in_full_mode_with_code_findings_and_endpoints(self) -> None:
        runner = AsyncMock()
        runner.run.return_value = [_finding("guided hit")]
        ingestion = AsyncMock()
        ingestion.ingest.return_value = _repo_snapshot()

        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            repo_ingestion_service=ingestion,
            sast_scanners=[_sast_scanner([_code_finding()])],
            guided_dast_runner=runner,
        )
        events = await _collect(agent.scan(
            target_url="https://example.com",
            repo_url="https://github.com/o/r",
            scan_mode=ScanMode.FULL,
        ))

        report = _report(events)
        assert any(f["title"] == "guided hit" for f in report["findings"])

    @pytest.mark.asyncio
    async def test_skipped_in_code_only_mode(self) -> None:
        """Guided DAST needs a live target; code-only has none."""
        runner = AsyncMock()
        runner.run.return_value = [_finding("guided hit")]
        ingestion = AsyncMock()
        ingestion.ingest.return_value = _repo_snapshot()

        agent = _agent(
            repo_ingestion_service=ingestion,
            sast_scanners=[_sast_scanner([_code_finding()])],
            guided_dast_runner=runner,
        )
        await _collect(agent.scan(
            repo_url="https://github.com/o/r", scan_mode=ScanMode.CODE_ONLY
        ))

        runner.run.assert_not_awaited()


# ---------------------------------------------------------------------------
# Phase 3 / 5 — authenticated crawl and authenticated DAST
# ---------------------------------------------------------------------------


def _credentials(email: str = "a@example.com"):
    from isitsecure.engine.auth.protocols import AuthCredentials, AuthProvider

    return AuthCredentials(
        provider=AuthProvider.SUPABASE, email=email, password="pw"
    )


def _crawl_result(*, pages=3, endpoints=(), tables=(), headers=None, errors=()):
    result = MagicMock()
    result.pages_visited = pages
    result.discovered_endpoints = list(endpoints)
    result.tables_discovered = list(tables)
    result.auth_headers = headers or {}
    result.errors = list(errors)
    return result


class TestAuthenticatedCrawl:
    @pytest.mark.asyncio
    async def test_crawler_endpoints_are_added_to_the_scan(self) -> None:
        found = DiscoveredEndpoint(url="https://example.com/api/behind-login")
        agent = _agent(endpoints=[DiscoveredEndpoint(url="https://example.com/a")])

        with patch.object(
            agent, "_run_authenticated_crawl",
            AsyncMock(return_value=_crawl_result(endpoints=[found])),
        ):
            events = await _collect(agent.scan(
                target_url="https://example.com",
                credentials_a=_credentials(),
                scan_mode=ScanMode.AUTHENTICATED,
            ))

        report = _report(events)
        urls = [e["url"] for e in report["discovered_endpoints"]]
        assert "https://example.com/api/behind-login" in urls

    @pytest.mark.asyncio
    async def test_endpoints_already_known_are_not_duplicated(self) -> None:
        same = DiscoveredEndpoint(url="https://example.com/a")
        agent = _agent(endpoints=[DiscoveredEndpoint(url="https://example.com/a")])

        with patch.object(
            agent, "_run_authenticated_crawl",
            AsyncMock(return_value=_crawl_result(endpoints=[same])),
        ):
            events = await _collect(agent.scan(
                target_url="https://example.com",
                credentials_a=_credentials(),
                scan_mode=ScanMode.AUTHENTICATED,
            ))

        urls = [e["url"] for e in _report(events)["discovered_endpoints"]]
        assert urls.count("https://example.com/a") == 1

    @pytest.mark.asyncio
    async def test_a_crawl_that_visits_nothing_reports_why(self) -> None:
        agent = _agent(endpoints=[DiscoveredEndpoint(url="https://example.com/a")])

        with patch.object(
            agent, "_run_authenticated_crawl",
            AsyncMock(return_value=_crawl_result(pages=0, errors=["login failed"])),
        ):
            events = await _collect(agent.scan(
                target_url="https://example.com",
                credentials_a=_credentials(),
                scan_mode=ScanMode.AUTHENTICATED,
            ))

        messages = " ".join(e.message or "" for e in events)
        assert "login failed" in messages

    @pytest.mark.asyncio
    async def test_no_crawl_without_credentials(self) -> None:
        agent = _agent(endpoints=[DiscoveredEndpoint(url="https://example.com/a")])
        with patch.object(agent, "_run_authenticated_crawl", AsyncMock()) as crawl:
            await _collect(agent.scan(target_url="https://example.com"))
        crawl.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_api_auth_is_the_fallback_when_the_crawl_yields_no_session(
        self,
    ) -> None:
        """Browser login is tried first; the auth provider backs it up."""
        provider = AsyncMock()
        provider.authenticate.return_value = MagicMock()
        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            auth_provider=provider,
        )

        with patch.object(
            agent, "_run_authenticated_crawl",
            AsyncMock(return_value=_crawl_result(pages=0)),
        ), patch.object(
            agent, "_run_authenticated_scanners",
            AsyncMock(return_value=([], [])),
        ):
            await _collect(agent.scan(
                target_url="https://example.com",
                credentials_a=_credentials(),
                scan_mode=ScanMode.AUTHENTICATED,
            ))

        provider.authenticate.assert_awaited()

    @pytest.mark.asyncio
    async def test_a_failing_auth_provider_does_not_end_the_scan(self) -> None:
        provider = AsyncMock()
        provider.authenticate.side_effect = RuntimeError("bad credentials")
        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            auth_provider=provider,
        )

        with patch.object(
            agent, "_run_authenticated_crawl",
            AsyncMock(return_value=_crawl_result(pages=0)),
        ):
            events = await _collect(agent.scan(
                target_url="https://example.com",
                credentials_a=_credentials(),
                scan_mode=ScanMode.AUTHENTICATED,
            ))

        assert "report" in events[-1].data


class TestAuthenticatedDAST:
    @pytest.mark.asyncio
    async def test_authenticated_scanners_run_once_a_session_exists(self) -> None:
        provider = AsyncMock()
        provider.authenticate.return_value = MagicMock()
        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            auth_provider=provider,
        )

        with patch.object(
            agent, "_run_authenticated_crawl",
            AsyncMock(return_value=_crawl_result(pages=0)),
        ), patch.object(
            agent, "_run_authenticated_scanners",
            AsyncMock(return_value=([_finding("idor cross-user")], ["idor_scanner"])),
        ) as auth_scanners:
            events = await _collect(agent.scan(
                target_url="https://example.com",
                credentials_a=_credentials(),
                credentials_b=_credentials("b@example.com"),
                scan_mode=ScanMode.AUTHENTICATED,
            ))

        auth_scanners.assert_awaited_once()
        report = _report(events)
        assert "idor_scanner" in report["scanners_run"]
        assert any(f["title"] == "idor cross-user" for f in report["findings"])

    @pytest.mark.asyncio
    async def test_skipped_when_no_session_was_established(self) -> None:
        agent = _agent(endpoints=[DiscoveredEndpoint(url="https://example.com/a")])
        with patch.object(
            agent, "_run_authenticated_crawl",
            AsyncMock(return_value=_crawl_result(pages=0)),
        ), patch.object(
            agent, "_run_authenticated_scanners", AsyncMock()
        ) as auth_scanners:
            await _collect(agent.scan(
                target_url="https://example.com",
                credentials_a=_credentials(),
                scan_mode=ScanMode.AUTHENTICATED,
            ))
        auth_scanners.assert_not_awaited()


# ---------------------------------------------------------------------------
# Phase 9.2 — LLM business-logic attacks
# ---------------------------------------------------------------------------


class TestBusinessLogic:
    """This phase is gated on eight preconditions at once, so most of what
    matters is which combinations do *not* run it."""

    @staticmethod
    def _agent_with_everything(scanner_findings):
        reviewer = _llm_reviewer()
        # The phase needs a client behind the reviewer; give it the shape
        # _collect_token_usage expects rather than auto-created mocks.
        llm = MagicMock()
        llm.token_usage = None
        llm._model_name = ""
        reviewer._llm = llm
        repo = _repo_snapshot()
        repo.file_index = {"src/app.ts": "code", "empty.ts": ""}
        ingestion = AsyncMock()
        ingestion.ingest.return_value = repo

        provider = AsyncMock()
        provider.authenticate.return_value = MagicMock()

        agent = _agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/a")],
            repo_ingestion_service=ingestion,
            llm_code_reviewer=reviewer,
            auth_provider=provider,
        )
        scanner = MagicMock()
        scanner.scan = AsyncMock(return_value=scanner_findings)
        return agent, scanner

    async def _run(self, agent, scanner, **kwargs):
        with patch.object(
            agent, "_run_authenticated_crawl",
            AsyncMock(return_value=_crawl_result(pages=0)),
        ), patch.object(
            agent, "_run_authenticated_scanners", AsyncMock(return_value=([], [])),
        ), patch(
            "isitsecure.engine.scanners.llm_business_logic_scanner"
            ".LLMBusinessLogicScanner",
            return_value=scanner,
        ):
            return await _collect(agent.scan(**kwargs))

    @pytest.mark.asyncio
    async def test_runs_with_two_sessions_a_repo_and_a_target(self) -> None:
        agent, scanner = self._agent_with_everything([_finding("price manipulation")])
        events = await self._run(
            agent, scanner,
            target_url="https://example.com",
            repo_url="https://github.com/o/r",
            credentials_a=_credentials(),
            credentials_b=_credentials("b@example.com"),
            scan_mode=ScanMode.FULL,
        )

        report = _report(events)
        assert any(f["title"] == "price manipulation" for f in report["findings"])

    @pytest.mark.asyncio
    async def test_empty_files_are_not_sent_to_the_model(self) -> None:
        agent, scanner = self._agent_with_everything([])
        await self._run(
            agent, scanner,
            target_url="https://example.com",
            repo_url="https://github.com/o/r",
            credentials_a=_credentials(),
            credentials_b=_credentials("b@example.com"),
            scan_mode=ScanMode.FULL,
        )

        sent = scanner.scan.await_args.kwargs["repo_files"]
        assert "src/app.ts" in sent and "empty.ts" not in sent

    @pytest.mark.asyncio
    async def test_skipped_without_a_second_session(self) -> None:
        """Cross-role attacks need two identities to compare."""
        agent, scanner = self._agent_with_everything([_finding()])
        await self._run(
            agent, scanner,
            target_url="https://example.com",
            repo_url="https://github.com/o/r",
            credentials_a=_credentials(),
            scan_mode=ScanMode.FULL,
        )
        scanner.scan.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skipped_without_a_repo(self) -> None:
        agent, scanner = self._agent_with_everything([_finding()])
        await self._run(
            agent, scanner,
            target_url="https://example.com",
            credentials_a=_credentials(),
            credentials_b=_credentials("b@example.com"),
            scan_mode=ScanMode.AUTHENTICATED,
        )
        scanner.scan.assert_not_awaited()
