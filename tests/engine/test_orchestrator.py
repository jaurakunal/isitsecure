"""Tests for the unified DeepSecurityScanAgent orchestrator and FindingCrossReferencer."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from isitsecure.engine.agent import DeepSecurityScanAgent, DeepScanEvent
from isitsecure.engine.constants import CrossRefConfig, OrchestratorConfig
from isitsecure.engine.cross_referencer import (
    FindingCrossReferencer,
    _SeverityOrder,
)
from isitsecure.engine.enums import DeepScanPhase, ScanMode
from isitsecure.engine.models import (
    CodeLocation,
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.scanners.dom_xss_scanner import DOMXSSScanner


# ---------------------------------------------------------------------------
# Keep these tests off the network
# ---------------------------------------------------------------------------


class _StubOOBCallbackService:
    """OOB service that never registers, so both OOB phases no-op."""

    is_registered = False

    async def register(self) -> bool:
        return False


class _StubDOMXSSScanner:
    """DOM XSS scanner that finds nothing without launching a browser.

    Keeps the real scanner name so the phase still records itself in
    ``scanners_run`` exactly as a live run would.
    """

    SCANNER_NAME = DOMXSSScanner.SCANNER_NAME

    async def scan(self, **_kwargs) -> list:
        return []


@pytest.fixture(autouse=True)
def stub_networked_scanners(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop ``scan()`` reaching the live internet from a unit test.

    ``scan()`` constructs the OOB callback service and the DOM XSS scanner
    itself, so there is no seam to inject through — and un-stubbed, every test
    that drives it registered a real session against the production
    oob.isitsecure.ai and launched a real Playwright browser against
    example.com. That cost ~58s per test, ~5 of the suite's 7 minutes, and made
    these tests fail whenever the OOB host was unreachable.

    Neither collaborator is what this module covers: the OOB service (including
    the agent's own ``_inject_oob_payloads``) is tested in
    ``test_oob_callback.py``, and DOM XSS in ``test_dom_xss_scanner.py``.
    """
    monkeypatch.setattr(
        "isitsecure.engine.shared.oob_callback.OOBCallbackService",
        _StubOOBCallbackService,
    )
    monkeypatch.setattr(
        "isitsecure.engine.scanners.dom_xss_scanner.DOMXSSScanner",
        _StubDOMXSSScanner,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    source: FindingSource = FindingSource.DAST_URL,
    category: FindingCategory = FindingCategory.IDOR,
    severity: SeverityLevel = SeverityLevel.HIGH,
    scanner_name: str = "test_scanner",
    **kwargs,
) -> DeepFinding:
    """Build a DeepFinding with sensible defaults."""
    defaults = {
        "source": source,
        "category": category,
        "severity": severity,
        "title": "Test finding",
        "description": "Test description",
        "confidence": 0.9,
        "scanner_name": scanner_name,
    }
    defaults.update(kwargs)
    return DeepFinding(**defaults)


def _make_dast_finding(
    category: FindingCategory = FindingCategory.IDOR,
    severity: SeverityLevel = SeverityLevel.HIGH,
    **kwargs,
) -> DeepFinding:
    return _make_finding(
        source=FindingSource.DAST_URL,
        category=category,
        severity=severity,
        scanner_name="dast_scanner",
        evidence="DAST evidence",
        **kwargs,
    )


def _make_sast_finding(
    category: FindingCategory = FindingCategory.IDOR,
    severity: SeverityLevel = SeverityLevel.MEDIUM,
    **kwargs,
) -> DeepFinding:
    return _make_finding(
        source=FindingSource.SAST_CODE,
        category=category,
        severity=severity,
        scanner_name="sast_scanner",
        code_location=CodeLocation(file_path="src/api/route.ts", line_number=42),
        **kwargs,
    )


def _make_mock_agent(
    snapshot=None,
    endpoints=None,
    dast_scanners=None,
    sast_scanners=None,
    **extra_scanners,
) -> DeepSecurityScanAgent:
    """Create a DeepSecurityScanAgent with mocked dependencies."""
    ingestion = AsyncMock()
    if snapshot is not None:
        ingestion.ingest.return_value = snapshot
    else:
        # Build a minimal snapshot mock
        mock_snapshot = MagicMock()
        mock_snapshot.all_js_content = "const api = '/api/users'"
        mock_snapshot.html_content = "<html></html>"
        mock_snapshot.assets = []
        ingestion.ingest.return_value = mock_snapshot

    endpoint_scanner = AsyncMock()
    endpoint_scanner.discover.return_value = endpoints or []

    return DeepSecurityScanAgent(
        ingestion_service=ingestion,
        endpoint_scanner=endpoint_scanner,
        dast_scanners=dast_scanners or [],
        sast_scanners=sast_scanners or [],
        **extra_scanners,
    )


async def _collect_events(gen) -> list[DeepScanEvent]:
    """Collect all events from an async generator."""
    events = []
    async for event in gen:
        events.append(event)
    return events


# ===========================================================================
# TestDeepSecurityScanAgent
# ===========================================================================

class TestDeepSecurityScanAgent:
    """Tests for the unified orchestrator."""

    def test_detect_scan_mode_url_only(self) -> None:
        """URL without credentials -> URL_ONLY mode."""
        agent = _make_mock_agent()
        mode = agent._detect_scan_mode("https://example.com", None, None)
        assert mode == ScanMode.URL_ONLY

    def test_detect_scan_mode_authenticated(self) -> None:
        """URL + credentials -> AUTHENTICATED mode."""
        agent = _make_mock_agent()
        creds = MagicMock()
        mode = agent._detect_scan_mode("https://example.com", None, creds)
        assert mode == ScanMode.AUTHENTICATED

    def test_detect_scan_mode_code_only(self) -> None:
        """Repo only -> CODE_ONLY mode."""
        agent = _make_mock_agent()
        mode = agent._detect_scan_mode(None, "https://github.com/org/repo", None)
        assert mode == ScanMode.CODE_ONLY

    def test_detect_scan_mode_full(self) -> None:
        """URL + repo -> FULL mode."""
        agent = _make_mock_agent()
        mode = agent._detect_scan_mode(
            "https://example.com", "https://github.com/org/repo", None,
        )
        assert mode == ScanMode.FULL

    @pytest.mark.asyncio
    async def test_url_only_scan_runs_ingestion_and_discovery(self) -> None:
        """URL_ONLY scan should ingest URL and discover endpoints."""
        agent = _make_mock_agent()
        events = await _collect_events(agent.scan(target_url="https://example.com"))

        phases = [e.phase for e in events]
        assert DeepScanPhase.INGESTING_URL in phases
        assert DeepScanPhase.DISCOVERING_ENDPOINTS in phases
        assert DeepScanPhase.COMPLETE in phases

    @pytest.mark.asyncio
    async def test_url_only_scan_returns_report(self) -> None:
        """Final event should contain a report dict."""
        agent = _make_mock_agent()
        events = await _collect_events(agent.scan(target_url="https://example.com"))

        final = events[-1]
        assert final.phase == DeepScanPhase.COMPLETE
        assert "report" in final.data

    @pytest.mark.asyncio
    async def test_ingestion_failure_stops_scan(self) -> None:
        """If URL ingestion fails, scan should yield COMPLETE with error."""
        ingestion = AsyncMock()
        ingestion.ingest.return_value = None

        agent = DeepSecurityScanAgent(
            ingestion_service=ingestion,
            endpoint_scanner=AsyncMock(),
        )
        events = await _collect_events(agent.scan(target_url="https://bad.com"))

        final = events[-1]
        assert final.phase == DeepScanPhase.COMPLETE
        assert final.data.get("error") is True

    @pytest.mark.asyncio
    async def test_dast_scanners_run_in_parallel(self) -> None:
        """DAST scanners should be invoked when endpoints exist."""
        mock_snapshot = MagicMock()
        mock_snapshot.all_js_content = "js"
        mock_snapshot.html_content = "<html></html>"
        mock_snapshot.assets = ["a.js"]

        ep = DiscoveredEndpoint(url="https://example.com/api/users")

        xss = AsyncMock()
        xss.scanner_name = "xss_scanner"
        xss.scan.return_value = [
            _make_dast_finding(category=FindingCategory.INJECTION_RISK),
        ]

        agent = _make_mock_agent(
            snapshot=mock_snapshot,
            endpoints=[ep],
            dast_scanners=[xss],
        )
        events = await _collect_events(agent.scan(target_url="https://example.com"))

        final = events[-1]
        report = final.data["report"]
        assert "xss_scanner" in report["scanners_run"]
        assert len(report["findings"]) >= 1

    @pytest.mark.asyncio
    async def test_dom_xss_phase_runs_on_a_url_only_scan(self) -> None:
        """The DOM XSS phase must still execute, browser or not.

        Also guards ``stub_networked_scanners``: a stub that skipped the phase
        instead of standing in for it would make these tests fast and wrong.
        """
        agent = _make_mock_agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/api/users")],
        )
        events = await _collect_events(agent.scan(target_url="https://example.com"))

        report = events[-1].data["report"]
        assert DOMXSSScanner.SCANNER_NAME in report["scanners_run"]

    @pytest.mark.asyncio
    async def test_sast_scanners_run_for_code_only(self) -> None:
        """CODE_ONLY mode should run SAST scanners when repo snapshot available."""
        from isitsecure.engine.code_analysis.models import CodeFinding

        mock_repo = MagicMock(branch="main", commit_hash="abc123")
        mock_code_finding = CodeFinding(
            scanner_name="route_auth",
            severity=SeverityLevel.HIGH,
            category=FindingCategory.AUTH_WEAKNESS,
            title="Missing auth",
            description="Route has no auth check",
            file_path="src/app/api/route.ts",
            line_number=10,
            confidence=0.85,
        )

        route_analyzer = AsyncMock()
        route_analyzer.scanner_name = "route_auth"
        route_analyzer.scan.return_value = [mock_code_finding]

        repo_ingestion = AsyncMock()
        repo_ingestion.ingest.return_value = mock_repo

        agent = _make_mock_agent(
            sast_scanners=[route_analyzer],
            repo_ingestion_service=repo_ingestion,
        )
        events = await _collect_events(
            agent.scan(repo_url="https://github.com/org/repo", scan_mode=ScanMode.CODE_ONLY),
        )

        phases = [e.phase for e in events]
        assert DeepScanPhase.CODE_INGESTION in phases
        assert DeepScanPhase.SAST_SCANNING in phases

        final = events[-1]
        report = final.data["report"]
        assert "route_auth" in report["scanners_run"]
        assert len(report["findings"]) == 1
        assert report["findings"][0]["source"] == FindingSource.SAST_CODE.value

    @pytest.mark.asyncio
    async def test_cross_referencing_runs_in_full_mode(self) -> None:
        """FULL mode with cross_referencer should produce cross-ref findings."""
        from isitsecure.engine.code_analysis.models import CodeFinding

        mock_snapshot = MagicMock()
        mock_snapshot.all_js_content = "js"
        mock_snapshot.html_content = "<html></html>"
        mock_snapshot.assets = ["a.js"]

        ep = DiscoveredEndpoint(url="https://example.com/api/users")

        # DAST scanner that finds IDOR
        xss = AsyncMock()
        xss.scanner_name = "xss_scanner"
        xss.scan.return_value = [
            _make_dast_finding(category=FindingCategory.IDOR),
        ]

        # SAST scanner that finds IDOR
        mock_code_finding = CodeFinding(
            scanner_name="route_auth",
            severity=SeverityLevel.MEDIUM,
            category=FindingCategory.IDOR,
            title="IDOR in route",
            description="Route missing ownership check",
            file_path="src/api/route.ts",
            line_number=10,
            confidence=0.85,
        )
        route_analyzer = AsyncMock()
        route_analyzer.scanner_name = "route_auth"
        route_analyzer.scan.return_value = [mock_code_finding]

        mock_repo = MagicMock(branch="main", commit_hash="abc123")
        repo_ingestion = AsyncMock()
        repo_ingestion.ingest.return_value = mock_repo

        agent = _make_mock_agent(
            snapshot=mock_snapshot,
            endpoints=[ep],
            dast_scanners=[xss],
            sast_scanners=[route_analyzer],
            repo_ingestion_service=repo_ingestion,
            cross_referencer=FindingCrossReferencer(),
        )
        events = await _collect_events(
            agent.scan(
                target_url="https://example.com",
                repo_url="https://github.com/org/repo",
                scan_mode=ScanMode.FULL,
            ),
        )

        phases = [e.phase for e in events]
        assert DeepScanPhase.CROSS_REFERENCING in phases

        final = events[-1]
        report = final.data["report"]
        cross_ref = [
            f for f in report["findings"]
            if f["source"] == FindingSource.CROSS_REFERENCED.value
        ]
        assert len(cross_ref) == 1

    def test_code_finding_to_deep_finding(self) -> None:
        """CodeFinding should convert to DeepFinding with correct fields."""
        from isitsecure.engine.code_analysis.models import CodeFinding

        cf = CodeFinding(
            scanner_name="secret_scanner",
            severity=SeverityLevel.CRITICAL,
            category=FindingCategory.EXPOSED_SECRETS,
            title="Hardcoded API key",
            description="Found API key in source",
            file_path="src/config.ts",
            line_number=5,
            line_end=5,
            code_snippet="const key = 'sk-...'",
            confidence=0.95,
            github_url="https://github.com/org/repo/blob/main/src/config.ts#L5",
        )

        df = DeepSecurityScanAgent._code_finding_to_deep_finding(cf)

        assert df.source == FindingSource.SAST_CODE
        assert df.category == FindingCategory.EXPOSED_SECRETS
        assert df.severity == SeverityLevel.CRITICAL
        assert df.scanner_name == "secret_scanner"
        assert df.code_location is not None
        assert df.code_location.file_path == "src/config.ts"
        assert df.code_location.line_number == 5

    def test_deep_scan_event_to_dict(self) -> None:
        """DeepScanEvent.to_dict should include phase, message, progress."""
        event = DeepScanEvent(
            phase=DeepScanPhase.DAST_SCANNING,
            message="Running scanners",
            progress=50,
            data={"extra": "info"},
        )
        d = event.to_dict()
        assert d["phase"] == DeepScanPhase.DAST_SCANNING.value
        assert d["message"] == "Running scanners"
        assert d["progress"] == 50
        assert d["extra"] == "info"


# ===========================================================================
# TestFindingCrossReferencer
# ===========================================================================

class TestFindingCrossReferencer:
    """Tests for DAST <-> SAST cross-referencing logic."""

    def test_cross_references_idor(self) -> None:
        """DAST IDOR + SAST IDOR -> cross-referenced finding."""
        xref = FindingCrossReferencer()
        dast = [_make_dast_finding(category=FindingCategory.IDOR)]
        sast = [_make_sast_finding(category=FindingCategory.IDOR)]

        results = xref.cross_reference(dast, sast)

        assert len(results) == 1
        assert results[0].source == FindingSource.CROSS_REFERENCED
        assert results[0].category == FindingCategory.IDOR
        assert results[0].confidence == CrossRefConfig.CONFIDENCE_CROSS_REF
        assert results[0].scanner_name == CrossRefConfig.SCANNER_NAME
        assert len(results[0].related_finding_ids) == 2

    def test_cross_references_rls(self) -> None:
        """DAST RLS + SAST RLS -> cross-referenced."""
        xref = FindingCrossReferencer()
        dast = [_make_dast_finding(category=FindingCategory.RLS_MISCONFIGURATION)]
        sast = [_make_sast_finding(category=FindingCategory.RLS_MISCONFIGURATION)]

        results = xref.cross_reference(dast, sast)

        assert len(results) == 1
        assert results[0].category == FindingCategory.RLS_MISCONFIGURATION

    def test_cross_references_secrets(self) -> None:
        """DAST secret + SAST secret -> cross-referenced."""
        xref = FindingCrossReferencer()
        dast = [_make_dast_finding(category=FindingCategory.EXPOSED_SECRETS)]
        sast = [_make_sast_finding(category=FindingCategory.EXPOSED_SECRETS)]

        results = xref.cross_reference(dast, sast)

        assert len(results) == 1
        assert results[0].category == FindingCategory.EXPOSED_SECRETS

    def test_cross_references_injection(self) -> None:
        """DAST injection + SAST injection -> cross-referenced."""
        xref = FindingCrossReferencer()
        dast = [_make_dast_finding(category=FindingCategory.INJECTION_RISK)]
        sast = [_make_sast_finding(category=FindingCategory.INJECTION_RISK)]

        results = xref.cross_reference(dast, sast)

        assert len(results) == 1
        assert results[0].category == FindingCategory.INJECTION_RISK

    def test_cross_references_idor_auth_weakness(self) -> None:
        """DAST IDOR + SAST AUTH_WEAKNESS -> cross-referenced."""
        xref = FindingCrossReferencer()
        dast = [_make_dast_finding(category=FindingCategory.IDOR)]
        sast = [_make_sast_finding(category=FindingCategory.AUTH_WEAKNESS)]

        results = xref.cross_reference(dast, sast)

        assert len(results) == 1
        assert "missing auth" in results[0].title.lower()

    def test_no_cross_ref_unrelated(self) -> None:
        """Different, non-paired categories -> no cross-reference."""
        xref = FindingCrossReferencer()
        dast = [_make_dast_finding(category=FindingCategory.MISSING_HEADERS)]
        sast = [_make_sast_finding(category=FindingCategory.DEPENDENCY_VULNERABILITY)]

        results = xref.cross_reference(dast, sast)

        assert len(results) == 0

    def test_boost_severity(self) -> None:
        """Cross-ref should boost severity by one level."""
        xref = FindingCrossReferencer()
        dast = [_make_dast_finding(
            category=FindingCategory.IDOR,
            severity=SeverityLevel.MEDIUM,
        )]
        sast = [_make_sast_finding(
            category=FindingCategory.IDOR,
            severity=SeverityLevel.HIGH,
        )]

        results = xref.cross_reference(dast, sast)

        assert len(results) == 1
        # HIGH (rank 3) boosted by 1 -> CRITICAL (rank 4)
        assert results[0].severity == SeverityLevel.CRITICAL

    def test_boost_severity_caps_at_critical(self) -> None:
        """Boosting CRITICAL should remain CRITICAL (not overflow)."""
        xref = FindingCrossReferencer()
        dast = [_make_dast_finding(
            category=FindingCategory.IDOR,
            severity=SeverityLevel.CRITICAL,
        )]
        sast = [_make_sast_finding(
            category=FindingCategory.IDOR,
            severity=SeverityLevel.CRITICAL,
        )]

        results = xref.cross_reference(dast, sast)

        assert len(results) == 1
        assert results[0].severity == SeverityLevel.CRITICAL

    def test_empty_inputs(self) -> None:
        """Empty finding lists -> no cross-references."""
        xref = FindingCrossReferencer()

        assert xref.cross_reference([], []) == []
        assert xref.cross_reference([_make_dast_finding()], []) == []
        assert xref.cross_reference([], [_make_sast_finding()]) == []

    def test_sast_not_double_matched(self) -> None:
        """Each SAST finding should only match one DAST finding."""
        xref = FindingCrossReferencer()
        dast = [
            _make_dast_finding(category=FindingCategory.IDOR, title="IDOR A"),
            _make_dast_finding(category=FindingCategory.IDOR, title="IDOR B"),
        ]
        sast = [_make_sast_finding(category=FindingCategory.IDOR)]

        results = xref.cross_reference(dast, sast)

        # Only 1 SAST finding, so at most 1 cross-ref
        assert len(results) == 1
        # The first DAST finding should have matched
        assert dast[0].id in results[0].related_finding_ids
        assert sast[0].id in results[0].related_finding_ids

    def test_multiple_pairs_matched(self) -> None:
        """Multiple distinct pairs should each produce a cross-ref."""
        xref = FindingCrossReferencer()
        dast = [
            _make_dast_finding(category=FindingCategory.IDOR),
            _make_dast_finding(category=FindingCategory.EXPOSED_SECRETS),
        ]
        sast = [
            _make_sast_finding(category=FindingCategory.IDOR),
            _make_sast_finding(category=FindingCategory.EXPOSED_SECRETS),
        ]

        results = xref.cross_reference(dast, sast)

        assert len(results) == 2
        categories = {r.category for r in results}
        assert FindingCategory.IDOR in categories
        assert FindingCategory.EXPOSED_SECRETS in categories

    def test_cross_ref_preserves_endpoint_and_code_location(self) -> None:
        """Cross-referenced finding should carry DAST endpoint + SAST code location."""
        xref = FindingCrossReferencer()
        dast = [_make_dast_finding(
            category=FindingCategory.IDOR,
            endpoint_url="https://example.com/api/users/1",
        )]
        sast = [_make_sast_finding(category=FindingCategory.IDOR)]

        results = xref.cross_reference(dast, sast)

        assert results[0].endpoint_url == "https://example.com/api/users/1"
        assert results[0].code_location is not None
        assert results[0].code_location.file_path == "src/api/route.ts"

    def test_cross_ref_description_includes_titles(self) -> None:
        """Description should reference both DAST and SAST finding titles."""
        xref = FindingCrossReferencer()
        dast = [_make_dast_finding(
            category=FindingCategory.IDOR,
            title="IDOR on /api/users",
        )]
        sast = [_make_sast_finding(
            category=FindingCategory.IDOR,
            title="Missing ownership check in route",
        )]

        results = xref.cross_reference(dast, sast)

        assert "IDOR on /api/users" in results[0].description
        assert "Missing ownership check in route" in results[0].description


# ===========================================================================
# TestSeverityOrder
# ===========================================================================

class TestSeverityOrder:
    """Tests for the severity ranking helper."""

    def test_rank_order(self) -> None:
        assert _SeverityOrder.rank(SeverityLevel.INFO) == 0
        assert _SeverityOrder.rank(SeverityLevel.LOW) == 1
        assert _SeverityOrder.rank(SeverityLevel.MEDIUM) == 2
        assert _SeverityOrder.rank(SeverityLevel.HIGH) == 3
        assert _SeverityOrder.rank(SeverityLevel.CRITICAL) == 4

    def test_from_rank_clamps(self) -> None:
        assert _SeverityOrder.from_rank(-1) == SeverityLevel.INFO
        assert _SeverityOrder.from_rank(99) == SeverityLevel.CRITICAL

    def test_boosted_medium_high(self) -> None:
        result = _SeverityOrder.boosted(SeverityLevel.MEDIUM, SeverityLevel.HIGH)
        assert result == SeverityLevel.CRITICAL

    def test_boosted_info_info(self) -> None:
        result = _SeverityOrder.boosted(SeverityLevel.INFO, SeverityLevel.INFO)
        assert result == SeverityLevel.LOW


# ===========================================================================
# #147 — a repo we couldn't read must not read as a clean scan
# ===========================================================================

class TestRepoIngestionFailures:
    """A failed clone used to log an error and return a zero-finding report,
    which in CI is indistinguishable from "your code is fine"."""

    @pytest.mark.asyncio
    async def test_branch_is_passed_to_the_ingestion_service(self) -> None:
        repo_ingestion = AsyncMock()
        repo_ingestion.ingest.return_value = MagicMock(
            branch="release", commit_hash="abc123",
        )
        agent = _make_mock_agent(repo_ingestion_service=repo_ingestion)

        await _collect_events(agent.scan(
            repo_url="https://github.com/org/repo",
            scan_mode=ScanMode.CODE_ONLY,
            repo_branch="release",
        ))

        assert repo_ingestion.ingest.await_args.kwargs["branch"] == "release"

    @pytest.mark.asyncio
    async def test_no_branch_requested_stays_none(self) -> None:
        """None must reach the service so it can use the remote's default —
        substituting 'main' here is the bug."""
        repo_ingestion = AsyncMock()
        repo_ingestion.ingest.return_value = MagicMock(
            branch="master", commit_hash="abc123",
        )
        agent = _make_mock_agent(repo_ingestion_service=repo_ingestion)

        await _collect_events(agent.scan(
            repo_url="https://github.com/org/repo", scan_mode=ScanMode.CODE_ONLY,
        ))

        assert repo_ingestion.ingest.await_args.kwargs["branch"] is None

    @pytest.mark.asyncio
    async def test_code_only_failure_ends_the_scan_with_an_error(self) -> None:
        repo_ingestion = AsyncMock()
        repo_ingestion.ingest.side_effect = RuntimeError(
            "Branch 'nope' not found in repository"
        )
        agent = _make_mock_agent(repo_ingestion_service=repo_ingestion)

        events = await _collect_events(agent.scan(
            repo_url="https://github.com/org/repo", scan_mode=ScanMode.CODE_ONLY,
        ))

        final = events[-1]
        assert final.phase == DeepScanPhase.COMPLETE
        assert final.data.get("error") is True
        # No report at all — better than a clean-looking empty one.
        assert "report" not in final.data
        assert "nope" in final.message

    @pytest.mark.asyncio
    async def test_full_scan_keeps_dast_findings_but_records_the_failure(
        self,
    ) -> None:
        """The live-site half is still real, so don't throw it away — but the
        report has to admit the code was never scanned."""
        repo_ingestion = AsyncMock()
        repo_ingestion.ingest.side_effect = RuntimeError("Repository not found")

        xss = AsyncMock()
        xss.scanner_name = "xss"
        xss.scan.return_value = [_make_dast_finding()]

        agent = _make_mock_agent(
            endpoints=[DiscoveredEndpoint(url="https://example.com/api/users")],
            dast_scanners=[xss],
            repo_ingestion_service=repo_ingestion,
        )
        events = await _collect_events(agent.scan(
            target_url="https://example.com",
            repo_url="https://github.com/org/repo",
            scan_mode=ScanMode.FULL,
        ))

        report = events[-1].data["report"]
        assert report["ingestion_errors"] == ["Repository not found"]
        assert len(report["findings"]) == 1  # the DAST half survived

    @pytest.mark.asyncio
    async def test_successful_scan_records_no_ingestion_errors(self) -> None:
        repo_ingestion = AsyncMock()
        repo_ingestion.ingest.return_value = MagicMock(
            branch="main", commit_hash="abc123",
        )
        agent = _make_mock_agent(repo_ingestion_service=repo_ingestion)

        events = await _collect_events(agent.scan(
            repo_url="https://github.com/org/repo", scan_mode=ScanMode.CODE_ONLY,
        ))

        assert events[-1].data["report"]["ingestion_errors"] == []
