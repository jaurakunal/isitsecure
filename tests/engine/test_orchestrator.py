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
