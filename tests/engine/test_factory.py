"""Tests for the DeepSecurityScanAgent factory."""

from __future__ import annotations

from unittest.mock import MagicMock

from isitsecure.engine.agent import DeepSecurityScanAgent
from isitsecure.engine.cross_referencer import FindingCrossReferencer
from isitsecure.engine.factory import (
    create_deep_security_scan_agent,
    create_repo_ingestion_service,
)
from isitsecure.engine.scanners.endpoint_discovery import (
    EndpointDiscoveryScanner,
)
from isitsecure.engine.scanners.protocols import DASTScannerProtocol

# DAST scanner counts. QUICK (default) runs the fast set; DEEP adds 4 slow /
# aggressive scanners (XSS, rate-limit, auth-bypass, password-reset).
EXPECTED_DAST_SCANNER_COUNT_QUICK = 15
EXPECTED_DAST_SCANNER_COUNT_DEEP = 19
# Expected SAST scanner count based on factory.py sast_scanners list (without LLM)
EXPECTED_SAST_SCANNER_COUNT = 17


class TestFactory:
    """Tests for create_deep_security_scan_agent factory function."""

    def test_creates_agent(self):
        """Factory should return a DeepSecurityScanAgent instance."""
        agent = create_deep_security_scan_agent()
        assert isinstance(agent, DeepSecurityScanAgent)

    def test_creates_without_llm(self):
        """Should work without an LLM client; LLM reviewer should be None."""
        agent = create_deep_security_scan_agent(llm_client=None)
        assert agent._llm_code_reviewer is None

    def test_creates_with_mock_llm(self):
        """Should wire LLM reviewer when a client is provided."""
        mock_llm = MagicMock()
        agent = create_deep_security_scan_agent(llm_client=mock_llm)
        assert agent._llm_code_reviewer is not None

    def test_all_dast_scanners_wired(self):
        """QUICK depth (default) wires the fast DAST scanner set."""
        agent = create_deep_security_scan_agent()
        assert len(agent._dast_scanners) == EXPECTED_DAST_SCANNER_COUNT_QUICK
        for scanner in agent._dast_scanners:
            assert isinstance(scanner, DASTScannerProtocol)

    def test_deep_depth_adds_aggressive_scanners(self):
        """DEEP depth adds the slow/aggressive scanners."""
        from isitsecure.engine.enums import ScanDepth
        quick = create_deep_security_scan_agent(depth=ScanDepth.QUICK)
        deep = create_deep_security_scan_agent(depth=ScanDepth.DEEP)
        assert len(quick._dast_scanners) == EXPECTED_DAST_SCANNER_COUNT_QUICK
        assert len(deep._dast_scanners) == EXPECTED_DAST_SCANNER_COUNT_DEEP
        deep_names = {s.scanner_name for s in deep._dast_scanners}
        quick_names = {s.scanner_name for s in quick._dast_scanners}
        # XSS is deep-only; injection is present in both.
        assert "xss_scanner" in deep_names
        assert "xss_scanner" not in quick_names
        assert any("injection" in n for n in quick_names)

    def test_quick_injection_has_time_based_disabled(self):
        """QUICK depth builds the injection scanner with time-based SQLi off."""
        from isitsecure.engine.enums import ScanDepth
        quick = create_deep_security_scan_agent(depth=ScanDepth.QUICK)
        deep = create_deep_security_scan_agent(depth=ScanDepth.DEEP)
        q_inj = next(s for s in quick._dast_scanners if "injection" in s.scanner_name)
        d_inj = next(s for s in deep._dast_scanners if "injection" in s.scanner_name)
        assert q_inj._time_based is False
        assert d_inj._time_based is True

    def test_all_sast_scanners_wired(self):
        """All SAST scanners in the list should be present."""
        agent = create_deep_security_scan_agent()
        assert len(agent._sast_scanners) == EXPECTED_SAST_SCANNER_COUNT

    def test_special_scanners_wired(self):
        """Special scanners (non-standard signatures) should be present."""
        agent = create_deep_security_scan_agent()
        assert agent._idor_scanner is not None
        assert agent._jwt_scanner is not None
        assert agent._rls_deep_scanner is not None
        assert agent._privilege_escalation_scanner is not None

    def test_cross_referencer_wired(self):
        """Cross-referencer should be present."""
        agent = create_deep_security_scan_agent()
        assert agent._cross_referencer is not None
        assert isinstance(agent._cross_referencer, FindingCrossReferencer)

    def test_endpoint_scanner_wired(self):
        """EndpointDiscoveryScanner should be present."""
        agent = create_deep_security_scan_agent()
        assert agent._endpoint_scanner is not None
        assert isinstance(agent._endpoint_scanner, EndpointDiscoveryScanner)

    def test_ingestion_service_wired(self):
        """URLIngestionService should be present."""
        agent = create_deep_security_scan_agent()
        assert agent._ingestion is not None

    def test_new_sast_scanners_present(self):
        """All new SAST scanners (Phases 3-7) should be in the list."""
        agent = create_deep_security_scan_agent()
        scanner_names = [s.scanner_name for s in agent._sast_scanners]
        assert "express_middleware_analyzer" in scanner_names
        assert "drizzle_schema_analyzer" in scanner_names
        assert "iac_scanner" in scanner_names
        assert "docker_scanner" in scanner_names
        assert "shell_script_scanner" in scanner_names


class TestRepoIngestionFactory:
    """Tests for create_repo_ingestion_service factory function."""

    def test_creates_service(self):
        """Factory should return a RepoIngestionService."""
        from isitsecure.engine.code_analysis.repo_ingestion import (
            RepoIngestionService,
        )
        svc = create_repo_ingestion_service()
        assert isinstance(svc, RepoIngestionService)

    def test_has_workspace_detector(self):
        """Should have a WorkspaceDetector wired."""
        svc = create_repo_ingestion_service()
        assert svc._workspace_detector is not None

    def test_has_seven_route_mappers(self):
        """Should have NextJS + Express + tRPC + GraphQL + Django + FastAPI + Spring route mappers."""
        svc = create_repo_ingestion_service()
        assert len(svc._route_mappers) == 7

    def test_route_mapper_types(self):
        """Route mappers should be the expected types."""
        from isitsecure.engine.code_analysis.express_route_mapper import (
            ExpressRouteMapper,
        )
        from isitsecure.engine.code_analysis.route_mapper import (
            NextJSRouteMapper,
        )
        from isitsecure.engine.code_analysis.trpc_route_mapper import (
            TRPCRouteMapper,
        )
        svc = create_repo_ingestion_service()
        types = [type(m) for m in svc._route_mappers]
        assert NextJSRouteMapper in types
        assert ExpressRouteMapper in types
        assert TRPCRouteMapper in types
