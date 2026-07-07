"""Deep Security Scan Agent — orchestrates all DAST + SAST scanning.

This agent takes a target URL and/or a repository URL and runs up to 23
scanners in parallel, producing a unified DeepScanReport.  Backward
compatible: calling ``scan(target_url)`` still works as before.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import TYPE_CHECKING, AsyncGenerator
from urllib.parse import urlparse

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.constants import (
    GuidedDASTConfig,
    LLMBusinessLogicConfig,
    OrchestratorConfig,
    SharedPatterns,
)
from isitsecure.engine.cross_referencer import FindingCrossReferencer
from isitsecure.engine.enums import DeepScanPhase, ScanMode
from isitsecure.engine.models import (
    AuthenticatedCrawlResult,
    CodeLocation,
    DeepFinding,
    DeepScanReport,
    DiscoveredEndpoint,
    FindingSource,
    ScanTokenUsage,
)
from isitsecure.engine.shared.scanner_runner import (
    ScannerTimeouts,
    run_scanner_safe,
)
from isitsecure.engine.enums import SeverityLevel

if TYPE_CHECKING:
    from isitsecure.engine.guided_dast.runner import SASTGuidedDASTRunner
    from isitsecure.engine.auth.protocols import (
        AuthCredentials,
        AuthProviderProtocol,
        AuthSession,
    )
    from isitsecure.engine.code_analysis.lsp.protocols import (
        AuthFlowResult,
        LSPClientProtocol,
    )
    from isitsecure.engine.code_analysis.protocols import (
        CodeScannerProtocol,
        RepoSnapshot,
    )
    from isitsecure.engine.scanners.endpoint_discovery import (
        EndpointDiscoveryScanner,
    )
    from isitsecure.engine.scanners.idor_scanner import IDORScanner
    from isitsecure.engine.scanners.protocols import DASTScannerProtocol
    from isitsecure.engine.shared.oob_callback import OOBCallbackService
    from isitsecure.engine.ingestion.url_ingestion import URLIngestionService
    from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-scanner timeout mappings (scanner_name -> seconds).
# Scanners not listed here use ScannerTimeouts.DEFAULT_SECONDS.
# ---------------------------------------------------------------------------

_DAST_TIMEOUT_MAP: dict[str, float] = {
    "xss_scanner": ScannerTimeouts.XSS_ACTIVE_SECONDS,
    "active_injection_scanner": ScannerTimeouts.INJECTION_ACTIVE_SECONDS,
    "auth_bypass_scanner": ScannerTimeouts.AUTH_BYPASS_SECONDS,
    "rate_limit_scanner": ScannerTimeouts.RATE_LIMIT_SECONDS,
    "http_probe_scanner": ScannerTimeouts.HTTP_PROBE_SECONDS,
}

_SAST_TIMEOUT_MAP: dict[str, float] = {
    "secret_scanner": ScannerTimeouts.GIT_SECRET_SCAN_SECONDS,
}


# ---------------------------------------------------------------------------
# Event container
# ---------------------------------------------------------------------------

class DeepScanEvent:
    """Event yielded during scan for progress tracking."""

    def __init__(
        self,
        phase: DeepScanPhase,
        message: str,
        progress: int = 0,
        data: dict | None = None,
    ) -> None:
        self.phase = phase
        self.message = message
        self.progress = progress
        self.data = data or {}

    def to_dict(self) -> dict:
        return {
            "phase": self.phase.value,
            "message": self.message,
            "progress": self.progress,
            **self.data,
        }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class DeepSecurityScanAgent:
    """Unified orchestrator for all deep security scanning.

    Scan modes:
    - URL_ONLY:      Unauthenticated DAST only (existing behaviour)
    - AUTHENTICATED: DAST with credentials (cross-user IDOR, RLS deep testing)
    - CODE_ONLY:     SAST only (GitHub repo scanning)
    - FULL:          DAST + SAST + authenticated + cross-referencing

    Dependencies injected via constructor (DIP).
    """

    # ------------------------------------------------------------------
    # Constructor — every scanner is optional except ingestion + discovery
    # ------------------------------------------------------------------

    def __init__(
        self,
        # Required
        ingestion_service: URLIngestionService,
        endpoint_scanner: EndpointDiscoveryScanner,
        # Scanner lists (OCP — extend by adding to the list, not modifying code)
        dast_scanners: list[DASTScannerProtocol] | None = None,
        sast_scanners: list[CodeScannerProtocol] | None = None,
        # Special scanners with non-standard scan() signatures
        idor_scanner=None,
        authenticated_crawler_factory=None,
        rls_deep_scanner=None,
        privilege_escalation_scanner=None,
        jwt_scanner=None,
        # LLM reviewer (separate timeout / lifecycle)
        llm_code_reviewer=None,
        # Repo ingestion (optional)
        repo_ingestion_service=None,
        # Auth (optional)
        auth_provider: AuthProviderProtocol | None = None,
        # Cross-referencing (optional)
        cross_referencer: FindingCrossReferencer | None = None,
        # LSP client (optional — graceful degradation via NoOpLSPClient)
        lsp_client: LSPClientProtocol | None = None,
        # SAST-guided DAST (optional — targeted dynamic tests from code analysis)
        guided_dast_runner: SASTGuidedDASTRunner | None = None,
        # LLM triage (optional — enriches findings with priority/guidance)
        llm_triage=None,
        # Judgment LLM client (optional — faster/cheaper for result analysis)
        judgment_llm_client=None,
    ) -> None:
        # Required
        self._ingestion = ingestion_service
        self._endpoint_scanner = endpoint_scanner

        # Scanner registries (OCP)
        self._dast_scanners: list[DASTScannerProtocol] = dast_scanners or []
        self._sast_scanners: list[CodeScannerProtocol] = sast_scanners or []

        # Special scanners with non-standard scan() signatures
        self._idor_scanner = idor_scanner
        self._authenticated_crawler_factory = authenticated_crawler_factory
        self._rls_deep_scanner = rls_deep_scanner
        self._privilege_escalation_scanner = privilege_escalation_scanner
        self._jwt_scanner = jwt_scanner

        # LLM reviewer
        self._llm_code_reviewer = llm_code_reviewer

        # Repo
        self._repo_ingestion = repo_ingestion_service

        # Auth + cross-ref
        self._auth_provider = auth_provider
        self._cross_referencer = cross_referencer

        # LSP (optional — degrades gracefully)
        self._lsp_client = lsp_client

        # SAST-guided DAST (optional)
        self._guided_dast_runner = guided_dast_runner

        # LLM triage (optional)
        self._llm_triage = llm_triage

        # Judgment LLM (optional — for result analysis, falls back to primary)
        self._judgment_llm_client = judgment_llm_client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(
        self,
        target_url: str | None = None,
        repo_url: str | None = None,
        github_token: str | None = None,
        credentials_a: AuthCredentials | None = None,
        credentials_b: AuthCredentials | None = None,
        scan_mode: ScanMode | None = None,
    ) -> AsyncGenerator[DeepScanEvent, None]:
        """Run a full deep security scan.

        Auto-detects scan mode if not specified:
        - URL + credentials + repo -> FULL
        - URL + credentials       -> AUTHENTICATED
        - URL only                -> URL_ONLY
        - Repo only               -> CODE_ONLY
        """
        start_time = time.monotonic()
        mode = scan_mode or self._detect_scan_mode(target_url, repo_url, credentials_a)

        # Auto-upgrade: if credentials were provided but mode doesn't include auth
        if credentials_a and mode == ScanMode.URL_ONLY:
            mode = ScanMode.AUTHENTICATED
            logger.info("Auto-upgraded scan mode to AUTHENTICATED (credentials provided)")

        all_findings: list[DeepFinding] = []
        scanners_run: list[str] = []

        snapshot: CodebaseSnapshot | None = None
        repo_snapshot: RepoSnapshot | None = None
        endpoints: list[DiscoveredEndpoint] = []
        session_a: AuthSession | None = None
        session_b: AuthSession | None = None
        supabase_url: str | None = None
        anon_key: str | None = None
        tables: list[str] = []

        # ==============================================================
        # Phase 1: URL Ingestion
        # ==============================================================
        if target_url and mode in (ScanMode.URL_ONLY, ScanMode.AUTHENTICATED, ScanMode.FULL):
            yield DeepScanEvent(
                DeepScanPhase.INGESTING_URL,
                OrchestratorConfig.MSG_FETCHING_URL.format(url=target_url),
                OrchestratorConfig.PROGRESS_INGESTION,
            )
            snapshot = await self._ingest_url(target_url)
            if not snapshot:
                yield DeepScanEvent(
                    DeepScanPhase.COMPLETE,
                    OrchestratorConfig.MSG_INGESTION_FAILED.format(url=target_url),
                    data={"error": True},
                )
                return

            yield DeepScanEvent(
                DeepScanPhase.INGESTING_URL,
                OrchestratorConfig.MSG_FETCHED_ASSETS.format(
                    count=len(snapshot.assets),
                    js_size=len(snapshot.all_js_content),
                ),
                OrchestratorConfig.PROGRESS_INGESTION,
            )

        # ==============================================================
        # Phase 2: Endpoint Discovery
        # ==============================================================
        if snapshot:
            yield DeepScanEvent(
                DeepScanPhase.DISCOVERING_ENDPOINTS,
                OrchestratorConfig.MSG_DISCOVERING,
                OrchestratorConfig.PROGRESS_ENDPOINT_DISCOVERY,
            )
            endpoints = await self._endpoint_scanner.discover(
                js_content=snapshot.all_js_content,
                html_content=snapshot.html_content,
                base_url=target_url,
            )

            # Extract Supabase info from discovery results
            supabase_url, anon_key, tables = self._extract_supabase_info(
                endpoints, snapshot,
            )

            # Fallback: query Supabase schema directly if no tables found
            if supabase_url and anon_key and not tables:
                tables = await self._discover_supabase_tables(
                    supabase_url, anon_key,
                )

        # Build auth provider lazily once Supabase URL + anon key are known
        if (
            credentials_a
            and supabase_url
            and anon_key
            and not self._auth_provider
        ):
            self._auth_provider = self._build_auth_provider(
                supabase_url, anon_key,
            )
            logger.info("Built auth provider for %s", supabase_url)

        # ==============================================================
        # Phase 3: Authenticated Crawl (browser login + BFS discovery)
        # ==============================================================
        crawl_result = None
        if (
            credentials_a
            and target_url
            and mode in (ScanMode.AUTHENTICATED, ScanMode.FULL)
        ):
            yield DeepScanEvent(
                DeepScanPhase.AUTHENTICATING,
                OrchestratorConfig.MSG_AUTHENTICATING,
                OrchestratorConfig.PROGRESS_AUTH_AND_IDOR - 10,
            )

            crawl_result = await self._run_authenticated_crawl(
                credentials_a, target_url, endpoints,
            )

            if crawl_result and crawl_result.pages_visited > 0:
                # Merge crawled endpoints into main list
                existing_urls = {ep.url for ep in endpoints}
                new_count = 0
                for ep in crawl_result.discovered_endpoints:
                    if ep.url not in existing_urls:
                        endpoints.append(ep)
                        existing_urls.add(ep.url)
                        new_count += 1
                logger.info(
                    "Authenticated crawl added %d new endpoints (total: %d)",
                    new_count, len(endpoints),
                )

                # Merge Supabase tables
                for table in crawl_result.tables_discovered:
                    if table not in tables:
                        tables.append(table)

                # Build auth session from crawl tokens for downstream scanners
                auth_header = crawl_result.auth_headers.get(
                    SharedPatterns.HEADER_AUTHORIZATION
                )
                if auth_header:
                    token = auth_header.removeprefix(SharedPatterns.BEARER_PREFIX)
                    session_a = AuthSession(
                        user_id=(
                            credentials_a.email
                            or OrchestratorConfig.DEFAULT_CRAWL_USER_ID
                        ),
                        access_token=token,
                        headers=crawl_result.auth_headers,
                        user_email=credentials_a.email,
                        provider=credentials_a.provider,
                    )
                    logger.info(
                        "Extracted auth session from crawl (token=%s...)",
                        token[:20],
                    )

                    # Wire auth session into JWT scanner so it can test the token
                    if self._jwt_scanner:
                        self._jwt_scanner._auth_session = session_a

                yield DeepScanEvent(
                    DeepScanPhase.AUTHENTICATING,
                    OrchestratorConfig.MSG_CRAWL_SUMMARY.format(
                        pages=crawl_result.pages_visited,
                        endpoints=len(crawl_result.discovered_endpoints),
                        tables=len(crawl_result.tables_discovered),
                    ),
                )
            else:
                if crawl_result and crawl_result.errors:
                    msg = OrchestratorConfig.MSG_CRAWL_ERROR.format(
                        error=crawl_result.errors[0],
                    )
                else:
                    msg = OrchestratorConfig.MSG_CRAWL_NO_PAGES
                yield DeepScanEvent(
                    DeepScanPhase.AUTHENTICATING, msg,
                )

        # Supabase API auth fallback (if crawler didn't produce a session)
        if (
            not session_a
            and credentials_a
            and self._auth_provider
            and mode in (ScanMode.AUTHENTICATED, ScanMode.FULL)
        ):
            try:
                session_a = await self._auth_provider.authenticate(credentials_a)
                if credentials_b:
                    session_b = await self._auth_provider.authenticate(credentials_b)
            except Exception as e:
                logger.warning("Supabase API authentication failed: %s", e)
                yield DeepScanEvent(
                    DeepScanPhase.AUTHENTICATING,
                    OrchestratorConfig.MSG_AUTH_FAILED.format(error=str(e)),
                )

        # Generic REST login fallback (plain APIs, --auth-provider token).
        # Logs in both users directly against the API's login endpoint so
        # cross-user IDOR works without a Supabase project or a browser crawl.
        if (
            not session_a
            and credentials_a
            and target_url
            and mode in (ScanMode.AUTHENTICATED, ScanMode.FULL)
        ):
            from isitsecure.engine.enums import AuthProvider
            if credentials_a.provider == AuthProvider.TOKEN:
                try:
                    from isitsecure.engine.auth.rest_login_auth import (
                        RestLoginAuthProvider,
                    )
                    rest_auth = RestLoginAuthProvider(target_url)
                    session_a = await rest_auth.authenticate(credentials_a)
                    if credentials_b:
                        session_b = await rest_auth.authenticate(credentials_b)
                except Exception as e:
                    logger.warning("REST login failed: %s", e)

        # Wire auth session into JWT scanner (fallback path — API auth)
        if session_a and self._jwt_scanner and not self._jwt_scanner._auth_session:
            self._jwt_scanner._auth_session = session_a

        # Auth User B (always via API — crawler only handles User A)
        if (
            session_a
            and credentials_b
            and not session_b
            and self._auth_provider
        ):
            try:
                session_b = await self._auth_provider.authenticate(credentials_b)
            except Exception as e:
                logger.warning("User B authentication failed: %s", e)

        # ==============================================================
        # Phase 3.5: OOB Callback Registration (non-blocking)
        # ==============================================================
        oob_service = None
        if target_url and mode in (
            ScanMode.URL_ONLY, ScanMode.AUTHENTICATED, ScanMode.FULL,
        ):
            from isitsecure.engine.shared.oob_callback import (
                OOBCallbackService,
            )

            oob_service = OOBCallbackService()
            try:
                await asyncio.wait_for(
                    oob_service.register(),
                    timeout=ScannerTimeouts.OOB_POLL_SECONDS,
                )
            except (asyncio.TimeoutError, Exception) as e:
                logger.warning("OOB registration failed: %s", e)
                oob_service = None

            if oob_service and oob_service.is_registered:
                await self._inject_oob_payloads(oob_service, endpoints)

        # ==============================================================
        # Phase 4: DAST Scanners (parallel)
        # ==============================================================
        if endpoints and snapshot:
            yield DeepScanEvent(
                DeepScanPhase.DAST_SCANNING,
                OrchestratorConfig.MSG_DAST_RUNNING,
                OrchestratorConfig.PROGRESS_DAST_SCANNERS,
            )
            dast_findings, dast_names = await self._run_dast_scanners(endpoints, snapshot)
            all_findings.extend(dast_findings)
            scanners_run.extend(dast_names)

        # IDOR (unauthenticated — returns IDORTestResult + mutation DeepFindings)
        idor_results = []
        if self._idor_scanner and endpoints:
            try:
                idor_results, mutation_findings = await self._idor_scanner.scan(
                    endpoints
                )
                all_findings.extend(mutation_findings)
                # Convert confirmed read-access IDORs to findings
                read_idor_findings = self._idor_results_to_findings(idor_results)
                all_findings.extend(read_idor_findings)
            except Exception:
                logger.warning("IDOR scanner failed", exc_info=True)
                idor_results = []
            scanners_run.append("idor")

        # DOM XSS (unauthenticated — browser-based sink hooking on page URLs)
        # Only runs when there is no authenticated crawl (which runs its own DOM XSS)
        if (
            target_url
            and not crawl_result
            and mode in (ScanMode.URL_ONLY, ScanMode.FULL)
        ):
            from isitsecure.engine.scanners.dom_xss_scanner import (
                DOMXSSScanner,
            )
            page_urls = self._extract_page_urls(target_url, endpoints)
            if page_urls:
                dom_xss_scanner = DOMXSSScanner()
                dom_xss_findings = await run_scanner_safe(
                    DOMXSSScanner.SCANNER_NAME,
                    dom_xss_scanner.scan(pages_to_test=page_urls),
                    ScannerTimeouts.DOM_XSS_SECONDS,
                )
                all_findings.extend(dom_xss_findings)
                scanners_run.append(DOMXSSScanner.SCANNER_NAME)

        # ==============================================================
        # Phase 5: Authenticated DAST
        # ==============================================================
        if session_a and mode in (ScanMode.AUTHENTICATED, ScanMode.FULL):
            yield DeepScanEvent(
                DeepScanPhase.AUTHENTICATED_CRAWL,
                OrchestratorConfig.MSG_AUTH_SCANNING,
                OrchestratorConfig.PROGRESS_AUTH_AND_IDOR,
            )
            auth_findings, auth_names = await self._run_authenticated_scanners(
                session_a, session_b, endpoints, target_url,
                supabase_url, anon_key, tables, crawl_result,
                js_content=snapshot.all_js_content if snapshot else None,
            )
            all_findings.extend(auth_findings)
            scanners_run.extend(auth_names)

        # ==============================================================
        # Phase 5.5: Cross-probe analysis
        # ==============================================================
        if all_findings:
            from isitsecure.engine.shared.probe_analyzer import (
                ProbeAnalyzer,
            )

            try:
                analyzer = ProbeAnalyzer()
                analysis_findings = await asyncio.wait_for(
                    analyzer.analyze(all_findings),
                    timeout=ScannerTimeouts.PROBE_ANALYZER_SECONDS,
                )
                all_findings.extend(analysis_findings)
            except asyncio.TimeoutError:
                logger.warning(
                    "Probe analyzer timed out after %ds",
                    ScannerTimeouts.PROBE_ANALYZER_SECONDS,
                )
                analysis_findings = []
            except Exception as e:
                logger.warning("Probe analyzer failed: %s", e)
                analysis_findings = []
            if analysis_findings:
                scanners_run.append("probe_analyzer")

        # ==============================================================
        # Phase 5.6: OOB Callback Collection
        # ==============================================================
        if oob_service and oob_service.is_registered:
            try:
                await asyncio.wait_for(
                    oob_service.poll(),
                    timeout=ScannerTimeouts.OOB_POLL_SECONDS,
                )
                oob_findings = oob_service.get_findings()
                if oob_findings:
                    all_findings.extend(oob_findings)
                    scanners_run.append("oob_callback")
                    logger.info(
                        "OOB callback: %d blind vulnerabilities confirmed",
                        len(oob_findings),
                    )
            except (asyncio.TimeoutError, Exception) as e:
                logger.warning("OOB poll failed: %s", e)

        # ==============================================================
        # Phase 6: Repo Ingestion
        # ==============================================================
        if repo_url and mode in (ScanMode.CODE_ONLY, ScanMode.FULL):
            yield DeepScanEvent(
                DeepScanPhase.CODE_INGESTION,
                OrchestratorConfig.MSG_CLONING_REPO.format(repo_url=repo_url),
                OrchestratorConfig.PROGRESS_CODE_INGESTION,
            )
            repo_snapshot = await self._ingest_repo(repo_url, github_token)

        # ==============================================================
        # Phase 6.5: LSP Initialization (optional — graceful degradation)
        # ==============================================================
        lsp_initialized = False
        auth_flow_results: dict[str, AuthFlowResult] = {}
        if (
            repo_snapshot
            and self._lsp_client
            and mode in (ScanMode.CODE_ONLY, ScanMode.FULL)
        ):
            from isitsecure.engine.constants import LSPConfig

            if not self._lsp_client.is_available and not hasattr(self._lsp_client, '_process'):
                # NoOpLSPClient — LSP was disabled at factory level
                logger.info(LSPConfig.MSG_UNAVAILABLE)
            else:
                yield DeepScanEvent(
                    DeepScanPhase.LSP_INITIALIZATION,
                    LSPConfig.MSG_INIT,
                    OrchestratorConfig.PROGRESS_SAST_SCANNERS - 5,
                )
                import time as _time
                _lsp_start = _time.monotonic()
                try:
                    lsp_initialized = await asyncio.wait_for(
                        self._lsp_client.initialize(repo_snapshot.clone_path),
                        timeout=LSPConfig.INIT_TIMEOUT_SECONDS,
                    )
                    if lsp_initialized:
                        _lsp_duration = _time.monotonic() - _lsp_start
                        logger.info(
                            LSPConfig.MSG_INIT_SUCCESS.format(
                                duration=_lsp_duration
                            )
                        )
                    else:
                        logger.warning(
                            "LSP initialization returned False — "
                            "typescript-language-server may not be installed. "
                            "Falling back to regex-only analysis."
                        )
                except asyncio.TimeoutError:
                    logger.warning(
                        LSPConfig.MSG_INIT_FAILED.format(
                            error=f"Timed out after {LSPConfig.INIT_TIMEOUT_SECONDS}s"
                        )
                    )
                except Exception as e:
                    logger.warning(
                        LSPConfig.MSG_INIT_FAILED.format(error=str(e))
                    )

        # ==============================================================
        # Phase 7: SAST Scanners (parallel)
        # ==============================================================
        sast_code_findings: list[CodeFinding] = []
        if repo_snapshot and mode in (ScanMode.CODE_ONLY, ScanMode.FULL):
            yield DeepScanEvent(
                DeepScanPhase.SAST_SCANNING,
                OrchestratorConfig.MSG_SAST_RUNNING,
                OrchestratorConfig.PROGRESS_SAST_SCANNERS,
            )
            sast_findings, sast_names, sast_code_findings = (
                await self._run_sast_scanners(repo_snapshot)
            )
            all_findings.extend(sast_findings)
            scanners_run.extend(sast_names)

        # ==============================================================
        # Phase 7.5: LSP Validation (validate/suppress SAST findings)
        # ==============================================================
        if lsp_initialized and repo_snapshot and sast_code_findings:
            from isitsecure.engine.code_analysis.lsp.auth_flow_tracer import (
                AuthFlowTracer,
            )
            from isitsecure.engine.constants import LSPConfig

            yield DeepScanEvent(
                DeepScanPhase.LSP_VALIDATION,
                LSPConfig.MSG_TRACING.format(
                    count=len(repo_snapshot.route_map)
                ),
                OrchestratorConfig.PROGRESS_SAST_SCANNERS + 5,
            )

            try:
                tracer = AuthFlowTracer(self._lsp_client, repo_snapshot)
                auth_flow_results = await asyncio.wait_for(
                    tracer.trace_routes(repo_snapshot.route_map),
                    timeout=ScannerTimeouts.LSP_VALIDATION_SECONDS,
                )

                # Validate SAST findings with LSP results
                for scanner in self._sast_scanners:
                    if hasattr(scanner, "validate_with_lsp"):
                        sast_code_findings = scanner.validate_with_lsp(
                            sast_code_findings, auth_flow_results
                        )

                # Rebuild all_findings from validated sast_code_findings
                # (remove suppressed findings from the deep findings list)
                suppressed_ids = {
                    f.id for f in sast_code_findings if f.lsp_suppressed
                }
                all_findings = [
                    f for f in all_findings
                    if f.id not in suppressed_ids
                ]

                scanners_run.append("lsp_validator")

            except (asyncio.TimeoutError, Exception) as e:
                logger.warning("LSP validation failed: %s", e)

        # ==============================================================
        # Phase 8: LLM Review (with cross-scanner + LSP intelligence)
        # ==============================================================
        if repo_snapshot and self._llm_code_reviewer and mode in (ScanMode.CODE_ONLY, ScanMode.FULL):
            yield DeepScanEvent(
                DeepScanPhase.LLM_REVIEW,
                OrchestratorConfig.MSG_LLM_REVIEW,
                OrchestratorConfig.PROGRESS_LLM_REVIEW,
            )

            # Pass SAST findings to LLM reviewer for cross-scanner context
            if sast_code_findings:
                self._llm_code_reviewer.set_sast_context(sast_code_findings)

            # Pass LSP auth flow results for prompt enrichment
            if auth_flow_results:
                self._llm_code_reviewer.set_lsp_context(auth_flow_results)

            llm_code_findings = await run_scanner_safe(
                "llm_review",
                self._llm_code_reviewer.scan(repo_snapshot),
                ScannerTimeouts.LLM_CODE_REVIEW_SECONDS,
            )
            for cf in llm_code_findings:
                all_findings.append(self._code_finding_to_deep_finding(cf))
            scanners_run.append("llm_review")

        # ==============================================================
        # Phase 9: Cross-reference DAST <-> SAST
        # ==============================================================
        if mode == ScanMode.FULL and self._cross_referencer:
            yield DeepScanEvent(
                DeepScanPhase.CROSS_REFERENCING,
                OrchestratorConfig.MSG_CROSS_REF,
                OrchestratorConfig.PROGRESS_CROSS_REFERENCE,
            )
            dast = [
                f for f in all_findings
                if f.source in (FindingSource.DAST_URL, FindingSource.DAST_AUTHENTICATED)
            ]
            sast = [
                f for f in all_findings
                if f.source in (FindingSource.SAST_CODE, FindingSource.SAST_GIT_HISTORY)
            ]
            cross_findings = self._cross_referencer.cross_reference(dast, sast)
            all_findings.extend(cross_findings)

        # ==============================================================
        # Phase 9.1: SAST-Guided DAST (targeted dynamic tests from code)
        # ==============================================================
        if (
            mode == ScanMode.FULL
            and self._guided_dast_runner
            and sast_code_findings
            and endpoints
        ):
            yield DeepScanEvent(
                DeepScanPhase.SAST_GUIDED_DAST,
                GuidedDASTConfig.MSG_PHASE,
                GuidedDASTConfig.PROGRESS_GUIDED_DAST,
            )
            guided_dast_findings = await run_scanner_safe(
                GuidedDASTConfig.SCANNER_NAME,
                self._guided_dast_runner.run(
                    code_findings=sast_code_findings,
                    endpoints=endpoints,
                    repo_snapshot=repo_snapshot,
                    existing_findings=all_findings,
                ),
                ScannerTimeouts.GUIDED_DAST_SECONDS,
            )
            all_findings.extend(guided_dast_findings)
            scanners_run.append(GuidedDASTConfig.SCANNER_NAME)

        # ==============================================================
        # Phase 9.2: LLM Business Logic Attacks
        # ==============================================================
        if (
            repo_snapshot
            and session_a
            and session_b
            and endpoints
            and target_url
            and self._llm_code_reviewer
            and mode in (ScanMode.AUTHENTICATED, ScanMode.FULL)
        ):
            yield DeepScanEvent(
                DeepScanPhase.LLM_BUSINESS_LOGIC,
                "LLM analyzing code for business logic attack plans...",
            )

            llm_client = getattr(self._llm_code_reviewer, "_llm", None)
            if llm_client:
                from isitsecure.engine.scanners.llm_business_logic_scanner import (
                    LLMBusinessLogicScanner,
                )
                biz_logic_scanner = LLMBusinessLogicScanner(
                    llm_client=llm_client,
                    judgment_llm_client=self._judgment_llm_client,
                )

                # Build file dict from repo snapshot (file_index is path→content)
                repo_files = {
                    path: content
                    for path, content in repo_snapshot.file_index.items()
                    if content
                }

                biz_findings = await run_scanner_safe(
                    LLMBusinessLogicConfig.SCANNER_NAME,
                    biz_logic_scanner.scan(
                        repo_files=repo_files,
                        endpoints=endpoints,
                        admin_session=session_a,
                        regular_session=session_b,
                        target_url=target_url,
                    ),
                    ScannerTimeouts.GUIDED_DAST_SECONDS,
                )
                all_findings.extend(biz_findings)
                scanners_run.append(LLMBusinessLogicConfig.SCANNER_NAME)

                yield DeepScanEvent(
                    DeepScanPhase.LLM_BUSINESS_LOGIC,
                    f"LLM Business Logic: {len(biz_findings)} confirmed vulnerabilities",
                )

        # ==============================================================
        # Phase 9.5: LLM Triage (deduplicate, enrich, prioritize)
        # ==============================================================
        owner_summary = None
        themes = []
        if self._llm_triage and all_findings:
            from isitsecure.engine.constants import TriageConfig

            yield DeepScanEvent(
                DeepScanPhase.TRIAGE,
                TriageConfig.MSG_TRIAGING,
                TriageConfig.PROGRESS_TRIAGE,
            )
            try:
                triage_result = await asyncio.wait_for(
                    self._llm_triage.triage(
                        all_findings,
                        mode,
                        target_url,
                        repo_url,
                    ),
                    timeout=ScannerTimeouts.TRIAGE_SECONDS,
                )
                all_findings = triage_result.triaged_findings
                owner_summary = triage_result.owner_summary
                themes = triage_result.themes
                scanners_run.append(TriageConfig.SCANNER_NAME)
            except asyncio.TimeoutError:
                logger.warning(
                    "Triage timed out after %ds", ScannerTimeouts.TRIAGE_SECONDS,
                )
            except Exception as e:
                logger.warning("Triage failed: %s: %s", type(e).__name__, e)

        # ==============================================================
        # Phase 10: Build report
        # ==============================================================
        duration = time.monotonic() - start_time
        endpoints_with_ids = [ep for ep in endpoints if ep.has_id_params]
        report = DeepScanReport(
            target_url=target_url,
            repo_url=repo_url,
            repo_branch=repo_snapshot.branch if repo_snapshot else "",
            repo_commit_hash=repo_snapshot.commit_hash if repo_snapshot else "",
            framework=self._safe_enum_value(
                repo_snapshot.framework if repo_snapshot else None
            ),
            backend=self._safe_enum_value(
                repo_snapshot.backend if repo_snapshot else None
            ),
            scan_mode=mode.value if mode else "",
            total_endpoints_discovered=len(endpoints),
            endpoints_with_ids=len(endpoints_with_ids),
            endpoints_tested=len(idor_results),
            routes_in_code=(
                len(repo_snapshot.route_map) if repo_snapshot else 0
            ),
            tables_discovered=(
                len([
                    p for p in repo_snapshot.file_index
                    if "schema" in p.lower()
                ])
                if repo_snapshot
                else 0
            ),
            owner_summary=owner_summary,
            findings=self._sort_findings(all_findings),
            discovered_endpoints=endpoints,
            idor_results=idor_results,
            scan_duration_seconds=round(duration, 2),
            scanners_run=scanners_run,
            themes=themes,
            token_usage=self._collect_token_usage(),
        )

        yield DeepScanEvent(
            DeepScanPhase.ANALYZING_RESULTS,
            OrchestratorConfig.MSG_COMPILING,
        )

        yield DeepScanEvent(
            DeepScanPhase.COMPLETE,
            self._build_summary(report),
            OrchestratorConfig.PROGRESS_COMPLETE,
            {"report": report.model_dump(mode="json")},
        )

        # ==============================================================
        # Cleanup: Shutdown LSP
        # ==============================================================
        if self._lsp_client and lsp_initialized:
            try:
                await self._lsp_client.shutdown()
            except Exception as e:
                logger.debug("LSP shutdown error: %s", e)

    # ------------------------------------------------------------------
    # DAST parallel runner
    # ------------------------------------------------------------------

    async def _run_dast_scanners(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot,
    ) -> tuple[list[DeepFinding], list[str]]:
        """Run all registered DAST scanners in parallel.

        Scanners are iterated from ``self._dast_scanners`` (OCP).
        Per-scanner timeouts are resolved via ``_dast_timeout``.
        """
        if not self._dast_scanners:
            return [], []

        coros: list[tuple[str, asyncio.Task]] = [
            (
                s.scanner_name,
                run_scanner_safe(
                    s.scanner_name,
                    s.scan(endpoints, snapshot),
                    self._dast_timeout(s.scanner_name),
                ),
            )
            for s in self._dast_scanners
        ]

        results = await asyncio.gather(*[coro for _, coro in coros])
        all_findings: list[DeepFinding] = []
        names: list[str] = []
        for (name, _), findings in zip(coros, results):
            all_findings.extend(findings)
            names.append(name)
        return all_findings, names

    @staticmethod
    def _dast_timeout(scanner_name: str) -> float:
        """Resolve per-scanner timeout from ScannerTimeouts constants."""
        return _DAST_TIMEOUT_MAP.get(scanner_name, ScannerTimeouts.DEFAULT_SECONDS)

    # ------------------------------------------------------------------
    # IDOR result → finding conversion
    # ------------------------------------------------------------------

    @staticmethod
    def _idor_results_to_findings(
        results: list,
    ) -> list[DeepFinding]:
        """Convert confirmed/likely read-access IDOR results to DeepFindings.

        The IDOR scanner returns IDORTestResult objects for read-access tests.
        Confirmed and likely results indicate that an endpoint returns different
        data for different resource IDs without auth, which may be an IDOR.
        """
        from isitsecure.engine.enums import IDORRiskLevel
        from isitsecure.engine.enums import FindingCategory, SeverityLevel

        findings: list[DeepFinding] = []
        for result in results:
            if result.risk_level not in (IDORRiskLevel.CONFIRMED, IDORRiskLevel.LIKELY):
                continue

            severity = (
                SeverityLevel.HIGH
                if result.risk_level == IDORRiskLevel.CONFIRMED
                else SeverityLevel.MEDIUM
            )
            confidence = result.confidence

            findings.append(
                DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.IDOR,
                    severity=severity,
                    confidence=confidence,
                    title="IDOR — resource accessible via direct ID reference",
                    description=(
                        f"The endpoint {result.endpoint.url} returns data when "
                        f"accessed with arbitrary resource IDs. An attacker who "
                        f"can guess or enumerate IDs could access resources "
                        f"belonging to other users.\n\n"
                        f"**Risk level:** {result.risk_level.value}\n"
                        f"**Summary:** {result.summary}"
                    ),
                    endpoint_url=result.endpoint.url,
                    scanner_name="idor_scanner",
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Authenticated DAST runner
    # ------------------------------------------------------------------

    async def _run_authenticated_scanners(
        self,
        session_a: AuthSession,
        session_b: AuthSession | None,
        endpoints: list[DiscoveredEndpoint],
        target_url: str | None,
        supabase_url: str | None,
        anon_key: str | None,
        tables: list[str],
        crawl_result: AuthenticatedCrawlResult | None = None,
        js_content: str | None = None,
    ) -> tuple[list[DeepFinding], list[str]]:
        """Run JWT, RLS deep, privilege escalation, and cross-user IDOR scanners."""
        all_findings: list[DeepFinding] = []
        names: list[str] = []

        # JWT testing
        if self._jwt_scanner and target_url:
            jwt_findings = await run_scanner_safe(
                "jwt",
                self._jwt_scanner.scan(endpoints),
            )
            all_findings.extend(jwt_findings)
            names.append("jwt")

        # RLS deep testing
        if self._rls_deep_scanner and supabase_url and anon_key:
            rls_findings = await run_scanner_safe(
                "rls_deep",
                self._rls_deep_scanner.scan(
                    supabase_url=supabase_url,
                    anon_key=anon_key,
                    tables=tables,
                    user_a_session=session_a,
                    user_b_session=session_b,
                ),
                ScannerTimeouts.IDOR_CROSS_USER_SECONDS,
            )
            all_findings.extend(rls_findings)
            names.append("rls_deep")

        # Privilege escalation — test with both sessions
        # User A is the resource owner (admin), User B is the attacker (regular)
        if self._privilege_escalation_scanner:
            # Extract RPC functions from JS for Test 8
            rpc_functions: list[str] = []
            if js_content:
                from isitsecure.engine.shared.supabase_utils import (
                    extract_rpc_functions_from_js,
                )
                rpc_functions = extract_rpc_functions_from_js(js_content)

            priv_findings = await run_scanner_safe(
                "priv_esc",
                self._privilege_escalation_scanner.scan(
                    regular_user_session=session_b if session_b else session_a,
                    admin_session=session_a if session_b else None,
                    endpoints=endpoints,
                    supabase_url=supabase_url,
                    anon_key=anon_key,
                    tables=tables,
                    intercepted_requests=(
                        crawl_result.intercepted_requests if crawl_result else None
                    ),
                    owned_resource_ids=(
                        crawl_result.owned_resource_ids if crawl_result else None
                    ),
                    rpc_functions=rpc_functions or None,
                ),
                ScannerTimeouts.PRIVILEGE_ESCALATION_SECONDS,
            )
            all_findings.extend(priv_findings)
            names.append("priv_esc")

        # Use resource IDs from the Phase 3 crawl (already done)
        owned_resources: dict[str, list[str]] = {}
        if crawl_result:
            owned_resources = crawl_result.owned_resource_ids

        # Cross-user IDOR (requires two sessions + owned resources)
        if self._idor_scanner and session_b and owned_resources:
            cross_user_findings = await self._run_cross_user_idor(
                session_a, session_b, owned_resources,
                supabase_url, anon_key, tables,
            )
            all_findings.extend(cross_user_findings)
            names.append("idor_cross_user")

        # REST cross-user IDOR: two logged-in users vs. discovered id-bearing
        # endpoints (no Supabase project or crawler-found resources needed).
        if (
            self._idor_scanner and session_a and session_b and endpoints
            and not owned_resources
        ):
            rest_cu_findings = await self._run_rest_cross_user_idor(
                session_a, session_b, endpoints,
            )
            all_findings.extend(rest_cu_findings)
            if rest_cu_findings:
                names.append("idor_cross_user_api")

        # Body parameter fuzzing (fuzz JSON fields from intercepted requests)
        if crawl_result and crawl_result.intercepted_requests:
            from isitsecure.engine.scanners.body_param_fuzzer import (
                BodyParamFuzzer,
            )
            fuzzer = BodyParamFuzzer()
            fuzz_findings = await run_scanner_safe(
                "body_param_fuzzer",
                fuzzer.scan(crawl_result.intercepted_requests, session_a),
                ScannerTimeouts.INJECTION_ACTIVE_SECONDS,
            )
            all_findings.extend(fuzz_findings)
            names.append("body_param_fuzzer")

        # Race condition testing (concurrent mutation replay)
        if crawl_result and crawl_result.intercepted_requests:
            from isitsecure.engine.scanners.race_condition_scanner import (
                RaceConditionScanner,
            )
            race_scanner = RaceConditionScanner()
            race_findings = await run_scanner_safe(
                "race_condition",
                race_scanner.scan(crawl_result.intercepted_requests, session_a),
                ScannerTimeouts.DEFAULT_SECONDS,
            )
            all_findings.extend(race_findings)
            names.append("race_condition")

        # DOM XSS testing (Playwright-based sink hooking)
        if crawl_result and crawl_result.pages_discovered:
            from isitsecure.engine.scanners.dom_xss_scanner import (
                DOMXSSScanner,
            )
            dom_xss_scanner = DOMXSSScanner()
            dom_xss_findings = await run_scanner_safe(
                DOMXSSScanner.SCANNER_NAME,
                dom_xss_scanner.scan(
                    pages_to_test=crawl_result.pages_discovered,
                    auth_headers=session_a.headers if session_a else None,
                ),
                ScannerTimeouts.DOM_XSS_SECONDS,
            )
            all_findings.extend(dom_xss_findings)
            names.append(DOMXSSScanner.SCANNER_NAME)

        return all_findings, names

    # ------------------------------------------------------------------
    # SAST parallel runner
    # ------------------------------------------------------------------

    async def _run_sast_scanners(
        self,
        repo_snapshot: RepoSnapshot,
    ) -> tuple[list[DeepFinding], list[str], list[CodeFinding]]:
        """Run all registered SAST scanners in parallel.

        Scanners are iterated from ``self._sast_scanners`` (OCP).
        Per-scanner timeouts are resolved via ``_sast_timeout``.

        Returns:
            Tuple of (deep_findings, scanner_names, raw_code_findings).
            The raw_code_findings are passed to the LLM reviewer for
            cross-scanner intelligence.
        """
        if not self._sast_scanners:
            return [], [], []

        coros: list[tuple[str, asyncio.Task]] = [
            (
                s.scanner_name,
                run_scanner_safe(
                    s.scanner_name,
                    s.scan(repo_snapshot),
                    self._sast_timeout(s.scanner_name),
                ),
            )
            for s in self._sast_scanners
        ]

        results = await asyncio.gather(*[coro for _, coro in coros])
        all_findings: list[DeepFinding] = []
        all_code_findings: list[CodeFinding] = []
        names: list[str] = []
        for (name, _), code_findings in zip(coros, results):
            for cf in code_findings:
                all_findings.append(self._code_finding_to_deep_finding(cf))
                all_code_findings.append(cf)
            names.append(name)
        return all_findings, names, all_code_findings

    # Pricing per million tokens (USD) — keyed by model name prefix
    _MODEL_PRICING = {
        "claude-opus-4-7":   {"input": 5.0,  "output": 25.0},
        "claude-sonnet-4-6": {"input": 3.0,  "output": 15.0},
        "claude-sonnet-4":   {"input": 3.0,  "output": 15.0},
        "claude-haiku-4":    {"input": 0.80, "output": 4.0},
        "claude-opus-4":     {"input": 5.0,  "output": 25.0},
        "gemini-3.1-pro-preview":    {"input": 2.0,  "output": 12.0},
        "gemini-3-flash-preview":    {"input": 0.5,  "output": 3.0},
        "gemini-3.1-pro":    {"input": 2.0,  "output": 12.0},
        "gemini-2.5-pro":    {"input": 1.25, "output": 10.0},
        "gemini-2.5-flash":  {"input": 0.15, "output": 0.60},
    }

    def _collect_token_usage(self) -> ScanTokenUsage | None:
        """Collect cumulative token usage from all LLM clients.

        Aggregates tokens from both the planning client (code review,
        attack planning) and the judgment client (triage, result analysis).
        """
        # Gather all distinct LLM client instances
        clients: list[object] = []
        if self._llm_code_reviewer:
            llm = getattr(self._llm_code_reviewer, "_llm", None)
            if llm:
                clients.append(llm)
        if self._llm_triage:
            llm = getattr(self._llm_triage, "_llm", None)
            if llm and llm not in clients:
                clients.append(llm)
        if self._judgment_llm_client and self._judgment_llm_client not in clients:
            clients.append(self._judgment_llm_client)

        if not clients:
            return None

        total_input = 0
        total_output = 0
        total_calls = 0
        total_cost = 0.0
        model_names: list[str] = []

        for client in clients:
            usage = getattr(client, "token_usage", None)
            if not usage:
                continue

            inp = usage.get("input_tokens", 0)
            out = usage.get("output_tokens", 0)
            calls = usage.get("llm_calls", 0)
            model_name = getattr(client, "_model_name", "")

            total_input += inp
            total_output += out
            total_calls += calls

            if model_name and model_name not in model_names:
                model_names.append(model_name)

            # Calculate cost for this client's model
            price_in, price_out = 3.0, 15.0  # default to Sonnet
            for prefix, rates in self._MODEL_PRICING.items():
                if model_name.startswith(prefix):
                    price_in = rates["input"]
                    price_out = rates["output"]
                    break
            total_cost += (
                (inp / 1_000_000) * price_in
                + (out / 1_000_000) * price_out
            )

        if total_calls == 0:
            return None

        return ScanTokenUsage(
            input_tokens=total_input,
            output_tokens=total_output,
            total_tokens=total_input + total_output,
            llm_calls=total_calls,
            estimated_cost_usd=round(total_cost, 4),
            model=" + ".join(model_names),
        )

    @staticmethod
    def _sort_findings(findings: list[DeepFinding]) -> list[DeepFinding]:
        """Sort findings by severity (critical first), then priority (1 first).

        Ensures the report reads high-to-low impact so the customer
        sees the most important issues first.
        """
        severity_rank = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
        }
        return sorted(
            findings,
            key=lambda f: (
                severity_rank.get(f.severity, 4),
                f.priority if f.priority is not None else 99,
            ),
        )

    @staticmethod
    def _sast_timeout(scanner_name: str) -> float:
        """Resolve per-scanner timeout from ScannerTimeouts constants."""
        return _SAST_TIMEOUT_MAP.get(scanner_name, ScannerTimeouts.DEFAULT_SECONDS)

    # ------------------------------------------------------------------
    # Supabase discovery + lazy auth provider
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_supabase_info(
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot,
    ) -> tuple[str | None, str | None, list[str]]:
        """Extract Supabase URL, anon key, and table names from discovery results.

        Args:
            endpoints: Discovered API endpoints from Phase 2.
            snapshot: The ingested codebase snapshot (JS content).

        Returns:
            Tuple of (supabase_url, anon_key, table_names).
        """
        from isitsecure.engine.constants import EndpointDiscoveryConfig

        supabase_url: str | None = None
        anon_key: str | None = None
        tables: list[str] = []

        from isitsecure.engine.shared.supabase_utils import (
            extract_supabase_table_from_url,
        )

        # Find Supabase URL and table names from discovered endpoints
        for ep in endpoints:
            if "supabase.co/rest/v1/" in ep.url:
                parsed = urlparse(ep.url)
                if not supabase_url and parsed.hostname:
                    supabase_url = f"{parsed.scheme}://{parsed.hostname}"
                table = extract_supabase_table_from_url(ep.url)
                if table and table not in tables:
                    tables.append(table)

        # Fallback: extract Supabase URL from JS content if not found in endpoints
        if not supabase_url and snapshot and snapshot.all_js_content:
            url_match = re.search(
                EndpointDiscoveryConfig.SUPABASE_URL_PATTERN,
                snapshot.all_js_content,
            )
            if url_match:
                supabase_url = url_match.group(1)

        # Find anon key from JS content
        if snapshot and snapshot.all_js_content:
            match = re.search(
                EndpointDiscoveryConfig.SUPABASE_ANON_KEY_PATTERN,
                snapshot.all_js_content,
            )
            if match:
                anon_key = match.group(1)

        # Extract table names from JS .from('table') calls — works even
        # when the REST API is locked down with service_role (the client
        # SDK still references table names in the JS bundle)
        if snapshot and snapshot.all_js_content:
            for m in re.finditer(
                EndpointDiscoveryConfig.SUPABASE_FROM_PATTERN,
                snapshot.all_js_content,
            ):
                table = m.group(1)
                if table and table not in tables:
                    tables.append(table)

        # Also extract from endpoint URLs that were built as /rest/v1/<table>
        # by the endpoint discovery (these use the app base URL, not supabase.co)
        for ep in endpoints:
            if ep.source_pattern == "supabase_from":
                parsed = urlparse(ep.url)
                parts = parsed.path.strip("/").split("/")
                if len(parts) >= 3 and parts[0] == "rest" and parts[1] == "v1":
                    table = parts[2]
                    if table and table != "rpc" and table not in tables:
                        tables.append(table)

        if tables:
            logger.info("Supabase tables from JS analysis: %s", tables)

        return supabase_url, anon_key, tables

    @staticmethod
    async def _discover_supabase_tables(
        supabase_url: str, anon_key: str,
    ) -> list[str]:
        """Query Supabase's OpenAPI schema to discover table names.

        PostgREST exposes a root endpoint (GET /) that returns the
        OpenAPI spec, which lists all tables the anon key can see.
        This is the most reliable way to discover tables when JS
        analysis and crawler both come up empty.
        """
        import httpx

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{supabase_url}/rest/v1/",
                    headers={"apikey": anon_key},
                )
                if resp.status_code != 200:
                    return []

                data = resp.json()
                # PostgREST OpenAPI spec has paths like /table_name
                paths = data.get("paths", {})
                tables = [
                    path.lstrip("/")
                    for path in paths
                    if path.startswith("/")
                    and not path.startswith("/rpc/")
                    and path.count("/") == 1
                ]
                if tables:
                    logger.info(
                        "Discovered %d tables from Supabase schema: %s",
                        len(tables),
                        tables[:10],
                    )
                return tables
        except Exception as exc:
            logger.debug("Supabase schema discovery failed: %s", exc)
            return []

    @staticmethod
    def _build_auth_provider(
        supabase_url: str, anon_key: str,
    ) -> AuthProviderProtocol:
        """Build a SupabaseAuthProvider lazily after discovery.

        Args:
            supabase_url: Discovered Supabase project URL.
            anon_key: Discovered Supabase anon key.

        Returns:
            A SupabaseAuthProvider instance.
        """
        from isitsecure.engine.auth.supabase_auth import (
            SupabaseAuthProvider,
        )

        return SupabaseAuthProvider(supabase_url, anon_key)

    # ------------------------------------------------------------------
    # Authenticated crawling
    # ------------------------------------------------------------------

    async def _run_authenticated_crawl(
        self,
        credentials: AuthCredentials,
        target_url: str,
        endpoints: list[DiscoveredEndpoint],
    ) -> AuthenticatedCrawlResult | None:
        """Login via browser, then BFS-crawl to discover auth endpoints.

        Uses the injected ``authenticated_crawler_factory`` if provided,
        otherwise falls back to importing the concrete class (DIP).
        """
        from isitsecure.engine.constants import (
            AuthenticatedCrawlerConfig,
        )

        seed_routes = [
            urlparse(ep.url).path
            for ep in endpoints[: AuthenticatedCrawlerConfig.MAX_SEED_ROUTES]
        ]

        kwargs = dict(
            base_url=target_url,
            email=credentials.email or "",
            password=credentials.password or "",
            seed_routes=seed_routes,
        )

        if self._authenticated_crawler_factory:
            crawler = self._authenticated_crawler_factory(**kwargs)
        else:
            from isitsecure.engine.scanners.authenticated_crawler import (
                AuthenticatedCrawler,
            )
            crawler = AuthenticatedCrawler(**kwargs)

        try:
            return await crawler.crawl()
        except Exception as e:
            logger.warning("Authenticated crawl failed: %s", e)
            return None

    async def _run_cross_user_idor(
        self,
        session_a: AuthSession,
        session_b: AuthSession,
        owned_resources: dict[str, list[str]],
        supabase_url: str | None,
        anon_key: str | None,
        tables: list[str],
    ) -> list[DeepFinding]:
        """Run cross-user IDOR scanner and convert results to DeepFindings.

        Args:
            session_a: Resource owner session.
            session_b: Attacker session.
            owned_resources: Resources discovered by the authenticated crawler.
            supabase_url: Supabase project URL (if discovered).
            anon_key: Supabase anon key (if discovered).
            tables: Supabase table names (if discovered).

        Returns:
            List of DeepFindings from cross-user IDOR testing.
        """
        from isitsecure.engine.enums import IDORRiskLevel
        from isitsecure.engine.enums import FindingCategory, SeverityLevel

        findings: list[DeepFinding] = []
        try:
            cross_user_results = await run_scanner_safe(
                "idor_cross_user",
                self._idor_scanner.scan_cross_user(
                    user_a_session=session_a,
                    user_b_session=session_b,
                    user_a_resources=owned_resources,
                    supabase_url=supabase_url,
                    anon_key=anon_key,
                    tables=tables,
                ),
                ScannerTimeouts.IDOR_CROSS_USER_SECONDS,
            )
            for result in cross_user_results:
                if result.risk_level != IDORRiskLevel.SAFE:
                    severity = (
                        SeverityLevel.CRITICAL
                        if result.write_accessible
                        else SeverityLevel.HIGH
                    )
                    access_desc = (
                        "read and write"
                        if result.write_accessible
                        else "read"
                    )
                    findings.append(DeepFinding(
                        source=FindingSource.DAST_AUTHENTICATED,
                        category=FindingCategory.IDOR,
                        severity=severity,
                        title=f"Cross-user IDOR on {result.table_or_endpoint}",
                        description=(
                            f"User B can {access_desc} User A's data "
                            f"in {result.table_or_endpoint}"
                        ),
                        confidence=result.confidence,
                        scanner_name="idor_cross_user",
                        endpoint_url=result.table_or_endpoint,
                    ))
        except Exception as e:
            logger.warning("Cross-user IDOR scan failed: %s", e)

        return findings

    async def _run_rest_cross_user_idor(
        self,
        session_a: "AuthSession",
        session_b: "AuthSession",
        endpoints: list[DiscoveredEndpoint],
    ) -> list[DeepFinding]:
        """Convert REST cross-user IDOR results into findings.

        Reaches a resource that a *different* authenticated user can touch but
        an anonymous request cannot — i.e. broken object-level authorization.
        """
        from isitsecure.engine.enums import (
            FindingCategory,
            IDORRiskLevel,
            SeverityLevel,
        )

        findings: list[DeepFinding] = []
        try:
            results = await run_scanner_safe(
                "idor_cross_user_api",
                self._idor_scanner.scan_cross_user_api(
                    session_a, session_b, endpoints),
                ScannerTimeouts.IDOR_CROSS_USER_SECONDS,
            )
            for result in results:
                if result.risk_level == IDORRiskLevel.SAFE:
                    continue
                access = "modify" if result.write_accessible else "read"
                severity = (
                    SeverityLevel.CRITICAL if result.write_accessible
                    else SeverityLevel.HIGH
                )
                findings.append(DeepFinding(
                    source=FindingSource.DAST_AUTHENTICATED,
                    category=FindingCategory.IDOR,
                    severity=severity,
                    title=f"Cross-user IDOR on {result.table_or_endpoint}",
                    description=(
                        f"An authenticated user ('{result.attacker_user_id}') can "
                        f"{access} another user's ('{result.owner_user_id}') "
                        f"resource at {result.table_or_endpoint}. An anonymous "
                        f"request is rejected, so this is broken object-level "
                        f"authorization (BOLA), not a public endpoint."
                    ),
                    confidence=result.confidence,
                    scanner_name="idor_cross_user_api",
                    endpoint_url=result.table_or_endpoint,
                ))
        except Exception as e:
            logger.warning("REST cross-user IDOR scan failed: %s", e)

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _inject_oob_payloads(
        oob_service: OOBCallbackService,
        endpoints: list[DiscoveredEndpoint],
    ) -> None:
        """Inject OOB callback URLs for blind SSRF, injection, XXE, and XSS.

        Delegates to three strategy methods (SRP):
        1. ``_oob_ssrf_endpoints`` — URL param injection for SSRF scanner
        2. ``_oob_post_payloads`` — injection/XXE/XSS via POST bodies
        """
        from isitsecure.engine.constants import OOBConfig

        oob_count = DeepSecurityScanAgent._oob_ssrf_endpoints(
            oob_service, endpoints,
        )
        oob_count += await DeepSecurityScanAgent._oob_post_payloads(
            oob_service, endpoints,
        )

        if oob_count:
            logger.info(
                "OOB: sent %d callback payloads (SSRF + injection + XXE + XSS)",
                oob_count,
            )

    @staticmethod
    def _oob_ssrf_endpoints(
        oob_service: OOBCallbackService,
        endpoints: list[DiscoveredEndpoint],
    ) -> int:
        """Add OOB callback URLs to the endpoint list for blind SSRF.

        For each endpoint with a URL-accepting param, creates a new
        endpoint entry with the callback URL. The existing SSRF scanner
        picks these up during Phase 4.

        Returns:
            Number of OOB endpoints added.
        """
        from isitsecure.engine.constants import OOBConfig, SSRFConfig
        from isitsecure.engine.shared.url_utils import inject_query_param

        url_param_names = set(p.lower() for p in SSRFConfig.URL_PARAM_NAMES)
        count = 0

        for ep in list(endpoints):
            parsed = urlparse(ep.url)
            params = dict(
                p.split("=", 1)
                for p in parsed.query.split("&")
                if "=" in p
            ) if parsed.query else {}

            for param_name in params:
                if param_name.lower() in url_param_names:
                    callback_url = oob_service.generate_url(
                        scanner_name="ssrf",
                        payload_id=f"{param_name}-{parsed.path}",
                        endpoint_url=ep.url,
                        param_name=param_name,
                        description=OOBConfig.SSRF_OOB_LABEL,
                    )
                    if callback_url:
                        oob_url = inject_query_param(
                            ep.url, param_name, callback_url,
                        )
                        endpoints.append(DiscoveredEndpoint(
                            url=oob_url,
                            method=ep.method,
                            source_pattern=OOBConfig.SOURCE_PATTERN_SSRF,
                            category=ep.category,
                        ))
                        count += 1

        return count

    @staticmethod
    async def _oob_post_payloads(
        oob_service: OOBCallbackService,
        endpoints: list[DiscoveredEndpoint],
    ) -> int:
        """Send injection, XXE, and blind XSS OOB payloads via POST.

        Fires payloads directly to mutation endpoints. Each payload
        contains a unique OOB callback URL so hits are correlated
        back to the exact scanner + endpoint.

        Returns:
            Number of OOB payloads sent.
        """
        import json as _json

        from isitsecure.engine.constants import (
            DeepScanConfig,
            OOBConfig,
            SharedPatterns,
            XSSConfig,
        )
        from isitsecure.engine.shared.rate_limited_client import (
            RateLimitedClient,
        )

        post_endpoints = [
            ep for ep in endpoints
            if ep.method.value in OOBConfig.WRITE_METHODS
            and ep.source_pattern != OOBConfig.SOURCE_PATTERN_SSRF
        ][:OOBConfig.MAX_OOB_POST_ENDPOINTS]

        if not post_endpoints:
            return 0

        count = 0
        try:
            async with RateLimitedClient(
                max_concurrent=SharedPatterns.DEFAULT_MAX_CONCURRENT,
                delay_seconds=SharedPatterns.DEFAULT_PROBE_DELAY,
                timeout_seconds=OOBConfig.HTTP_TIMEOUT_SECONDS,
                user_agent=DeepScanConfig.USER_AGENT,
            ) as client:
                for ep in post_endpoints:
                    path = urlparse(ep.url).path

                    # Injection OOB (SQLi + command injection)
                    for tpl, label in OOBConfig.INJECTION_OOB_PAYLOADS:
                        callback = oob_service.generate_url(
                            scanner_name="injection",
                            payload_id=f"{label}-{path}",
                            endpoint_url=ep.url,
                            param_name=OOBConfig.PARAM_NAME_BODY,
                            description=f"blind {label}",
                        )
                        if not callback:
                            continue
                        try:
                            await client.request(
                                ep.method.value, ep.url,
                                content=tpl.replace("{callback}", callback),
                                headers={
                                    SharedPatterns.HEADER_CONTENT_TYPE: "text/plain",
                                },
                            )
                            count += 1
                        except Exception:
                            pass

                    # XXE OOB
                    xxe_cb = oob_service.generate_url(
                        scanner_name="xxe",
                        payload_id=f"xxe-{path}",
                        endpoint_url=ep.url,
                        param_name=OOBConfig.PARAM_NAME_BODY,
                        description="blind XXE entity fetch",
                    )
                    if xxe_cb:
                        try:
                            await client.request(
                                ep.method.value, ep.url,
                                content=OOBConfig.XXE_OOB_PAYLOAD.replace(
                                    "{callback}", xxe_cb,
                                ),
                                headers={
                                    SharedPatterns.HEADER_CONTENT_TYPE: "application/xml",
                                },
                            )
                            count += 1
                        except Exception:
                            pass

                    # Blind XSS OOB (stored payloads)
                    for xss_tpl in OOBConfig.XSS_OOB_PAYLOADS:
                        xss_cb = oob_service.generate_url(
                            scanner_name="xss",
                            payload_id=f"blind-xss-{path}",
                            endpoint_url=ep.url,
                            param_name=OOBConfig.PARAM_NAME_BODY,
                            description="blind/stored XSS callback",
                        )
                        if not xss_cb:
                            continue
                        xss_payload = xss_tpl.replace("{callback}", xss_cb)
                        for field in XSSConfig.POST_BODY_FIELD_NAMES:
                            try:
                                await client.request(
                                    ep.method.value, ep.url,
                                    content=_json.dumps({field: xss_payload}),
                                    headers={
                                        SharedPatterns.HEADER_CONTENT_TYPE:
                                            SharedPatterns.CONTENT_TYPE_JSON,
                                    },
                                )
                                count += 1
                                break  # One field per payload is enough
                            except Exception:
                                pass

        except Exception as exc:
            logger.debug("OOB POST payloads failed: %s", exc)

        return count

    @staticmethod
    def _extract_page_urls(
        target_url: str,
        endpoints: list[DiscoveredEndpoint],
    ) -> list[str]:
        """Extract page URLs (non-API) from the target and discovered endpoints.

        Used for unauthenticated DOM XSS scanning when no authenticated
        crawl was performed.  Filters out API endpoints and static assets,
        returning only HTML page URLs worth visiting in a browser.
        """
        from isitsecure.engine.constants import (
            AuthenticatedCrawlerConfig,
            EndpointDiscoveryConfig,
        )

        pages: list[str] = [target_url]
        seen: set[str] = {target_url.rstrip("/")}

        for ep in endpoints:
            url = ep.url.rstrip("/")
            if url in seen:
                continue

            parsed = urlparse(url)
            path = parsed.path.lower()

            # Skip API endpoints
            is_api = any(
                ind in url for ind in AuthenticatedCrawlerConfig.API_INDICATORS
            )
            if is_api:
                continue

            # Skip static assets
            is_static = any(
                path.endswith(ext)
                for ext in AuthenticatedCrawlerConfig.SKIP_EXTENSIONS
            )
            if is_static:
                continue

            # Skip external domains
            base_host = urlparse(target_url).netloc
            if parsed.netloc and parsed.netloc != base_host:
                continue

            seen.add(url)
            pages.append(ep.url)

        return pages

    def _detect_scan_mode(
        self,
        target_url: str | None,
        repo_url: str | None,
        credentials: AuthCredentials | None,
    ) -> ScanMode:
        """Auto-detect scan mode from provided inputs."""
        if target_url and repo_url:
            return ScanMode.FULL
        if target_url and credentials:
            return ScanMode.AUTHENTICATED
        if repo_url:
            return ScanMode.CODE_ONLY
        return ScanMode.URL_ONLY

    @staticmethod
    def _code_finding_to_deep_finding(cf: CodeFinding) -> DeepFinding:
        """Convert a CodeFinding to a unified DeepFinding."""
        code_location = None
        if cf.file_path:
            code_location = CodeLocation(
                file_path=cf.file_path,
                line_number=cf.line_number,
                line_end=cf.line_end,
                code_snippet=cf.code_snippet,
                github_url=cf.github_url,
            )
        return DeepFinding(
            source=FindingSource.SAST_CODE,
            category=cf.category,
            severity=cf.severity,
            title=cf.title,
            description=cf.description,
            confidence=cf.confidence,
            scanner_name=cf.scanner_name,
            code_location=code_location,
        )

    async def _ingest_url(self, url: str) -> CodebaseSnapshot | None:
        """Ingest a URL using the shared ingestion service."""
        try:
            return await self._ingestion.ingest(url)
        except Exception as e:
            logger.error(
                OrchestratorConfig.ERROR_INGESTION_FAILED.format(url=url, error=e),
            )
            return None

    async def _ingest_repo(self, repo_url: str, github_token: str | None = None) -> RepoSnapshot | None:
        """Ingest a repository using the repo ingestion service."""
        if not self._repo_ingestion:
            return None
        try:
            return await self._repo_ingestion.ingest(repo_url, github_token=github_token)
        except Exception as e:
            logger.error(
                OrchestratorConfig.ERROR_REPO_FAILED.format(error=e),
            )
            return None

    def _build_category_summary(self, endpoints: list[DiscoveredEndpoint]) -> dict:
        """Build a summary of endpoint categories."""
        categories: dict[str, int] = {}
        for ep in endpoints:
            cat = ep.category.value
            categories[cat] = categories.get(cat, 0) + 1
        return {"category_summary": categories}

    @staticmethod
    def _safe_enum_value(enum_val) -> str:
        """Safely extract .value from an enum, returning '' on failure."""
        if enum_val is None:
            return ""
        try:
            val = enum_val.value
            return val if isinstance(val, str) else str(val)
        except (AttributeError, TypeError):
            return ""

    def _build_summary(self, report: DeepScanReport) -> str:
        """Build a human-readable final summary."""
        parts = [
            OrchestratorConfig.SUMMARY_DURATION.format(duration=report.scan_duration_seconds),
            OrchestratorConfig.SUMMARY_MODE.format(mode=report.scan_mode),
            OrchestratorConfig.SUMMARY_SCANNERS.format(count=len(report.scanners_run)),
            OrchestratorConfig.SUMMARY_FINDINGS.format(total=len(report.findings)),
            OrchestratorConfig.SUMMARY_CRITICAL.format(count=report.critical_count),
            OrchestratorConfig.SUMMARY_HIGH.format(count=report.high_count),
        ]
        return OrchestratorConfig.SUMMARY_SEPARATOR.join(parts)
