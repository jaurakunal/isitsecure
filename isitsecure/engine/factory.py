"""Factory for wiring DeepSecurityScanAgent dependencies (DIP).

All concrete dependencies are instantiated here, keeping the agent
and scanners dependent only on abstractions.

OCP: New scanners are added to the ``dast_scanners`` or ``sast_scanners``
     lists — no agent code changes needed.

SRP: This module is responsible ONLY for constructing and wiring the
     dependency graph.  No business logic lives here.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

from isitsecure.engine.agent import DeepSecurityScanAgent
from isitsecure.engine.code_analysis.dependency_scanner import (
    DependencyScanner,
)
from isitsecure.engine.code_analysis.python_dependency_scanner import (
    PythonDependencyScanner,
)
from isitsecure.engine.code_analysis.java_dependency_scanner import (
    JavaDependencyScanner,
)
from isitsecure.engine.code_analysis.docker_scanner import (
    DockerScanner,
)
from isitsecure.engine.code_analysis.drizzle_schema_analyzer import (
    DrizzleSchemaAnalyzer,
)
from isitsecure.engine.code_analysis.prisma_schema_analyzer import (
    PrismaSchemaAnalyzer,
)
from isitsecure.engine.code_analysis.express_middleware_analyzer import (
    ExpressMiddlewareAnalyzer,
)
from isitsecure.engine.code_analysis.iac_scanner import (
    IaCScanner,
)
from isitsecure.engine.code_analysis.k8s_scanner import (
    K8sScanner,
)
from isitsecure.engine.code_analysis.openapi_scanner import (
    OpenAPIScanner,
)
from isitsecure.engine.code_analysis.shell_script_scanner import (
    ShellScriptScanner,
)
from isitsecure.engine.code_analysis.firebase_rules_analyzer import (
    FirebaseRulesAnalyzer,
)
# InjectionPatternTrigger is now a review trigger (invoked by
# PrioritizedRouteSelector), not a SAST scanner registered here.
from isitsecure.engine.code_analysis.middleware_analyzer import (
    MiddlewareAnalyzer,
)
from isitsecure.engine.code_analysis.rls_policy_analyzer import (
    RLSPolicyAnalyzer,
)
from isitsecure.engine.code_analysis.route_analyzer import (
    RouteAuthAnalyzer,
)
from isitsecure.engine.code_analysis.secret_scanner import (
    GitSecretScanner,
)
from isitsecure.engine.cross_referencer import FindingCrossReferencer
from isitsecure.engine.guided_dast.runner import SASTGuidedDASTRunner
from isitsecure.engine.guided_dast.strategies.auth_bypass import (
    AuthBypassGuidedStrategy,
)
from isitsecure.engine.guided_dast.strategies.idor_targeted import (
    IDORTargetedStrategy,
)
from isitsecure.engine.guided_dast.strategies.injection_targeted import (
    InjectionTargetedStrategy,
)
from isitsecure.engine.guided_dast.strategies.mass_assignment import (
    MassAssignmentSchemaStrategy,
)
from isitsecure.engine.guided_dast.strategies.race_condition import (
    RaceConditionStrategy,
)
from isitsecure.engine.guided_dast.strategies.rls_bypass import (
    RLSBypassStrategy,
)
from isitsecure.engine.scanners.active_injection_scanner import (
    ActiveInjectionScanner,
)
from isitsecure.engine.scanners.auth_bypass_scanner import (
    AuthBypassScanner,
)
from isitsecure.engine.scanners.csrf_scanner import CSRFScanner
from isitsecure.engine.scanners.http_probe_scanner import (
    HTTPProbeScanner,
)
from isitsecure.engine.scanners.endpoint_discovery import (
    EndpointDiscoveryScanner,
)
from isitsecure.engine.scanners.file_upload_scanner import (
    FileUploadScanner,
)
from isitsecure.engine.scanners.graphql_scanner import GraphQLScanner
from isitsecure.engine.scanners.idor_scanner import IDORScanner
from isitsecure.engine.scanners.jwt_scanner import JWTScanner
from isitsecure.engine.scanners.mass_assignment_scanner import (
    MassAssignmentScanner,
)
from isitsecure.engine.scanners.password_reset_scanner import (
    PasswordResetScanner,
)
from isitsecure.engine.scanners.privilege_escalation_scanner import (
    PrivilegeEscalationScanner,
)
from isitsecure.engine.scanners.rate_limit_scanner import (
    RateLimitScanner,
)
from isitsecure.engine.scanners.rls_deep_scanner import RLSDeepScanner
from isitsecure.engine.scanners.security_headers_scanner import (
    SecurityHeadersScanner,
)
from isitsecure.engine.scanners.session_scanner import SessionScanner
from isitsecure.engine.scanners.cors_scanner import CORSScanner
from isitsecure.engine.scanners.open_redirect_scanner import (
    OpenRedirectScanner,
)
from isitsecure.engine.scanners.ssrf_scanner import SSRFScanner
from isitsecure.engine.scanners.xss_scanner import XSSScanner
from isitsecure.engine.ingestion.url_ingestion import URLIngestionService

if TYPE_CHECKING:
    from isitsecure.engine.auth.protocols import AuthProviderProtocol
    from isitsecure.llm.protocol import LLMClientProtocol


def create_repo_ingestion_service():
    """Create a fully wired RepoIngestionService with monorepo support.

    SRP: Separated from agent creation — repo ingestion wiring is its
    own concern.

    Returns:
        A RepoIngestionService configured with workspace detection and
        all available route mappers.
    """
    from isitsecure.engine.code_analysis.framework_detector import (
        FrameworkDetector,
    )
    from isitsecure.engine.code_analysis.repo_ingestion import (
        RepoIngestionService,
    )
    from isitsecure.engine.code_analysis.express_route_mapper import (
        ExpressRouteMapper,
    )
    from isitsecure.engine.code_analysis.route_mapper import (
        NextJSRouteMapper,
    )
    from isitsecure.engine.code_analysis.trpc_route_mapper import (
        TRPCRouteMapper,
    )
    from isitsecure.engine.code_analysis.graphql_route_mapper import (
        GraphQLRouteMapper,
    )
    from isitsecure.engine.code_analysis.django_route_mapper import (
        DjangoRouteMapper,
    )
    from isitsecure.engine.code_analysis.fastapi_route_mapper import (
        FastAPIRouteMapper,
    )
    from isitsecure.engine.code_analysis.spring_route_mapper import (
        SpringRouteMapper,
    )
    from isitsecure.engine.code_analysis.workspace_detector import (
        WorkspaceDetector,
    )

    framework_detector = FrameworkDetector()

    # OCP: add new route mappers here without modifying RepoIngestionService
    route_mappers = [
        NextJSRouteMapper(),
        ExpressRouteMapper(),
        TRPCRouteMapper(),
        GraphQLRouteMapper(),
        DjangoRouteMapper(),
        FastAPIRouteMapper(),
        SpringRouteMapper(),
    ]

    workspace_detector = WorkspaceDetector(
        framework_detector=framework_detector,
    )

    return RepoIngestionService(
        framework_detector=framework_detector,
        route_mappers=route_mappers,
        workspace_detector=workspace_detector,
    )


def create_deep_security_scan_agent(
    llm_client: LLMClientProtocol | None = None,
    judgment_llm_client: LLMClientProtocol | None = None,
    repo_ingestion_service=None,
    auth_provider: AuthProviderProtocol | None = None,
) -> DeepSecurityScanAgent:
    """Create a fully wired DeepSecurityScanAgent with all scanners.

    All concrete dependencies are instantiated here, keeping the agent
    and scanners dependent only on abstractions (DIP).

    Args:
        llm_client: Primary LLM client for code review and attack planning
            (should be the most capable model, e.g., Opus).
        judgment_llm_client: Optional faster/cheaper LLM for triage and
            result judgment (e.g., Sonnet). Falls back to llm_client.
        repo_ingestion_service: Optional service for cloning and indexing repos.
        auth_provider: Optional auth provider for authenticated scanning.
    """
    # Judgment client falls back to the primary client
    _judgment_client = judgment_llm_client or llm_client

    # Conditional import — only needed if llm_client is provided
    llm_code_reviewer = None
    llm_triage = None
    if llm_client:
        from isitsecure.engine.code_analysis.llm_code_reviewer import (
            LLMCodeReviewer,
        )
        from isitsecure.engine.code_analysis.semantic_rule_verifier import (
            SemanticRuleVerifier,
        )
        from isitsecure.engine.triage.llm_triage_service import (
            LLMTriageService,
        )
        # Code review uses the planning model (most capable)
        llm_code_reviewer = LLMCodeReviewer(llm_client)
        # Triage uses the judgment model (faster/cheaper)
        llm_triage = LLMTriageService(_judgment_client)

    # OCP: new scanners are added to these lists — no agent code changes needed
    dast_scanners = [
        XSSScanner(),
        ActiveInjectionScanner(),
        CSRFScanner(),
        RateLimitScanner(),
        SessionScanner(),
        GraphQLScanner(),
        SSRFScanner(),
        FileUploadScanner(),
        MassAssignmentScanner(),
        SecurityHeadersScanner(),
        CORSScanner(),
        OpenRedirectScanner(),
        AuthBypassScanner(),
        HTTPProbeScanner(),
        PasswordResetScanner(),
    ]

    sast_scanners = [
        GitSecretScanner(),
        RouteAuthAnalyzer(),
        RLSPolicyAnalyzer(),
        MiddlewareAnalyzer(),
        ExpressMiddlewareAnalyzer(),
        DrizzleSchemaAnalyzer(),
        PrismaSchemaAnalyzer(),
        IaCScanner(),
        DockerScanner(),
        ShellScriptScanner(),
        DependencyScanner(),
        PythonDependencyScanner(),
        JavaDependencyScanner(),
        FirebaseRulesAnalyzer(),
        OpenAPIScanner(),
        K8sScanner(),
    ]

    # LLM-powered semantic rule verifier (only if LLM client is available)
    if llm_client:
        sast_scanners.append(SemanticRuleVerifier(llm_client))

    # SAST-guided DAST strategies (OCP — add new strategies to this list)
    guided_dast_strategies = [
        AuthBypassGuidedStrategy(),
        IDORTargetedStrategy(),
        MassAssignmentSchemaStrategy(),
        RaceConditionStrategy(),
        InjectionTargetedStrategy(),
        RLSBypassStrategy(),
    ]
    guided_dast_runner = SASTGuidedDASTRunner(guided_dast_strategies)

    # LSP client — auto-detect Node.js availability (DIP: graceful degradation)
    lsp_client = _create_lsp_client()

    return DeepSecurityScanAgent(
        # Required
        ingestion_service=URLIngestionService(),
        endpoint_scanner=EndpointDiscoveryScanner(),
        # Scanner lists (OCP)
        dast_scanners=dast_scanners,
        sast_scanners=sast_scanners,
        # Special scanners with non-standard scan() signatures
        idor_scanner=IDORScanner(),
        jwt_scanner=JWTScanner(),
        rls_deep_scanner=RLSDeepScanner(),
        privilege_escalation_scanner=PrivilegeEscalationScanner(),
        # LLM reviewer
        llm_code_reviewer=llm_code_reviewer,
        # Repo + Auth
        repo_ingestion_service=repo_ingestion_service,
        auth_provider=auth_provider,
        # Cross-referencing
        cross_referencer=FindingCrossReferencer(),
        # SAST-guided DAST
        guided_dast_runner=guided_dast_runner,
        # LSP (optional — NoOp if Node.js unavailable)
        lsp_client=lsp_client,
        # LLM triage (dedup, enrich, prioritize, owner summary)
        llm_triage=llm_triage,
        # Judgment LLM (faster model for result analysis)
        judgment_llm_client=_judgment_client,
    )


def _create_lsp_client():
    """Create an LSP client with auto-detection.

    Tries language servers in order:
    1. TypeScript (typescript-language-server) — for JS/TS projects
    2. Python (pylsp / pyright) — for Python projects
    3. Java (jdtls) — for Java/Kotlin projects
    4. NoOpLSPClient — graceful fallback

    The agent will initialize the first available client at scan time
    based on the detected framework.

    SRP: LSP client selection is isolated from agent creation.
    """
    import shutil

    from isitsecure.engine.code_analysis.lsp.noop_client import (
        NoOpLSPClient,
    )
    from isitsecure.engine.code_analysis.lsp.tsserver_client import (
        TypeScriptLSPClient,
    )
    from isitsecure.engine.code_analysis.lsp.python_client import (
        PythonLSPClient,
    )
    from isitsecure.engine.code_analysis.lsp.java_client import (
        JavaLSPClient,
    )

    # Try TypeScript LSP first (most common for target audience)
    if TypeScriptLSPClient.is_node_available():
        has_ts_ls = shutil.which("typescript-language-server") is not None
        has_npx = shutil.which("npx") is not None

        if has_ts_ls or has_npx:
            logger.info(
                "LSP ENABLED: TypeScript Language Server "
                "(typescript-language-server=%s, npx=%s)",
                "yes" if has_ts_ls else "no",
                "yes" if has_npx else "no",
            )
            return TypeScriptLSPClient()

    # Try Python LSP
    if PythonLSPClient.is_server_available():
        logger.info("LSP ENABLED: Python Language Server (pylsp/pyright)")
        return PythonLSPClient()

    # Try Java LSP
    if JavaLSPClient.is_runtime_available() and JavaLSPClient.is_server_available():
        logger.info("LSP ENABLED: Java Language Server (jdtls)")
        return JavaLSPClient()

    logger.warning(
        "LSP DISABLED: No language server found. "
        "Install one of: npm install -g typescript-language-server, "
        "pip install python-lsp-server, or install jdtls. "
        "Scan will use regex-only analysis (higher false positive rate)."
    )
    return NoOpLSPClient()
