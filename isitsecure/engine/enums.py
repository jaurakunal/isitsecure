"""Enums for the isitsecure security scanner.

Includes both the deep scan enums and the finding classification enums
(originally from security_audit) unified into a single module.
"""

from enum import Enum


# ---------------------------------------------------------------------------
# Finding classification enums (inlined from security_audit)
# ---------------------------------------------------------------------------


class SeverityLevel(str, Enum):
    """Severity classification for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    """Categories of security findings."""

    EXPOSED_SECRETS = "exposed_secrets"
    MISSING_HEADERS = "missing_headers"
    DEAD_FUNCTIONALITY = "dead_functionality"
    DEPENDENCY_VULNERABILITY = "dependency_vuln"
    CLIENT_EXPOSURE = "client_exposure"
    SOURCE_MAP_LEAK = "source_map_leak"
    AUTH_WEAKNESS = "auth_weakness"
    INJECTION_RISK = "injection_risk"
    RLS_MISCONFIGURATION = "rls_misconfiguration"
    UNENCRYPTED_PII = "unencrypted_pii"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    OPEN_REDIRECT = "open_redirect"
    EXPOSED_API_ENDPOINT = "exposed_api_endpoint"
    MISSING_SRI = "missing_sri"
    MIXED_CONTENT = "mixed_content"
    INFO_DISCLOSURE = "info_disclosure"
    IDOR = "idor"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class AssetType(str, Enum):
    """Types of web assets captured during ingestion."""

    HTML = "html"
    JAVASCRIPT = "javascript"
    CSS = "css"
    SOURCE_MAP = "source_map"
    CONFIG_FILE = "config_file"


# ---------------------------------------------------------------------------
# Deep scan enums
# ---------------------------------------------------------------------------


class DeepScanPhase(str, Enum):
    """Phases of the deep security scan pipeline."""

    INITIALIZING = "initializing"
    INGESTING_URL = "ingesting_url"
    DISCOVERING_ENDPOINTS = "discovering_endpoints"
    CLASSIFYING_ENDPOINTS = "classifying_endpoints"
    TESTING_IDOR = "testing_idor"
    ANALYZING_RESULTS = "analyzing_results"
    COMPLETE = "complete"

    # LSP analysis phases
    LSP_INITIALIZATION = "lsp_initialization"
    LSP_VALIDATION = "lsp_validation"

    # Unified orchestrator phases
    FREE_SCAN = "free_scan"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED_CRAWL = "authenticated_crawl"
    DAST_SCANNING = "dast_scanning"
    CODE_INGESTION = "code_ingestion"
    SAST_SCANNING = "sast_scanning"
    LLM_REVIEW = "llm_review"
    CROSS_REFERENCING = "cross_referencing"
    SAST_GUIDED_DAST = "sast_guided_dast"
    LLM_BUSINESS_LOGIC = "llm_business_logic"
    TRIAGE = "triage"
    REPORT_GENERATION = "report_generation"


class ScanMode(str, Enum):
    """Scan mode determines which scanners run."""

    URL_ONLY = "url_only"
    AUTHENTICATED = "authenticated"
    CODE_ONLY = "code_only"
    FULL = "full"


class EndpointMethod(str, Enum):
    """HTTP methods discovered for API endpoints."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class IDORTestType(str, Enum):
    """Types of IDOR tests performed."""

    PATH_PARAM_SWAP = "path_param_swap"
    QUERY_PARAM_SWAP = "query_param_swap"
    BODY_PARAM_SWAP = "body_param_swap"
    UNAUTHED_ACCESS = "unauthed_access"
    SEQUENTIAL_ID_ENUM = "sequential_id_enum"
    CROSS_USER_READ = "cross_user_read"
    CROSS_USER_WRITE = "cross_user_write"
    CROSS_USER_DELETE = "cross_user_delete"
    FULL_TABLE_SELECT = "full_table_select"
    MUTATION_PUT_PATCH = "mutation_put_patch"
    MUTATION_DELETE = "mutation_delete"


class IDORRiskLevel(str, Enum):
    """Risk classification for IDOR findings."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    SAFE = "safe"


class EndpointCategory(str, Enum):
    """Semantic category of discovered endpoints."""

    USER_DATA = "user_data"
    RESOURCE_CRUD = "resource_crud"
    AUTH = "auth"
    ADMIN = "admin"
    PUBLIC = "public"
    FILE_ACCESS = "file_access"
    PAYMENT = "payment"
    UNKNOWN = "unknown"


class AuthProvider(str, Enum):
    """Authentication provider types supported for deep security scanning."""

    SUPABASE = "supabase"
    FIREBASE = "firebase"
    BROWSER = "browser"
    TOKEN = "token"


class FrameworkType(str, Enum):
    """Detected web framework."""

    NEXTJS = "nextjs"
    REMIX = "remix"
    SVELTEKIT = "sveltekit"
    NUXT = "nuxt"
    ASTRO = "astro"
    EXPRESS = "express"
    UNKNOWN = "unknown"


class BackendType(str, Enum):
    """Detected backend/database provider."""

    SUPABASE = "supabase"
    FIREBASE = "firebase"
    PRISMA = "prisma"
    DRIZZLE = "drizzle"
    TRPC = "trpc"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class WorkspaceType(str, Enum):
    """Classification of a workspace within a monorepo."""

    FRONTEND = "frontend"
    BACKEND = "backend"
    LAMBDA = "lambda"
    INFRASTRUCTURE = "infrastructure"
    SHARED = "shared"
    UNKNOWN = "unknown"


class VerificationMethod(str, Enum):
    """Methods for verifying target ownership before scanning."""

    DNS_TXT = "dns_txt"
    META_TAG = "meta_tag"
    FILE = "file"
    GITHUB = "github"
    MANUAL = "manual"


class VerificationStatus(str, Enum):
    """Status of ownership verification."""

    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    SKIPPED = "skipped"


class CICDProvider(str, Enum):
    """Supported CI/CD providers."""

    GITHUB_ACTIONS = "github_actions"
    VERCEL = "vercel"
    NETLIFY = "netlify"


class WebhookEventType(str, Enum):
    """Events that trigger CI/CD scans."""

    DEPLOYMENT = "deployment"
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    MANUAL = "manual"


class PlanTier(str, Enum):
    """Customer plan tiers."""

    FREE = "free"
    PRO = "pro"
    CERTIFICATION = "certification"


class ScanStatus(str, Enum):
    """Status of a scan execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanTrigger(str, Enum):
    """What triggered the scan."""

    MANUAL = "manual"
    CI_CD = "ci_cd"
    SCHEDULED = "scheduled"
    WEBHOOK = "webhook"


class ImpactCategory(str, Enum):
    """Business impact classification for findings.

    Used alongside ``LikelihoodLevel`` to derive priority.
    """

    FINANCIAL = "financial"
    DATA_BREACH = "data_breach"
    LEGAL = "legal"
    OPERATIONAL = "operational"
    REPUTATIONAL = "reputational"


class LikelihoodLevel(str, Enum):
    """Exploitability classification for findings.

    Used alongside ``ImpactCategory`` to derive priority.
    """

    ACTIVELY_EXPLOITABLE = "actively_exploitable"
    REQUIRES_AUTH = "requires_auth"
    REQUIRES_ADMIN = "requires_admin"
    THEORETICAL = "theoretical"


class ReviewTriggerType(str, Enum):
    """Why a route was selected for LLM review.

    Priority order (lower value = reviewed first when token budget is limited):
    FINANCIAL_OPERATION > CROSS_SCANNER_FLAGGED > STATE_MUTATION > RISK_INDICATOR
    """

    FINANCIAL_OPERATION = "financial_operation"
    CROSS_SCANNER_FLAGGED = "cross_scanner_flagged"
    STATE_MUTATION = "state_mutation"
    RISK_INDICATOR = "risk_indicator"
    IMPORT_GRAPH_CENTRALITY = "import_graph_centrality"
    INJECTION_PATTERN_FLAG = "injection_pattern_flag"
