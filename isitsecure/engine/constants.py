"""Configuration constants for the Deep Security Scan Agent."""

from isitsecure.engine.enums import FindingCategory, SeverityLevel


class SharedPatterns:
    """Shared regex patterns and constants used across multiple scanners."""

    UUID_PATTERN = (
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    )
    NUMERIC_ID_PATTERN = r'\b\d{1,10}\b'
    BEARER_PREFIX = "Bearer "
    HEADER_AUTHORIZATION = "Authorization"
    HEADER_APIKEY = "apikey"
    HEADER_CONTENT_TYPE = "Content-Type"
    CONTENT_TYPE_JSON = "application/json"
    HEADER_USER_AGENT = "User-Agent"
    DEFAULT_HTTP_TIMEOUT_SECONDS = 10
    DEFAULT_MAX_CONCURRENT = 3
    DEFAULT_PROBE_DELAY = 0.3
    SAFE_PATCH_BODY = "{}"
    SAFE_PATCH_PREFER = "return=minimal"
    RESPONSE_PREVIEW_LENGTH = 300


class CommonAuthPatterns:
    """Auth check patterns shared between route analyzer and middleware analyzer."""

    COMMON_AUTH_PATTERNS = (
        r'getUser\s*\(',
        r'getSession\s*\(',
        r'auth\s*\(\s*\)',
        r'verifyToken\s*\(',
        r'validateSession\s*\(',
        r'cookies\s*\(\s*\)\s*\.get',
    )


class HTTPStatusCodes:
    """Shared HTTP status code constants used across all DAST scanners.

    DRY: Avoids each scanner defining its own status code constants.
    """

    OK_MIN = 200
    OK_MAX = 299
    REDIRECT_MIN = 300
    REDIRECT_MAX = 399
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    TOO_MANY_REQUESTS = 429
    LOCKED = 423
    SERVER_ERROR_MIN = 500

    @classmethod
    def is_success(cls, status: int) -> bool:
        """Check if status code indicates success (2xx)."""
        return cls.OK_MIN <= status <= cls.OK_MAX

    @classmethod
    def is_redirect(cls, status: int) -> bool:
        """Check if status code indicates redirect (3xx)."""
        return cls.REDIRECT_MIN <= status <= cls.REDIRECT_MAX


class DeepScanConfig:
    """Top-level configuration for deep security scanning."""

    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    HTTP_TIMEOUT_SECONDS = 15
    MAX_CONCURRENT_PROBES = 5
    SCAN_TIMEOUT_SECONDS = 300


class EndpointDiscoveryConfig:
    """Configuration for API endpoint discovery from JS bundles."""

    MAX_ENDPOINTS_TO_DISCOVER = 100
    MAX_JS_BUNDLE_SIZE_BYTES = 10 * 1024 * 1024  # 10MB

    # --- Regex patterns for extracting endpoints from JS ---

    # fetch("url") / fetch('url')
    FETCH_PATTERN = r'fetch\s*\(\s*["\']([^"\']+)["\']'

    # fetch(url, { method: "POST" }) — captures URL and method
    FETCH_WITH_METHOD_PATTERN = (
        r'fetch\s*\(\s*["\']([^"\']+)["\']\s*,\s*\{[^}]*'
        r'method\s*:\s*["\'](\w+)["\']'
    )

    # axios.get/post/put/delete("url")
    AXIOS_PATTERN = r'axios\.(\w+)\s*\(\s*["\']([^"\']+)["\']'

    # XMLHttpRequest .open("METHOD", "url")
    XHR_PATTERN = (
        r'\.open\s*\(\s*["\']([A-Z]+)["\']\s*,\s*["\']([^"\']+)["\']'
    )

    # Generic API path literals: "/api/...", "/v1/...", "/v2/..."
    API_PATH_PATTERN = r'["\'](/?(?:api|rest|graphql|v[0-9]+)/[a-zA-Z0-9_/\-]+)(?:\?[^"\']*)?["\']'
    # Interpolated / template-literal API paths, e.g. `${server}/rest/products/search?q=${e}`.
    # Matches a /api|/rest|... path that follows a template-interpolation `}` or a backtick.
    TEMPLATE_API_PATH_PATTERN = r'[`}](/(?:api|rest|graphql|v[0-9]+)/[a-zA-Z0-9_\-/]+)'

    # Supabase RPC / REST calls: .from("table") or .rpc("function")
    SUPABASE_FROM_PATTERN = r'\.from\s*\(\s*["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']'
    SUPABASE_RPC_PATTERN = r'\.rpc\s*\(\s*["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']'

    # REST-style URL patterns with path params: /users/:id, /items/{id}
    PATH_PARAM_COLON_PATTERN = r'["\'](/[a-zA-Z0-9_/\-]*:[a-zA-Z_]+[a-zA-Z0-9_/\-]*)["\']'
    PATH_PARAM_BRACE_PATTERN = (
        r'["\'](/[a-zA-Z0-9_/\-]*\{[a-zA-Z_]+\}[a-zA-Z0-9_/\-]*)["\']'
    )

    # Paths to skip (static assets, known SDKs, analytics)
    SKIP_PATH_PREFIXES = (
        "/assets/",
        "/static/",
        "/_next/",
        "/favicon",
        "/manifest",
        "/robots.txt",
        "/sitemap",
        "/.well-known/",
        "/fonts/",
        "/images/",
        "/img/",
    )

    # Route path patterns found in minified JS (Next.js, React Router, etc.)
    ROUTE_PATH_PATTERN = r'"(/[a-zA-Z][a-zA-Z0-9_/\-]{2,50})"'

    # External API base URL pattern (e.g., https://api.example.com)
    EXTERNAL_API_URL_PATTERN = (
        r'(https?://(?:api|backend|server|gateway)[a-zA-Z0-9.\-]*\.[a-zA-Z]{2,})'
    )

    # Supabase project URL pattern
    SUPABASE_URL_PATTERN = r'(https://[a-zA-Z0-9]+\.supabase\.co)'

    # Supabase Edge Function pattern
    SUPABASE_EDGE_FUNCTION_PATTERN = r'functions/v1/([a-zA-Z0-9_\-]+)'

    # Auth-related method patterns (to detect auth flows)
    AUTH_METHOD_PATTERNS = (
        r'auth\.sign\w+',
        r'signIn|signUp|signOut',
        r'getSession|getUser',
    )

    # Common API paths to probe on discovered API base URLs
    COMMON_API_PROBE_PATHS = (
        "/api",
        "/api/v1",
        "/v1",
        "/graphql",
        "/health",
        "/status",
        "/users",
        "/me",
        "/profile",
        "/accounts",
        "/listings",
        "/products",
        "/orders",
        "/docs",
        "/openapi.json",
        "/swagger.json",
        "/.well-known/openapi",
    )

    # Supabase anon key pattern (full JWT: header.payload.signature)
    SUPABASE_ANON_KEY_PATTERN = (
        r'(eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)'
    )

    # Supabase REST paths to probe
    SUPABASE_PROBE_PATHS = (
        "/rest/v1/",  # OpenAPI spec (lists all tables)
    )

    # Third-party domains to skip
    SKIP_DOMAINS = (
        "googleapis.com",
        "google-analytics.com",
        "googletagmanager.com",
        "facebook.com",
        "twitter.com",
        "cdn.jsdelivr.net",
        "unpkg.com",
        "cloudflare.com",
        "sentry.io",
        "amplitude.com",
        "segment.com",
        "mixpanel.com",
        "hotjar.com",
        "intercom.io",
        "stripe.com",
    )


class IDORConfig:
    """Configuration for IDOR vulnerability testing."""

    MAX_ENDPOINTS_TO_TEST = 50
    MAX_IDOR_PROBES_PER_ENDPOINT = 5
    HTTP_TIMEOUT_SECONDS = SharedPatterns.DEFAULT_HTTP_TIMEOUT_SECONDS
    MAX_CONCURRENT_PROBES = SharedPatterns.DEFAULT_MAX_CONCURRENT
    PROBE_DELAY_SECONDS = 0.5  # Rate limiting between probes

    # Confidence thresholds
    CONFIDENCE_CONFIRMED_IDOR = 0.95
    CONFIDENCE_LIKELY_IDOR = 0.80
    CONFIDENCE_POSSIBLE_IDOR = 0.60

    # Response comparison thresholds
    RESPONSE_SIMILARITY_THRESHOLD = 0.9  # Bodies >90% similar = likely same object
    MIN_RESPONSE_SIZE_BYTES = 10  # Ignore trivially small responses

    # ID patterns to detect in URLs (path segments and query params)
    NUMERIC_ID_PATTERN = SharedPatterns.NUMERIC_ID_PATTERN
    UUID_PATTERN = SharedPatterns.UUID_PATTERN
    SHORT_HASH_PATTERN = r'[0-9a-f]{8,32}'

    # Test IDs for probing — swap real IDs with these
    NUMERIC_TEST_IDS = ["1", "2", "99999", "0"]
    UUID_TEST_ID = "00000000-0000-0000-0000-000000000000"
    HASH_TEST_ID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

    # Query params commonly used for object references
    ID_QUERY_PARAMS = (
        "id",
        "user_id",
        "userId",
        "account_id",
        "accountId",
        "org_id",
        "orgId",
        "project_id",
        "projectId",
        "order_id",
        "orderId",
        "item_id",
        "itemId",
        "resource_id",
        "resourceId",
        "document_id",
        "documentId",
        "file_id",
        "fileId",
        "record_id",
        "recordId",
        "slug",
        "uid",
        "uuid",
    )

    # Path segments that typically precede an ID
    ID_PATH_INDICATORS = (
        "users",
        "user",
        "accounts",
        "account",
        "profiles",
        "profile",
        "orders",
        "order",
        "items",
        "item",
        "projects",
        "project",
        "documents",
        "document",
        "files",
        "file",
        "records",
        "record",
        "organizations",
        "org",
        "teams",
        "team",
        "workspaces",
        "workspace",
        "listings",
        "listing",
        "products",
        "product",
        "invoices",
        "invoice",
        "marketplace",
        "apps",
        "deals",
        "agents",
        "services",
        "resources",
        "posts",
        "comments",
        "reviews",
        "subscriptions",
        "transactions",
    )

    # Evidence truncation
    MAX_EVIDENCE_LENGTH = 500
    MAX_RESPONSE_BODY_LOG = 300

    # --- Mutation IDOR testing ---
    MUTATION_SAFE_BODY = '{"_test": true}'
    MUTATION_PREFER_HEADER = "return=minimal"
    MUTATION_CONTENT_TYPE = "application/json"
    MUTATION_HTTP_TIMEOUT_SECONDS = 10
    MAX_MUTATION_PROBES_PER_ENDPOINT = 3

    # HTTP methods that indicate state-changing endpoints
    MUTATION_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
    # Methods to attempt for mutation IDOR
    MUTATION_WRITE_METHODS = ("PUT", "PATCH")
    MUTATION_DELETE_METHOD = "DELETE"

    # Confidence for mutation IDOR findings
    CONFIDENCE_MUTATION_WRITE_IDOR = 0.95
    CONFIDENCE_MUTATION_DELETE_IDOR = 0.98

    # Finding titles / descriptions for mutation IDOR
    TITLE_MUTATION_WRITE_IDOR = (
        "Mutation IDOR — unauthorized resource update via swapped ID"
    )
    TITLE_MUTATION_DELETE_IDOR = (
        "Mutation IDOR — unauthorized resource deletion via swapped ID"
    )
    DESC_MUTATION_WRITE_IDOR = (
        "A {method} request to {url} with a swapped resource ID returned "
        "status {status}, suggesting the endpoint allows updating another "
        "user's resource without proper authorization."
    )
    DESC_MUTATION_DELETE_IDOR = (
        "A DELETE request to {url} with a swapped resource ID returned "
        "status {status}. The server may have accepted the deletion of "
        "another user's resource without authorization."
    )

    # Error messages
    ERROR_TIMEOUT = "IDOR probe timed out for endpoint: {endpoint}"
    ERROR_CONNECTION = "Connection failed for IDOR probe: {endpoint}"
    ERROR_SCAN_FAILED = "IDOR scanner failed: {error}"


class SupabaseAuthConfig:
    """Configuration constants for Supabase authentication."""

    AUTH_TOKEN_ENDPOINT = "/auth/v1/token?grant_type=password"
    AUTH_REFRESH_ENDPOINT = "/auth/v1/token?grant_type=refresh_token"
    AUTH_USER_ENDPOINT = "/auth/v1/user"
    HTTP_TIMEOUT_SECONDS = SharedPatterns.DEFAULT_HTTP_TIMEOUT_SECONDS

    HEADER_APIKEY = SharedPatterns.HEADER_APIKEY
    HEADER_CONTENT_TYPE = SharedPatterns.HEADER_CONTENT_TYPE
    HEADER_AUTHORIZATION = SharedPatterns.HEADER_AUTHORIZATION
    CONTENT_TYPE_JSON = SharedPatterns.CONTENT_TYPE_JSON
    BEARER_PREFIX = SharedPatterns.BEARER_PREFIX

    ERROR_AUTH_FAILED = "Authentication failed: {error}"
    ERROR_INVALID_CREDENTIALS = "Invalid email or password"
    ERROR_TOKEN_EXPIRED = "Session expired, refresh failed"
    ERROR_MISSING_CREDENTIALS = "Email and password are required for Supabase auth"
    ERROR_MISSING_SUPABASE_URL = "Supabase URL is required"
    ERROR_MISSING_ANON_KEY = "Supabase anon key is required"
    ERROR_MISSING_REFRESH_TOKEN = "Refresh token is required to refresh session"


class BrowserLoginConfig:
    """Shared constants for browser-based login (form-filling + token extraction).

    Used by both BrowserAuthProvider and AuthenticatedCrawler via
    BrowserLoginHelper to ensure a single source of truth for selectors,
    timeouts, and token keys.
    """

    # Timeouts
    NAVIGATION_TIMEOUT_MS = 25000
    LOGIN_WAIT_TIMEOUT_MS = 15000
    NETWORK_IDLE_TIMEOUT_MS = 10000
    POST_LOGIN_SETTLE_MS = 5000
    MIN_TOKEN_LENGTH = 20

    # Form selectors (tried in order)
    EMAIL_INPUT_SELECTORS = (
        'input[type="email"]',
        'input[name="email"]',
        'input[autocomplete="email"]',
        'input[autocomplete="username"]',
        '#email',
        'input[placeholder*="email" i]',
    )
    PASSWORD_INPUT_SELECTORS = (
        'input[type="password"]',
        'input[name="password"]',
        '#password',
    )
    SUBMIT_BUTTON_SELECTORS = (
        'button[type="submit"]',
        'input[type="submit"]',
        'button:has-text("Sign in")',
        'button:has-text("Log in")',
        'button:has-text("Login")',
        'button:has-text("Sign In")',
        'button:has-text("Continue")',
    )

    # Login page URL indicators (used to detect if we're still on the login page)
    LOGIN_PAGE_INDICATORS = ("/login", "/signin", "/sign-in", "/auth")

    # Token extraction from browser storage
    LOCAL_STORAGE_TOKEN_KEYS = (
        "access_token", "token", "auth_token", "jwt", "sb-access-token",
    )
    SESSION_STORAGE_TOKEN_KEYS = (
        "access_token", "token", "auth_token", "jwt",
    )
    LOCAL_STORAGE_KEY_INDICATORS = ("auth", "supabase", "session", "token")

    # JSON token parsing keys
    JSON_TOKEN_KEYS = ("access_token", "token")
    JSON_SESSION_WRAPPER_KEYS = ("currentSession", "session")

    # Error messages
    ERROR_LOGIN_FAILED = "Browser login failed: {error}"
    ERROR_NO_TOKEN_FOUND = "No auth token found after login"


class BrowserAuthConfig:
    """Provider-specific constants for BrowserAuthProvider (standalone auth)."""

    DEFAULT_USER_ID = "browser-user"
    HEADER_AUTHORIZATION = SharedPatterns.HEADER_AUTHORIZATION
    BEARER_PREFIX = SharedPatterns.BEARER_PREFIX

    ERROR_PLAYWRIGHT_MISSING = (
        "playwright is required for browser auth. "
        "Install with: pip install playwright && playwright install chromium"
    )
    ERROR_NAVIGATION_FAILED = "Failed to navigate to login URL: {error}"
    ERROR_MISSING_LOGIN_URL = "Login URL is required for browser auth"
    ERROR_MISSING_CREDENTIALS = "Email and password are required for browser auth"
    ERROR_REFRESH_NOT_SUPPORTED = "Browser auth does not support token refresh"


class TokenAuthConfig:
    """Configuration constants for direct token authentication."""

    DEFAULT_USER_ID = "unknown"

    # JWT claim keys
    JWT_CLAIM_SUB = "sub"
    JWT_CLAIM_EMAIL = "email"
    JWT_CLAIM_EXP = "exp"
    JWT_CLAIM_USER_ID = "user_id"

    ERROR_MISSING_TOKEN = "Access token is required for token auth"
    ERROR_INVALID_JWT = "Failed to decode JWT: {error}"
    ERROR_REFRESH_NOT_SUPPORTED = "Token auth does not support token refresh"

    JWT_PARTS_COUNT = 3
    JWT_PAYLOAD_INDEX = 1
    HEADER_AUTHORIZATION = SharedPatterns.HEADER_AUTHORIZATION
    BEARER_PREFIX = SharedPatterns.BEARER_PREFIX


class RepoIngestionConfig:
    """Configuration for repository ingestion."""

    CLONE_TIMEOUT_SECONDS = 120
    MAX_REPO_SIZE_MB = 500
    MAX_FILE_SIZE_BYTES = 500_000  # Skip files larger than 500KB

    # Key files to always index
    KEY_FILE_NAMES = (
        "middleware.ts",
        "middleware.js",
        "next.config.js",
        "next.config.ts",
        "next.config.mjs",
        ".env",
        ".env.local",
        ".env.production",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "firestore.rules",
        "storage.rules",
        "database.rules.json",
        "Dockerfile",
        "Dockerfile.dev",
        "docker-compose.yml",
        "docker-compose.yaml",
        "turbo.json",
        "pnpm-workspace.yaml",
        "drizzle.config.ts",
        "drizzle.config.js",
        "schema.prisma",
        "openapi.yaml",
        "openapi.json",
        "swagger.yaml",
        "swagger.json",
        "Chart.yaml",
        "values.yaml",
        # Python projects
        "requirements.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "manage.py",
        "urls.py",
        "settings.py",
        "wsgi.py",
        # Java/Kotlin projects
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "application.properties",
        "application.yml",
    )

    # Directories to skip during indexing
    SKIP_DIRECTORIES = (
        "node_modules",
        ".git",
        ".next",
        "dist",
        "build",
        ".vercel",
        ".netlify",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".mypy_cache",
        ".pytest_cache",
        ".gradle",
        "target",
        ".turbo",
        "coverage",
        ".nyc_output",
    )

    # File extensions to index for code analysis
    CODE_EXTENSIONS = (
        ".ts", ".tsx", ".js", ".jsx", ".mjs", ".sql",
        ".tf", ".tfvars", ".sh", ".prisma",
        ".graphql", ".gql",
        ".py",  # Python support
        ".java", ".kt",  # Java/Kotlin support
    )

    ERROR_CLONE_FAILED = "Failed to clone repository: {error}"
    ERROR_CLONE_TIMEOUT = "Repository clone timed out after {timeout}s"
    ERROR_REPO_TOO_LARGE = "Repository exceeds maximum size of {max_size}MB"
    ERROR_BRANCH_NOT_FOUND = "Branch '{branch}' not found in repository"


class FrameworkDetectorConfig:
    """Configuration for framework and backend detection."""

    FRAMEWORK_INDICATORS = {
        "nextjs": {"package": "next", "section": "dependencies"},
        "remix": {"package": "@remix-run/node", "section": "dependencies"},
        "sveltekit": {"package": "@sveltejs/kit", "section": "dependencies"},
        "nuxt": {"package": "nuxt", "section": "dependencies"},
        "astro": {"package": "astro", "section": "dependencies"},
        "express": {"package": "express", "section": "dependencies"},
    }

    BACKEND_INDICATORS = {
        "supabase": {"package": "@supabase/supabase-js", "section": "dependencies"},
        "firebase": {"package": "firebase", "section": "dependencies"},
        "prisma": {"package": "prisma", "section": "devDependencies"},
        "drizzle": {"package": "drizzle-orm", "section": "dependencies"},
        "trpc": {"package": "@trpc/server", "section": "dependencies"},
    }

    AUTH_INDICATORS = {
        "supabase_auth": "@supabase/auth-helpers-nextjs",
        "supabase_ssr": "@supabase/ssr",
        "nextauth": "next-auth",
        "clerk": "@clerk/nextjs",
        "auth0": "@auth0/nextjs-auth0",
        "lucia": "lucia",
    }


class RouteMapperConfig:
    """Configuration for Next.js route mapping."""

    # App Router route file patterns
    APP_ROUTER_ROUTE_FILES = ("route.ts", "route.js")

    # Pages Router API directory
    PAGES_API_DIR = "pages/api"

    # Alternative source directories
    SOURCE_DIRS = ("src/app", "app", "src/pages", "pages")

    # HTTP methods exported by App Router
    EXPORTED_HTTP_METHODS = (
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
    )

    # Index file suffixes to strip from route paths
    INDEX_FILE_NAMES = ("index.ts", "index.js", "index.tsx", "index.jsx")

    # Default HTTP methods for Pages Router handlers
    DEFAULT_PAGES_METHODS = ["GET", "POST"]

    # Dynamic segment patterns
    DYNAMIC_SEGMENT_PATTERN = r"\[([^\]]+)\]"
    CATCH_ALL_PATTERN = r"\[\.\.\.([^\]]+)\]"


class AuthenticatedCrawlerConfig:
    """Configuration for the authenticated web crawler.

    Login-related constants (selectors, timeouts, token keys) are in
    ``BrowserLoginConfig`` to avoid duplication with BrowserAuthProvider.
    This class holds crawler-specific constants only.
    """

    # Page limits
    MAX_PAGES_TO_VISIT = 50
    MAX_LINKS_PER_PAGE = 30
    MAX_INTERCEPTED_REQUESTS = 500
    MAX_BODY_PREVIEW_LENGTH = 2000
    MAX_REQUEST_BODY_LENGTH = 2000
    MAX_JSON_DEPTH = 5
    MAX_SEED_ROUTES = 20

    # Timeouts
    NAVIGATION_TIMEOUT_MS = 20000
    PAGE_LOAD_WAIT_MS = 3000
    BFS_NETWORK_IDLE_TIMEOUT_MS = 8000

    # ID extraction
    UUID_PATTERN = SharedPatterns.UUID_PATTERN
    NUMERIC_ID_PATTERN = SharedPatterns.NUMERIC_ID_PATTERN
    NUMERIC_ID_PATH_PATTERN = r"\d{1,10}"

    # Static asset extensions to skip
    SKIP_EXTENSIONS = (
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".woff", ".woff2", ".ttf", ".ico", ".map", ".webp", ".avif",
    )

    # External domains to skip when crawling links
    SKIP_LINK_DOMAINS = (
        "google.com", "googleapis.com", "gstatic.com",
        "facebook.com", "twitter.com", "linkedin.com",
        "cloudflare.com", "sentry.io", "hotjar.com", "intercom.io",
    )

    # URL patterns that indicate an API call (not a page)
    API_INDICATORS = (
        "/api/", "/rest/v1/", "/rpc/", "/functions/v1/",
        "supabase.co", "/trpc/", "/graphql",
    )

    SUPABASE_REST_INDICATOR = "/rest/v1/"
    RPC_PATH_SEGMENT = "rpc"

    # Headers to capture from intercepted requests
    CAPTURED_HEADER_NAMES = (
        "authorization", "apikey", "content-type",
        "x-client-info", "cookie",
    )
    BODY_CAPTURE_METHODS = ("POST", "PUT", "PATCH")

    # Common authenticated paths to seed the BFS queue
    COMMON_AUTH_PATHS = (
        "/dashboard", "/dashboard/home", "/profile", "/settings",
        "/account", "/billing", "/admin", "/marketplace",
    )

    # Source pattern label for discovered endpoints
    SOURCE_PATTERN = "authenticated_crawl"

    # URL categorization rules: (path_segments, category)
    CATEGORY_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
        (("/admin",), "admin"),
        (("/auth", "/login"), "auth"),
        (("/user", "/profile", "/me", "/account"), "user_data"),
        (("/file", "/upload", "/storage"), "file_access"),
        (("/payment", "/billing", "/checkout"), "payment"),
    )

    # Error messages
    ERROR_CRAWL_FAILED = "Authenticated crawl failed: {error}"
    ERROR_PAGE_TIMEOUT = "Page navigation timed out: {url}"
    ERROR_PLAYWRIGHT_UNAVAILABLE = "Playwright is not installed"

    # Log template
    LOG_CRAWL_SUMMARY = (
        "AuthenticatedCrawler: login=%s, visited %d pages, "
        "intercepted %d API calls, %d unique endpoints, "
        "%d resource ID groups, %d tables"
    )


class CrossUserIDORConfig:
    """Configuration for cross-user IDOR testing."""

    MAX_RESOURCES_TO_TEST = 30
    MAX_TABLES_TO_TEST = 20
    PROBE_DELAY_SECONDS = 0.5
    HTTP_TIMEOUT_SECONDS = SharedPatterns.DEFAULT_HTTP_TIMEOUT_SECONDS

    # Safe write test: empty body PATCH
    SAFE_PATCH_BODY = SharedPatterns.SAFE_PATCH_BODY
    SAFE_PATCH_PREFER_HEADER = SharedPatterns.SAFE_PATCH_PREFER

    # Supabase query params
    SUPABASE_SELECT_ID_ONLY = "select=id"
    SUPABASE_EQ_FILTER = "id=eq.{resource_id}"

    # Confidence thresholds
    CONFIDENCE_CONFIRMED_READ = 0.95
    CONFIDENCE_CONFIRMED_WRITE = 0.98
    CONFIDENCE_FULL_TABLE_LEAK = 0.99

    ERROR_CROSS_USER_FAILED = "Cross-user IDOR test failed: {error}"
    ERROR_BASELINE_FAILED = "Baseline request failed for {url}: {error}"


class ScanRateLimits:
    """Global rate limits for scanning a single target."""

    MAX_CONCURRENT_REQUESTS = 5
    PROBE_DELAY_SECONDS = 0.3
    MAX_TOTAL_REQUESTS_PER_SCAN = 500
    MAX_REQUESTS_PER_MINUTE = 100
    SUPABASE_MAX_REQUESTS_PER_SECOND = 10
    SCAN_TIMEOUT_SECONDS = 600
    CODE_SCAN_TIMEOUT_SECONDS = 300
    FULL_SCAN_TIMEOUT_SECONDS = 900


class ReportConfig:
    """Configuration for report generation."""

    SCANNER_NAME = "report_generator"

    # Grade thresholds (based on finding counts)
    GRADE_A = 0       # 0 critical, 0 high
    GRADE_B = 2       # 0 critical, <=2 high
    GRADE_C = 5       # 0 critical, <=5 high
    GRADE_D = 10      # <=1 critical, <=10 high
    GRADE_F = 999     # Everything else

    GRADE_LABELS = {
        "A": "Excellent — No significant vulnerabilities found",
        "B": "Good — Minor issues found",
        "C": "Fair — Several issues need attention",
        "D": "Poor — Significant vulnerabilities present",
        "F": "Critical — Immediate action required",
    }

    REPORT_TITLE = "isitsecure — Security Scan Report"
    SECTION_EXECUTIVE_SUMMARY = "Executive Summary"
    SECTION_CRITICAL_FINDINGS = "Critical & High Findings"
    SECTION_DAST_RESULTS = "Dynamic Testing (DAST) Results"
    SECTION_SAST_RESULTS = "Code Analysis (SAST) Results"
    SECTION_CROSS_REF = "Cross-Referenced Insights"
    SECTION_ENDPOINTS = "Discovered Endpoints"
    SECTION_REMEDIATION = "Remediation Checklist"

    # Executive summary templates
    SUMMARY_EXCELLENT = (
        "The deep security scan of {target} found no critical or high-severity "
        "vulnerabilities. {total} total findings were identified across {scanners} "
        "scanners. The application demonstrates strong security posture."
    )
    SUMMARY_GOOD = (
        "The deep security scan of {target} identified {high} high-severity "
        "findings with no critical vulnerabilities. {total} total findings were "
        "identified across {scanners} scanners. Minor improvements are recommended."
    )
    SUMMARY_FAIR = (
        "The deep security scan of {target} identified {high} high-severity "
        "findings. {total} total findings were identified across {scanners} "
        "scanners. Several issues require attention to improve security posture."
    )
    SUMMARY_POOR = (
        "The deep security scan of {target} identified {critical} critical and "
        "{high} high-severity vulnerabilities. {total} total findings were "
        "identified across {scanners} scanners. Significant vulnerabilities must "
        "be addressed promptly."
    )
    SUMMARY_CRITICAL = (
        "The deep security scan of {target} identified {critical} critical and "
        "{high} high-severity vulnerabilities. {total} total findings were "
        "identified across {scanners} scanners. Immediate remediation is required "
        "to prevent potential exploitation."
    )

    # HTML rendering constants
    HTML_TITLE = "isitsecure — Security Scan Report"
    HTML_GRADE_COLORS = {
        "A": "#22c55e",
        "B": "#84cc16",
        "C": "#eab308",
        "D": "#f97316",
        "F": "#ef4444",
    }
    HTML_SEVERITY_COLORS = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#3b82f6",
        "info": "#6b7280",
    }
    HTML_NO_FINDINGS_MESSAGE = "No findings in this category."


class SecretScannerConfig:
    """Configuration for git history secret scanning."""

    SCANNER_NAME = "git_secret_scanner"
    CONFIDENCE_SENSITIVE_FILE = 0.95
    CONFIDENCE_SECRET_MATCH = 0.90
    MASK_MIN_LENGTH = 12
    MASK_PREFIX_LENGTH = 4
    MASK_FULL_PREFIX_LENGTH = 8
    MASK_SUFFIX_LENGTH = 4
    TITLE_SENSITIVE_FILE = "Sensitive file in git history: {filename}"
    DESC_SENSITIVE_FILE = (
        "The file '{filename}' was committed to git. "
        "Even if deleted, it remains in git history "
        "and can be recovered."
    )
    DETAIL_SECRET_IN_HEAD = "This secret is currently in the codebase."
    DETAIL_SECRET_IN_HISTORY = (
        "This secret exists in git history but not at HEAD "
        "— it may still be valid if not rotated."
    )

    MAX_COMMITS_TO_SCAN = 500
    MAX_DIFF_SIZE_BYTES = 1_000_000  # 1MB per diff
    GIT_LOG_TIMEOUT_SECONDS = 60

    # Entropy threshold for detecting unknown secret formats
    ENTROPY_THRESHOLD = 4.5
    MIN_SECRET_LENGTH = 8
    MAX_SECRET_LENGTH = 500

    # Secret patterns: name -> {pattern, severity, description}
    SECRET_PATTERNS = {
        "supabase_service_role": {
            "pattern": r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
            "severity": SeverityLevel.CRITICAL.value,
            "description": "Supabase service role key (bypasses RLS)",
        },
        "stripe_secret_key": {
            "pattern": r"sk_live_[a-zA-Z0-9]{24,}",
            "severity": SeverityLevel.CRITICAL.value,
            "description": "Stripe secret API key",
        },
        "stripe_restricted_key": {
            "pattern": r"rk_live_[a-zA-Z0-9]{24,}",
            "severity": SeverityLevel.HIGH.value,
            "description": "Stripe restricted API key",
        },
        "aws_access_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "severity": SeverityLevel.CRITICAL.value,
            "description": "AWS access key ID",
        },
        "github_pat": {
            "pattern": r"ghp_[a-zA-Z0-9]{36}",
            "severity": SeverityLevel.CRITICAL.value,
            "description": "GitHub personal access token",
        },
        "github_oauth": {
            "pattern": r"gho_[a-zA-Z0-9]{36}",
            "severity": SeverityLevel.HIGH.value,
            "description": "GitHub OAuth token",
        },
        "openai_key": {
            "pattern": r"sk-[a-zA-Z0-9]{48}",
            "severity": SeverityLevel.HIGH.value,
            "description": "OpenAI API key",
        },
        "anthropic_key": {
            "pattern": r"sk-ant-[a-zA-Z0-9\-]{90,}",
            "severity": SeverityLevel.HIGH.value,
            "description": "Anthropic API key",
        },
        "database_url": {
            "pattern": r"(?:postgres|mysql|mongodb)://[^\s\"']+",
            "severity": SeverityLevel.CRITICAL.value,
            "description": "Database connection string",
        },
        "firebase_key": {
            "pattern": r"AIza[0-9A-Za-z\-_]{35}",
            "severity": SeverityLevel.HIGH.value,
            "description": "Firebase/Google API key",
        },
        "sendgrid_key": {
            "pattern": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
            "severity": SeverityLevel.HIGH.value,
            "description": "SendGrid API key",
        },
        "twilio_key": {
            "pattern": r"SK[a-f0-9]{32}",
            "severity": SeverityLevel.HIGH.value,
            "description": "Twilio API key",
        },
        "private_key": {
            "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
            "severity": SeverityLevel.CRITICAL.value,
            "description": "Private key file content",
        },
    }

    # Files that should never be committed
    SENSITIVE_FILE_PATTERNS = (
        r"\.env(?:\.local|\.production|\.staging)?$",
        r"\.pem$",
        r"\.key$",
        r"credentials\.json$",
        r"service[_-]?account.*\.json$",
    )

    # Files to skip (too noisy)
    SKIP_FILE_PATTERNS = (
        r"package-lock\.json$",
        r"yarn\.lock$",
        r"pnpm-lock\.yaml$",
        r"\.min\.js$",
        r"node_modules/",
    )

    ERROR_GIT_LOG_FAILED = "Git log scan failed: {error}"
    ERROR_GIT_LOG_TIMEOUT = "Git log scan timed out after {timeout}s"


class RouteAuthAnalyzerConfig:
    """Configuration for route authentication analysis."""

    SCANNER_NAME = "route_auth_analyzer"

    # Patterns indicating authentication check is present
    AUTH_CHECK_PATTERNS = CommonAuthPatterns.COMMON_AUTH_PATTERNS + (
        r'currentUser\s*\(',
        r'getServerSession\s*\(',
        r'headers\s*\(\s*\)\s*\.get\s*\(\s*["\']authorization',
        r'requireAuth\s*\(',
        r'withAuth\s*\(',
        r'isAuthenticated',
    )

    # Patterns indicating authorization/ownership check
    OWNERSHIP_CHECK_PATTERNS = (
        r'\.eq\s*\(\s*["\']user_id["\']\s*,',
        r'\.eq\s*\(\s*["\']owner_id["\']\s*,',
        r'\.eq\s*\(\s*["\']created_by["\']\s*,',
        r'\.eq\s*\(\s*["\']author_id["\']\s*,',
        r'where\s*\(\s*\{[^}]*userId',
        r'where\s*\(\s*\{[^}]*user_id',
        r'findUnique\s*\(\s*\{[^}]*userId',
        r'user\.id\s*===',
        r'session\.user\.id\s*===',
    )

    # Patterns indicating service_role usage (dangerous — bypasses RLS)
    SERVICE_ROLE_PATTERNS = (
        r'service_role',
        r'serviceRole',
        r'supabaseAdmin',
        r'createClient\s*\([^)]*service',
        r'SUPABASE_SERVICE_ROLE',
        r'SERVICE_ROLE_KEY',
    )

    # Patterns indicating input validation
    VALIDATION_PATTERNS = (
        r'\.parse\s*\(',
        r'\.safeParse\s*\(',
        r'\.validate\s*\(',
        r'z\.\w+\s*\(',
        r'Joi\.\w+',
        r'yup\.\w+',
        r'zod',
    )

    # Server Action detection
    USE_SERVER_DIRECTIVE = r'["\']use server["\']'

    # Supabase operation patterns
    SUPABASE_OPERATION_PATTERNS = (
        r'\.from\s*\(\s*["\'](\w+)["\']\s*\)\s*\.(select|insert|update|delete|upsert)',
        r'\.rpc\s*\(\s*["\'](\w+)["\']',
    )

    # IDOR risk: query with user-supplied param but no ownership filter
    USER_SUPPLIED_ID_PATTERNS = (
        r'params\.\w+',
        r'searchParams\.get\s*\(',
        r'req\.query\.',
        r'req\.params\.',
        r'request\.nextUrl\.searchParams',
        r'\[id\]',
        r'slug',
    )

    # Severity mapping
    SEVERITY_MISSING_AUTH = SeverityLevel.HIGH.value
    SEVERITY_MISSING_OWNERSHIP = SeverityLevel.HIGH.value
    SEVERITY_SERVICE_ROLE = SeverityLevel.MEDIUM.value
    SEVERITY_MISSING_VALIDATION = SeverityLevel.MEDIUM.value
    SEVERITY_IDOR_RISK = SeverityLevel.CRITICAL.value
    SEVERITY_SERVER_ACTION_NO_AUTH = SeverityLevel.HIGH.value

    # Error messages
    ERROR_ANALYSIS_FAILED = "Route analysis failed for {file_path}: {error}"

    # Finding titles
    TITLE_MISSING_AUTH = "API route missing authentication check"
    TITLE_MISSING_OWNERSHIP = "API route missing ownership/authorization check"
    TITLE_SERVICE_ROLE = "API route uses service_role key (bypasses RLS)"
    TITLE_MISSING_VALIDATION = "API route missing input validation"
    TITLE_IDOR_RISK = "Potential IDOR: user-supplied ID without ownership check"
    TITLE_SERVER_ACTION_NO_AUTH = "Server Action missing authentication check"


class XSSConfig:
    """Configuration for active XSS scanning."""

    SCANNER_NAME = "xss_scanner"
    MAX_ENDPOINTS_TO_TEST = 20
    MAX_PARAMS_PER_ENDPOINT = 5
    HTTP_TIMEOUT_SECONDS = 10
    MAX_CONCURRENT = SharedPatterns.DEFAULT_MAX_CONCURRENT
    PROBE_DELAY = SharedPatterns.DEFAULT_PROBE_DELAY

    # Canary-based detection: inject unique string, check if reflected unescaped
    CANARY_PREFIX = "xss_canary_"
    CANARY_BOUNDARY_CHARS = ('<', '>', '"', "'")

    CONFIDENCE_REFLECTED_CONFIRMED = 0.95
    CONFIDENCE_REFLECTED_POSSIBLE = 0.40  # Low — chars encoded, no confirmed execution
    CONFIDENCE_DOM_BASED = 0.60

    # Reflection test payloads — ordered from safe to specific
    REFLECTION_PROBES = (
        # Stage 1: Canary with HTML-significant chars to test encoding
        '<canary_xss_{id}>',
        '"canary_xss_{id}"',
        "'canary_xss_{id}'",
    )

    # XSS payloads for confirmation (only used if reflection detected)
    CONFIRMATION_PAYLOADS = (
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
        '<script>alert(1)</script>',
        'javascript:alert(1)',
    )

    # DOM-based XSS dangerous sinks (passive JS analysis)
    DANGEROUS_SINKS = (
        r'\.innerHTML\s*=',
        r'\.outerHTML\s*=',
        r'document\.write\s*\(',
        r'document\.writeln\s*\(',
        r'eval\s*\(',
        r'setTimeout\s*\(\s*["\']',
        r'setInterval\s*\(\s*["\']',
        r'Function\s*\(\s*["\']',
        r'\.insertAdjacentHTML\s*\(',
        r'location\.href\s*=\s*[^"\'`]',
        r'location\.replace\s*\(\s*[^"\'`]',
        r'dangerouslySetInnerHTML',
    )

    # Safe sources (not user-controllable — reduce false positives)
    SAFE_SINK_CONTEXTS = (
        r'\.innerHTML\s*=\s*["\']',      # Static string assignment
        r'\.innerHTML\s*=\s*``',           # Empty template literal
        r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*["\']',  # Static HTML
    )

    # Query parameters to test for reflection
    COMMON_REFLECTABLE_PARAMS = (
        "q", "query", "search", "s", "keyword", "term",
        "name", "title", "message", "comment", "text",
        "redirect", "url", "next", "return", "callback",
        "error", "msg", "status",
    )

    # Context-aware confirmation payloads
    # After detecting reflection, determine the injection context and send
    # a context-appropriate confirmation payload.
    CONTEXT_PAYLOADS = {
        # Context name -> (detection_regex, confirmation_payload, description)
        "html_attr_double": (
            # Canary inside a double-quoted HTML attribute: value="...CANARY..."
            r'="[^"]*{canary}[^"]*"',
            '" onmouseover=alert(1) x="',
            "HTML attribute breakout (double-quoted)",
        ),
        "html_attr_single": (
            r"='[^']*{canary}[^']*'",
            "' onmouseover=alert(1) x='",
            "HTML attribute breakout (single-quoted)",
        ),
        "js_string_double": (
            # Canary inside a JS double-quoted string: var x = "...CANARY..."
            r'"[^"]*{canary}[^"]*"',
            '";alert(1);//',
            "JavaScript string breakout (double-quoted)",
        ),
        "js_string_single": (
            r"'[^']*{canary}[^']*'",
            "';alert(1);//",
            "JavaScript string breakout (single-quoted)",
        ),
        "js_template_literal": (
            r"`[^`]*{canary}[^`]*`",
            "${alert(1)}",
            "JavaScript template literal injection",
        ),
        "url_href": (
            r'href="[^"]*{canary}',
            "javascript:alert(1)",
            "URL/href JavaScript protocol injection",
        ),
        "html_comment": (
            r"<!--[^>]*{canary}",
            "--><script>alert(1)</script><!--",
            "HTML comment breakout",
        ),
    }

    CONFIDENCE_CONTEXT_CONFIRMED = 0.95

    TITLE_CONTEXT_XSS = (
        "Confirmed XSS — {context_desc} in '{param}'"
    )
    DESC_CONTEXT_XSS = (
        "The endpoint {url} reflects user input from '{param}' inside "
        "a {context_desc} context. The scanner confirmed the injection "
        "by sending a context-specific breakout payload that was "
        "reflected unescaped.\n\n"
        "**Injection context:** {context_desc}\n"
        "**Confirmation payload:** `{payload}`\n\n"
        "**Impact:** An attacker can execute arbitrary JavaScript in "
        "the victim's browser via a crafted URL."
    )

    # POST body XSS testing
    MAX_POST_ENDPOINTS_TO_TEST = 15
    POST_BODY_FIELD_NAMES = (
        "name", "comment", "description", "title",
        "message", "bio", "content", "text",
    )
    CONFIDENCE_POST_BODY_REFLECTED = 0.90
    STATE_CHANGING_METHODS = ("POST", "PUT", "PATCH")

    ERROR_XSS_SCAN_FAILED = "XSS scan failed for {endpoint}: {error}"
    TITLE_REFLECTED_XSS = "Confirmed reflected XSS — unescaped HTML injection"
    TITLE_REFLECTED_XSS_POSSIBLE = "Possible reflected XSS — input reflected with encoding"
    TITLE_POST_BODY_XSS = "Confirmed reflected XSS via POST body"
    TITLE_POST_BODY_XSS_POSSIBLE = "Possible reflected XSS via POST body — input reflected with encoding"
    TITLE_DOM_XSS = "DOM-based XSS risk: dangerous sink in JavaScript"
    DESC_REFLECTED_XSS = (
        "The endpoint {url} reflects user input from the '{param}' query "
        "parameter in the HTML response without escaping HTML-significant "
        "characters (<, >, \", '). This allows an attacker to craft a URL "
        "like `{url}?{param}=<script>alert(1)</script>` that executes "
        "arbitrary JavaScript when a victim clicks it.\n\n"
        "**Impact:** Session hijacking (steal cookies), credential phishing "
        "(inject fake login form), or defacement. The attack is "
        "unauthenticated — the attacker only needs the victim to click a link.\n\n"
        "**What to verify:** Open the URL with `?{param}=<b>test</b>` — if "
        "'test' appears bold, the input is not encoded."
    )
    DESC_REFLECTED_XSS_POSSIBLE = (
        "The endpoint {url} reflects the text content of the '{param}' "
        "query parameter in the HTML response, but HTML-significant "
        "characters (<, >) appear to be encoded by the framework (e.g., "
        "React JSX auto-escaping, Angular template sanitization).\n\n"
        "**Current risk:** LOW — the encoding likely prevents script "
        "execution. However, if any rendering path bypasses the framework's "
        "escaping (e.g., `dangerouslySetInnerHTML`, server-side template "
        "concatenation), this becomes exploitable.\n\n"
        "**What to verify:** Check if the parameter value appears inside "
        "a `<script>` block, HTML attribute, or `dangerouslySetInnerHTML` "
        "call. If it only appears as text content in JSX, this is safe."
    )
    DESC_POST_BODY_XSS = (
        "The endpoint {url} reflects user input from the POST body field "
        "'{field}' in the HTML response without escaping HTML characters. "
        "An attacker can submit a form or API call with malicious content "
        "in the '{field}' field that executes JavaScript when rendered.\n\n"
        "**Impact:** Stored XSS if the content is persisted, or reflected "
        "XSS if rendered immediately. Can lead to session hijacking or "
        "credential theft for any user who views the injected content."
    )
    DESC_DOM_XSS = (
        "JavaScript code on this page contains a dangerous DOM manipulation "
        "pattern: `{sink}`. This function writes directly to the DOM or "
        "navigates the browser without sanitization.\n\n"
        "**Risk depends on data flow:** If the argument to `{sink}` comes "
        "from user-controllable sources (URL parameters, `location.hash`, "
        "`postMessage`, `document.referrer`), an attacker can inject "
        "`javascript:` URIs or malicious HTML.\n\n"
        "**What to verify:** Trace the argument to `{sink}` — if it's a "
        "hardcoded string or internally constructed path, this is safe. "
        "If it reads from `window.location` or URL params, it's exploitable."
    )


class DOMXSSConfig:
    """Configuration for browser-based DOM XSS scanning via Playwright.

    Unlike the static XSSScanner (regex on JS bundles), this scanner
    hooks DOM sinks in a real browser and confirms data flow from
    user-controlled sources to sinks at runtime.
    """

    SCANNER_NAME = "dom_xss_scanner"

    # Browser settings
    VIEWPORT_WIDTH = 1280
    VIEWPORT_HEIGHT = 720
    NAVIGATION_TIMEOUT_MS = 15000
    NETWORK_IDLE_TIMEOUT_MS = 8000
    POST_INJECT_WAIT_SECONDS = 1.5

    # Limits
    MAX_PAGES_TO_TEST = 30

    # Confidence
    CONFIDENCE_CONFIRMED = 0.95

    # Injection sources — URL query params to inject canary into
    INJECTION_PARAMS = (
        "q", "query", "search", "s", "keyword", "term",
        "redirect", "url", "next", "return", "callback",
        "ref", "page", "view", "tab", "id", "name",
    )

    # postMessage payloads (canary inserted at {canary})
    POSTMESSAGE_PAYLOADS = (
        '"{canary}"',
        '{{"data": "{canary}"}}',
        '{{"type": "navigate", "url": "{canary}"}}',
        '{{"html": "<img src=x onerror={canary}>", "action": "render"}}',
    )

    # Error messages
    ERROR_PLAYWRIGHT_UNAVAILABLE = (
        "DOM XSS scanner requires Playwright. "
        "Install with: pip install playwright && playwright install chromium"
    )
    ERROR_SCAN_FAILED = "DOM XSS scan failed: {error}"

    # Logging
    LOG_SCAN_COMPLETE = "DOMXSSScanner: %d findings from %d pages tested"

    # Finding text
    TITLE_CONFIRMED = "Confirmed DOM XSS — canary reached `{sink}` sink"
    DESC_CONFIRMED = (
        "The page {url} has a confirmed DOM-based XSS vulnerability. "
        "User-controlled input injected via {vector} reached the "
        "dangerous `{sink}` DOM sink during live browser execution.\n\n"
        "**Impact:** An attacker can craft a URL that executes arbitrary "
        "JavaScript in the victim's browser when clicked. This enables "
        "session hijacking (steal cookies/tokens), credential phishing, "
        "or actions performed as the victim.\n\n"
        "**How this was found:** A unique canary string was injected via "
        "{vector} and the scanner detected it arriving at the `{sink}` "
        "API inside a real Chromium browser — this is not a static "
        "pattern match, it is confirmed execution."
    )


class InjectionConfig:
    """Configuration for active injection scanning."""

    SCANNER_NAME = "active_injection_scanner"
    MAX_ENDPOINTS_TO_TEST = 30
    MAX_PARAMS_PER_ENDPOINT = 5
    HTTP_TIMEOUT_SECONDS = 15
    MAX_CONCURRENT = SharedPatterns.DEFAULT_MAX_CONCURRENT
    PROBE_DELAY = 0.5  # Slightly higher delay for injection testing
    TIME_BASED_DELAY_THRESHOLD = 2.5  # seconds

    CONFIDENCE_ERROR_BASED = 0.90
    CONFIDENCE_TIME_BASED = 0.85
    CONFIDENCE_BOOLEAN_BASED = 0.75
    CONFIDENCE_NOSQL = 0.80
    CONFIDENCE_COMMAND_INJECTION = 0.85

    # Error-based SQL injection payloads — trigger SQL error messages
    SQLI_ERROR_PAYLOADS = (
        "' OR '1'='1",
        "1; SELECT 1--",
        "1 UNION SELECT NULL--",
        "' AND 1=CONVERT(int, @@version)--",
    )

    # Time-based blind SQL injection — measure response time delta
    SQLI_TIME_PAYLOADS = (
        ("'; WAITFOR DELAY '0:0:3'--", "mssql"),
        ("' OR SLEEP(3)--", "mysql"),
        ("'; SELECT pg_sleep(3)--", "postgresql"),
    )

    # SQL error indicators in responses
    SQL_ERROR_PATTERNS = (
        r"SQL syntax",
        r"mysql_fetch",
        r"pg_query",
        r"ORA-\d{5}",
        r"SQLITE_ERROR",
        r"Unclosed quotation mark",
        r"syntax error at or near",
        r"unterminated string",
        r"invalid input syntax",
        r"SQLSTATE\[",
        r"PDOException",
        r"PostgreSQL.*ERROR",
        r"MySQL.*Error",
    )

    # NoSQL injection payloads (JSON body format)
    NOSQL_PAYLOADS = (
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
    )

    # NoSQL injection payloads (query string format)
    NOSQL_QUERY_PAYLOADS = (
        "[$ne]=null",
    )

    # NoSQL indicators in response that suggest injection worked
    NOSQL_INDICATORS = (
        r'"_id"\s*:',          # MongoDB document ID field
        r'"ObjectId\("',       # MongoDB ObjectId
        r"MongoError",         # MongoDB error leak
        r"CastError",          # Mongoose cast error
    )

    # Response size ratio: if injected response is > this * baseline, likely leak
    NOSQL_RESPONSE_SIZE_RATIO = 2.0
    # Minimum baseline response size to compare against
    NOSQL_MIN_BASELINE_SIZE = 20

    # XXE / XML injection
    CONFIDENCE_XXE = 0.90

    XXE_CONTENT_TYPES = ("application/xml", "text/xml")

    XXE_PAYLOAD = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<foo>&xxe;</foo>'
    )

    XXE_INDICATORS = (
        r"root:x:0:0",
        r"/bin/bash",
        r"/bin/sh",
        r"/usr/sbin/nologin",
        r"daemon:x:",
        r"nobody:x:",
    )

    TITLE_XXE = "XML External Entity (XXE) injection vulnerability"
    DESC_XXE = (
        "The endpoint {url} processes XML input and appears vulnerable to "
        "XXE injection. The response contained file-system content indicators "
        "after submitting an XXE payload."
    )

    # Command injection payloads (safe — use timing/output detection)
    COMMAND_INJECTION_PAYLOADS = (
        "; echo xss_cmd_test",
        "| echo xss_cmd_test",
        "$(echo xss_cmd_test)",
        "`echo xss_cmd_test`",
    )
    COMMAND_INJECTION_CANARY = "xss_cmd_test"

    # Default params to fuzz when endpoint has no known query params
    DEFAULT_FUZZ_PARAMS = ("id", "q", "search", "query", "email", "username", "name")

    # Finding titles
    TITLE_SQLI_ERROR = "SQL injection vulnerability (error-based)"
    TITLE_SQLI_TIME = "SQL injection vulnerability (time-based blind)"
    TITLE_NOSQL = "NoSQL injection vulnerability"
    TITLE_COMMAND_INJECTION = "Command injection vulnerability"

    # Finding descriptions (templates)
    DESC_SQLI_ERROR = (
        "The endpoint {url} returned a SQL error when injected with the payload "
        "'{payload}' in parameter '{param}'. This indicates the input is directly "
        "embedded in a SQL query without parameterization."
    )
    DESC_SQLI_TIME = (
        "The endpoint {url} responded {delta:.1f}s slower when injected with a "
        "time-delay SQL payload via parameter '{param}'. This suggests a blind "
        "SQL injection vulnerability."
    )
    DESC_NOSQL = (
        "The endpoint {url} returned different data when injected with NoSQL "
        "operator '{payload}' in parameter '{param}'."
    )
    DESC_COMMAND_INJECTION = (
        "The endpoint {url} appears to reflect command output when injected "
        "with '{payload}' in parameter '{param}'."
    )

    # Error messages
    ERROR_INJECTION_SCAN_FAILED = "Injection scan failed for {endpoint}: {error}"


class CSRFConfig:
    """Configuration for CSRF scanning."""

    SCANNER_NAME = "csrf_scanner"
    MAX_ENDPOINTS_TO_TEST = 30
    HTTP_TIMEOUT_SECONDS = 10

    CONFIDENCE_NO_CSRF_TOKEN = 0.85
    CONFIDENCE_FORGED_ORIGIN_ACCEPTED = 0.90
    CONFIDENCE_MISSING_SAMESITE = 0.70

    FORGED_ORIGIN = "https://evil-attacker.com"
    FORGED_REFERER = "https://evil-attacker.com/attack"

    # State-changing methods that need CSRF protection
    STATE_CHANGING_METHODS = ("POST", "PUT", "PATCH", "DELETE")

    # CSRF token field names to look for in HTML forms
    CSRF_TOKEN_FIELD_NAMES = (
        "csrf_token", "csrfToken", "_csrf", "csrf",
        "authenticity_token", "_token", "token",
        "xsrf-token", "xsrf_token",
    )

    # CSRF token header names
    CSRF_TOKEN_HEADERS = (
        "x-csrf-token", "x-xsrf-token", "csrf-token",
    )

    # Cookie flags to check
    SAMESITE_VALUES = ("strict", "lax", "none")

    TITLE_MISSING_CSRF = "State-changing endpoint lacks CSRF protection"
    TITLE_FORGED_ORIGIN = "Endpoint accepts requests with forged Origin header"
    TITLE_MISSING_SAMESITE = "Authentication cookie missing SameSite attribute"

    DESC_MISSING_CSRF = (
        "The {method} endpoint {url} does not require a CSRF token. "
        "If this endpoint uses cookie-based authentication, an attacker "
        "can craft a malicious page that submits requests on behalf of "
        "a logged-in user."
    )
    DESC_FORGED_ORIGIN = (
        "The {method} endpoint {url} accepts requests with Origin header "
        "set to '{origin}'. This means cross-origin requests are not blocked, "
        "making CSRF attacks possible."
    )
    DESC_MISSING_SAMESITE = (
        "The cookie '{cookie_name}' does not have the SameSite attribute set. "
        "Without SameSite=Lax or Strict, browsers will send this cookie with "
        "cross-site requests, enabling CSRF."
    )

    ERROR_CSRF_SCAN_FAILED = "CSRF scan failed for {endpoint}: {error}"


class RLSPolicyAnalyzerConfig:
    """Configuration for Supabase RLS policy analysis."""

    SCANNER_NAME = "rls_policy_analyzer"
    DEFAULT_MIGRATION_DIR = "supabase/migrations/"
    PAREN_CONTENT_PATTERN = r'\(([^()]*(?:\([^()]*\)[^()]*)*)\)'

    # SQL patterns for parsing migrations
    CREATE_TABLE_PATTERN = r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?["\']?(\w+)["\']?'
    ENABLE_RLS_PATTERN = r'ALTER\s+TABLE\s+(?:public\.)?["\']?(\w+)["\']?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY'
    CREATE_POLICY_PATTERN = r'CREATE\s+POLICY\s+["\']?(\w+)["\']?\s+ON\s+(?:public\.)?["\']?(\w+)["\']?'
    POLICY_USING_PATTERN = r'USING\s*\(\s*(.*?)\s*\)'
    POLICY_WITH_CHECK_PATTERN = r'WITH\s+CHECK\s*\(\s*(.*?)\s*\)'
    POLICY_FOR_PATTERN = r'FOR\s+(SELECT|INSERT|UPDATE|DELETE|ALL)'

    # Dangerous policy expressions
    PERMISSIVE_EXPRESSIONS = (
        r'^\s*true\s*$',
        r'^\s*1\s*=\s*1\s*$',
    )

    # Good policy patterns (using auth.uid())
    AUTH_UID_PATTERN = r'auth\.uid\s*\(\s*\)'

    CONFIDENCE_NO_RLS = 0.95
    CONFIDENCE_NO_POLICIES = 0.90
    CONFIDENCE_PERMISSIVE = 0.90
    CONFIDENCE_MISSING_AUTH_UID = 0.75

    TITLE_NO_RLS = "Table '{table}' does not have Row Level Security enabled"
    TITLE_NO_POLICIES = "Table '{table}' has RLS enabled but no policies defined"
    TITLE_PERMISSIVE_POLICY = "Table '{table}' has overly permissive RLS policy"
    TITLE_MISSING_SELECT_POLICY = (
        "Table '{table}' has no SELECT policy — data may be readable by any user"
    )
    TITLE_MISSING_AUTH_UID = (
        "Table '{table}' policy does not use auth.uid() — may allow cross-user access"
    )

    DESC_NO_RLS = (
        "The table '{table}' in migration file '{file}' does not have "
        "Row Level Security (RLS) enabled. Without RLS, any authenticated "
        "user with the anon key can read/write all rows."
    )
    DESC_NO_POLICIES = (
        "The table '{table}' has RLS enabled but no policies are defined. "
        "This effectively blocks ALL access including the app itself. "
        "If the app works, it's likely using service_role to bypass RLS, "
        "which means RLS is not providing any protection."
    )
    DESC_PERMISSIVE_POLICY = (
        "The policy '{policy}' on table '{table}' uses '{expression}' which "
        "allows unrestricted access. Any authenticated user can {operation} all rows."
    )
    DESC_MISSING_AUTH_UID = (
        "The {operation} policy '{policy}' on table '{table}' does not filter by "
        "auth.uid(). Without this, users can {operation} other users' data."
    )

    ERROR_ANALYSIS_FAILED = "RLS analysis failed for {file}: {error}"


class RLSDeepScanConfig:
    """Configuration for live Supabase RLS testing."""

    SCANNER_NAME = "rls_deep_scanner"
    MAX_TABLES_TO_TEST = 25
    PROBE_DELAY_SECONDS = SharedPatterns.DEFAULT_PROBE_DELAY
    HTTP_TIMEOUT_SECONDS = SharedPatterns.DEFAULT_HTTP_TIMEOUT_SECONDS
    MAX_CONCURRENT_PROBES = SharedPatterns.DEFAULT_MAX_CONCURRENT

    # Supabase REST query params
    SELECT_ALL = "select=*"
    SELECT_COUNT = "select=count"
    SELECT_ID_ONLY = "select=id"
    LIMIT_ONE = "limit=1"
    PREFER_COUNT = "Prefer"
    PREFER_COUNT_EXACT = "count=exact"

    # Confidence values
    CONFIDENCE_ANON_READ = 0.95
    CONFIDENCE_ANON_WRITE = 0.98
    CONFIDENCE_CROSS_USER_READ = 0.95
    CONFIDENCE_CROSS_USER_WRITE = 0.98

    # Finding titles (templates)
    TITLE_ANON_READ = "Table '{table}' readable with anon key (no auth required)"
    TITLE_ANON_WRITE = "Table '{table}' writable with anon key (no auth required)"
    TITLE_CROSS_USER_READ = "Table '{table}' leaks data across users (RLS bypass)"
    TITLE_CROSS_USER_WRITE = "Table '{table}' allows cross-user writes (RLS bypass)"
    TITLE_RPC_NO_AUTH = "RPC function '{func}' callable without authentication"

    # Finding descriptions (templates)
    DESC_ANON_READ = (
        "The Supabase table '{table}' returned {count} row(s) when queried with "
        "only the anon key (no user authentication). If this table contains "
        "user-specific data, RLS SELECT policies are missing or misconfigured."
    )
    DESC_ANON_WRITE = (
        "The Supabase table '{table}' accepted a write operation (INSERT/PATCH) "
        "with only the anon key. Any unauthenticated user can modify this table."
    )
    DESC_CROSS_USER_READ = (
        "User B was able to read {count} row(s) from table '{table}' that belong "
        "to User A. The RLS SELECT policy does not properly filter by auth.uid()."
    )
    DESC_CROSS_USER_WRITE = (
        "User B was able to write to table '{table}' affecting User A's rows. "
        "The RLS UPDATE/DELETE policy does not properly filter by auth.uid()."
    )
    DESC_RPC_NO_AUTH = (
        "The Supabase RPC function '{func}' executed successfully without "
        "authentication. If this function accesses sensitive data or performs "
        "mutations, it should require an authenticated user."
    )

    # Safe write test body
    SAFE_WRITE_BODY = SharedPatterns.SAFE_PATCH_BODY
    SAFE_WRITE_PREFER = SharedPatterns.SAFE_PATCH_PREFER

    # Error messages
    ERROR_RLS_SCAN_FAILED = "RLS deep scan failed for table '{table}': {error}"
    ERROR_RPC_SCAN_FAILED = "RLS deep scan failed for RPC '{func}': {error}"


class PrivilegeEscalationConfig:
    """Configuration for privilege escalation testing."""

    SCANNER_NAME = "privilege_escalation_scanner"
    HTTP_TIMEOUT_SECONDS = 10
    PROBE_DELAY_SECONDS = 0.3
    MAX_CONCURRENT_PROBES = 3

    # Table/endpoint names that indicate admin functionality
    ADMIN_INDICATORS = (
        "admin", "user_roles", "roles", "permissions",
        "platform_settings", "settings", "config",
        "audit_logs", "admin_edit_logs", "system",
    )

    # Admin route path indicators
    ADMIN_PATH_INDICATORS = (
        "/admin", "/dashboard/admin", "/api/admin",
        "/settings", "/config", "/system",
    )

    # Role table indicators
    ROLE_INDICATORS = ("role", "permission")

    # Role escalation field names to try
    ROLE_ESCALATION_FIELDS = (
        ("role", "admin"),
        ("is_admin", "true"),
        ("is_verified", "true"),
        ("plan", "enterprise"),
        ("permissions", "all"),
    )

    # HTTP method classifications
    WRITE_METHODS = ("POST", "PUT", "PATCH")
    MUTATION_METHODS = ("POST", "PUT", "PATCH", "DELETE")

    # HTTP success status codes
    SUCCESS_READ_CODES = (200, 201)
    SUCCESS_WRITE_CODES = (200, 204)
    SUCCESS_MUTATION_CODES = (200, 201, 204)

    # Response preview length
    RESPONSE_PREVIEW_LENGTH = SharedPatterns.RESPONSE_PREVIEW_LENGTH

    # JSON record count keys (for tRPC/REST responses)
    JSON_RECORD_KEYS = ("data", "result", "results", "items")

    # Limits
    MAX_AUTH_ENDPOINTS_TO_TEST = 30
    MAX_MUTATIONS_TO_REPLAY = 20
    MAX_RESOURCES_FOR_WRITE_TEST = 15
    MAX_DIFFERENTIAL_ENDPOINTS = 20

    # Differential response thresholds
    DIFFERENTIAL_SIZE_RATIO = 1.5  # Admin response 50%+ larger → suspicious
    DIFFERENTIAL_MIN_SIZE = 50     # Ignore responses smaller than this

    # Confidence values
    CONFIDENCE_ADMIN_TABLE_ACCESS = 0.90
    CONFIDENCE_ADMIN_ROUTE_ACCESS = 0.90
    CONFIDENCE_ROLE_ESCALATION = 0.95
    CONFIDENCE_AUTH_ENDPOINT = 0.75
    CONFIDENCE_DIFFERENTIAL = 0.80
    CONFIDENCE_MUTATION_REPLAY = 0.85
    CONFIDENCE_OBJECT_WRITE = 0.90
    CONFIDENCE_RPC_ACCESS = 0.80

    # Finding titles (templates)
    TITLE_ADMIN_TABLE = "Regular user can access admin table '{table}'"
    TITLE_ADMIN_ROUTE = "Regular user can access admin endpoint '{path}'"
    TITLE_ROLE_ESCALATION = "User can modify their own role in '{table}'"
    TITLE_AUTH_ENDPOINT = (
        "Authenticated endpoint accessible by regular user: '{path}'"
    )
    TITLE_DIFFERENTIAL = (
        "Privilege escalation — admin sees more data at '{path}'"
    )
    TITLE_MUTATION_REPLAY = (
        "Regular user can perform admin mutation: {method} '{path}'"
    )
    TITLE_OBJECT_WRITE = (
        "Regular user can modify another user's resource in '{table}'"
    )
    TITLE_RPC_ACCESS = (
        "Regular user can call server function '{function}'"
    )

    # Finding descriptions (templates)
    DESC_ADMIN_TABLE = (
        "A regular (non-admin) user was able to read from the admin table '{table}'. "
        "This table likely contains sensitive administrative data. "
        "RLS or application-level access control should restrict access."
    )
    DESC_ADMIN_ROUTE = (
        "A regular user was able to access the admin endpoint '{path}' "
        "and received a {status} response. Admin functionality should require "
        "admin-level authorization."
    )
    DESC_ROLE_ESCALATION = (
        "A regular user was able to PATCH the '{table}' table with "
        "'{field}': '{value}'. This could allow privilege escalation "
        "by setting their own role to admin."
    )
    DESC_AUTH_ENDPOINT = (
        "A regular (non-admin) user was able to access the authenticated "
        "endpoint '{path}' via {method} and received a {status} response. "
        "If this endpoint should be restricted to admin or higher-privilege "
        "roles, it indicates a horizontal or vertical privilege escalation."
    )
    DESC_DIFFERENTIAL = (
        "The admin user receives significantly more data ({admin_size} bytes) "
        "than the regular user ({regular_size} bytes) from the same endpoint "
        "'{path}'. However, the regular user still gets a successful response, "
        "indicating missing or incomplete authorization filtering. The server "
        "should either deny access entirely or ensure equal data visibility "
        "based on the user's role."
    )
    DESC_MUTATION_REPLAY = (
        "A state-changing request ({method}) to '{path}' that was originally "
        "performed by an admin user succeeded when replayed with a regular "
        "user's credentials (HTTP {status}). This indicates the endpoint lacks "
        "proper role-based access control for write operations."
    )
    DESC_OBJECT_WRITE = (
        "A regular user was able to {method} a resource (ID: {resource_id}) "
        "in table '{table}' that belongs to another user. The server returned "
        "HTTP {status}. This indicates missing Row-Level Security or "
        "application-level ownership checks on write operations."
    )
    DESC_RPC_ACCESS = (
        "A regular user was able to call the server-side function '{function}' "
        "via Supabase RPC (HTTP {status}). Server functions may bypass RLS "
        "and return sensitive data or perform privileged operations."
    )

    # Error messages
    ERROR_PRIV_ESC_FAILED = "Privilege escalation test failed: {error}"
    ERROR_ADMIN_TABLE_FAILED = (
        "Privilege escalation test failed for admin table '{table}': {error}"
    )
    ERROR_ADMIN_ROUTE_FAILED = (
        "Privilege escalation test failed for admin route '{path}': {error}"
    )
    ERROR_AUTH_ENDPOINT_FAILED = (
        "Auth endpoint test failed for '{path}': {error}"
    )
    ERROR_DIFFERENTIAL_FAILED = (
        "Differential response test failed for '{path}': {error}"
    )
    ERROR_MUTATION_REPLAY_FAILED = (
        "Mutation replay test failed for '{url}': {error}"
    )
    ERROR_OBJECT_WRITE_FAILED = (
        "Object write test failed for '{table}/{resource_id}': {error}"
    )
    ERROR_RPC_ACCESS_FAILED = (
        "RPC access test failed for '{function}': {error}"
    )


class LLMBusinessLogicConfig:
    """Configuration for LLM-driven business logic attack engine."""

    SCANNER_NAME = "llm_business_logic_attacker"
    MAX_FILES_FOR_ANALYSIS = 30
    MAX_FILE_CHARS = 0  # 0 = no truncation — send the full file
    MAX_ATTACK_PLANS = 10
    MAX_STEPS_PER_PLAN = 8
    MAX_TOKENS_ANALYSIS = 20480
    MAX_TOKENS_RESULT = 2048
    MAX_CONCURRENT_PLANS = 3
    HTTP_TIMEOUT_SECONDS = 15

    RESPONSE_PREVIEW_LENGTH = SharedPatterns.RESPONSE_PREVIEW_LENGTH
    MAX_ENDPOINTS_IN_PROMPT = 50
    DEFAULT_FINDING_TITLE = "Business logic vulnerability"
    FALLBACK_TEXT = "N/A"

    # File skip patterns
    FILE_SKIP_PATTERNS = ("node_modules/", "test", ".test.", ".spec.", "__pycache__")

    # Framework detection rules: (path_indicators, framework_name)
    FRAMEWORK_PATTERNS = (
        (("trpc", ".trpc"), "tRPC/Next.js"),
        (("next", "pages/api", "app/api"), "Next.js"),
        (("express",), "Express.js"),
        (("fastapi", "django"), "Python"),
    )
    DEFAULT_FRAMEWORK = "unknown"

    # File patterns that contain business logic
    BUSINESS_LOGIC_FILE_PATTERNS = (
        "router", "route", "controller", "handler", "service",
        "checkout", "payment", "order", "billing", "subscription",
        "webhook", "mutation", "procedure", "middleware", "policy",
        "deal", "listing", "transaction", "cart", "invoice",
    )

    # File extensions to consider
    CODE_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rs")

    ANALYSIS_SYSTEM_PROMPT = (
        "You are an elite penetration tester analyzing source code to plan "
        "targeted attacks against a LIVE running application.\n\n"
        "You have:\n"
        "- Full source code of the application\n"
        "- Two authenticated user sessions (admin_user and regular_user)\n"
        "- The ability to send arbitrary HTTP requests\n\n"
        "Your job: identify business logic vulnerabilities that automated "
        "scanners CANNOT find. Focus on:\n"
        "1. Authorization bypass (can regular_user do admin-only operations?)\n"
        "2. State machine violations (can you skip steps in a workflow?)\n"
        "3. Price/amount manipulation (client-controlled financial values)\n"
        "4. Race conditions (TOCTOU in check-then-act patterns)\n"
        "5. Cross-tenant data access (missing org/user scoping)\n"
        "6. Webhook replay/forgery (missing idempotency/signature checks)\n"
        "7. Mass assignment (extra fields accepted in mutations)\n\n"
        "For EACH vulnerability you find, generate an ATTACK PLAN: "
        "a sequence of HTTP requests to PROVE the vulnerability exists.\n\n"
        "Respond with valid JSON only."
    )

    ANALYSIS_USER_PROMPT = (
        "Analyze these source code files from a {framework} application "
        "and generate attack plans.\n\n"
        "Available endpoints discovered on the live app:\n"
        "{endpoints}\n\n"
        "Source code files:\n"
        "{code_files}\n\n"
        "Respond with this JSON structure:\n"
        "```json\n"
        '{{\n'
        '  "attack_plans": [\n'
        '    {{\n'
        '      "id": "plan-1",\n'
        '      "title": "Brief vulnerability title",\n'
        '      "severity": "CRITICAL|HIGH|MEDIUM",\n'
        '      "description": "What the vulnerability is and why it matters",\n'
        '      "affected_file": "path/to/file.ts",\n'
        '      "affected_line": 42,\n'
        '      "steps": [\n'
        '        {{\n'
        '          "action": "request",\n'
        '          "user": "admin_user|regular_user|no_auth",\n'
        '          "method": "GET|POST|PUT|PATCH|DELETE",\n'
        '          "url": "https://target.com/api/endpoint",\n'
        '          "body": {{"key": "value"}},\n'
        '          "description": "What this step does",\n'
        '          "expect": "What response indicates success/vulnerability"\n'
        '        }}\n'
        '      ],\n'
        '      "success_criteria": "How to determine if the attack worked"\n'
        '    }}\n'
        '  ]\n'
        '}}\n'
        "```\n\n"
        "Rules:\n"
        "- Only generate plans for REAL vulnerabilities you see in the code\n"
        "- Each step must use a real endpoint URL from the discovered list\n"
        "- Use admin_user for setup steps, regular_user for attack steps\n"
        "- Include the exact JSON body to send\n"
        "- Be specific about success_criteria (e.g., 'HTTP 200 with modified price')\n"
        "- Maximum {max_plans} plans, {max_steps} steps each\n"
        "- If no vulnerabilities found, return empty attack_plans array"
    )

    RESULT_ANALYSIS_SYSTEM_PROMPT = (
        "You are a security analyst reviewing the results of an automated "
        "penetration test. You executed an attack plan and got responses. "
        "Determine if the vulnerability was CONFIRMED or NOT CONFIRMED.\n\n"
        "Respond with valid JSON only."
    )

    RESULT_ANALYSIS_USER_PROMPT = (
        "Attack plan: {plan_title}\n"
        "Description: {plan_description}\n"
        "Success criteria: {success_criteria}\n\n"
        "Steps executed and responses:\n"
        "{step_results}\n\n"
        "Respond with:\n"
        "```json\n"
        '{{\n'
        '  "confirmed": true|false,\n'
        '  "confidence": 0.0-1.0,\n'
        '  "evidence": "Specific response data proving the vulnerability",\n'
        '  "severity": "CRITICAL|HIGH|MEDIUM|LOW",\n'
        '  "remediation": "How to fix this"\n'
        '}}\n'
        "```"
    )

    # Error messages
    ERROR_ANALYSIS_FAILED = "LLM business logic analysis failed: {error}"
    ERROR_PLAN_EXECUTION_FAILED = "Attack plan '{plan}' execution failed: {error}"
    ERROR_RESULT_ANALYSIS_FAILED = "Result analysis failed for '{plan}': {error}"

    # Logging
    LOG_ANALYSIS_COMPLETE = (
        "LLM Business Logic: analyzed %d files, generated %d attack plans"
    )
    LOG_EXECUTION_COMPLETE = (
        "LLM Business Logic: %d confirmed vulnerabilities from %d plans"
    )


class BodyParamFuzzerConfig:
    """Configuration for JSON body parameter fuzzing."""

    SCANNER_NAME = "body_param_fuzzer"
    MAX_REQUESTS_TO_FUZZ = 20
    MAX_PARAMS_PER_REQUEST = 10
    HTTP_TIMEOUT_SECONDS = 10
    PROBE_DELAY_SECONDS = 0.3
    MAX_CONCURRENT = 3
    RESPONSE_PREVIEW_LENGTH = SharedPatterns.RESPONSE_PREVIEW_LENGTH

    WRITE_METHODS = ("POST", "PUT", "PATCH")
    SUCCESS_CODES = (200, 201, 204)

    # Fuzzing payloads per type
    SQLI_PAYLOADS = (
        "' OR '1'='1' --",
        "1; DROP TABLE users--",
        "' UNION SELECT NULL,NULL--",
    )
    XSS_PAYLOADS = (
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
    )
    TYPE_CONFUSION_PAYLOADS = (
        ("string_to_int", 99999),
        ("string_to_bool", True),
        ("string_to_array", []),
        ("string_to_null", None),
        ("negative_number", -1),
        ("zero", 0),
        ("huge_number", 999999999999),
    )

    # Prototype pollution payloads (Node.js specific)
    PROTOTYPE_POLLUTION_PAYLOADS = (
        ("__proto__", {"polluted": "true"}),
        ("constructor", {"prototype": {"polluted": "true"}}),
        ("__proto__.polluted", "true"),
    )

    CONFIDENCE_PROTOTYPE_POLLUTION = 0.90
    TITLE_PROTOTYPE_POLLUTION = (
        "Prototype pollution via JSON body parameter '{param}'"
    )
    DESC_PROTOTYPE_POLLUTION = (
        "The server accepted a request with the '{param}' key in a "
        "{method} request to '{path}' and returned a 2xx response. "
        "In Node.js, setting __proto__ or constructor.prototype on a "
        "parsed JSON object can pollute Object.prototype globally, "
        "affecting all subsequent object operations. This can lead to "
        "authentication bypass (e.g., polluting isAdmin), RCE via "
        "gadget chains, or denial of service."
    )

    # Error indicators in responses
    ERROR_INDICATORS = (
        r"SQL syntax",
        r"pg_query",
        r"ORA-\d{5}",
        r"SQLITE_ERROR",
        r"syntax error",
        r"unterminated",
        r"SQLSTATE",
        r"stack trace",
        r"Traceback",
        r"TypeError",
        r"ValueError",
        r"Internal Server Error",
        r"NullPointerException",
    )

    # Confidence
    CONFIDENCE_SQL_ERROR = 0.90
    CONFIDENCE_XSS_REFLECTED = 0.85
    CONFIDENCE_TYPE_ERROR = 0.70
    CONFIDENCE_SERVER_ERROR = 0.60

    # Titles
    TITLE_SQL_ERROR = "SQL injection via JSON body parameter '{param}'"
    TITLE_XSS_BODY = "XSS via JSON body parameter '{param}'"
    TITLE_TYPE_CONFUSION = "Type confusion in JSON body parameter '{param}'"
    TITLE_SERVER_ERROR = "Server error triggered by malformed body parameter '{param}'"

    # Descriptions
    DESC_SQL_ERROR = (
        "Sending SQL injection payload in the '{param}' field of a {method} "
        "request to '{path}' triggered a database error in the response. "
        "This indicates the input is being interpolated into SQL queries "
        "without proper parameterization."
    )
    DESC_XSS_BODY = (
        "The XSS payload sent in the '{param}' field was reflected in the "
        "response body from '{path}'. This indicates insufficient output "
        "encoding for user-supplied data."
    )
    DESC_TYPE_CONFUSION = (
        "Sending a {payload_type} value for the '{param}' field (expected "
        "{original_type}) in a {method} request to '{path}' caused the "
        "server to return a {status} error. This may indicate missing "
        "input validation that could be exploited for logic bugs."
    )
    DESC_SERVER_ERROR = (
        "Sending a malformed value for '{param}' in a {method} request to "
        "'{path}' triggered a {status} server error. Detailed error messages "
        "may leak implementation details useful to an attacker."
    )

    ERROR_FUZZ_FAILED = "Body param fuzzing failed for '{url}': {error}"


class RaceConditionConfig:
    """Configuration for race condition / TOCTOU testing."""

    SCANNER_NAME = "race_condition_scanner"
    CONCURRENT_REQUESTS = 10
    MAX_MUTATIONS_TO_TEST = 10
    HTTP_TIMEOUT_SECONDS = 15
    RESPONSE_PREVIEW_LENGTH = SharedPatterns.RESPONSE_PREVIEW_LENGTH

    WRITE_METHODS = ("POST", "PUT", "PATCH")
    SUCCESS_STATUS_CODES = (200, 201, 204)

    # How many of the concurrent requests must succeed to flag
    SUCCESS_THRESHOLD = 2

    CONFIDENCE_RACE = 0.80

    TITLE_RACE_CONDITION = (
        "Race condition — {method} '{path}' succeeds {count} times concurrently"
    )
    DESC_RACE_CONDITION = (
        "Sending {total} concurrent {method} requests to '{path}' resulted in "
        "{count} successful responses (HTTP 2xx). For state-changing operations "
        "like payments, purchases, or balance updates, this could allow "
        "double-spending or duplicate resource creation. The server should use "
        "database transactions, optimistic locking, or idempotency keys."
    )
    ERROR_RACE_FAILED = "Race condition test failed for '{url}': {error}"


class PasswordResetConfig:
    """Configuration for password reset flow testing."""

    SCANNER_NAME = "password_reset_tester"
    RATE_LIMIT_BURST_COUNT = 5
    ENUM_SIZE_DIFF_THRESHOLD = 20
    SUCCESS_STATUS_CODES = (200, 201, 202, 204)
    RATE_LIMITED_STATUS = 429

    RESET_PATH_INDICATORS = (
        "/forgot-password", "/forgot", "/reset-password",
        "/password-reset", "/api/auth/forgot",
        "/api/forgot-password", "/api/reset-password",
    )

    # Test emails for enumeration
    TEST_NONEXISTENT_EMAIL = "definitely_not_a_real_user_9x8z@test.invalid"
    TEST_VALID_LOOKING_EMAIL = "admin@test.com"

    HTTP_TIMEOUT_SECONDS = 10
    RESPONSE_PREVIEW_LENGTH = SharedPatterns.RESPONSE_PREVIEW_LENGTH
    PROBE_DELAY_SECONDS = 1.0  # Be gentle with reset endpoints

    CONFIDENCE_ENUM = 0.80
    CONFIDENCE_NO_RATE_LIMIT = 0.75
    CONFIDENCE_TOKEN_IN_RESPONSE = 0.95

    TITLE_RESET_ENUM = "Password reset reveals account existence"
    TITLE_RESET_NO_LIMIT = "Password reset endpoint has no rate limiting"
    TITLE_RESET_TOKEN_LEAK = "Password reset token leaked in response body"

    DESC_RESET_ENUM = (
        "The password reset endpoint '{path}' returns different responses "
        "for existing vs non-existing email addresses ({status_a} vs {status_b}, "
        "body size {size_a} vs {size_b}). An attacker can enumerate valid "
        "accounts by observing these differences."
    )
    DESC_RESET_NO_LIMIT = (
        "The password reset endpoint '{path}' accepted {count} consecutive "
        "requests without rate limiting or CAPTCHA. An attacker could flood "
        "a user's inbox with reset emails or brute-force reset tokens."
    )
    DESC_RESET_TOKEN_LEAK = (
        "The password reset endpoint '{path}' returned what appears to be "
        "a reset token in the response body. Reset tokens should only be "
        "sent via email, not exposed in API responses."
    )

    # Token patterns in responses
    TOKEN_PATTERNS = (
        r'"token"\s*:\s*"([a-zA-Z0-9\-_\.]{20,})"',
        r'"reset_token"\s*:\s*"([a-zA-Z0-9\-_\.]{20,})"',
        r'"link"\s*:\s*"[^"]*token=([a-zA-Z0-9\-_\.]{20,})"',
    )

    ERROR_RESET_FAILED = "Password reset test failed for '{path}': {error}"


class MiddlewareAnalyzerConfig:
    """Configuration for middleware auth coverage analysis."""

    SCANNER_NAME = "middleware_analyzer"

    # Middleware file locations (Next.js)
    MIDDLEWARE_FILE_NAMES = (
        "middleware.ts",
        "middleware.js",
        "src/middleware.ts",
        "src/middleware.js",
    )

    # Pattern to extract matcher config
    MATCHER_CONFIG_PATTERN = r"config\s*=\s*\{[^}]*matcher\s*:\s*(\[.*?\]|\S+)"
    MATCHER_STRING_PATTERN = r'["\']([^"\']+)["\']'

    # Auth verification patterns — actual token/session verification.
    # NextResponse.redirect is intentionally excluded because it is a
    # response mechanism, not an auth verification step.  Even weak
    # middleware that only checks cookie existence will redirect on failure.
    MIDDLEWARE_AUTH_PATTERNS = CommonAuthPatterns.COMMON_AUTH_PATTERNS + (
        r"getToken\s*\(",
        r'request\.headers\.get\s*\(\s*["\']authorization',
        r"supabase\.auth\.getUser",
        r"createMiddlewareClient",
        r"createServerClient",
        r"updateSession",
    )

    # Weak auth patterns (checking cookie exists but not verifying)
    WEAK_AUTH_PATTERNS = (
        r"cookies\s*\(\s*\)\s*\.has\s*\(",
        r"request\.cookies\.has\s*\(",
        r"request\.cookies\.get\s*\([^)]+\)\s*$",
    )

    # Bypass check flags
    BYPASS_TRAILING_SLASH = True
    BYPASS_CASE_SENSITIVITY = True

    # Confidence thresholds
    CONFIDENCE_UNCOVERED_ROUTE = 0.85
    CONFIDENCE_WEAK_AUTH = 0.75
    CONFIDENCE_NO_MIDDLEWARE = 0.90
    CONFIDENCE_BYPASS_POSSIBLE = 0.70

    # Finding titles
    TITLE_NO_MIDDLEWARE = "No auth middleware found"
    TITLE_UNCOVERED_ROUTE = "API route not covered by auth middleware"
    TITLE_WEAK_AUTH = "Middleware uses weak authentication check"
    TITLE_BYPASS_POSSIBLE = "Middleware matcher may be bypassable"

    # Finding descriptions
    DESC_NO_MIDDLEWARE = (
        "No middleware.ts/middleware.js file was found in the project. "
        "Without middleware, API routes must individually implement auth checks. "
        "A centralized auth middleware is recommended for consistent protection."
    )
    DESC_UNCOVERED_ROUTE = (
        "The API route '{route}' ({file}) is not covered by the middleware "
        "matcher pattern. Requests to this route bypass the auth middleware "
        "entirely, relying only on route-level auth checks."
    )
    DESC_WEAK_AUTH = (
        "The middleware checks for the existence of an auth cookie/token "
        "but does not appear to verify its validity. An attacker could "
        "craft a fake cookie to bypass this check."
    )
    DESC_BYPASS_POSSIBLE = (
        "The middleware matcher '{matcher}' may be bypassable. "
        "{bypass_detail}"
    )

    # Bypass detail messages
    BYPASS_TRAILING_SLASH_DETAIL = (
        "The pattern does not account for trailing slashes. "
        "A request to '{route}/' may bypass the matcher."
    )
    BYPASS_CASE_SENSITIVITY_DETAIL = (
        "The pattern may be case-sensitive. "
        "A request with mixed-case path segments (e.g. '/Api/...') may bypass the matcher."
    )

    # Error messages
    ERROR_ANALYSIS_FAILED = "Middleware analysis failed: {error}"


class LLMCodeReviewConfig:
    """Configuration for LLM-powered code review."""

    SCANNER_NAME = "llm_code_reviewer"

    CHARS_PER_TOKEN_ESTIMATE = 4
    FALLBACK_FINDING_TITLE = "Security issue found by LLM review"

    # Review budget — let PrioritizedRouteSelector decide what to review
    # based on trigger priority, not an arbitrary file count cap.
    MAX_FILES_TO_REVIEW = 500
    MAX_TOKENS_PER_REVIEW = 4096
    # Parallel LLM calls — 10 concurrent reviews for throughput
    MAX_CONCURRENT_REVIEWS = 10
    # 50K chars ≈ 1,200 lines — covers virtually all route handlers.
    # Filters out genuinely huge generated/bundled files.
    MAX_FILE_SIZE_CHARS = 50_000
    # No hard token limit — review all selected routes thoroughly.
    # At $250-400/hr engagement rates, completeness is more valuable
    # than cost savings on LLM tokens.
    MAX_TOTAL_INPUT_TOKENS = 0  # 0 = unlimited

    # Only review files flagged as risky
    REVIEW_ONLY_FLAGGED = True

    # Risk indicators that trigger LLM review
    RISK_INDICATORS = (
        "no_auth_check",
        "no_ownership_check",
        "service_role_usage",
        "user_supplied_id",
        "mutation_without_auth",
    )

    CONFIDENCE_LLM_FINDING = 0.80

    # ------------------------------------------------------------------
    # Severity rubric (shared across all review prompts)
    # ------------------------------------------------------------------

    SEVERITY_RUBRIC = (
        "Severity definitions:\n"
        "- CRITICAL: Directly exploitable by an unauthenticated attacker, "
        "leads to data breach, financial loss, or full system compromise. "
        "No user interaction required.\n"
        "- HIGH: Exploitable by an authenticated attacker or requires "
        "minimal conditions. Leads to privilege escalation, data exposure "
        "across tenants, or significant business logic bypass.\n"
        "- MEDIUM: Requires specific conditions or chaining with another "
        "issue. Leads to limited data exposure, DoS, or information "
        "disclosure that aids further attacks.\n"
        "- LOW: Theoretical risk, defense-in-depth gap, or best-practice "
        "violation with minimal direct exploitability.\n"
    )

    # ------------------------------------------------------------------
    # Route review prompt (code-level security review)
    # ------------------------------------------------------------------

    ROUTE_REVIEW_SYSTEM_PROMPT = (
        "You are a senior security engineer reviewing API route code.\n\n"
        "Focus on:\n"
        "- Missing or bypassable authorization checks\n"
        "- IDOR (accessing resources by guessing IDs without ownership check)\n"
        "- Business logic flaws (price manipulation, state machine bypass)\n"
        "- Race conditions (TOCTOU, double-spend, check-then-act)\n"
        "- Injection risks (SQL, NoSQL, command, template)\n"
        "- Data over-exposure (returning internal fields to clients)\n"
        "- Multi-tenant isolation failures\n\n"
        "Do NOT flag these specific non-security items:\n"
        "- Code style (DRY, SOLID, naming, comments)\n"
        "- Soft-delete vs hard-delete design choices\n"
        "- Generic error message wording\n\n"
        "Auth context: if the route uses 'protectedProcedure', "
        "'tenantProcedure', or 'requireAuth', authentication IS present. "
        "Focus on authorization gaps — what can an authenticated user "
        "access or modify that they shouldn't.\n\n"
    ) + SEVERITY_RUBRIC

    ROUTE_REVIEW_USER_PROMPT = (
        "Review this {framework} API route for security vulnerabilities.\n\n"
        "Route: {route_pattern}\n"
        "Methods: {http_methods}\n"
        "File: {file_path}\n\n"
        "```{language}\n{code}\n```\n\n"
        "{db_context}\n"
        "For each vulnerability found, respond in this exact JSON format:\n"
        "```json\n"
        "[\n"
        "  {{\n"
        '    "severity": "CRITICAL|HIGH|MEDIUM|LOW",\n'
        '    "title": "Brief title",\n'
        '    "description": "What the vulnerability is, why it matters, '
        'and how an attacker would exploit it",\n'
        '    "line_number": 10,  // Use the line numbers shown in the code above\n'
        '    "remediation_guidance": "High-level fix approach without specific code"\n'
        "  }}\n"
        "]\n"
        "```\n\n"
        "If no vulnerabilities found, respond with an empty array: []\n\n"
        "Focus on real security vulnerabilities that an attacker could "
        "exploit. Do not pad with code style or best-practice observations."
    )

    MAX_FINDINGS_PER_FILE = 7

    # ------------------------------------------------------------------
    # RLS review prompt (database row-level security)
    # ------------------------------------------------------------------

    RLS_REVIEW_SYSTEM_PROMPT = (
        "You are a database security expert reviewing Row Level Security "
        "(RLS) policies in PostgreSQL migration files.\n\n"
        "Identify:\n"
        "- Tables with no RLS policies enabled\n"
        "- Policies that don't filter by the authenticated user's identity\n"
        "- Overly permissive policies (e.g., using 'true' as the check)\n"
        "- Policies that can be bypassed via alternative query paths\n"
        "- Missing tenant isolation in multi-tenant schemas\n\n"
    ) + SEVERITY_RUBRIC

    RLS_REVIEW_USER_PROMPT = (
        "Review these database migration files for RLS security issues.\n\n"
        "```sql\n{migration_sql}\n```\n\n"
        "Known tables from route analysis: {known_tables}\n\n"
        "For each issue, respond in this exact JSON format:\n"
        "```json\n"
        "[\n"
        "  {{\n"
        '    "severity": "CRITICAL|HIGH|MEDIUM|LOW",\n'
        '    "title": "Brief title",\n'
        '    "description": "What the issue is and its security impact",\n'
        '    "table": "table_name",\n'
        '    "remediation_guidance": "High-level fix approach"\n'
        "  }}\n"
        "]\n"
        "```\n\n"
        "If no issues found, respond with an empty array: []"
    )

    ERROR_LLM_REVIEW_FAILED = "LLM review failed for {file}: {error}"
    ERROR_PARSE_RESPONSE = "Failed to parse LLM response: {error}"


class RateLimitConfig:
    """Configuration for the rate limit scanner."""

    SCANNER_NAME = "rate_limit_scanner"
    BURST_REQUEST_COUNT = 20
    BURST_WINDOW_SECONDS = 5
    HTTP_TIMEOUT_SECONDS = 10
    CONFIDENCE_NO_RATE_LIMIT = 0.85
    CONFIDENCE_THRESHOLD_MEASURED = 0.90

    # Threshold measurement configuration
    THRESHOLD_BURST_SIZES: tuple[int, ...] = (10, 50, 100)
    MIN_DELAY_BETWEEN_REQUESTS = 0.05
    MAX_SEQUENTIAL_REQUESTS = 150

    CRITICAL_ENDPOINT_INDICATORS = (
        "/login", "/signin", "/auth", "/signup", "/register",
        "/password", "/reset", "/forgot", "/token", "/otp",
    )

    TITLE_NO_RATE_LIMIT = "No rate limiting on critical endpoint"
    TITLE_RATE_LIMIT_THRESHOLD = "Rate limit threshold measured"
    TITLE_RATE_LIMIT_PER_IP = "Rate limit appears IP-based only"
    DESC_NO_RATE_LIMIT = (
        "The endpoint {url} accepted {count} rapid requests within {window}s "
        "without returning a 429 (Too Many Requests) response. "
        "Without rate limiting, this endpoint is vulnerable to brute force attacks."
    )
    DESC_RATE_LIMIT_THRESHOLD = (
        "The endpoint {url} triggers rate limiting after approximately "
        "{threshold} requests. Burst size tested: {burst_size} requests. "
        "Consider whether this threshold is sufficient to prevent brute-force attacks."
    )
    DESC_RATE_LIMIT_PER_IP = (
        "The endpoint {url} applies rate limiting per IP address but not per user. "
        "An attacker with multiple IPs (botnets, proxies) can bypass the limit."
    )
    ERROR_RATE_LIMIT_SCAN_FAILED = "Rate limit scan failed for {endpoint}: {error}"

    # Test auth headers for IP vs user rate limit detection
    TEST_AUTH_HEADER_ALPHA = "Bearer test-rate-limit-user-alpha"
    TEST_AUTH_HEADER_BETA = "Bearer test-rate-limit-user-beta"


class JWTAttackConfig:
    """Configuration for the JWT attack scanner."""

    SCANNER_NAME = "jwt_attack_scanner"
    HTTP_TIMEOUT_SECONDS = 10
    MAX_CONCURRENT = SharedPatterns.DEFAULT_MAX_CONCURRENT
    PROBE_DELAY = SharedPatterns.DEFAULT_PROBE_DELAY
    CONFIDENCE_ALG_NONE = 0.95
    CONFIDENCE_WEAK_SECRET = 0.90
    CONFIDENCE_KEY_CONFUSION = 0.95
    CONFIDENCE_JWKS_EXPOSED = 0.50
    CONFIDENCE_TOKEN_IN_URL = 0.85
    CONFIDENCE_MISSING_EXP = 0.75
    CONFIDENCE_MISSING_CLAIMS = 0.60

    COMMON_WEAK_SECRETS = (
        "secret", "password", "123456", "jwt_secret",
        "your-256-bit-secret", "changeme", "test",
        "key", "supersecret", "default",
        "admin", "development", "staging", "",
    )

    JWKS_ENDPOINT_PATH = "/.well-known/jwks.json"
    JWT_URL_PATTERN = r'[?&](?:token|access_token|jwt|auth)=([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)'

    REQUIRED_CLAIMS = ("exp", "iat", "iss")

    # Claim manipulation — modify payload claims to test privilege escalation
    CLAIM_ESCALATION_MUTATIONS = (
        # (claim_name, test_value, description)
        ("role", "admin", "role escalation to admin"),
        ("role", "super_admin", "role escalation to super_admin"),
        ("is_admin", True, "admin flag set to true"),
        ("admin", True, "admin flag set to true"),
        ("user_role", "administrator", "role escalation to administrator"),
    )
    # Claims that identify the user — swap to test impersonation
    CLAIM_IDENTITY_FIELDS = ("sub", "user_id", "uid", "email")
    CLAIM_IMPERSONATION_VALUE = "00000000-0000-0000-0000-000000000000"

    CONFIDENCE_CLAIM_MANIPULATION = 0.90

    TITLE_CLAIM_ESCALATION = (
        "JWT claim manipulation accepted — '{claim}' set to '{value}'"
    )
    DESC_CLAIM_ESCALATION = (
        "The server accepted a JWT with the '{claim}' claim modified to "
        "'{value}' without rejecting the signature. This indicates the "
        "server either does not validate the JWT signature or trusts "
        "claims without verification, enabling {desc}."
    )

    TITLE_ALG_NONE = "JWT accepts algorithm 'none' (signature bypass)"
    TITLE_WEAK_SECRET = "JWT signed with weak/common secret"
    TITLE_KEY_CONFUSION = "JWT RS256/ES256 key confusion vulnerability"
    TITLE_JWKS_EXPOSED = "JWKS endpoint publicly accessible"
    TITLE_TOKEN_IN_URL = "JWT token passed in URL query string"
    TITLE_MISSING_EXP = "JWT missing expiration claim"
    TITLE_MISSING_CLAIMS = "JWT missing recommended claims"

    DESC_ALG_NONE = (
        "The server accepted a JWT with algorithm set to 'none' and an empty "
        "signature. This allows any attacker to forge valid tokens."
    )
    DESC_WEAK_SECRET = (
        "The JWT was successfully verified using the weak secret '{secret}'. "
        "An attacker can forge tokens by signing them with this secret."
    )
    DESC_KEY_CONFUSION = (
        "The server accepted a JWT signed with HMAC using the RSA/EC public key "
        "as the secret. This is a critical algorithm confusion attack: an attacker "
        "with the public key (from JWKS) can forge arbitrary valid tokens."
    )
    DESC_JWKS_EXPOSED = (
        "The JWKS endpoint at {url} is publicly accessible. While not a "
        "vulnerability by itself, it exposes the public keys used for JWT "
        "verification, which is a prerequisite for key confusion attacks."
    )
    DESC_TOKEN_IN_URL = (
        "A JWT token was found in the URL query string of {url}. "
        "Tokens in URLs are logged in server access logs, browser history, "
        "and referrer headers, increasing the risk of token leakage."
    )
    DESC_MISSING_EXP = (
        "The JWT does not contain an 'exp' (expiration) claim. "
        "Tokens without expiration never become invalid, even after logout."
    )
    DESC_MISSING_CLAIMS = (
        "The JWT is missing these recommended claims: {claims}. "
        "Missing 'iss' allows tokens from other services to be accepted."
    )
    ERROR_JWT_SCAN_FAILED = "JWT scan failed: {error}"


class SessionScanConfig:
    """Configuration for the session scanner."""

    SCANNER_NAME = "session_scanner"
    HTTP_TIMEOUT_SECONDS = 10
    CONFIDENCE_INSECURE_STORAGE = 0.80
    CONFIDENCE_NO_HTTPONLY = 0.85
    CONFIDENCE_NO_SECURE = 0.85
    CONFIDENCE_LONG_EXPIRY = 0.60

    MAX_RECOMMENDED_EXPIRY_HOURS = 24

    TITLE_TOKEN_IN_LOCALSTORAGE = "Auth token stored in localStorage (XSS-accessible)"
    TITLE_MISSING_HTTPONLY = "Auth cookie missing HttpOnly flag"
    TITLE_MISSING_SECURE = "Auth cookie missing Secure flag"
    TITLE_LONG_EXPIRY = "Session token has very long expiration"

    DESC_TOKEN_IN_LOCALSTORAGE = (
        "The application stores authentication tokens in localStorage. "
        "localStorage is accessible to any JavaScript on the page, meaning "
        "an XSS vulnerability would allow token theft. Use httpOnly cookies instead."
    )
    DESC_MISSING_HTTPONLY = (
        "The cookie '{cookie}' does not have the HttpOnly flag. "
        "This means JavaScript can read the cookie via document.cookie, "
        "enabling token theft via XSS."
    )
    DESC_MISSING_SECURE = (
        "The cookie '{cookie}' does not have the Secure flag. "
        "The cookie will be sent over unencrypted HTTP connections."
    )
    DESC_LONG_EXPIRY = (
        "The session token expires in {hours} hours ({days} days). "
        "Long-lived tokens increase the window for token theft."
    )
    ERROR_SESSION_SCAN_FAILED = "Session scan failed: {error}"

    # Patterns to detect localStorage token storage in JS
    LOCALSTORAGE_TOKEN_PATTERNS = (
        r'localStorage\.setItem\s*\(\s*["\'](?:token|access_token|auth_token|jwt)',
        r'localStorage\[[\'"](token|access_token|auth_token|jwt)',
    )

    # Cookie names commonly used for auth
    AUTH_COOKIE_NAMES = (
        "token", "access_token", "auth_token", "session",
        "sid", "jwt", "sb-access-token", "sb-refresh-token",
        "__session", "connect.sid",
    )


class GraphQLConfig:
    """Configuration for GraphQL vulnerability scanning."""

    SCANNER_NAME = "graphql_scanner"
    MAX_CONCURRENT = SharedPatterns.DEFAULT_MAX_CONCURRENT
    PROBE_DELAY = SharedPatterns.DEFAULT_PROBE_DELAY
    HTTP_TIMEOUT_SECONDS = 10

    GRAPHQL_PATH_INDICATORS = ("/graphql", "/api/graphql", "/gql")

    INTROSPECTION_QUERY = '{"query":"{ __schema { types { name fields { name } } } }"}'
    DEPTH_BOMB_QUERY_TEMPLATE = '{{"query":"{{ {nested_query} }}"}}'
    BATCH_QUERY = '[{"query":"{ __typename }"},{"query":"{ __typename }"}]'

    MAX_DEPTH_TEST = 10
    CONFIDENCE_INTROSPECTION = 0.90
    CONFIDENCE_NO_DEPTH_LIMIT = 0.80
    CONFIDENCE_BATCH_ALLOWED = 0.70

    TITLE_INTROSPECTION = "GraphQL introspection enabled (schema exposed)"
    TITLE_NO_DEPTH_LIMIT = "GraphQL has no query depth limit"
    TITLE_BATCH_ALLOWED = "GraphQL allows batch queries (potential DoS)"

    DESC_INTROSPECTION = (
        "The GraphQL endpoint {url} has introspection enabled, exposing the "
        "entire API schema. Attackers can enumerate all types, fields, and "
        "relationships to find sensitive data and hidden functionality."
    )
    DESC_NO_DEPTH_LIMIT = (
        "The GraphQL endpoint {url} accepted a deeply nested query ({depth} levels). "
        "Without depth limits, attackers can craft queries that cause exponential "
        "resource consumption (DoS)."
    )
    DESC_BATCH_ALLOWED = (
        "The GraphQL endpoint {url} accepted a batch of multiple queries in a "
        "single request. Batch queries can bypass rate limiting and amplify attacks."
    )
    ERROR_GRAPHQL_SCAN_FAILED = "GraphQL scan failed for {endpoint}: {error}"


class SSRFConfig:
    """Configuration for SSRF vulnerability scanning."""

    SCANNER_NAME = "ssrf_scanner"
    HTTP_TIMEOUT_SECONDS = 10
    MAX_CONCURRENT = SharedPatterns.DEFAULT_MAX_CONCURRENT
    PROBE_DELAY = SharedPatterns.DEFAULT_PROBE_DELAY
    CONFIDENCE_SSRF = 0.80

    # Parameters that commonly accept URLs
    URL_PARAM_NAMES = (
        "url", "uri", "link", "href", "src", "source",
        "redirect", "next", "return", "callback",
        "image", "img", "photo", "avatar",
        "webhook", "endpoint", "target", "dest",
        "fetch", "load", "proxy",
    )

    # SSRF probes (internal/cloud metadata)
    SSRF_PROBES = (
        ("http://127.0.0.1", "localhost"),
        ("http://localhost", "localhost"),
        ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
        ("http://metadata.google.internal/", "gcp_metadata"),
        ("http://[::1]", "ipv6_localhost"),
        ("http://0.0.0.0", "zero_address"),
    )

    # Response indicators that suggest SSRF worked
    SSRF_SUCCESS_INDICATORS = (
        "ami-id", "instance-id", "iam/", "meta-data",  # AWS
        "computeMetadata", "project/project-id",  # GCP
        "<!DOCTYPE html>",  # Got actual page content from internal
    )

    TITLE_SSRF = "Server-Side Request Forgery (SSRF) vulnerability"
    DESC_SSRF = (
        "The parameter '{param}' on endpoint {url} appears to accept a URL "
        "that the server fetches. When set to '{probe}', the server responded "
        "with data suggesting it reached the internal resource. An attacker "
        "could access internal services, cloud metadata, or perform port scanning."
    )
    ERROR_SSRF_SCAN_FAILED = "SSRF scan failed for {endpoint}: {error}"


class FileUploadConfig:
    """Configuration for file upload vulnerability scanning."""

    SCANNER_NAME = "file_upload_scanner"
    HTTP_TIMEOUT_SECONDS = 10
    MAX_CONCURRENT = SharedPatterns.DEFAULT_MAX_CONCURRENT
    PROBE_DELAY = SharedPatterns.DEFAULT_PROBE_DELAY
    CONFIDENCE_UNRESTRICTED = 0.85
    CONFIDENCE_PATH_TRAVERSAL = 0.90

    # Endpoint indicators for file upload
    UPLOAD_PATH_INDICATORS = (
        "/upload", "/file", "/media", "/attachment",
        "/image", "/avatar", "/document", "/import",
    )
    UPLOAD_CONTENT_TYPES = ("multipart/form-data",)

    # Dangerous file types to test: (extension, content_type, payload)
    DANGEROUS_EXTENSIONS = (
        (".html", "text/html", "<script>alert(1)</script>"),
        (".svg", "image/svg+xml", '<svg onload="alert(1)">'),
    )

    # Path traversal filenames
    PATH_TRAVERSAL_FILENAMES = (
        "../../../etc/passwd",
        "..\\..\\..\\etc\\passwd",
        "....//....//etc/passwd",
    )

    TITLE_UNRESTRICTED_TYPE = "File upload accepts dangerous file types"
    TITLE_PATH_TRAVERSAL = "File upload vulnerable to path traversal"
    DESC_UNRESTRICTED_TYPE = (
        "The upload endpoint {url} accepted a file with extension '{ext}' "
        "and content-type '{content_type}'. This could allow XSS via "
        "uploaded HTML/SVG files."
    )
    DESC_PATH_TRAVERSAL = (
        "The upload endpoint {url} accepted a filename containing path "
        "traversal characters ('{filename}'). This could allow writing "
        "files outside the intended directory."
    )
    ERROR_UPLOAD_SCAN_FAILED = "File upload scan failed for {endpoint}: {error}"


class MassAssignmentConfig:
    """Configuration for mass assignment vulnerability scanning."""

    SCANNER_NAME = "mass_assignment_scanner"
    HTTP_TIMEOUT_SECONDS = 10
    MAX_CONCURRENT = SharedPatterns.DEFAULT_MAX_CONCURRENT
    PROBE_DELAY = SharedPatterns.DEFAULT_PROBE_DELAY
    CONFIDENCE_MASS_ASSIGNMENT = 0.85

    # Fields to inject that indicate privilege escalation
    ESCALATION_FIELDS = (
        ("role", "admin"),
        ("is_admin", True),
        ("is_verified", True),
        ("email_verified", True),
        ("plan", "enterprise"),
        ("credits", 99999),
        ("permissions", "all"),
    )

    # Supabase-specific: try injecting extra columns
    SUPABASE_ESCALATION_FIELDS = (
        ("role", "admin"),
        ("is_admin", True),
        ("stripe_customer_id", "cus_fake"),
    )

    # HTTP methods that accept body payloads for object creation/update
    STATE_CHANGING_METHODS = ("POST", "PUT", "PATCH")

    # Prefer header to get back the representation
    PREFER_RETURN_REPRESENTATION = "return=representation"

    TITLE_MASS_ASSIGNMENT = "Mass assignment: extra fields accepted"
    DESC_MASS_ASSIGNMENT = (
        "The endpoint {url} accepted the extra field '{field}' with value '{value}' "
        "in a {method} request. If this field controls permissions, billing, or "
        "verification status, an attacker could escalate privileges."
    )
    ERROR_MASS_ASSIGNMENT_FAILED = (
        "Mass assignment scan failed for {endpoint}: {error}"
    )


class StaticInjectionConfig:
    """Configuration for injection pattern file flagging.

    The injection analyzer no longer produces findings directly.
    It flags files containing injection-relevant patterns and sends
    them to the LLM code reviewer for human-quality analysis.
    """

    SCANNER_NAME = "injection_pattern_trigger"

    # File extensions to scan
    CODE_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs")

    # Skip patterns (test files, generated code)
    SKIP_FILE_PATTERNS = (
        r'\.test\.',
        r'\.spec\.',
        r'__tests__',
        r'\.d\.ts$',
        r'node_modules/',
    )

    # Maximum files to flag for LLM review (budget control)
    MAX_FILES_TO_FLAG = 15

    # Prefix for synthetic RouteEntry route_pattern
    SYNTHETIC_ROUTE_PREFIX = "[injection-check] "

    # --- Injection flag patterns ---
    # Each entry: (human-readable label, tuple of regex patterns)
    # If ANY pattern matches, the file is flagged for that type.
    INJECTION_FLAG_PATTERNS = (
        (
            "SQL injection",
            (
                r'\.raw\s*\(\s*`[^`]*\$\{',
                r'query\s*\(\s*["\'][^"\']*\'\s*\+',
                r'execute\s*\(\s*`[^`]*\$\{',
                r'supabase\s*\.\s*rpc\s*\([^)]*\+',
                r'`\s*SELECT\s.*\$\{',
                r'`\s*INSERT\s.*\$\{',
                r'`\s*UPDATE\s.*\$\{',
                r'`\s*DELETE\s.*\$\{',
            ),
        ),
        (
            "XSS",
            (
                r'dangerouslySetInnerHTML\s*=\s*\{',
                r'\.innerHTML\s*=\s*(?![\s"\'`])',
                r'document\.write\s*\(\s*(?![\s"\'`])',
            ),
        ),
        (
            "Command injection",
            (
                r'exec\s*\(\s*`[^`]*\$\{',
                r'execSync\s*\(\s*`[^`]*\$\{',
                r'spawn\s*\(\s*[^,]+\+',
                r'child_process.*exec\s*\(\s*`[^`]*\$\{',
            ),
        ),
        (
            "Path traversal",
            (
                r'readFile(?:Sync)?\s*\(\s*(?:req\.|params\.|query\.)',
                r'createReadStream\s*\(\s*(?:req\.|params\.|query\.)',
                r'path\.join\s*\([^)]*(?:req\.|params\.|query\.)',
                r'fs\.\w+\s*\(\s*`[^`]*\$\{',
            ),
        ),
    )

    # --- LLM review prompt ---
    INJECTION_REVIEW_SYSTEM_PROMPT = (
        "You are a senior security engineer reviewing code for injection "
        "vulnerabilities.\n\n"
        "This file was flagged because it contains patterns that MIGHT be "
        "injection vectors. Your job is to determine which are REAL "
        "vulnerabilities vs safe usage (parameterized queries, tagged "
        "templates, ORM methods, constants, sanitized input).\n\n"
        "For each real vulnerability, consider:\n"
        "- Where does the interpolated value come from? (user input = dangerous, "
        "constant/config = safe)\n"
        "- Is the query parameterized? (prepared statements, $1 placeholders, "
        "ORM .where() = safe)\n"
        "- Is the output sanitized? (DOMPurify, escapeHtml = safe)\n"
        "- Is the command built from trusted sources only?\n\n"
        "Do NOT flag:\n"
        "- ORM query builders (Drizzle .where(), Prisma .findMany())\n"
        "- Tagged template literals (sql`...`) — these are parameterized\n"
        "- Template literals with hardcoded/constant values\n"
        "- React JSX expressions (these are auto-escaped)\n\n"
        "Do NOT flag code style issues (DRY, SOLID, naming, comments).\n\n"
    ) + LLMCodeReviewConfig.SEVERITY_RUBRIC

    INJECTION_REVIEW_USER_PROMPT = (
        "Review this file for injection vulnerabilities.\n\n"
        "File: {file_path}\n"
        "Flagged patterns: {flagged_patterns}\n\n"
        "```{language}\n{code}\n```\n\n"
        "{db_context}\n"
        "For each vulnerability found, respond in this exact JSON format:\n"
        "```json\n"
        "[\n"
        "  {{\n"
        '    "severity": "CRITICAL|HIGH|MEDIUM|LOW",\n'
        '    "title": "Brief title",\n'
        '    "description": "What the vulnerability is, why it matters, '
        'and how an attacker would exploit it",\n'
        '    "line_number": 10,\n'
        '    "remediation_guidance": "High-level fix approach"\n'
        "  }}\n"
        "]\n"
        "```\n\n"
        "If no real vulnerabilities found (all patterns are safe usage), "
        "respond with an empty array: []\n\n"
        "Focus on REAL injection risks where user input flows into "
        "dangerous sinks. Ignore safe ORM usage and tagged templates."
    )


class DependencyScannerConfig:
    """Configuration for dependency vulnerability scanning."""

    SCANNER_NAME = "dependency_scanner"

    # CVSS score thresholds for severity mapping
    CVSS_CRITICAL_THRESHOLD = 9.0
    CVSS_HIGH_THRESHOLD = 7.0
    CVSS_MEDIUM_THRESHOLD = 4.0
    DEFAULT_OSV_SEVERITY = SeverityLevel.HIGH.value

    OSV_API_URL = "https://api.osv.dev/v1/query"
    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
    HTTP_TIMEOUT_SECONDS = 30
    MAX_PACKAGES_TO_CHECK = 200
    BATCH_SIZE = 100
    CONFIDENCE_KNOWN_CVE = 0.95
    CONFIDENCE_OUTDATED = 0.50

    ECOSYSTEM = "npm"
    PACKAGE_JSON_FILE = "package.json"

    TITLE_KNOWN_CVE = "Vulnerable dependency: {package}@{version}"
    TITLE_OUTDATED = "Severely outdated package: {package}@{version}"

    DESC_KNOWN_CVE = (
        "The package '{package}' at version {version} has a known vulnerability: "
        "{summary}. Severity: {severity}. "
        "Update to a patched version to fix this issue."
    )
    DESC_OUTDATED = (
        "The package '{package}' at version {version} is severely outdated. "
        "Outdated packages may contain unpatched security vulnerabilities."
    )

    ERROR_OSV_QUERY_FAILED = "OSV vulnerability query failed: {error}"
    ERROR_PARSE_LOCKFILE = "Failed to parse lock file: {error}"


class FirebaseRulesConfig:
    """Configuration for Firebase rules analysis."""

    SCANNER_NAME = "firebase_rules_analyzer"
    CONFIDENCE_OPEN_RULES = 0.95
    CONFIDENCE_MISSING_AUTH = 0.85
    CONFIDENCE_WILDCARD = 0.75

    # Firebase rules file locations
    RULES_FILE_NAMES = (
        "firestore.rules",
        "storage.rules",
        "database.rules.json",
        "firebase/firestore.rules",
        "firebase/storage.rules",
    )

    # Dangerous rule patterns
    OPEN_READ_WRITE = r'allow\s+read\s*,\s*write\s*:\s*if\s+true'
    OPEN_READ = r'allow\s+read\s*:\s*if\s+true'
    OPEN_WRITE = r'allow\s+write\s*:\s*if\s+true'
    MISSING_AUTH_CHECK = r'allow\s+(?:read|write|create|update|delete)\s*:'
    AUTH_CHECK_PATTERN = r'request\.auth\s*!=\s*null|request\.auth\.uid'
    ALLOW_OPERATION_PATTERN = r'allow\s+(\w+)'

    # Realtime DB dangerous patterns
    RTDB_OPEN_READ = r'"\.read"\s*:\s*true'
    RTDB_OPEN_WRITE = r'"\.write"\s*:\s*true'

    # Wildcard collection pattern
    WILDCARD_COLLECTION_PATTERN = r'match\s+/\{[^}]+=\*\*\}'

    # Firebase type detection
    FIRESTORE_INDICATOR = "service cloud.firestore"
    STORAGE_INDICATOR = "service firebase.storage"

    TITLE_OPEN_RULES = "Firebase {type} rules allow unrestricted access"
    TITLE_MISSING_AUTH = "Firebase {type} rule missing authentication check"
    TITLE_WILDCARD_COLLECTION = "Firebase {type} rule uses broad wildcard"

    DESC_OPEN_RULES = (
        "The Firebase {type} rules file '{file}' contains 'allow read, write: if true' "
        "which grants unrestricted access to all users, including unauthenticated ones."
    )
    DESC_MISSING_AUTH = (
        "The Firebase {type} rule for '{path}' allows {operation} without checking "
        "request.auth. Any unauthenticated user can {operation} this data."
    )
    DESC_WILDCARD_COLLECTION = (
        "The Firebase {type} rule uses a broad wildcard match '{path}' that "
        "may unintentionally expose multiple collections/documents."
    )

    ERROR_RULES_PARSE_FAILED = "Firebase rules analysis failed for {file}: {error}"


class OrchestratorConfig:
    """Configuration for the unified scan orchestrator."""

    PROGRESS_FREE_SCAN = 15
    PROGRESS_INGESTION = 20
    PROGRESS_ENDPOINT_DISCOVERY = 25
    PROGRESS_DAST_SCANNERS = 50
    PROGRESS_AUTH_AND_IDOR = 65
    PROGRESS_CODE_INGESTION = 70
    PROGRESS_SAST_SCANNERS = 85
    PROGRESS_LLM_REVIEW = 95
    PROGRESS_CROSS_REFERENCE = 98
    PROGRESS_COMPLETE = 100

    SUMMARY_SEPARATOR = " | "

    ERROR_SCAN_FAILED = "Deep scan failed: {error}"
    ERROR_AUTH_FAILED = "Authentication failed: {error}"
    ERROR_REPO_FAILED = "Repository ingestion failed: {error}"
    ERROR_INGESTION_FAILED = "URL ingestion failed for {url}: {error}"

    MSG_FETCHING_URL = "Fetching {url} and extracting assets..."
    MSG_FETCHED_ASSETS = "Fetched {count} assets ({js_size:,} bytes JS)"
    MSG_INGESTION_FAILED = "Failed to fetch {url}"
    MSG_CLONING_REPO = "Cloning {repo_url}..."
    MSG_DISCOVERING = "Discovering API endpoints..."
    MSG_AUTHENTICATING = "Authenticating..."
    MSG_AUTH_FAILED = "Auth failed: {error}"
    MSG_DAST_RUNNING = "Running DAST scanners..."
    MSG_AUTH_SCANNING = "Authenticated scanning..."
    MSG_CRAWL_SUMMARY = (
        "Authenticated crawl: {pages} pages, "
        "{endpoints} API endpoints, {tables} tables discovered"
    )
    MSG_CRAWL_NO_PAGES = "Authenticated crawl completed but no pages visited"
    MSG_CRAWL_ERROR = "Authenticated crawl issues: {error}"
    DEFAULT_CRAWL_USER_ID = "crawl-user"
    MSG_SAST_RUNNING = "Running code analysis..."
    MSG_LLM_REVIEW = "LLM code review..."
    MSG_CROSS_REF = "Cross-referencing DAST and SAST findings..."
    MSG_COMPILING = "Compiling results..."

    SUMMARY_DURATION = "Scan complete in {duration}s"
    SUMMARY_MODE = "Mode: {mode}"
    SUMMARY_SCANNERS = "Scanners run: {count}"
    SUMMARY_FINDINGS = "Findings: {total} total"
    SUMMARY_CRITICAL = "Critical: {count}"
    SUMMARY_HIGH = "High: {count}"


class RateLimitedClientConfig:
    """Configuration for the rate-limited HTTP client wrapper."""

    ERROR_NOT_CONTEXT_MANAGER = (
        "RateLimitedClient must be used as an async context manager"
    )


class OOBConfig:
    """Configuration for Out-of-Band callback detection via interact.sh.

    Uses a self-hosted interactsh server (primary) with public servers as
    fallback.  Detects blind SSRF, blind XSS, blind injection, and blind
    XXE by checking if the target server makes outbound requests to
    callback URLs.

    Protocol (interactsh v1):
        Register:  POST /register  with RSA public key (base64-PEM)
        Generate:  ``<correlation_id><nonce>.<domain>``
        Poll:      GET /poll?id=<corr_id>&secret=<secret>
        Decrypt:   AES-CFB with RSA-OAEP-decrypted key
    """

    # interact.sh servers (tried in order — self-hosted first)
    SERVERS = (
        "http://oob.isitsecure.ai",
        "https://oast.pro",
        "https://oast.live",
        "https://oast.fun",
        "https://oast.me",
    )

    # Domain suffix for the self-hosted server (used to build callback URLs)
    SELF_HOSTED_DOMAIN = "oob.isitsecure.ai"

    REGISTER_PATH = "/register"
    POLL_PATH = "/poll"

    HTTP_TIMEOUT_SECONDS = 10
    POLL_DELAY_SECONDS = 5  # Wait before first poll (DNS propagation)
    POLL_INTERVAL_SECONDS = 3  # Between poll attempts
    POLL_ATTEMPTS = 3

    # interactsh v1 protocol constants
    CORRELATION_ID_LENGTH = 20
    NONCE_LENGTH = 13
    RSA_KEY_SIZE = 2048

    CONFIDENCE_OOB_CONFIRMED = 0.95
    MAX_OOB_POST_ENDPOINTS = 10  # Cap POST endpoints for injection/XXE/XSS OOB

    # Source pattern and param name constants
    SOURCE_PATTERN_SSRF = "oob_ssrf"
    PARAM_NAME_BODY = "body"

    # Write methods for selecting POST endpoints
    WRITE_METHODS = ("POST", "PUT", "PATCH")

    # Per-scanner severity for OOB-confirmed findings
    SCANNER_SEVERITY = {
        "ssrf": SeverityLevel.CRITICAL,
        "injection": SeverityLevel.CRITICAL,
        "xss": SeverityLevel.HIGH,
        "xxe": SeverityLevel.HIGH,
        "cmd": SeverityLevel.CRITICAL,
    }

    SCANNER_CATEGORY = {
        "ssrf": FindingCategory.INJECTION_RISK,
        "injection": FindingCategory.INJECTION_RISK,
        "xss": FindingCategory.INJECTION_RISK,
        "xxe": FindingCategory.INJECTION_RISK,
        "cmd": FindingCategory.INJECTION_RISK,
    }

    # OOB payloads injected by each scanner
    # SSRF: URL parameters that accept URLs
    SSRF_OOB_LABEL = "blind SSRF"

    # Injection: payloads that trigger outbound requests from the DB/OS
    INJECTION_OOB_PAYLOADS = (
        # MySQL
        ("LOAD_FILE('http://{callback}')", "mysql_load_file"),
        # PostgreSQL
        ("COPY (SELECT '') TO PROGRAM 'curl {callback}'", "pg_copy_program"),
        # Command injection
        ("`curl {callback}`", "cmd_backtick"),
        ("$(curl {callback})", "cmd_subshell"),
        ("; curl {callback} ;", "cmd_semicolon"),
        ("| curl {callback}", "cmd_pipe"),
    )

    # XXE: external entity pointing to callback
    XXE_OOB_PAYLOAD = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{callback}">]>'
        '<root>&xxe;</root>'
    )

    # Blind XSS: payloads stored and rendered later
    XSS_OOB_PAYLOADS = (
        '<img src=http://{callback}>',
        '"><img src=http://{callback}>',
        "'-fetch('http://{callback}')-'",
    )

    # Finding text
    TITLE_OOB_CONFIRMED = (
        "Blind {scanner} confirmed via OOB callback — {desc}"
    )
    DESC_OOB_CONFIRMED = (
        "The scanner confirmed a blind {scanner} vulnerability on "
        "{endpoint} (parameter: '{param}'). The target server made an "
        "outbound {interaction_type} request to an external callback "
        "URL controlled by the scanner.\n\n"
        "**Why this matters:** The server processed attacker-controlled "
        "input and made a server-side request. Unlike reflected "
        "vulnerabilities (visible in the HTTP response), blind "
        "vulnerabilities leave NO trace in the response — they can "
        "only be detected via out-of-band callbacks.\n\n"
        "**What was tested:** {desc}"
    )

    # Logging
    LOG_REGISTERED = "OOB callback registered: %s (server: %s)"
    LOG_POLL_COMPLETE = "OOB poll: %d interactions from %d pending tags"
    ERROR_REGISTER_FAILED = (
        "OOB callback registration failed on all servers. "
        "Blind vulnerability detection will be skipped."
    )


class CrossRefConfig:
    """Configuration for cross-referencing DAST and SAST findings."""

    SCANNER_NAME = "cross_referencer"
    CONFIDENCE_CROSS_REF = 0.95

    TITLE_IDOR_CONFIRMED = "IDOR confirmed: live testing + code analysis"
    TITLE_IDOR_AUTH_MISSING = "IDOR confirmed: endpoint exposed + missing auth in code"
    TITLE_RLS_GAP_CONFIRMED = "RLS gap confirmed: live probing + migration analysis"
    TITLE_SECRET_EXPOSURE_CONFIRMED = "Secret exposure confirmed: JS bundle + git history"
    TITLE_EXPOSED_ENDPOINT_CONFIRMED = "Exposed endpoint confirmed: accessible + no auth in code"
    TITLE_INJECTION_CONFIRMED = "Injection risk confirmed: active testing + code patterns"

    TITLE_DAST_SAST_CONFIRMED = "Confirmed by both live testing and code analysis"
    DESC_DAST_SAST_CONFIRMED = (
        "This vulnerability was independently discovered by both dynamic testing "
        "(DAST) and static code analysis (SAST), providing high confidence. "
        "DAST finding: {dast_title}. SAST finding: {sast_title}."
    )
    EVIDENCE_TEMPLATE = "Cross-referenced: {dast_scanner} + {sast_scanner}"
    TECHNICAL_DAST_PREFIX = "DAST: "
    TECHNICAL_SAST_PREFIX = "SAST: "
    TECHNICAL_DETAIL_SEPARATOR = "\n"
    SAST_FALLBACK_DESCRIPTION_LIMIT = 100


class OwnershipVerificationConfig:
    """Configuration for ownership verification."""

    DNS_TXT_PREFIX = "_deepscan"
    DNS_TXT_RECORD_NAME = "_deepscan.{domain}"
    DNS_TXT_VALUE_PREFIX = "deepscan-verify="

    META_TAG_NAME = "deepscan-verify"
    META_TAG_PATTERN = (
        r'<meta\s+name=["\']deepscan-verify["\']\s+content=["\']([^"\']+)["\']'
    )

    VERIFICATION_FILE_PATH = "/.well-known/deepscan-verify.txt"

    HTTP_TIMEOUT_SECONDS = 10
    DNS_TIMEOUT_SECONDS = 5
    TOKEN_LENGTH = 32

    CONFIDENCE_DNS = 0.99
    CONFIDENCE_META = 0.95
    CONFIDENCE_FILE = 0.95
    CONFIDENCE_GITHUB = 0.90
    CONFIDENCE_MANUAL = 1.0

    ERROR_VERIFICATION_FAILED = (
        "Ownership verification failed: {method} - {error}"
    )
    ERROR_TOKEN_MISMATCH = (
        "Verification token mismatch. Expected: {expected}, Found: {found}"
    )
    ERROR_DNS_LOOKUP_FAILED = "DNS TXT lookup failed for {domain}: {error}"
    ERROR_META_NOT_FOUND = (
        "Meta tag 'deepscan-verify' not found in page HTML"
    )
    ERROR_FILE_NOT_FOUND = "Verification file not found at {url}"
    ERROR_GITHUB_ACCESS_DENIED = (
        "GitHub token does not have read access to {repo}"
    )

    MSG_VERIFICATION_SKIPPED = "Ownership verification skipped (manual mode)"
    MSG_VERIFIED = "Ownership verified via {method}"


class ScanConfigDefaults:
    """Default values for scan configuration."""

    MAX_CRAWL_DEPTH = 3
    MAX_ENDPOINTS_TO_TEST = 50
    MAX_FILES_FOR_LLM_REVIEW = 500
    LLM_TOKEN_BUDGET = 0  # 0 = unlimited

    DEFAULT_EXCLUDE_PATHS: tuple[str, ...] = ()
    DEFAULT_EXCLUDE_TABLES: tuple[str, ...] = ()


class CICDConfig:
    """Configuration for CI/CD integration."""

    GITHUB_API_BASE = "https://api.github.com"
    GITHUB_COMMIT_STATUS_ENDPOINT = "/repos/{owner}/{repo}/statuses/{sha}"
    GITHUB_CHECK_RUN_ENDPOINT = "/repos/{owner}/{repo}/check-runs"

    VERCEL_WEBHOOK_PATH = "/webhooks/vercel-deploy"
    NETLIFY_WEBHOOK_PATH = "/webhooks/netlify-deploy"

    STATUS_CONTEXT = "security/deepscan"
    STATUS_PENDING_DESC = "Deep security scan in progress..."
    STATUS_SUCCESS_DESC = (
        "Security scan passed — {grade} grade, {findings} findings"
    )
    STATUS_FAILURE_DESC = (
        "Security scan found {critical} critical, {high} high severity issues"
    )
    STATUS_ERROR_DESC = "Security scan encountered an error"

    FAIL_ON_SEVERITY_DEFAULT = "high"

    HTTP_TIMEOUT_SECONDS = 15

    GITHUB_DESC_MAX_LENGTH = 140

    SUCCESS_STATUS_CODES = (200, 201)

    ERROR_WEBHOOK_FAILED = "CI/CD webhook failed: {error}"
    ERROR_STATUS_UPDATE_FAILED = (
        "Failed to update commit status: {error}"
    )
    ERROR_MISSING_CONFIG = "CI/CD configuration missing: {field}"


class NotificationConfig:
    """Configuration for scan notifications."""

    HTTP_TIMEOUT_SECONDS = 15

    # Email templates
    EMAIL_SUBJECT_COMPLETE = (
        "Security Scan Complete: {grade} — {target}"
    )
    EMAIL_SUBJECT_CRITICAL = (
        "CRITICAL: Security vulnerability found in {target}"
    )

    # Slack message templates
    SLACK_COMPLETE_TEXT = (
        ":shield: Security scan complete for *{target}*\n"
        "Grade: *{grade}* | Findings: {total} "
        "({critical} critical, {high} high)\n{report_url}"
    )
    SLACK_CRITICAL_TEXT = (
        ":rotating_light: *CRITICAL vulnerability found* in {target}\n"
        "_{title}_\n{description}"
    )

    # Webhook payload keys
    WEBHOOK_EVENT_KEY = "event"
    WEBHOOK_REPORT_KEY = "report"
    WEBHOOK_FINDINGS_KEY = "findings"

    EVENT_SCAN_COMPLETE = "scan_complete"
    EVENT_CRITICAL_FINDING = "critical_finding"

    DESCRIPTION_PREVIEW_LENGTH = 200

    MAX_SUCCESS_STATUS_CODE = 400

    ERROR_WEBHOOK_FAILED = "Webhook notification failed: {error}"
    ERROR_SLACK_FAILED = "Slack notification failed: {error}"
    ERROR_EMAIL_FAILED = "Email notification failed: {error}"


class ProjectConfig:
    """Configuration for project management."""

    MAX_SCANS_FREE = 3
    MAX_SCANS_PRO = 100
    MAX_SCANS_CERTIFICATION = 999

    MAX_PROJECTS_FREE = 1
    MAX_PROJECTS_PRO = 10
    MAX_PROJECTS_CERTIFICATION = 50

    SCAN_RETENTION_DAYS_FREE = 7
    SCAN_RETENTION_DAYS_PRO = 90
    SCAN_RETENTION_DAYS_CERTIFICATION = 365

    ERROR_PROJECT_LIMIT = "Project limit reached for {tier} plan (max {max})"
    ERROR_SCAN_LIMIT = "Scan limit reached for {tier} plan (max {max})"
    ERROR_PROJECT_NOT_FOUND = "Project not found: {project_id}"
    ERROR_SCAN_NOT_FOUND = "Scan not found: {scan_id}"


class CertificationConfig:
    """Configuration for security certification badges."""

    CERTIFICATION_VALIDITY_DAYS = 90
    BADGE_BASE_URL = "https://isitsecure.ai/badge"
    VERIFY_BASE_URL = "https://isitsecure.ai/verify"

    # Grade requirements for certification
    MIN_GRADE_FOR_CERTIFICATION = "B"  # A or B
    MAX_CRITICAL_FOR_CERTIFICATION = 0
    MAX_HIGH_FOR_CERTIFICATION = 0

    BADGE_SVG_TEMPLATE = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="32" viewBox="0 0 200 32">\n'
        '  <rect width="200" height="32" rx="4" fill="#1a1a2e"/>\n'
        '  <rect x="0" width="120" height="32" rx="4" fill="#16213e"/>\n'
        '  <text x="60" y="21" text-anchor="middle" fill="white" font-family="Arial" font-size="12" font-weight="bold">IsItSecure.ai</text>\n'
        '  <rect x="120" width="80" height="32" rx="4" fill="{color}"/>\n'
        '  <text x="160" y="21" text-anchor="middle" fill="white" font-family="Arial" font-size="12" font-weight="bold">{grade}</text>\n'
        '</svg>'
    )

    GRADE_COLORS = {
        "A": "#27ae60",
        "B": "#2ecc71",
        "C": "#f39c12",
        "D": "#e67e22",
        "F": "#e74c3c",
    }

    ERROR_NOT_ELIGIBLE = "Not eligible for certification: {reason}"
    ERROR_CERT_EXPIRED = "Certification expired on {expires_at}"
    ERROR_CERT_NOT_FOUND = "Certification not found: {cert_id}"

    TITLE_CERTIFIED = "Security Certified by IsItSecure.ai"
    DESC_CERTIFIED = "This application passed a deep security scan with grade {grade} on {date}"


class WorkspaceDetectorConfig:
    """Configuration for monorepo workspace detection."""

    # Files that explicitly define workspaces
    WORKSPACE_DEFINITION_FILES = (
        "pnpm-workspace.yaml",
        "turbo.json",
        "nx.json",
        "lerna.json",
    )

    # Maximum depth for heuristic workspace detection
    MAX_HEURISTIC_DEPTH = 2

    # Maximum number of workspaces to detect (performance guard)
    MAX_WORKSPACES = 20

    # Directories to skip during heuristic workspace detection
    SKIP_DIRECTORIES = (
        "node_modules",
        ".git",
        ".next",
        "dist",
        "build",
        ".vercel",
        ".netlify",
        "__pycache__",
        ".turbo",
        "coverage",
        ".nyc_output",
        ".cache",
        ".output",
    )

    # Package names that indicate workspace type → WorkspaceType mapping
    # Maps package dependency name → WorkspaceType value
    FRONTEND_INDICATORS = (
        "next",
        "react",
        "vue",
        "svelte",
        "@sveltejs/kit",
        "nuxt",
        "astro",
        "@angular/core",
        "solid-js",
    )

    BACKEND_INDICATORS = (
        "express",
        "fastify",
        "hono",
        "koa",
        "nestjs",
        "@nestjs/core",
        "hapi",
        "@trpc/server",
        "drizzle-orm",
        "prisma",
        "typeorm",
        "sequelize",
    )

    LAMBDA_INDICATORS = (
        "aws-lambda",
        "@aws-sdk/client-lambda",
        "@aws-sdk/client-ecs",
        "@aws-sdk/client-s3",
        "@aws-sdk/client-sns",
        "@aws-sdk/client-sqs",
        "aws-cdk-lib",
        "serverless",
    )

    INFRASTRUCTURE_DIR_INDICATORS = (
        "terraform",
        "infra",
        "infrastructure",
        "deploy",
        "cdk",
        "pulumi",
    )

    # File extensions that indicate IaC directories
    IAC_FILE_EXTENSIONS = (".tf", ".tfvars", ".hcl")

    # Migration directory patterns to search (relative to any workspace)
    MIGRATION_DIR_PATTERNS = (
        "supabase/migrations",
        "migrations",
        "db/migrations",
        "drizzle",
    )

    # Error messages
    ERROR_WORKSPACE_DETECTION_FAILED = (
        "Workspace detection failed: {error}"
    )
    ERROR_PACKAGE_JSON_PARSE_FAILED = (
        "Failed to parse package.json at {path}: {error}"
    )

    # Log messages
    LOG_MONOREPO_DETECTED = (
        "Monorepo detected via {method}: {count} workspaces found"
    )
    LOG_WORKSPACE_FOUND = (
        "Workspace '{name}' at '{path}' — type={workspace_type}, "
        "framework={framework}, backend={backend}"
    )
    LOG_NOT_MONOREPO = "No monorepo structure detected — using single-repo mode"


class ExpressRouteMapperConfig:
    """Configuration for Express.js route detection."""

    SCANNER_NAME = "express_route_mapper"

    # Directories to search for Express route files
    SOURCE_DIRS = ("src", "routes", "src/routes", "api", "src/api")

    # File extensions to scan
    CODE_EXTENSIONS = (".js", ".ts", ".mjs")

    # Regex patterns for Express route definitions
    # Captures: (method, path) from app.get('/path', ...) or router.post('/path', ...)
    ROUTE_DEFINITION_PATTERN = (
        r'(?:app|router)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*'
        r"""['"](/[^'"]*?)['"]"""
    )

    # Regex pattern for app.use mount points
    # Captures: (mount_path) from app.use('/api/webhooks', ...)
    MOUNT_PATTERN = (
        r'app\s*\.\s*use\s*\(\s*'
        r"""['"](/[^'"]*?)['"]"""
    )

    # Patterns that indicate auth middleware in route chain.
    # These are generic names used across Express.js applications.
    AUTH_MIDDLEWARE_INDICATORS = (
        "requireAuth",
        "verifyAuth",
        "authenticate",
        "isAuthenticated",
        "passport.authenticate",
        "jwt.verify",
        "verifyToken",
        "authMiddleware",
        "requireLogin",
        "ensureAuth",
        "protectedRoute",
        "requireUser",
        "checkAuth",
        "guardRoute",
    )

    # Patterns that indicate rate limiting middleware
    RATE_LIMIT_INDICATORS = (
        "rateLimit",
        "rateLimiter",
        "slowDown",
        "express-rate-limit",
    )

    # Express Router file indicators (to distinguish router files from
    # other JS/TS files)
    ROUTER_FILE_INDICATORS = (
        "express.Router()",
        "Router()",
        "app.get(",
        "app.post(",
        "app.use(",
        "router.get(",
        "router.post(",
        "router.put(",
        "router.patch(",
        "router.delete(",
    )

    # HTTP methods to detect
    HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")

    # Error messages
    ERROR_ROUTE_DETECTION_FAILED = (
        "Express route detection failed for {file}: {error}"
    )


class TRPCRouteMapperConfig:
    """Configuration for tRPC route detection."""

    SCANNER_NAME = "trpc_route_mapper"

    # Directories to search for tRPC router files
    SOURCE_DIRS = (
        "src/trpc",
        "trpc",
        "src/server/trpc",
        "server/trpc",
        "src/routers",
        "src/trpc/routers",
    )

    # File extensions to scan
    CODE_EXTENSIONS = (".js", ".ts", ".mjs")

    # Patterns to identify tRPC router definition files
    ROUTER_DEFINITION_PATTERNS = (
        r'(?:export\s+const\s+\w+Router|export\s+const\s+\w+)\s*=\s*(?:router|createTRPCRouter)\s*\(\s*\{',
        r'router\s*\(\s*\{',
        r'createTRPCRouter\s*\(\s*\{',
    )

    # Pattern to extract procedure names and their types
    # Matches: procedureName: publicProcedure.query(
    #          procedureName: protectedProcedure.mutation(
    #          procedureName: protectedProcedure.input(...).mutation(
    # Uses [\s\S]*? to handle multi-line .input() blocks with nested parens
    PROCEDURE_PATTERN = (
        r'(\w+)\s*:\s*'
        r'(publicProcedure|protectedProcedure|tenantProcedure|'
        r't\.procedure|procedure)'
        r'[\s\S]*?'
        r'\.(query|mutation|subscription)\s*\('
    )

    # Pattern to extract router name from file export
    ROUTER_NAME_PATTERN = (
        r'export\s+const\s+(\w+Router)\s*='
    )

    # Root router pattern — extracts namespace mappings
    # Matches: tenant: tenantRouter, user: userRouter, etc.
    ROOT_ROUTER_MAPPING_PATTERN = (
        r'(\w+)\s*:\s*(\w+Router)'
    )

    # Auth level classification
    AUTH_LEVEL_PUBLIC = "public"
    AUTH_LEVEL_PROTECTED = "protected"
    AUTH_LEVEL_TENANT = "tenant"

    # Procedure type to HTTP method mapping
    PROCEDURE_TYPE_TO_METHOD = {
        "query": "GET",
        "mutation": "POST",
        "subscription": "GET",
    }

    # Procedure base to auth level mapping
    PROCEDURE_AUTH_MAP = {
        "publicProcedure": AUTH_LEVEL_PUBLIC,
        "protectedProcedure": AUTH_LEVEL_PROTECTED,
        "tenantProcedure": AUTH_LEVEL_TENANT,
        "t.procedure": AUTH_LEVEL_PUBLIC,
        "procedure": AUTH_LEVEL_PUBLIC,
    }

    # Error messages
    ERROR_ROUTE_DETECTION_FAILED = (
        "tRPC route detection failed for {file}: {error}"
    )


class ExpressMiddlewareAnalyzerConfig:
    """Configuration for Express.js middleware security analysis."""

    SCANNER_NAME = "express_middleware_analyzer"

    # Directories where Express middleware files are typically found
    MIDDLEWARE_DIR_PATTERNS = (
        "middleware",
        "middlewares",
        "src/middleware",
        "src/middlewares",
    )

    # File extensions to scan
    CODE_EXTENSIONS = (".js", ".ts", ".mjs")

    # --- Auth verification patterns ---
    # Patterns that indicate actual JWT/session verification (strong auth)
    AUTH_VERIFICATION_PATTERNS = (
        r'supabase\.auth\.getUser\s*\(',
        r'jwt\.verify\s*\(',
        r'jsonwebtoken.*verify',
        r'getUser\s*\(\s*token',
        r'verifyToken\s*\(',
        r'getSession\s*\(',
        r'passport\.authenticate\s*\(',
    )

    # Patterns that indicate auth enforcement (returns 401/403 on failure)
    AUTH_ENFORCEMENT_PATTERNS = (
        r'res\s*\.\s*status\s*\(\s*401\s*\)',
        r'res\s*\.\s*status\s*\(\s*403\s*\)',
        r"throw\s+new\s+.*(?:UNAUTHORIZED|Unauthorized)",
        r"return\s+res\s*\.\s*status\s*\(\s*401",
    )

    # Patterns indicating weak auth (checks existence but not validity)
    # These match code that checks IF a token/cookie exists without
    # verifying its contents (e.g., jwt.verify)
    WEAK_AUTH_PATTERNS = (
        r'req\.headers\.authorization\s*[&|)\]};]',
        r'req\.headers\[.authorization.\]\s*[&|)\]};]',
        r'if\s*\(\s*!?\s*req\.cookies\.\w+\s*\)',
        r'if\s*\(\s*!?\s*req\.cookies\.(?:has|get)\s*\(',
    )

    # --- Rate limiting patterns ---
    RATE_LIMIT_PATTERNS = (
        r'rateLimit\s*\(',
        r'createRateLimiter\s*\(',
        r'express-rate-limit',
        r'rateLimiters\.',
        r'slowDown\s*\(',
    )

    # --- Security header patterns ---
    SECURITY_HEADER_PATTERNS = (
        r"Strict-Transport-Security",
        r"X-Frame-Options",
        r"X-Content-Type-Options",
        r"Content-Security-Policy",
        r"X-XSS-Protection",
        r"Referrer-Policy",
        r"Permissions-Policy",
    )

    # Minimum recommended security headers
    RECOMMENDED_SECURITY_HEADERS = (
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Content-Security-Policy",
    )

    # helmet.js detection
    HELMET_PATTERNS = (
        r"require\s*\(\s*['\"]helmet['\"]\s*\)",
        r"import\s+helmet\s+from\s+['\"]helmet['\"]",
        r"app\.use\s*\(\s*helmet\s*\(",
    )

    # --- CORS patterns ---
    CORS_WILDCARD_PATTERN = r"""origin\s*:\s*['"]?\*['"]?"""
    CORS_CREDENTIALS_PATTERN = r'credentials\s*:\s*true'

    # --- Tenant isolation patterns ---
    # Generic patterns for multi-tenant middleware across frameworks
    TENANT_ISOLATION_PATTERNS = (
        r'req\.tenantId',
        r'req\.tenant\b',
        r'req\.orgId',
        r'req\.organization\b',
        r'tenantContext\s*\(',
        r'orgContext\s*\(',
        r'requireTenant\s*\(',
        r'requireOrg\s*\(',
        r'withTenant\s*\(',
        r'tenantMiddleware',
        r'organizationMiddleware',
    )

    # --- Express route patterns for cross-referencing ---
    # Endpoints that should have auth middleware.
    # These are generic API path patterns common across web applications.
    SENSITIVE_ROUTE_INDICATORS = (
        "/api/",
        "/trpc",
        "/graphql",
        "/admin",
        "/user",
        "/account",
        "/settings",
        "/payment",
        "/billing",
        "/profile",
        "/dashboard",
    )

    # Routes that are legitimately public
    PUBLIC_ROUTE_INDICATORS = (
        "/health",
        "/ping",
        "/status",
        "/docs",
        "/swagger",
        "/openapi",
        "/webhook",
    )

    # --- Confidence thresholds ---
    CONFIDENCE_NO_AUTH_MIDDLEWARE = 0.90
    CONFIDENCE_WEAK_AUTH = 0.80
    CONFIDENCE_NO_RATE_LIMIT = 0.80
    CONFIDENCE_MISSING_SECURITY_HEADERS = 0.85
    CONFIDENCE_CORS_WILDCARD = 0.85
    CONFIDENCE_ROUTE_UNPROTECTED = 0.85
    CONFIDENCE_NO_TENANT_ISOLATION = 0.75
    CONFIDENCE_IN_MEMORY_RATE_LIMIT = 0.70

    # --- Finding titles ---
    TITLE_NO_AUTH_MIDDLEWARE = "No auth verification middleware found"
    TITLE_WEAK_AUTH = "Auth middleware checks token existence but not validity"
    TITLE_ROUTE_NO_AUTH = (
        "Express route '{route}' has no auth middleware"
    )
    TITLE_NO_RATE_LIMIT = "No rate limiting middleware found"
    TITLE_IN_MEMORY_RATE_LIMIT = (
        "Rate limiting uses in-memory store (not shared across instances)"
    )
    TITLE_MISSING_SECURITY_HEADERS = (
        "Missing security header: {header}"
    )
    TITLE_NO_HELMET = "Security headers set manually instead of using helmet"
    TITLE_CORS_WILDCARD = "CORS allows all origins with credentials"
    TITLE_NO_TENANT_ISOLATION = (
        "No tenant isolation middleware found for multi-tenant app"
    )

    # --- Finding descriptions ---
    DESC_NO_AUTH_MIDDLEWARE = (
        "No middleware file was found that verifies JWT tokens or sessions. "
        "Without centralized auth middleware, each route must implement its "
        "own authentication, which is error-prone and inconsistent."
    )
    DESC_WEAK_AUTH = (
        "The auth middleware in '{file}' checks for the presence of an "
        "Authorization header but does not appear to verify the token's "
        "validity. An attacker could send any string as a Bearer token "
        "to bypass authentication."
    )
    DESC_ROUTE_NO_AUTH = (
        "The Express route '{method} {route}' in '{file}' does not use "
        "auth middleware (e.g., requireAuth, verifyAuth). This endpoint "
        "is accessible without authentication. If it accesses user data "
        "or performs mutations, this is a security vulnerability."
    )
    DESC_NO_RATE_LIMIT = (
        "No rate limiting middleware was found. Without rate limiting, "
        "the API is vulnerable to brute force attacks, credential "
        "stuffing, and denial of service."
    )
    DESC_IN_MEMORY_RATE_LIMIT = (
        "The rate limiting implementation in '{file}' uses an in-memory "
        "store (Map/Object). In a multi-instance deployment (ECS, "
        "Kubernetes), each instance has its own counter, allowing "
        "attackers to multiply their effective rate limit by the number "
        "of instances. Use Redis or a shared store instead."
    )
    DESC_MISSING_SECURITY_HEADERS = (
        "The security header '{header}' is not set in any middleware. "
        "This header helps protect against {protection}."
    )
    DESC_NO_HELMET = (
        "Security headers are set manually in '{file}' instead of using "
        "helmet.js. While the current headers may be sufficient, helmet "
        "provides sensible defaults and is easier to maintain."
    )
    DESC_CORS_WILDCARD = (
        "CORS is configured with origin: '*' and credentials: true in "
        "'{file}'. This allows any website to make authenticated "
        "cross-origin requests, enabling CSRF-like attacks."
    )
    DESC_NO_TENANT_ISOLATION = (
        "The app uses multi-tenant patterns (tenant tables, tenant IDs) "
        "but no middleware enforces tenant isolation on API routes. "
        "Without tenant-scoped middleware, one tenant's user may access "
        "another tenant's data."
    )

    # Security header protection descriptions (for finding details)
    HEADER_PROTECTIONS = {
        "Strict-Transport-Security": "man-in-the-middle attacks by enforcing HTTPS",
        "X-Frame-Options": "clickjacking attacks by preventing iframe embedding",
        "X-Content-Type-Options": "MIME type sniffing attacks",
        "Content-Security-Policy": "XSS and data injection attacks",
    }

    # --- Error messages ---
    ERROR_ANALYSIS_FAILED = "Express middleware analysis failed: {error}"


class SchemaAnalyzerSharedConfig:
    """Shared configuration for all ORM schema security analyzers.

    Both DrizzleSchemaAnalyzerConfig and PrismaSchemaAnalyzerConfig
    reference these constants to avoid duplication (DRY).
    """

    # Names indicating a multi-tenant model/table
    MULTI_TENANT_INDICATORS = frozenset({
        "tenant", "tenants", "organization", "organizations",
        "org", "orgs", "workspace", "workspaces", "company", "companies",
        # PascalCase variants (for Prisma models)
        "Tenant", "Organization", "Org", "Workspace", "Company",
    })

    # Payment field substrings that are NOT secrets (e.g., stripe_customer_id
    # is an ID, not a secret — but stripe_secret_key IS a secret)
    PAYMENT_FIELD_SECRET_INDICATORS = ("secret", "key", "token", "password")


class DrizzleSchemaAnalyzerConfig:
    """Configuration for Drizzle ORM schema security analysis."""

    SCANNER_NAME = "drizzle_schema_analyzer"

    # --- Table detection patterns ---
    # Matches: pgTable('table_name', { ... })
    TABLE_DEFINITION_PATTERN = (
        r'(?:pgTable|mysqlTable|sqliteTable)\s*\(\s*'
        r"""['"]([\w]+)['"]"""
    )

    # Column extraction: columnName: type('db_name')
    # Covers all common Drizzle column types across pg, mysql, sqlite
    COLUMN_PATTERN = (
        r'(\w+)\s*:\s*'
        r'(uuid|text|integer|boolean|timestamp|numeric|jsonb|json|varchar|char|'
        r'serial|bigserial|smallserial|bigint|smallint|real|doublePrecision|'
        r'decimal|bytea|date|time|interval|inet|cidr|macaddr|tsvector|'
        r'mysqlEnum|pgEnum|blob|binary)'
        r"""\s*\(\s*['"](\w+)['"]"""
    )

    # --- Sensitive column indicators ---
    # Column names that should use encryption or hashing
    SECRET_COLUMN_INDICATORS = (
        "secret",
        "api_key",
        "api_secret",
        "private_key",
        "access_token",
        "refresh_token",
        "password",
        "password_hash",
        "service_role",
        "webhook_secret",
    )

    # PII column indicators (should have encrypted counterpart)
    PII_COLUMN_INDICATORS = (
        "email",
        "phone",
        "ssn",
        "social_security",
        "credit_card",
        "card_number",
        "ip_address",
        "address",
        "date_of_birth",
    )

    # Patterns indicating a column has encryption (good practice)
    ENCRYPTION_SUFFIX_PATTERNS = ("_encrypted", "_hash", "_hashed")

    # --- Tenant isolation indicators ---
    TENANT_COLUMN_NAMES = ("tenant_id",)

    # Tables that typically need tenant scoping in multi-tenant apps
    TENANT_SCOPED_TABLE_INDICATORS = (
        "users",
        "apps",
        "subscriptions",
        "purchases",
        "orders",
        "invoices",
        "settings",
        "profiles",
    )

    # Tables that are legitimately global (no tenant_id needed)
    GLOBAL_TABLE_INDICATORS = (
        "tenants",
        "platform_settings",
        "webhook_logs",
        "audit_logs",
        "admin_edit_logs",
        "migrations",
    )

    # --- Audit column indicators ---
    AUDIT_COLUMNS = ("created_at", "updated_at")

    # Tables that should have audit columns
    AUDIT_REQUIRED_TABLE_INDICATORS = (
        "users",
        "purchases",
        "payouts",
        "roles",
        "subscriptions",
    )

    # --- Payment provider column indicators ---
    # Column name substrings that indicate payment provider data.
    # Generic prefixes cover Stripe, PayPal, Square, Adyen, Braintree, etc.
    PAYMENT_COLUMN_PREFIXES = (
        "stripe_",
        "paypal_",
        "square_",
        "adyen_",
        "braintree_",
        "razorpay_",
        "mollie_",
    )

    # Column name suffixes that indicate payment provider IDs
    # regardless of provider prefix
    PAYMENT_COLUMN_SUFFIXES = (
        "_customer_id",
        "_subscription_id",
        "_charge_id",
        "_price_id",
        "_product_id",
        "_account_id",
        "_payment_id",
        "_invoice_id",
        "_payout_id",
    )

    # --- Confidence thresholds ---
    CONFIDENCE_SECRET_PLAINTEXT = 0.90
    CONFIDENCE_PII_NO_ENCRYPTION = 0.80
    CONFIDENCE_MISSING_TENANT_SCOPE = 0.75
    CONFIDENCE_MISSING_AUDIT = 0.60
    CONFIDENCE_PAYMENT_DATA_EXPOSURE = 0.70

    # --- Finding titles ---
    TITLE_SECRET_PLAINTEXT = (
        "Secret stored in plaintext: '{column}' in table '{table}'"
    )
    TITLE_PII_NO_ENCRYPTION = (
        "PII column without encryption: '{column}' in table '{table}'"
    )
    TITLE_MISSING_TENANT_SCOPE = (
        "Table '{table}' missing tenant_id in multi-tenant app"
    )
    TITLE_PAYMENT_DATA_STORED = (
        "Payment provider ID stored in plaintext: '{column}' in table '{table}'"
    )

    # --- Finding descriptions ---
    DESC_SECRET_PLAINTEXT = (
        "The column '{column}' in table '{table}' ({file}) stores a secret "
        "value as plaintext. If the database is compromised, this secret "
        "is immediately exposed. Encrypt secrets at rest using "
        "application-level encryption or a KMS."
    )
    DESC_PII_NO_ENCRYPTION = (
        "The column '{column}' in table '{table}' ({file}) contains PII "
        "but has no corresponding encrypted column (e.g., '{column}_encrypted'). "
        "Consider encrypting PII at rest to comply with GDPR/CCPA and "
        "reduce impact of a database breach."
    )
    DESC_MISSING_TENANT_SCOPE = (
        "The table '{table}' ({file}) does not have a 'tenant_id' column "
        "but stores data that is typically tenant-specific. In a multi-tenant "
        "application, missing tenant scoping can lead to data leaks between "
        "tenants. Add a tenant_id column with a foreign key to the tenants table."
    )
    DESC_PAYMENT_DATA_STORED = (
        "The column '{column}' in table '{table}' ({file}) stores a payment "
        "provider identifier as plaintext. While not as critical as secrets, "
        "Stripe customer/account IDs can be used for targeted attacks if "
        "the database is breached. Consider the sensitivity of this data "
        "in your threat model."
    )

    # --- Error messages ---
    ERROR_ANALYSIS_FAILED = "Drizzle schema analysis failed for {file}: {error}"


class PrismaSchemaAnalyzerConfig:
    """Configuration for Prisma schema security analysis."""

    SCANNER_NAME = "prisma_schema_analyzer"

    # --- Model detection patterns ---
    # Matches: model TableName { ... }
    MODEL_PATTERN = r"model\s+(\w+)\s*\{"

    # Field extraction: fieldName FieldType @modifiers
    # Covers all Prisma scalar types
    FIELD_PATTERN = (
        r"^\s*(\w+)\s+"
        r"(String|Int|BigInt|Float|Decimal|Boolean|DateTime|Json|Bytes)"
    )

    # Relation fields to skip (virtual, not DB columns)
    RELATION_PATTERN = r"@relation\("

    # System models to skip
    SYSTEM_MODELS = ("_prisma_migrations",)

    # --- Sensitive column indicators ---
    # Reuse the same indicators as Drizzle for consistency
    SECRET_COLUMN_INDICATORS = DrizzleSchemaAnalyzerConfig.SECRET_COLUMN_INDICATORS

    PII_COLUMN_INDICATORS = DrizzleSchemaAnalyzerConfig.PII_COLUMN_INDICATORS

    ENCRYPTION_SUFFIX_PATTERNS = DrizzleSchemaAnalyzerConfig.ENCRYPTION_SUFFIX_PATTERNS

    # --- Tenant isolation indicators ---
    TENANT_COLUMN_NAMES = DrizzleSchemaAnalyzerConfig.TENANT_COLUMN_NAMES

    TENANT_SCOPED_TABLE_INDICATORS = (
        DrizzleSchemaAnalyzerConfig.TENANT_SCOPED_TABLE_INDICATORS
    )

    GLOBAL_TABLE_INDICATORS = DrizzleSchemaAnalyzerConfig.GLOBAL_TABLE_INDICATORS

    # --- Payment provider column indicators ---
    PAYMENT_COLUMN_PREFIXES = DrizzleSchemaAnalyzerConfig.PAYMENT_COLUMN_PREFIXES

    PAYMENT_COLUMN_SUFFIXES = DrizzleSchemaAnalyzerConfig.PAYMENT_COLUMN_SUFFIXES

    # --- Confidence thresholds ---
    CONFIDENCE_SECRET_PLAINTEXT = 0.90
    CONFIDENCE_PII_NO_ENCRYPTION = 0.80
    CONFIDENCE_MISSING_TENANT_SCOPE = 0.75
    CONFIDENCE_PAYMENT_DATA_EXPOSURE = 0.70

    # --- Finding titles ---
    TITLE_SECRET_PLAINTEXT = (
        "Secret stored in plaintext: '{column}' in model '{table}'"
    )
    TITLE_PII_NO_ENCRYPTION = (
        "PII field without encryption: '{column}' in model '{table}'"
    )
    TITLE_MISSING_TENANT_SCOPE = (
        "Model '{table}' missing tenantId in multi-tenant app"
    )
    TITLE_PAYMENT_DATA_STORED = (
        "Payment provider ID stored in plaintext: '{column}' in model '{table}'"
    )

    # --- Finding descriptions ---
    DESC_SECRET_PLAINTEXT = (
        "The field '{column}' in model '{table}' ({file}) stores a secret "
        "value as plaintext. If the database is compromised, this secret "
        "is immediately exposed. Encrypt secrets at rest using "
        "application-level encryption or a KMS."
    )
    DESC_PII_NO_ENCRYPTION = (
        "The field '{column}' in model '{table}' ({file}) contains PII "
        "but has no corresponding encrypted field (e.g., '{column}_encrypted'). "
        "Consider encrypting PII at rest to comply with GDPR/CCPA and "
        "reduce impact of a database breach."
    )
    DESC_MISSING_TENANT_SCOPE = (
        "The model '{table}' ({file}) does not have a 'tenantId' field "
        "but stores data that is typically tenant-specific. In a multi-tenant "
        "application, missing tenant scoping can lead to data leaks between "
        "tenants. Add a tenantId field with a relation to the Tenant model."
    )
    DESC_PAYMENT_DATA_STORED = (
        "The field '{column}' in model '{table}' ({file}) stores a payment "
        "provider identifier as plaintext. While not as critical as secrets, "
        "Stripe customer/account IDs can be used for targeted attacks if "
        "the database is breached. Consider the sensitivity of this data "
        "in your threat model."
    )

    # --- Error messages ---
    ERROR_ANALYSIS_FAILED = "Prisma schema analysis failed for {file}: {error}"


class IaCScannerConfig:
    """Configuration for Infrastructure-as-Code security scanning."""

    SCANNER_NAME = "iac_scanner"

    # File extensions to scan
    IAC_EXTENSIONS = (".tf", ".tfvars")

    # --- Security group checks ---
    # Patterns for ingress blocks with 0.0.0.0/0 or ::/0 (IPv6)
    OPEN_INGRESS_PATTERNS = (
        r'ingress\s*\{[^}]*cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        r'ingress\s*\{[^}]*ipv6_cidr_blocks\s*=\s*\[\s*"::/0"\s*\]',
    )

    # Ports that are acceptable to expose to 0.0.0.0/0
    ACCEPTABLE_PUBLIC_PORTS = (80, 443)

    # Port extraction from ingress blocks
    INGRESS_PORT_PATTERN = r'from_port\s*=\s*(\d+)'

    # --- IAM checks ---
    # Overly permissive IAM actions (JSON and HCL formats)
    WILDCARD_ACTION_PATTERNS = (
        r'"Action"\s*:\s*"\*"',           # JSON (in jsonencode)
        r'actions\s*=\s*\[\s*"\*"\s*\]',  # HCL array
        r'action\s*=\s*"\*"',             # HCL string
    )
    WILDCARD_RESOURCE_PATTERNS = (
        r'"Resource"\s*:\s*"\*"',              # JSON
        r'resources\s*=\s*\[\s*"\*"\s*\]',     # HCL array
        r'resource\s*=\s*"\*"',                # HCL string (rare)
    )

    # --- Hardcoded secrets checks ---
    # Default values that look like secrets in variable blocks
    SECRET_IN_DEFAULT_PATTERNS = (
        (r'default\s*=\s*"(sk_live_[a-zA-Z0-9]+)"', "Stripe secret key"),
        (r'default\s*=\s*"(sk-ant-[a-zA-Z0-9\-]+)"', "Anthropic API key"),
        (r'default\s*=\s*"(AKIA[0-9A-Z]{16})"', "AWS access key"),
        (r'default\s*=\s*"(ghp_[a-zA-Z0-9]{36})"', "GitHub PAT"),
        (r'default\s*=\s*"(sk-[a-zA-Z0-9]{48})"', "OpenAI API key"),
        (
            r'default\s*=\s*"((?:postgres|mysql|mongodb)://[^\s"]+)"',
            "Database connection string",
        ),
        (
            r'default\s*=\s*"(eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)"',
            "JWT/Supabase key",
        ),
    )

    # --- S3 bucket checks ---
    PUBLIC_ACL_PATTERNS = (
        r'acl\s*=\s*"public-read"',
        r'acl\s*=\s*"public-read-write"',
    )
    BUCKET_NO_ENCRYPTION_PATTERN = r'aws_s3_bucket(?!_server_side_encryption)'
    BUCKET_NO_VERSIONING_PATTERN = r'aws_s3_bucket(?!_versioning)'

    # --- Secrets Manager checks ---
    RECOVERY_WINDOW_ZERO_PATTERN = r'recovery_window_in_days\s*=\s*0'

    # --- ALB/HTTPS checks ---
    # HTTP listener forwarding (not redirecting to HTTPS)
    HTTP_FORWARD_PATTERN = (
        r'protocol\s*=\s*"HTTP"[\s\S]*?type\s*=\s*"forward"'
    )

    # --- ECS checks ---
    # ECS task with public IP
    ECS_PUBLIC_IP_PATTERN = r'assign_public_ip\s*=\s*true'

    # --- Egress checks ---
    OPEN_EGRESS_PATTERN = (
        r'egress\s*\{[^}]*cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]'
    )

    # --- Log retention checks ---
    SHORT_LOG_RETENTION_THRESHOLD = 7
    LOG_RETENTION_PATTERN = r'retention_in_days\s*=\s*(\d+)'

    # --- Confidence thresholds ---
    CONFIDENCE_OPEN_SG = 0.90
    CONFIDENCE_WILDCARD_IAM = 0.90
    CONFIDENCE_HARDCODED_SECRET = 0.95
    CONFIDENCE_PUBLIC_S3 = 0.90
    CONFIDENCE_RECOVERY_ZERO = 0.80
    CONFIDENCE_HTTP_FORWARD = 0.85
    CONFIDENCE_ECS_PUBLIC_IP = 0.70
    CONFIDENCE_SHORT_LOG_RETENTION = 0.65

    # --- Finding titles ---
    TITLE_OPEN_SG = (
        "Security group allows 0.0.0.0/0 ingress on port {port}"
    )
    TITLE_WILDCARD_IAM_ACTION = (
        "IAM policy uses wildcard Action: '*'"
    )
    TITLE_WILDCARD_IAM_RESOURCE = (
        "IAM policy uses wildcard Resource: '*'"
    )
    TITLE_HARDCODED_SECRET = (
        "Hardcoded {secret_type} in Terraform variable default"
    )
    TITLE_PUBLIC_S3 = "S3 bucket has public-read ACL"
    TITLE_RECOVERY_ZERO = (
        "Secrets Manager secret has recovery_window_in_days = 0"
    )
    TITLE_HTTP_FORWARD = (
        "ALB listener forwards HTTP traffic without HTTPS redirect"
    )
    TITLE_ECS_PUBLIC_IP = (
        "ECS task has public IP assigned directly"
    )
    TITLE_SHORT_LOG_RETENTION = (
        "CloudWatch log retention is only {days} days"
    )

    # --- Finding descriptions ---
    DESC_OPEN_SG = (
        "The security group in '{file}' allows inbound traffic from "
        "0.0.0.0/0 (any IP) on port {port}. Only ports 80 and 443 "
        "should be exposed to the internet. Exposing other ports "
        "(e.g., database, SSH, application) creates attack surface."
    )
    DESC_WILDCARD_IAM_ACTION = (
        "The IAM policy in '{file}' grants Action: '*', which allows "
        "all AWS API actions. Follow the principle of least privilege "
        "and grant only the specific actions needed."
    )
    DESC_WILDCARD_IAM_RESOURCE = (
        "The IAM policy in '{file}' grants access to Resource: '*', "
        "which applies to all resources in the account. Scope the "
        "resource to specific ARNs."
    )
    DESC_HARDCODED_SECRET = (
        "A {secret_type} is hardcoded as a default value in '{file}'. "
        "Secrets should never be stored in Terraform files — use "
        "AWS Secrets Manager, SSM Parameter Store, or environment "
        "variables instead."
    )
    DESC_PUBLIC_S3 = (
        "The S3 bucket in '{file}' has ACL set to 'public-read', "
        "making all objects publicly accessible. Unless this is "
        "intentional (e.g., static assets), use private ACL and "
        "CloudFront for public access."
    )
    DESC_RECOVERY_ZERO = (
        "The Secrets Manager secret in '{file}' has "
        "recovery_window_in_days = 0, which means deleted secrets "
        "are immediately and permanently destroyed. Set to at least "
        "7 days to allow recovery from accidental deletion."
    )
    DESC_HTTP_FORWARD = (
        "The ALB listener in '{file}' forwards HTTP traffic directly "
        "to the target group without redirecting to HTTPS. This allows "
        "unencrypted traffic to reach the application. Configure the "
        "HTTP listener to redirect to HTTPS (port 443)."
    )
    DESC_ECS_PUBLIC_IP = (
        "The ECS service in '{file}' assigns public IPs directly to "
        "tasks. While this may be needed in public subnets without a "
        "NAT gateway, consider using private subnets with a NAT "
        "gateway for better network isolation."
    )
    DESC_SHORT_LOG_RETENTION = (
        "The CloudWatch log group in '{file}' has a retention period "
        "of only {days} days. For security investigation and "
        "compliance, consider retaining logs for at least 30–90 days."
    )

    # --- Error messages ---
    ERROR_ANALYSIS_FAILED = "IaC scan failed for {file}: {error}"


class DockerScannerConfig:
    """Configuration for Docker and Docker Compose security scanning."""

    SCANNER_NAME = "docker_scanner"

    # --- File detection ---
    DOCKERFILE_NAMES = (
        "Dockerfile",
        "Dockerfile.dev",
        "Dockerfile.prod",
        "Dockerfile.staging",
    )
    COMPOSE_NAMES = (
        "docker-compose.yml",
        "docker-compose.yaml",
        "docker-compose.dev.yml",
        "docker-compose.prod.yml",
        "compose.yml",
        "compose.yaml",
    )

    # --- Dockerfile checks ---

    # Running as root (no USER directive)
    USER_DIRECTIVE_PATTERN = r'^\s*USER\s+\S+'

    # Using :latest tag
    LATEST_TAG_PATTERN = r'^\s*FROM\s+\S+:latest\b'
    NO_TAG_PATTERN = r'^\s*FROM\s+(\S+)\s*$'

    # Sensitive ports exposed
    EXPOSE_PATTERN = r'^\s*EXPOSE\s+(\d+)'
    SENSITIVE_PORTS = {
        22: "SSH",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
        9200: "Elasticsearch",
        11211: "Memcached",
        2375: "Docker daemon (unencrypted)",
        2376: "Docker daemon",
    }

    # Hardcoded secrets in ENV
    ENV_SECRET_PATTERNS = (
        (r'^\s*ENV\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN)\w*\s*=\s*(\S+)', "secret in ENV"),
        (r'^\s*ENV\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN)\w*\s+"([^"]+)"', "secret in ENV"),
    )

    # ADD with remote URL (supply chain risk)
    ADD_REMOTE_PATTERN = r'^\s*ADD\s+https?://'

    # COPY . . without multi-stage (may copy secrets)
    COPY_ALL_PATTERN = r'^\s*COPY\s+\.\s+\.'

    # Health check presence
    HEALTHCHECK_PATTERN = r'^\s*HEALTHCHECK\s+'

    # --- Docker Compose checks ---

    # Default/weak passwords in environment
    COMPOSE_DEFAULT_PASSWORD_PATTERNS = (
        r'(?:PASSWORD|PASSWD)\s*[:=]\s*(password|admin|root|changeme|123456|default|postgres|mysql|redis|secret|test)\s*$',
        r'(?:PASSWORD|PASSWD)\s*[:=]\s*(\w{1,8})\s*$',
    )

    # Privileged mode
    PRIVILEGED_PATTERN = r'privileged\s*:\s*true'

    # Ports bound to 0.0.0.0 (or without host binding = default 0.0.0.0)
    COMPOSE_PORT_PATTERN = r'^\s*-\s*["\']?(\d+):(\d+)'
    COMPOSE_HOST_PORT_PATTERN = r'^\s*-\s*["\']?(\d+\.\d+\.\d+\.\d+):(\d+):(\d+)'

    # Sensitive service ports exposed to host
    COMPOSE_SENSITIVE_PORTS = {
        5432: "PostgreSQL",
        3306: "MySQL",
        6379: "Redis",
        27017: "MongoDB",
        9200: "Elasticsearch",
    }

    # --- Confidence thresholds ---
    CONFIDENCE_ROOT_USER = 0.85
    CONFIDENCE_LATEST_TAG = 0.70
    CONFIDENCE_SENSITIVE_PORT = 0.80
    CONFIDENCE_ENV_SECRET = 0.85
    CONFIDENCE_ADD_REMOTE = 0.80
    CONFIDENCE_DEFAULT_PASSWORD = 0.90
    CONFIDENCE_PRIVILEGED = 0.95
    CONFIDENCE_COMPOSE_PORT_EXPOSED = 0.75
    CONFIDENCE_NO_HEALTHCHECK = 0.60

    # --- Finding titles ---
    TITLE_ROOT_USER = "Dockerfile runs as root (no USER directive)"
    TITLE_LATEST_TAG = "Dockerfile uses ':latest' or untagged base image"
    TITLE_SENSITIVE_PORT = (
        "Dockerfile exposes sensitive port {port} ({service})"
    )
    TITLE_ENV_SECRET = "Hardcoded secret in Dockerfile ENV"
    TITLE_ADD_REMOTE = "Dockerfile uses ADD with remote URL"
    TITLE_DEFAULT_PASSWORD = (
        "Docker Compose uses default/weak password"
    )
    TITLE_PRIVILEGED = "Docker Compose container runs in privileged mode"
    TITLE_COMPOSE_PORT_EXPOSED = (
        "Docker Compose exposes {service} port {port} to host"
    )
    TITLE_NO_HEALTHCHECK = (
        "Dockerfile has no HEALTHCHECK instruction"
    )

    # --- Finding descriptions ---
    DESC_ROOT_USER = (
        "The Dockerfile '{file}' does not include a USER directive. "
        "The container will run as root, which means a container "
        "escape vulnerability gives the attacker root access to the "
        "host. Add a non-root USER directive."
    )
    DESC_LATEST_TAG = (
        "The Dockerfile '{file}' uses '{image}' without a specific "
        "version tag. This means builds are not reproducible and a "
        "compromised upstream image could be pulled. Pin to a specific "
        "version (e.g., node:20-alpine)."
    )
    DESC_SENSITIVE_PORT = (
        "The Dockerfile '{file}' exposes port {port} ({service}). "
        "Database and service ports should not be exposed from the "
        "application container. Use Docker networking instead."
    )
    DESC_ENV_SECRET = (
        "The Dockerfile '{file}' contains a hardcoded secret in an "
        "ENV instruction. Docker image layers are cached and can be "
        "inspected with 'docker history'. Use build args, secrets "
        "mount, or runtime environment variables instead."
    )
    DESC_ADD_REMOTE = (
        "The Dockerfile '{file}' uses ADD with a remote URL. This "
        "downloads content at build time without integrity verification. "
        "Use COPY with a pre-downloaded file, or use curl/wget with "
        "checksum verification."
    )
    DESC_DEFAULT_PASSWORD = (
        "The Docker Compose file '{file}' uses a default or weak "
        "password for a service. Even in development, weak passwords "
        "can be accidentally deployed or expose local dev environments."
    )
    DESC_PRIVILEGED = (
        "The Docker Compose file '{file}' runs a container in "
        "privileged mode. Privileged containers have full access to "
        "the host system, defeating container isolation entirely."
    )
    DESC_COMPOSE_PORT_EXPOSED = (
        "The Docker Compose file '{file}' exposes {service} (port "
        "{port}) to the host on 0.0.0.0. In development this may be "
        "intentional, but in production, database ports should not "
        "be accessible outside the Docker network."
    )
    DESC_NO_HEALTHCHECK = (
        "The Dockerfile '{file}' does not include a HEALTHCHECK "
        "instruction. Without health checks, orchestrators cannot "
        "detect unhealthy containers for automatic restart."
    )

    # --- Error messages ---
    ERROR_ANALYSIS_FAILED = "Docker scan failed for {file}: {error}"


class ShellScriptScannerConfig:
    """Configuration for shell script security scanning."""

    SCANNER_NAME = "shell_script_scanner"

    # File extensions to scan
    SHELL_EXTENSIONS = (".sh", ".bash")

    # --- Hardcoded secrets patterns ---
    # Generic patterns covering multiple cloud/SaaS providers
    HARDCODED_SECRET_PATTERNS = (
        (r'(?:export\s+)?(?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*=\s*["\']?([A-Za-z0-9/+=]{20,})', "AWS secret"),
        (r'(?:export\s+)?(?:\w*STRIPE_SECRET\w*)\s*=\s*["\']?(sk_live_[a-zA-Z0-9]+)', "Stripe secret key"),
        (r'(?:export\s+)?(?:DATABASE_URL|DB_URL)\s*=\s*["\']?((?:postgres|mysql|mongodb)://[^\s"\']+)', "database URL"),
        (r'(?:export\s+)?(?:SUPABASE_SERVICE_ROLE_KEY)\s*=\s*["\']?(eyJ[a-zA-Z0-9_\-]+\.eyJ[^\s"\']+)', "Supabase service role key"),
        (r'(?:export\s+)?(?:\w*PASSWORD)\s*=\s*["\']?([^\s"\'$]{8,})', "password"),
        (r'(?:export\s+)?(?:\w*TOKEN\w*)\s*=\s*["\']?(ghp_[a-zA-Z0-9]{36})', "GitHub PAT"),
        (r'(?:export\s+)?(?:\w*API_KEY\w*)\s*=\s*["\']?([^\s"\'$]{20,})', "API key"),
        (r'(?:export\s+)?(?:\w*SECRET\w*)\s*=\s*["\']?([^\s"\'$]{16,})', "secret value"),
    )

    # Skip patterns — variable references and common non-secrets
    SECRET_SKIP_PATTERNS = (
        r'^\$',          # Variable reference
        r'^\$\{',        # Variable reference
        r'^<',           # Placeholder
        r'^\*+$',        # Masked value
        r'^your[_-]',    # Placeholder
        r'^xxx',         # Placeholder
        r'^TODO',        # TODO marker
        r'^saas-',       # Resource path (not a secret)
        r'^arn:aws:',    # AWS ARN (not a secret)
        r'^https?://',   # URL (not a secret)
        r'/',            # Path-like value
    )

    # --- Hardcoded AWS account IDs ---
    AWS_ACCOUNT_ID_PATTERN = r'\b(\d{12})\.dkr\.ecr\.'

    # --- Dangerous patterns ---
    # curl piped to shell
    CURL_PIPE_BASH_PATTERN = r'curl\s+[^|]*\|\s*(?:bash|sh|zsh)\b'

    # chmod 777 or overly permissive
    CHMOD_PERMISSIVE_PATTERN = r'chmod\s+(?:777|666|a\+rwx)'

    # eval with variables
    EVAL_VARIABLE_PATTERN = r'eval\s+.*\$'

    # Missing error handling (no set -e at top)
    SET_E_PATTERN = r'set\s+-[euo]'

    # Credentials printed to stdout
    ECHO_SECRET_PATTERN = (
        r'echo\s+.*(?:password|secret|token|key)\s*[:=]'
    )

    # Insecure curl (-k / --insecure)
    CURL_INSECURE_PATTERN = r'curl\s+.*(?:-k\b|--insecure\b)'

    # --- Confidence thresholds ---
    CONFIDENCE_HARDCODED_SECRET = 0.85
    CONFIDENCE_AWS_ACCOUNT_ID = 0.70
    CONFIDENCE_CURL_PIPE = 0.90
    CONFIDENCE_CHMOD_PERMISSIVE = 0.85
    CONFIDENCE_EVAL_VARIABLE = 0.75
    CONFIDENCE_NO_SET_E = 0.60
    CONFIDENCE_ECHO_SECRET = 0.70
    CONFIDENCE_CURL_INSECURE = 0.80

    # --- Finding titles ---
    TITLE_HARDCODED_SECRET = "Hardcoded {secret_type} in shell script"
    TITLE_AWS_ACCOUNT_ID = "Hardcoded AWS account ID in shell script"
    TITLE_CURL_PIPE = "Script pipes curl output to shell (supply chain risk)"
    TITLE_CHMOD_PERMISSIVE = "Script uses overly permissive chmod"
    TITLE_EVAL_VARIABLE = "Script uses eval with variable expansion"
    TITLE_NO_SET_E = "Shell script missing 'set -e' error handling"
    TITLE_ECHO_SECRET = "Script may print secrets to stdout"
    TITLE_CURL_INSECURE = "Script uses curl with --insecure (skips TLS verification)"

    # --- Finding descriptions ---
    DESC_HARDCODED_SECRET = (
        "The shell script '{file}' contains a hardcoded {secret_type}. "
        "Secrets in scripts are visible in version control history and "
        "to anyone with read access. Use environment variables or a "
        "secrets manager instead."
    )
    DESC_AWS_ACCOUNT_ID = (
        "The shell script '{file}' contains a hardcoded AWS account ID "
        "({account_id}). While not a secret, hardcoded account IDs make "
        "it harder to use the script across environments and may "
        "disclose your AWS account to unauthorized viewers."
    )
    DESC_CURL_PIPE = (
        "The script '{file}' pipes curl output directly to a shell "
        "(bash/sh). If the remote server is compromised or the "
        "connection is intercepted, arbitrary code will execute. "
        "Download first, verify integrity, then execute."
    )
    DESC_CHMOD_PERMISSIVE = (
        "The script '{file}' sets overly permissive file permissions. "
        "chmod 777 allows any user to read, write, and execute the "
        "file. Use the minimum permissions needed (e.g., 755 or 700)."
    )
    DESC_EVAL_VARIABLE = (
        "The script '{file}' uses eval with variable expansion, which "
        "can lead to command injection if the variable contains "
        "user-controlled or untrusted data."
    )
    DESC_NO_SET_E = (
        "The script '{file}' does not use 'set -e' (or set -euo "
        "pipefail). Without this, the script will continue executing "
        "after errors, potentially leaving the system in an "
        "inconsistent state or masking failures."
    )
    DESC_ECHO_SECRET = (
        "The script '{file}' may print secrets (passwords, tokens, "
        "keys) to stdout. Log output may be captured by CI/CD systems "
        "or stored in shell history."
    )
    DESC_CURL_INSECURE = (
        "The script '{file}' uses curl with -k/--insecure, which "
        "disables TLS certificate verification. This makes the "
        "connection vulnerable to man-in-the-middle attacks."
    )

    # --- Error messages ---
    ERROR_ANALYSIS_FAILED = "Shell script scan failed for {file}: {error}"


class LSPConfig:
    """Configuration for Language Server Protocol integration.

    Controls tsserver lifecycle, request timeouts, auth flow tracing
    depth, and graceful degradation behavior.
    """

    # --- Subprocess lifecycle ---
    INIT_TIMEOUT_SECONDS = 30
    REQUEST_TIMEOUT_SECONDS = 5
    SHUTDOWN_TIMEOUT_SECONDS = 5
    MAX_RETRIES = 2

    # --- Performance guards ---
    MAX_FILES_TO_OPEN = 100
    MAX_TRACE_DEPTH = 5  # prevent infinite recursion in go-to-definition chains
    MAX_CONCURRENT_REQUESTS = 10

    # --- tsserver command detection ---
    # Tried in order until one works
    # Tried in order — prefer direct binary over npx (npx adds stdout noise)
    TSSERVER_COMMANDS = (
        ("typescript-language-server", "--stdio"),
        ("npx", "typescript-language-server", "--stdio"),
    )

    # --- Default tsconfig for repos without one ---
    DEFAULT_TSCONFIG = {
        "compilerOptions": {
            "target": "ES2020",
            "module": "ESNext",
            "moduleResolution": "bundler",
            "strict": True,
            "jsx": "react-jsx",
            "esModuleInterop": True,
            "allowJs": True,
            "checkJs": False,
            "noEmit": True,
            "skipLibCheck": True,
        },
        "include": ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx"],
        "exclude": ["node_modules", "dist", "build", ".next"],
    }

    # --- Auth terminal patterns ---
    # Functions/methods that confirm real authentication is happening.
    # Generic patterns that work across frameworks (Supabase, Firebase,
    # Clerk, Auth0, Passport, custom JWT, etc.).
    AUTH_TERMINAL_PATTERNS = (
        # Generic token/session verification
        r'verifyToken\s*\(',
        r'validateToken\s*\(',
        r'verifyIdToken\s*\(',
        r'verifyAccessToken\s*\(',
        r'getSession\s*\(',
        r'getUser\s*\(',
        r'authenticate\s*\(',
        r'getServerSession\s*\(',
        r'getToken\s*\(',
        # JWT libraries
        r'jwt\.verify\s*\(',
        r'jwtVerify\s*\(',
        r'jose\.jwtVerify\s*\(',
        r'jsonwebtoken.*\.verify\s*\(',
        # Supabase
        r'\.auth\.getUser\s*\(',
        r'\.auth\.getSession\s*\(',
        r'createServerClient\s*\(',
        # Passport
        r'passport\.authenticate\s*\(',
        # Firebase
        r'admin\.auth\(\)\.verifyIdToken\s*\(',
        r'getAuth\(\)\.verifyIdToken\s*\(',
        # Clerk
        r'clerkClient\.verifyToken\s*\(',
        r'getAuth\s*\(\s*req\s*\)',
        # Auth0
        r'auth0\.getSession\s*\(',
        # bcrypt/argon (password verification)
        r'bcrypt\.compare\s*\(',
        r'argon2\.verify\s*\(',
    )

    # Patterns that confirm auth enforcement (throws/returns on failure).
    # Generic across frameworks — matches status codes and error types.
    AUTH_ENFORCEMENT_PATTERNS = (
        # HTTP 401/403 responses (universal)
        r'res\s*\.\s*status\s*\(\s*401\s*\)',
        r'res\s*\.\s*status\s*\(\s*403\s*\)',
        r'return\s+.*status\s*\(\s*401\s*\)',
        r'return\s+.*status\s*\(\s*403\s*\)',
        r'ctx\.throw\s*\(\s*401',
        r'ctx\.throw\s*\(\s*403',
        # tRPC errors
        r'throw\s+new\s+TRPCError\s*\(\s*\{[^}]*UNAUTHORIZED',
        r'throw\s+new\s+TRPCError\s*\(\s*\{[^}]*FORBIDDEN',
        # NestJS / generic exceptions
        r'throw\s+new\s+UnauthorizedException',
        r'throw\s+new\s+ForbiddenException',
        r'throw\s+new\s+.*Unauthorized',
        # Python (FastAPI / Django / Flask)
        r'raise\s+HTTPException\s*\(\s*status_code\s*=\s*401',
        r'raise\s+HTTPException\s*\(\s*status_code\s*=\s*403',
        r'raise\s+PermissionDenied',
        # Generic error text patterns
        r'["\']UNAUTHORIZED["\']',
        r'["\']Unauthorized["\']',
    )

    # --- Ownership terminal patterns ---
    # Patterns in traced function bodies that confirm ownership filtering.
    OWNERSHIP_TERMINAL_PATTERNS = (
        r'\.eq\s*\(\s*["\']user_id',
        r'\.eq\s*\(\s*["\']owner_id',
        r'\.eq\s*\(\s*["\']created_by',
        r'\.eq\s*\(\s*["\']author_id',
        r'\.eq\s*\(\s*["\']buyer_id',
        r'\.eq\s*\(\s*["\']seller_id',
        r'where\s*\(\s*\{[^}]*userId',
        r'where\s*\(\s*\{[^}]*user_id',
        r'\.user\.id\s*===',
        r'ctx\.user\.id',
    )

    # --- Framework auth guard patterns ---
    # Identifiers that indicate auth is enforced at the procedure/route level.
    # Generic across tRPC, NestJS, Fastify, etc.
    PROTECTED_PROCEDURE_BASES = (
        # tRPC
        "protectedProcedure",
        "tenantProcedure",
        "adminProcedure",
        "authedProcedure",
        # Generic
        "authenticatedProcedure",
        "authorizedProcedure",
    )

    PUBLIC_PROCEDURE_BASES = (
        "publicProcedure",
        "t.procedure",
    )

    # Decorator/guard patterns that indicate auth at the route level.
    # These are checked in file content, not as identifier names.
    AUTH_DECORATOR_PATTERNS = (
        # NestJS
        r'@UseGuards\s*\(\s*AuthGuard',
        r'@UseGuards\s*\(\s*JwtAuthGuard',
        r'@UseGuards\s*\(\s*RolesGuard',
        # Fastify
        r'preHandler\s*:\s*\[\s*authenticate',
        r'onRequest\s*:\s*\[\s*authenticate',
        # Python decorators
        r'@login_required',
        r'@requires_auth',
        r'@jwt_required',
        r'@permission_required',
        # Spring
        r'@PreAuthorize',
        r'@Secured',
    )

    # --- Confidence adjustments ---
    CONFIDENCE_LSP_CONFIRMED = 0.95
    CONFIDENCE_LSP_BOOST = 0.10  # added to existing confidence when LSP agrees

    # --- File detection ---
    # File extensions worth tracing through LSP
    TRACEABLE_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs")

    # --- Log/event messages ---
    MSG_INIT = "Initializing TypeScript analysis..."
    MSG_TRACING = "Tracing auth flows across {count} routes..."
    MSG_UNAVAILABLE = "TypeScript LSP unavailable — using regex-only analysis"
    MSG_INIT_FAILED = "LSP initialization failed: {error}"
    MSG_INIT_SUCCESS = "LSP initialized in {duration:.1f}s"
    MSG_VALIDATION_COMPLETE = (
        "LSP validation: {confirmed} findings confirmed, "
        "{suppressed} findings suppressed"
    )
    MSG_TRACE_COMPLETE = (
        "Auth flow tracing complete: {traced} routes traced, "
        "{auth_found} with verified auth"
    )

    ERROR_SUBPROCESS_FAILED = "tsserver subprocess failed: {error}"
    ERROR_REQUEST_TIMEOUT = "LSP request timed out after {timeout}s: {method}"
    ERROR_TRACE_FAILED = "Auth flow trace failed for {file}: {error}"


class TriageConfig:
    """Configuration for the LLM triage layer."""

    SCANNER_NAME = "llm_triage"
    MAX_FINDINGS_PER_TRIAGE = 100
    # Output token limit per triage batch.  Batches are ~20 findings each
    # (20 × ~300 tokens ≈ 6K output), so 16K provides generous headroom.
    MAX_TOKENS_PER_TRIAGE = 16384

    # Progress values
    PROGRESS_TRIAGE = 97

    # Priority matrix: (impact, likelihood) → priority (1=highest, 4=lowest)
    PRIORITY_MATRIX = {
        ("financial", "actively_exploitable"): 1,
        ("data_breach", "actively_exploitable"): 1,
        ("legal", "actively_exploitable"): 1,
        ("operational", "actively_exploitable"): 2,
        ("reputational", "actively_exploitable"): 2,
        ("financial", "requires_auth"): 2,
        ("data_breach", "requires_auth"): 2,
        ("legal", "requires_auth"): 2,
        ("operational", "requires_auth"): 3,
        ("reputational", "requires_auth"): 3,
        ("financial", "requires_admin"): 3,
        ("data_breach", "requires_admin"): 3,
        ("legal", "requires_admin"): 3,
        ("operational", "requires_admin"): 3,
        ("reputational", "requires_admin"): 4,
        ("financial", "theoretical"): 3,
        ("data_breach", "theoretical"): 3,
        ("legal", "theoretical"): 4,
        ("operational", "theoretical"): 4,
        ("reputational", "theoretical"): 4,
    }

    DEFAULT_PRIORITY = 3

    # --- Scope disclaimers per scan mode ---
    SCOPE_DISCLAIMERS = {
        "code_only": (
            "This report is based on static analysis of the source code only. "
            "No live testing was performed against the running application. "
            "The deployed application may differ from the analyzed code due to "
            "environment-specific configuration, CDN/WAF protections, or "
            "runtime dependencies. Runtime behaviors such as cookie flags, "
            "CORS enforcement, and rate limiting were NOT tested."
        ),
        "full": (
            "This report combines static source code analysis with dynamic "
            "testing of the live application. While comprehensive, this is "
            "NOT a full penetration test. No social engineering, physical "
            "access testing, or denial-of-service testing was performed."
        ),
        "url_only": (
            "This report is based on black-box testing of the live application "
            "only. No source code was analyzed. Vulnerabilities in internal "
            "logic, database access controls, or infrastructure configuration "
            "cannot be detected without code access."
        ),
        "authenticated": (
            "This report includes authenticated dynamic testing but no source "
            "code analysis. Server-side vulnerabilities that are not observable "
            "through API responses may not be detected."
        ),
    }

    # --- "What this report is NOT" per scan mode ---
    REPORT_IS_NOT = {
        "code_only": (
            "This report is NOT:\n"
            "- A penetration test of the running application\n"
            "- A verification that the deployed code matches this analysis\n"
            "- A review of runtime behavior, auth flows, or session management\n"
            "- An audit of third-party service configurations (AWS console, "
            "Stripe dashboard, Supabase settings)\n"
            "- A review of cloud infrastructure beyond IaC files in the repo\n"
            "- A compliance certification (SOC 2, PCI-DSS, HIPAA, GDPR)\n"
            "- A guarantee that no vulnerabilities exist beyond what was found"
        ),
        "full": (
            "This report is NOT:\n"
            "- A full penetration test (no social engineering or physical access)\n"
            "- A denial-of-service or stress test\n"
            "- An audit of cloud console configurations beyond IaC files\n"
            "- A compliance certification (SOC 2, PCI-DSS, HIPAA, GDPR)\n"
            "- A guarantee that no vulnerabilities exist beyond what was found"
        ),
        "url_only": (
            "This report is NOT:\n"
            "- A source code review\n"
            "- An assessment of server-side logic or database security\n"
            "- An audit of infrastructure or cloud configurations\n"
            "- A compliance certification\n"
            "- A guarantee that no vulnerabilities exist beyond what was found"
        ),
        "authenticated": (
            "This report is NOT:\n"
            "- A source code review\n"
            "- A full penetration test\n"
            "- An audit of infrastructure configurations\n"
            "- A compliance certification\n"
            "- A guarantee that no vulnerabilities exist beyond what was found"
        ),
    }

    # --- Triage LLM prompt ---
    # ------------------------------------------------------------------
    # Step 1: Developer triage — dedup, enrich, prioritize
    # ------------------------------------------------------------------

    DEV_TRIAGE_SYSTEM_PROMPT = (
        "You are a security triage analyst producing a developer-facing "
        "report. You receive raw findings from multiple automated "
        "scanners (SAST pattern matchers + LLM code review).\n\n"
        "Your job:\n\n"
        "1. DEDUPLICATE: Two findings are duplicates if they describe "
        "the same root cause in the same file/function. Different "
        "manifestations of the same bug (e.g., missing auth flagged by "
        "both route_auth_analyzer and llm_code_reviewer) are duplicates. "
        "Keep the more detailed one and list the other's ID in "
        "duplicate_ids.\n\n"
        "2. FLAG FALSE POSITIVES: Add to duplicate_ids if the finding:\n"
        "   - Describes an intentional design choice (public endpoint "
        "flagged as 'missing auth')\n"
        "   - Is a code quality issue, not a security vulnerability\n"
        "   - Describes a theoretical exploit without a concrete, "
        "provable attack scenario (e.g., 'floating-point rounding "
        "could cause errors' without showing a specific input that "
        "produces wrong output)\n"
        "   - Is information disclosure of non-sensitive data\n\n"
        "3. For each REAL finding, assess:\n"
        "   - IMPACT: financial (money lost), data_breach (user data "
        "exposed), legal (compliance violation), operational (downtime/DoS), "
        "or reputational (trust damage).\n"
        "   - LIKELIHOOD: actively_exploitable (unauthenticated attacker "
        "can exploit from the internet today), requires_auth (needs a "
        "valid user account), requires_admin (needs admin/super_admin), "
        "or theoretical (requires chaining multiple issues or very "
        "specific conditions).\n\n"
        "4. Write technical_detail: Describe the vulnerability mechanism "
        "and realistic attack scenario. Be specific.\n\n"
        "5. Write evidence: Quote the specific code pattern, config line, "
        "or code_snippet that proves this finding. If no code_snippet is "
        "available, reference the file and line.\n\n"
        "6. Write remediation_guidance: Describe the architectural fix "
        "approach (e.g., 'wrap check-and-update in a database transaction', "
        "'add tenant_id to the WHERE clause'). Do NOT write specific code.\n\n"
        "7. Adjust severity if the scanner got it wrong. Use this rubric:\n"
        "   - CRITICAL: Exploitable by unauthenticated attacker, leads to "
        "data breach or financial loss.\n"
        "   - HIGH: Exploitable by authenticated attacker, privilege "
        "escalation, or cross-tenant data leak.\n"
        "   - MEDIUM: Requires specific conditions, limited exposure, or "
        "defense-in-depth gap.\n"
        "   - LOW: Theoretical, best-practice violation.\n\n"
        "Respond with valid JSON only."
    )

    DEV_TRIAGE_USER_PROMPT = (
        "Scan mode: {scan_mode}\n"
        "Target: {target}\n"
        "Total findings: {count}\n\n"
        "Findings:\n{findings_json}\n\n"
        "Respond with this JSON structure:\n"
        "{{\n"
        '  "triaged_findings": [\n'
        "    {{\n"
        '      "id": "original-finding-id",\n'
        '      "impact": "financial|data_breach|legal|operational|reputational",\n'
        '      "likelihood": "actively_exploitable|requires_auth|requires_admin|theoretical",\n'
        '      "technical_detail": "...",\n'
        '      "evidence": "...",\n'
        '      "remediation_guidance": "...",\n'
        '      "severity_adjustment": null or "critical|high|medium|low",\n'
        '      "merged_ids": []\n'
        "    }}\n"
        "  ],\n"
        '  "duplicate_ids": ["ids-to-remove"]\n'
        "}}"
    )

    # ------------------------------------------------------------------
    # Step 2: Owner summary — plain-language risk report
    # ------------------------------------------------------------------

    OWNER_SUMMARY_SYSTEM_PROMPT = (
        "You are a security advisor writing a plain-language risk summary "
        "for a non-technical business owner (e.g., a SaaS founder or "
        "startup CEO). They need to understand what's at risk and what "
        "to tell their developer to fix first.\n\n"
        "Rules:\n"
        "- No jargon. Say 'someone could steal customer data' not "
        "'IDOR via BOLA in the REST API'.\n"
        "- Describe risks as business consequences: lost revenue, "
        "customer trust, legal liability, downtime.\n"
        "- Be honest but not alarmist. Many findings are defense-in-depth "
        "improvements, not active emergencies.\n\n"
        "Grading rubric:\n"
        "- A: No critical or high issues. Good security hygiene.\n"
        "- B: No critical issues, a few high-severity items. "
        "Solid foundation with some gaps to close.\n"
        "- C: No critical issues but multiple high-severity items, "
        "or 1 critical. Needs attention soon.\n"
        "- D: 1-2 critical issues or many high-severity items. "
        "Significant risk that should be addressed before scaling.\n"
        "- F: Multiple critical issues. Immediate action required — "
        "real money or data is at risk.\n\n"
        "Respond with valid JSON only."
    )

    OWNER_SUMMARY_USER_PROMPT = (
        "Scan mode: {scan_mode}\n"
        "Target: {target}\n"
        "Total findings: {total} ({critical} critical, {high} high, "
        "{medium} medium)\n\n"
        "Top findings by priority:\n{summary_json}\n\n"
        "Respond with this JSON structure:\n"
        "{{\n"
        '  "grade": "A|B|C|D|F",\n'
        '  "risk_summary": "2-4 sentences summarizing the overall security '
        'posture for a non-technical owner. Include what is going well, '
        'not just problems.",\n'
        '  "key_risks": [\n'
        '    "Risk described as a business consequence (e.g., '
        "'A seller could set their own commission rate, reducing your "
        "platform revenue')\"]\n"
        "  ,\n"
        '  "remediation_phases": [\n'
        "    {{\n"
        '      "phase_number": 1,\n'
        '      "title": "Immediate (this week)",\n'
        '      "description": "Plain-language description of what to fix '
        'and why it is urgent"\n'
        "    }},\n"
        "    {{\n"
        '      "phase_number": 2,\n'
        '      "title": "Short-term (next 2-4 weeks)",\n'
        '      "description": "..."\n'
        "    }},\n"
        "    {{\n"
        '      "phase_number": 3,\n'
        '      "title": "Ongoing improvements",\n'
        '      "description": "..."\n'
        "    }}\n"
        "  ]\n"
        "}}"
    )

    MAX_TOKENS_OWNER_SUMMARY = 4096

    # --- Theme detection ---
    THEME_DETECTION_SYSTEM_PROMPT = (
        "You are a security analyst grouping vulnerability findings into "
        "thematic clusters. Each theme represents a systemic security concern "
        "— not individual bugs, but patterns that share a root cause or "
        "affected subsystem.\n\n"
        "Rules:\n"
        "- Create 3-8 themes (fewer is better if findings are closely related)\n"
        "- Every finding must be assigned to exactly one theme\n"
        "- Theme titles should be specific and actionable "
        "(e.g., 'Webhook Payment Processing Integrity' not 'Security Issues')\n"
        "- theme_id should be a short kebab-case slug\n"
        "- Description should explain the systemic risk in 2-3 sentences\n"
        "- Set severity to the highest severity among the theme's findings\n\n"
        "Respond with valid JSON only."
    )

    THEME_DETECTION_USER_PROMPT = (
        "Group these {count} security findings into themes:\n\n"
        "{findings_json}\n\n"
        "Respond with this JSON structure:\n"
        "{{\n"
        '  "themes": [\n'
        "    {{\n"
        '      "theme_id": "payment-integrity",\n'
        '      "title": "Payment Processing Integrity",\n'
        '      "description": "Multiple issues in webhook and checkout '
        "handling could allow duplicate charges, missed payments, or "
        'revenue manipulation.",\n'
        '      "severity": "critical",\n'
        '      "finding_ids": ["id1", "id2", "id3"]\n'
        "    }}\n"
        "  ]\n"
        "}}"
    )

    MAX_TOKENS_THEME_DETECTION = 4096

    # --- Messages ---
    MSG_TRIAGING = "Triaging and prioritizing findings..."
    ERROR_TRIAGE_FAILED = "LLM triage failed: {error}"
    FALLBACK_RISK_SUMMARY = (
        "Automated security analysis identified issues that should be "
        "reviewed by your development team."
    )


class CrossScannerIntelligenceConfig:
    """Configuration for cross-scanner intelligence in LLM review.

    Controls how SAST findings from rule-based scanners are used to
    prioritize and enrich LLM code review.
    """

    # --- Priority values (lower = reviewed first) ---
    PRIORITY_FINANCIAL = 0
    PRIORITY_CROSS_SCANNER = 1
    PRIORITY_MUTATION = 2
    PRIORITY_RISK_INDICATOR = 3
    PRIORITY_IMPORT_CENTRALITY = 4
    PRIORITY_INJECTION_PATTERN = 5

    # --- Financial operation patterns ---
    # Routes containing these patterns are ALWAYS reviewed by the LLM
    # because business logic flaws in payment flows are critical and
    # undetectable by regex.
    FINANCIAL_PATTERNS = (
        r'\bstripe\b',
        r'\bpayment\b',
        r'\bcharge\b',
        r'\brefund\b',
        r'\bbalance\b',
        r'\btransfer\b',
        r'\bpayout\b',
        r'\bsubscription\b',
        r'\binvoice\b',
        r'\bcredit\b',
        r'\bdebit\b',
        r'\bbilling\b',
        r'\bcheckout\b',
        r'\border\b',
        r'\bprice\b',
        r'\bdiscount\b',
        r'\bcoupon\b',
        r'\bwallet\b',
    )

    # --- State mutation patterns ---
    # Files with mutations + conditional logic are prone to TOCTOU races
    MUTATION_PATTERNS = (
        r'\.insert\s*\(',
        r'\.update\s*\(',
        r'\.delete\s*\(',
        r'\.upsert\s*\(',
        r'\.create\s*\(',
        r'\.destroy\s*\(',
        r'\.save\s*\(',
        r'\.remove\s*\(',
        r'db\.\w+\.set\s*\(',
        r'\bINSERT\s+INTO\b',
        r'\bUPDATE\s+\w+\s+SET\b',
        r'\bDELETE\s+FROM\b',
    )

    # Conditional logic patterns (must co-occur with mutations)
    CONDITIONAL_PATTERNS = (
        r'\bif\s*\(',
        r'\bswitch\s*\(',
        r'\?\s*.*\s*:',
        r'\.filter\s*\(',
        r'\.find\s*\(',
    )

    # --- Cross-scanner entity extraction ---
    # Regex to extract table names from SAST finding titles/descriptions
    TABLE_NAME_FROM_FINDING_PATTERN = (
        r"table\s+['\"]?(\w+)['\"]?"
    )

    # Regex to extract route patterns from SAST finding titles/descriptions
    ROUTE_FROM_FINDING_PATTERN = (
        r"route\s+['\"]?(/[^\s'\"]+)['\"]?"
    )

    # Regex to find table references in route content
    TABLE_REFERENCE_IN_CODE_PATTERNS = (
        r"\.from\s*\(\s*['\"](\w+)['\"]",
        r"\.into\s*\(\s*['\"](\w+)['\"]",
        r"\.table\s*\(\s*['\"](\w+)['\"]",
    )

    # Max SAST findings to include in prompt context (avoid token bloat)
    MAX_SAST_CONTEXT_FINDINGS = 5

    # --- Enhanced LLM prompts ---

    FINANCIAL_REVIEW_SYSTEM_PROMPT = (
        "You are a senior security engineer reviewing payment/financial "
        "code.\n\n"
        "Focus on:\n"
        "- Race conditions (TOCTOU in balance checks, inventory)\n"
        "- Double-spend / duplicate purchase vulnerabilities\n"
        "- Price manipulation (client-controlled amounts, fee bypass)\n"
        "- Unauthorized refunds or subscription billing bypass\n"
        "- Fee calculation errors (floating-point, rounding, currency)\n"
        "- Webhook idempotency failures (replay, partial refunds)\n"
        "- Revenue share / payout manipulation\n\n"
        "Do NOT flag code style issues (DRY, SOLID, naming, comments).\n\n"
    ) + LLMCodeReviewConfig.SEVERITY_RUBRIC

    MUTATION_REVIEW_SYSTEM_PROMPT = (
        "You are a senior security engineer reviewing code with database "
        "mutations and conditional logic.\n\n"
        "Focus on:\n"
        "- TOCTOU race conditions (check-then-act without transactions)\n"
        "- Authorization bypass through alternative code paths\n"
        "- Missing ownership checks before mutations\n"
        "- Inconsistent state from partial failures (no rollback)\n"
        "- Data over-exposure (SELECT * returning internal fields)\n"
        "- Multi-tenant data leakage (missing tenant scoping)\n\n"
        "Do NOT flag code style issues (DRY, SOLID, naming, comments).\n\n"
    ) + LLMCodeReviewConfig.SEVERITY_RUBRIC

    SAST_CONTEXT_SECTION = (
        "\n\nOther automated scanners flagged these related issues:\n"
        "{sast_context}\n\n"
        "Consider these findings when reviewing. Check if this route's "
        "logic makes these issues exploitable or introduces additional risks."
    )


class ImportGraphCentralityConfig:
    """Configuration for import-graph centrality review trigger.

    Identifies shared helpers, utilities, middleware, and DB layers
    that are imported by multiple high-risk route files.  A bug in
    these files has high blast radius.
    """

    # Minimum number of trigger-selected route files that must import
    # a non-route file for it to qualify for LLM review
    MIN_RISK_IMPORTER_COUNT = 2

    # Maximum non-route files to select per scan
    MAX_CENTRALITY_FILES = 10

    # File extensions eligible for import parsing
    PARSEABLE_EXTENSIONS = (
        ".ts", ".tsx", ".js", ".jsx", ".mjs", ".py",
    )

    # Directories to skip entirely (generated code, dependencies)
    SKIP_DIRECTORIES = (
        "node_modules", ".next", "dist", "build", "__pycache__",
        ".git", "coverage", ".turbo", ".venv", "vendor",
    )

    # Default alias mappings (overridden by tsconfig.json paths if found)
    DEFAULT_ALIAS_MAPPINGS = {
        "@/": "src/",
        "~/": "src/",
    }

    # Extensions to try when resolving bare imports (no extension)
    EXTENSION_PROBE_ORDER = (
        ".ts", ".tsx", ".js", ".jsx", ".mjs",
    )

    # Index files to try when import resolves to a directory
    INDEX_FILES = (
        "index.ts", "index.tsx", "index.js", "index.jsx",
    )

    # --- Import parsing regex patterns ---
    # ES6: import X from './foo'  or  import './foo'  or  export * from './foo'
    ES6_IMPORT_PATTERN = (
        r"""(?:import|export)\s+(?:[\s\S]*?\s+from\s+)?['"]([^'"]+)['"]"""
    )
    # CJS: require('./foo')
    CJS_REQUIRE_PATTERN = r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)"""
    # Dynamic: import('./foo')
    DYNAMIC_IMPORT_PATTERN = r"""import\s*\(\s*['"]([^'"]+)['"]\s*\)"""
    # Python: from x.y import z
    PYTHON_FROM_IMPORT_PATTERN = r"""^from\s+([\w.]+)\s+import"""
    # Python: import x.y
    PYTHON_IMPORT_PATTERN = r"""^import\s+([\w.]+)"""

    # --- Synthetic RouteEntry defaults ---
    SYNTHETIC_ROUTE_PREFIX = "[shared] "

    # --- LLM prompts for shared helper review ---
    SHARED_HELPER_REVIEW_SYSTEM_PROMPT = (
        "You are a senior security engineer reviewing a SHARED HELPER/UTILITY "
        "module that is imported by multiple API route handlers.\n\n"
        "This file is NOT an API route itself, but its logic is executed "
        "within route contexts. A vulnerability here has HIGH BLAST RADIUS — "
        "it affects every route that imports it.\n\n"
        "Focus on:\n"
        "- Input validation gaps (does this helper trust its callers blindly?)\n"
        "- SQL/NoSQL injection via parameter forwarding\n"
        "- Authorization logic flaws (incorrect role checks, missing tenant "
        "scoping)\n"
        "- Insecure defaults (permissive CORS, weak crypto, disabled "
        "validation)\n"
        "- Credential/secret handling (hardcoded keys, secrets in logs)\n"
        "- Race conditions in shared state (caching, connection pools)\n"
        "- Error handling that leaks internal details\n"
        "- Prototype pollution or object injection in utility functions\n\n"
        "Do NOT flag code style issues (DRY, SOLID, naming, comments).\n\n"
    ) + LLMCodeReviewConfig.SEVERITY_RUBRIC

    SHARED_HELPER_USER_PROMPT = (
        "Review this shared module for security vulnerabilities.\n\n"
        "File: {file_path}\n"
        "Imported by {importer_count} route files including: {importers}\n\n"
        "```{language}\n{code}\n```\n\n"
        "{db_context}\n"
        "For each vulnerability found, respond in this exact JSON format:\n"
        "```json\n"
        "[\n"
        "  {{\n"
        '    "severity": "CRITICAL|HIGH|MEDIUM|LOW",\n'
        '    "title": "Brief title",\n'
        '    "description": "What the vulnerability is, why it matters, '
        'and how an attacker would exploit it",\n'
        '    "line_number": 10,\n'
        '    "remediation_guidance": "High-level fix approach"\n'
        "  }}\n"
        "]\n"
        "```\n\n"
        "If no vulnerabilities found, respond with an empty array: []\n\n"
        "A bug in this file affects ALL importing routes. Focus on real "
        "security vulnerabilities, not code style."
    )


class GraphQLRouteMapperConfig:
    """Configuration for GraphQL route detection."""

    SCANNER_NAME = "graphql_route_mapper"

    # Directories to search for GraphQL schema and resolver files
    SOURCE_DIRS = (
        "src",
        "src/graphql",
        "graphql",
        "src/schema",
        "schema",
        "src/resolvers",
        "resolvers",
        "src/api",
        "api",
    )

    # SDL file extensions
    SDL_EXTENSIONS = (".graphql", ".gql")

    # Code-first resolver file extensions
    CODE_EXTENSIONS = (".ts", ".js", ".mjs")

    # Regex pattern to extract type blocks from SDL
    # Captures: (type_name, block_body) from
    #   type Query { ... }  or  extend type Mutation { ... }
    SDL_TYPE_BLOCK_PATTERN = (
        r'(?:extend\s+)?type\s+(Query|Mutation)\s*\{([^}]*)\}'
    )

    # Regex pattern to extract field names from inside a type block
    # Matches:  fieldName(args): ReturnType  or  fieldName: ReturnType
    SDL_FIELD_NAME_PATTERN = r'^\s*(\w+)\s*[\(:]'

    # Route pattern template
    ROUTE_PREFIX_TEMPLATE = "/graphql/{type_name}.{field_name}"

    # Operation types to extract
    OPERATION_TYPES = frozenset({"Query", "Mutation"})

    # Operation type to HTTP method mapping
    OPERATION_TYPE_TO_METHOD = {
        "Query": "GET",
        "Mutation": "POST",
    }

    # Patterns indicating code-first GraphQL resolver files
    RESOLVER_FILE_INDICATORS = (
        r'@Query\s*\(',
        r'@Mutation\s*\(',
        r'@Resolver\s*\(',
        r't\.field\s*\(',
        r't\.queryField\s*\(',
        r't\.mutationField\s*\(',
        r'queryField\s*\(',
        r'mutationField\s*\(',
        r'GraphQLObjectType\s*\(',
        r'builder\.queryType\s*\(',
        r'builder\.mutationType\s*\(',
    )

    # TypeGraphQL decorator pattern: @Query() or @Mutation()
    TYPEGRAPHQL_DECORATOR_PATTERN = r'@(Query|Mutation)\s*\('

    # Method name following a decorator (next non-empty line with a method def)
    DECORATOR_METHOD_NAME_PATTERN = (
        r'\s*(?:async\s+)?(\w+)\s*\('
    )

    # Pothos / Nexus field pattern: t.field('fieldName', ...)
    POTHOS_FIELD_PATTERN = (
        r't\.(?:field|queryField|mutationField)\s*\(\s*'
        r"""['"]([\w]+)['"]"""
    )

    # Nexus top-level field pattern: queryField('name', ...) / mutationField('name', ...)
    NEXUS_TOP_LEVEL_PATTERN = (
        r'(query|mutation)Field\s*\(\s*'
        r"""['"]([\w]+)['"]"""
    )

    # Auth indicators in resolver code
    AUTH_INDICATORS = (
        "ctx.user",
        "context.user",
        "@Authorized",
        "authGuard",
        "AuthGuard",
        "requireAuth",
        "isAuthenticated",
        "ctx.auth",
        "context.auth",
        "authMiddleware",
        "useAuth",
    )

    # Introspection and Apollo Federation fields to skip
    SKIP_FIELDS = frozenset({
        "__typename",
        "__schema",
        "__type",
        "_entities",
        "_service",
    })

    # Characters to look back for operation type context
    CONTEXT_LOOKBACK_CHARS = 500

    # Context indicators for mutation type
    MUTATION_CONTEXT_INDICATORS = (
        "mutationtype",
        "mutation",
        "mutationfield",
    )

    # Error messages
    ERROR_ROUTE_DETECTION_FAILED = (
        "GraphQL route detection failed for {file}: {error}"
    )


class SemanticRuleVerifierConfig:
    """Configuration for LLM-powered semantic rule verification."""

    SCANNER_NAME = "semantic_rule_verifier"

    CHARS_PER_TOKEN_ESTIMATE = 4
    MAX_TOKENS_PER_REVIEW = 4096
    MAX_RULE_SIZE_CHARS = 50_000
    MAX_FINDINGS_PER_FILE = 7

    CONFIDENCE_LLM_FINDING = 0.70

    FALLBACK_FINDING_TITLE = "Logical rule flaw found by semantic analysis"

    # Firebase rules file names to collect
    FIREBASE_RULES_FILES = (
        "firestore.rules",
        "storage.rules",
        "database.rules.json",
    )

    # SQL indicators that a migration file contains RLS definitions
    RLS_SQL_INDICATORS = (
        "CREATE POLICY",
        "ENABLE ROW LEVEL SECURITY",
    )

    # ------------------------------------------------------------------
    # Severity rubric (shared by both prompts)
    # ------------------------------------------------------------------

    SEVERITY_RUBRIC = (
        "Severity definitions:\n"
        "- CRITICAL: Directly exploitable, leads to data breach or "
        "full unauthorized access. No user interaction required.\n"
        "- HIGH: Exploitable by an authenticated attacker, leads to "
        "privilege escalation or cross-tenant data exposure.\n"
        "- MEDIUM: Requires specific conditions or chaining. Leads to "
        "limited data exposure or information disclosure.\n"
        "- LOW: Theoretical risk or defense-in-depth gap with minimal "
        "direct exploitability.\n"
    )

    # ------------------------------------------------------------------
    # JSON response format (shared by both prompts)
    # ------------------------------------------------------------------

    FINDING_JSON_FORMAT = (
        "For each flaw found, respond in this exact JSON format:\n"
        "```json\n"
        "[\n"
        "  {{\n"
        '    "severity": "CRITICAL|HIGH|MEDIUM|LOW",\n'
        '    "title": "Brief title of the logical flaw",\n'
        '    "description": "What the flaw is, why it matters, '
        'and how an attacker would exploit it",\n'
        '    "line_number": 10,\n'
        '    "remediation_guidance": "High-level fix approach"\n'
        "  }}\n"
        "]\n"
        "```\n\n"
        "If no logical flaws found, respond with an empty array: []\n\n"
        "Focus on LOGICAL flaws only. Do not repeat structural issues "
        "(missing policies, open rules) -- those are already caught by "
        "other scanners."
    )

    # ------------------------------------------------------------------
    # RLS prompts
    # ------------------------------------------------------------------

    RLS_SYSTEM_PROMPT = (
        "You are a database security expert. Analyze these RLS policies "
        "for LOGICAL flaws -- not structural issues like missing policies "
        "(those are already caught). Focus on:\n"
        "- Wrong column in auth.uid() check (e.g., checking 'id' instead "
        "of 'user_id')\n"
        "- Policies that allow privilege escalation (e.g., UPDATE then "
        "SELECT to read other users' data)\n"
        "- Inconsistent operation coverage (e.g., INSERT checks user_id "
        "but UPDATE does not)\n"
        "- Tenant isolation using wrong field (e.g., checking user_id "
        "instead of tenant_id for org-scoped data)\n"
        "- Policies that can be bypassed via joins or subqueries\n\n"
    ) + SEVERITY_RUBRIC

    RLS_USER_PROMPT = (
        "Analyze these RLS policies from '{file_path}' for logical flaws.\n\n"
        "```sql\n{sql_content}\n```\n\n"
    ) + FINDING_JSON_FORMAT

    # ------------------------------------------------------------------
    # Firebase prompts
    # ------------------------------------------------------------------

    FIREBASE_SYSTEM_PROMPT = (
        "You are a Firebase security expert. Analyze these security rules "
        "for LOGICAL flaws -- not structural issues like missing auth "
        "(those are already caught). Focus on:\n"
        "- Rules that check auth on wrong paths (e.g., checking parent "
        "auth but child path leaks data)\n"
        "- Write protected but read leaks data (asymmetric protection)\n"
        "- Custom claims checked incorrectly (e.g., checking "
        "request.auth.token.admin instead of "
        "request.auth.token.admin == true)\n"
        "- Timestamp validation bypass (e.g., rules that check "
        "request.time but can be bypassed with batch writes)\n"
        "- Rules that allow overwriting other users' documents via "
        "predictable document IDs\n\n"
    ) + SEVERITY_RUBRIC

    FIREBASE_USER_PROMPT = (
        "Analyze these Firebase security rules from '{file_path}' "
        "for logical flaws.\n\n"
        "```\n{rules_content}\n```\n\n"
    ) + FINDING_JSON_FORMAT

    # ------------------------------------------------------------------
    # Error messages
    # ------------------------------------------------------------------

    ERROR_LLM_REVIEW_FAILED = (
        "Semantic rule verification failed for {file}: {error}"
    )
    ERROR_PARSE_RESPONSE = (
        "Failed to parse semantic rule verifier LLM response: {error}"
    )


class OpenAPIScannerConfig:
    """Configuration for OpenAPI/Swagger specification security scanning."""

    SCANNER_NAME = "openapi_scanner"

    # File extensions to check for OpenAPI/Swagger specs
    SPEC_EXTENSIONS = (".yaml", ".yml", ".json")

    # Markers that identify a file as an OpenAPI/Swagger spec
    SPEC_MARKERS = (
        r'openapi\s*:',
        r'swagger\s*:',
        r'"openapi"\s*:',
        r'"swagger"\s*:',
    )

    # --- 1. Global security ---
    SECURITY_SCHEMES_PATTERN = r'securityDefinitions|securitySchemes'
    GLOBAL_SECURITY_PATTERN = r'^security\s*:'

    # --- 2. HTTP servers ---
    HTTP_SERVER_PATTERN = r'(?:url\s*:\s*|"url"\s*:\s*)["\']?http://[^\s"\',$]+'
    LOCALHOST_PATTERNS = (
        r'localhost',
        r'127\.0\.0\.1',
        r'0\.0\.0\.0',
    )

    # --- 3. Basic auth ---
    BASIC_AUTH_PATTERN = (
        r'type\s*:\s*http[\s\S]{0,50}scheme\s*:\s*basic'
    )

    # --- 4. API key in query ---
    APIKEY_IN_QUERY_PATTERN = (
        r'type\s*:\s*apiKey[\s\S]{0,50}in\s*:\s*query'
    )

    # --- 5. Empty security override ---
    EMPTY_SECURITY_PATTERN = r'security\s*:\s*\[\s*\]'

    # --- 6. Sensitive paths ---
    SENSITIVE_PATH_PATTERNS = (
        r'["\']?/admin[^\s"\']*["\']?\s*:',
        r'["\']?/users[^\s"\']*["\']?\s*:',
        r'["\']?/payments?[^\s"\']*["\']?\s*:',
        r'["\']?/billing[^\s"\']*["\']?\s*:',
        r'["\']?/tokens?[^\s"\']*["\']?\s*:',
        r'["\']?/auth[^\s"\']*["\']?\s*:',
        r'["\']?/secrets?[^\s"\']*["\']?\s*:',
    )

    # --- Confidence thresholds ---
    CONFIDENCE_NO_GLOBAL_SECURITY = 0.85
    CONFIDENCE_HTTP_SERVER = 0.80
    CONFIDENCE_BASIC_AUTH = 0.85
    CONFIDENCE_APIKEY_IN_QUERY = 0.85
    CONFIDENCE_EMPTY_SECURITY_OVERRIDE = 0.80
    CONFIDENCE_SENSITIVE_PATH = 0.75

    # --- Finding titles ---
    TITLE_NO_GLOBAL_SECURITY = (
        "OpenAPI spec has no global security scheme"
    )
    TITLE_HTTP_SERVER = (
        "OpenAPI spec defines HTTP (non-HTTPS) server URL"
    )
    TITLE_BASIC_AUTH = (
        "OpenAPI spec uses HTTP Basic authentication"
    )
    TITLE_APIKEY_IN_QUERY = (
        "OpenAPI spec passes API key in query parameter"
    )
    TITLE_EMPTY_SECURITY_OVERRIDE = (
        "OpenAPI endpoint explicitly disables security (security: [])"
    )
    TITLE_SENSITIVE_PATH = (
        "Sensitive path '{path}' defined without global security"
    )

    # --- Finding descriptions ---
    DESC_NO_GLOBAL_SECURITY = (
        "The OpenAPI spec '{file}' does not define a global security "
        "scheme. Without global security, every endpoint is publicly "
        "accessible by default. Define a securitySchemes component and "
        "apply a global security requirement."
    )
    DESC_HTTP_SERVER = (
        "The OpenAPI spec '{file}' defines a server URL using HTTP "
        "instead of HTTPS: '{url}'. API traffic over HTTP is "
        "unencrypted and vulnerable to interception. Use HTTPS for "
        "all non-local server URLs."
    )
    DESC_BASIC_AUTH = (
        "The OpenAPI spec '{file}' uses HTTP Basic authentication. "
        "Basic auth sends credentials as a Base64-encoded header "
        "on every request, making it vulnerable to interception "
        "without HTTPS. Prefer OAuth2 or API key authentication."
    )
    DESC_APIKEY_IN_QUERY = (
        "The OpenAPI spec '{file}' defines an API key passed via "
        "query parameter. Query parameters appear in server logs, "
        "browser history, and proxy logs. Pass API keys in headers "
        "instead (e.g., Authorization or X-API-Key)."
    )
    DESC_EMPTY_SECURITY_OVERRIDE = (
        "An endpoint in '{file}' explicitly sets security to an "
        "empty array (security: []), which disables authentication "
        "for that endpoint. Verify this is intentional and that the "
        "endpoint does not expose sensitive data or operations."
    )
    DESC_SENSITIVE_PATH = (
        "The path '{path}' in '{file}' handles sensitive data but "
        "the spec has no global security scheme. Endpoints for admin, "
        "users, payments, and authentication must require auth. Add "
        "a global security requirement or per-operation security."
    )

    # --- Error messages ---
    ERROR_ANALYSIS_FAILED = "OpenAPI scan failed for {file}: {error}"


class K8sScannerConfig:
    """Configuration for Kubernetes and Helm manifest security scanning."""

    SCANNER_NAME = "k8s_scanner"

    # File extensions to scan
    K8S_EXTENSIONS = (".yaml", ".yml")

    # Marker to identify Kubernetes manifests
    API_VERSION_MARKER = r'apiVersion\s*:'

    # Directories to scan for K8s manifests via rglob
    K8S_DIRECTORIES = (
        "k8s",
        "deploy",
        "charts",
        "manifests",
        "helm",
        "kubernetes",
        "kube",
    )

    # Values file name for Helm secrets check
    VALUES_YAML_NAME = "values.yaml"

    # Helm template expression to skip when checking for hardcoded secrets
    HELM_TEMPLATE_PATTERN = r'\{\{.*\.Values\.'

    # --- 1. Privileged containers ---
    PRIVILEGED_PATTERN = r'privileged\s*:\s*true'

    # --- 2. Running as root ---
    RUN_AS_ROOT_PATTERNS = (
        r'runAsUser\s*:\s*0\b',
        r'runAsNonRoot\s*:\s*false',
    )

    # --- 3. Host namespace sharing ---
    HOST_NAMESPACE_PATTERNS = (
        (r'hostNetwork\s*:\s*true', "hostNetwork"),
        (r'hostPID\s*:\s*true', "hostPID"),
    )

    # --- 4. Secrets in env values ---
    ENV_SECRET_PATTERNS = (
        (
            r'(?:name\s*:\s*\w*(?:PASSWORD|PASSWD)\w*\s*\n\s*value\s*:\s*["\']?)([^\s"\'#]+)',
            "password",
        ),
        (
            r'(?:name\s*:\s*\w*(?:SECRET|API_KEY|TOKEN)\w*\s*\n\s*value\s*:\s*["\']?)([^\s"\'#]+)',
            "API key/secret",
        ),
        (
            r'(?:name\s*:\s*\w*(?:DATABASE_URL|DB_URL)\w*\s*\n\s*value\s*:\s*["\']?)((?:postgres|mysql|mongodb)://[^\s"\'#]+)',
            "database connection string",
        ),
    )

    # Patterns to skip when checking for secrets (variable refs, placeholders)
    SECRET_SKIP_PATTERNS = (
        r'^\$',
        r'^\$\{',
        r'^<',
        r'^\*+$',
        r'^your[_-]',
        r'^xxx',
        r'^TODO',
        r'^CHANGE_ME',
        r'^$',
    )

    # --- 5. Image tag checks ---
    IMAGE_TAG_PATTERNS = (
        r'image\s*:\s*["\']?(\S+):latest\b',
        r'image\s*:\s*["\']?([a-zA-Z0-9._/-]+)\s*$',
    )

    # --- 6. ALL capabilities ---
    ALL_CAPABILITIES_PATTERN = (
        r'capabilities\s*:[\s\S]{0,50}add\s*:[\s\S]{0,30}'
        r'(?:- \s*["\']?ALL["\']?|\[\s*["\']?ALL["\']?\s*\])'
    )

    # --- 7. LoadBalancer checks ---
    LOADBALANCER_PATTERN = r'type\s*:\s*LoadBalancer'
    INTERNAL_LB_ANNOTATION_PATTERNS = (
        r'service\.beta\.kubernetes\.io/aws-load-balancer-internal',
        r'cloud\.google\.com/load-balancer-type\s*:\s*["\']?Internal',
        r'service\.beta\.kubernetes\.io/azure-load-balancer-internal',
    )

    # --- 8. Helm values.yaml secrets ---
    HELM_SECRET_PATTERNS = (
        (
            r'(?:password|passwd)\s*:\s*["\']?([^\s"\'#]+)',
            "password",
        ),
        (
            r'(?:secret|secretKey|apiKey|api_key)\s*:\s*["\']?([^\s"\'#]+)',
            "secret/API key",
        ),
        (
            r'(?:token|accessToken|auth_token)\s*:\s*["\']?([^\s"\'#]+)',
            "token",
        ),
        (
            r'(?:databaseUrl|database_url|dsn)\s*:\s*["\']?((?:postgres|mysql|mongodb)://[^\s"\'#]+)',
            "database connection string",
        ),
    )

    # --- Confidence thresholds ---
    CONFIDENCE_PRIVILEGED = 0.95
    CONFIDENCE_RUN_AS_ROOT = 0.90
    CONFIDENCE_HOST_NAMESPACE = 0.90
    CONFIDENCE_ENV_SECRET = 0.85
    CONFIDENCE_IMAGE_TAG = 0.65
    CONFIDENCE_ALL_CAPABILITIES = 0.95
    CONFIDENCE_LOADBALANCER = 0.75
    CONFIDENCE_HELM_SECRET = 0.80

    # --- Finding titles ---
    TITLE_PRIVILEGED = "Container runs in privileged mode"
    TITLE_RUN_AS_ROOT = "Container configured to run as root"
    TITLE_HOST_NAMESPACE = (
        "Container shares host {namespace_type} namespace"
    )
    TITLE_ENV_SECRET = (
        "Hardcoded {secret_type} in container environment variable"
    )
    TITLE_IMAGE_TAG = (
        "Container image uses ':latest' or has no version tag"
    )
    TITLE_ALL_CAPABILITIES = (
        "Container adds ALL Linux capabilities"
    )
    TITLE_LOADBALANCER_EXTERNAL = (
        "LoadBalancer service without internal annotation"
    )
    TITLE_HELM_SECRET = (
        "Plaintext {secret_type} in Helm values.yaml"
    )

    # --- Finding descriptions ---
    DESC_PRIVILEGED = (
        "The manifest '{file}' sets privileged: true on a container. "
        "Privileged containers have full access to the host kernel, "
        "effectively bypassing all container isolation. Remove the "
        "privileged flag and grant only specific capabilities needed."
    )
    DESC_RUN_AS_ROOT = (
        "The manifest '{file}' configures a container to run as root "
        "(runAsUser: 0 or runAsNonRoot: false). If an attacker "
        "escapes the container, they have root access to the host. "
        "Set runAsNonRoot: true and specify a non-root runAsUser."
    )
    DESC_HOST_NAMESPACE = (
        "The manifest '{file}' enables {namespace_type}: true. "
        "Sharing the host namespace breaks container isolation -- the "
        "container can see host processes and network interfaces. "
        "Remove {namespace_type} unless absolutely required."
    )
    DESC_ENV_SECRET = (
        "A {secret_type} is hardcoded in a container environment "
        "variable in '{file}'. Secrets in manifests are visible in "
        "version control and kubectl output. Use Kubernetes Secrets "
        "or an external secrets manager (e.g., Vault, AWS Secrets "
        "Manager) with secretKeyRef instead."
    )
    DESC_IMAGE_TAG = (
        "The container image '{image}' in '{file}' uses ':latest' "
        "or has no version tag. This means deployments are not "
        "reproducible and a compromised upstream image could be "
        "pulled. Pin images to a specific digest or version tag."
    )
    DESC_ALL_CAPABILITIES = (
        "The manifest '{file}' adds ALL Linux capabilities to a "
        "container. This is equivalent to running in privileged mode "
        "and gives the container full access to kernel features. "
        "Add only the specific capabilities needed (e.g., NET_BIND_SERVICE)."
    )
    DESC_LOADBALANCER_EXTERNAL = (
        "The service in '{file}' uses type: LoadBalancer without an "
        "internal load balancer annotation. By default, this creates "
        "a public-facing load balancer. If the service should be "
        "internal-only, add the appropriate cloud provider annotation "
        "(e.g., service.beta.kubernetes.io/aws-load-balancer-internal)."
    )
    DESC_HELM_SECRET = (
        "A {secret_type} is stored in plaintext in '{file}'. Helm "
        "values.yaml files are typically committed to version control. "
        "Use Helm secrets plugin, sealed-secrets, or an external "
        "secrets manager to inject secrets at deploy time."
    )

    # --- Error messages ---
    ERROR_ANALYSIS_FAILED = "K8s scan failed for {file}: {error}"


class SecurityHeadersScannerConfig:
    """Configuration for the security headers scanner."""

    SCANNER_NAME = "security_headers_scanner"
    HTTP_TIMEOUT_SECONDS = 10
    MAX_CONCURRENT_REQUESTS = 3
    REQUEST_DELAY_SECONDS = 0.3

    # Maximum number of representative endpoints to test
    MAX_ENDPOINTS_TO_TEST = 5

    # --- Header names ---
    HEADER_HSTS = "strict-transport-security"
    HEADER_CONTENT_TYPE_OPTIONS = "x-content-type-options"
    HEADER_FRAME_OPTIONS = "x-frame-options"
    HEADER_CSP = "content-security-policy"
    HEADER_PERMISSIONS_POLICY = "permissions-policy"
    HEADER_REFERRER_POLICY = "referrer-policy"
    HEADER_SERVER = "server"
    HEADER_X_POWERED_BY = "x-powered-by"

    # Expected value for X-Content-Type-Options
    EXPECTED_CONTENT_TYPE_OPTIONS = "nosniff"

    # CSP frame-ancestors directive (alternative to X-Frame-Options)
    CSP_FRAME_ANCESTORS_DIRECTIVE = "frame-ancestors"

    # Regex to detect version info in Server header (e.g., "nginx/1.19.0")
    SERVER_VERSION_PATTERN = r"[/]\s*[\d]+\.[\d]+"

    # --- Confidence values ---
    CONFIDENCE_MISSING_HSTS = 0.95
    CONFIDENCE_MISSING_CONTENT_TYPE_OPTIONS = 0.95
    CONFIDENCE_MISSING_FRAME_PROTECTION = 0.90
    CONFIDENCE_MISSING_CSP = 0.85
    CONFIDENCE_MISSING_PERMISSIONS_POLICY = 0.80
    CONFIDENCE_MISSING_REFERRER_POLICY = 0.80
    CONFIDENCE_SERVER_VERSION_DISCLOSURE = 0.90
    CONFIDENCE_X_POWERED_BY_PRESENT = 0.90

    # --- Severity levels ---
    SEVERITY_MISSING_HSTS = SeverityLevel.HIGH
    SEVERITY_MISSING_CONTENT_TYPE_OPTIONS = SeverityLevel.MEDIUM
    SEVERITY_MISSING_FRAME_PROTECTION = SeverityLevel.MEDIUM
    SEVERITY_MISSING_CSP = SeverityLevel.MEDIUM
    SEVERITY_MISSING_PERMISSIONS_POLICY = SeverityLevel.LOW
    SEVERITY_MISSING_REFERRER_POLICY = SeverityLevel.LOW
    SEVERITY_SERVER_VERSION_DISCLOSURE = SeverityLevel.LOW
    SEVERITY_X_POWERED_BY_PRESENT = SeverityLevel.LOW

    # --- Finding titles ---
    TITLE_MISSING_HSTS = "Missing Strict-Transport-Security (HSTS) header"
    TITLE_MISSING_CONTENT_TYPE_OPTIONS = (
        "Missing X-Content-Type-Options header"
    )
    TITLE_MISSING_FRAME_PROTECTION = (
        "Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors)"
    )
    TITLE_MISSING_CSP = "Missing Content-Security-Policy header"
    TITLE_MISSING_PERMISSIONS_POLICY = "Missing Permissions-Policy header"
    TITLE_MISSING_REFERRER_POLICY = "Missing Referrer-Policy header"
    TITLE_SERVER_VERSION_DISCLOSURE = (
        "Server header discloses version information"
    )
    TITLE_X_POWERED_BY_PRESENT = (
        "X-Powered-By header exposes technology stack"
    )

    # --- Finding descriptions ---
    DESC_MISSING_HSTS = (
        "The response from '{url}' does not include a "
        "Strict-Transport-Security header. Without HSTS, browsers do not "
        "enforce HTTPS connections, leaving users vulnerable to "
        "man-in-the-middle attacks and SSL stripping."
    )
    DESC_MISSING_CONTENT_TYPE_OPTIONS = (
        "The response from '{url}' does not include "
        "X-Content-Type-Options: nosniff. Without this header, browsers "
        "may MIME-sniff response content, potentially treating non-executable "
        "content as executable and enabling cross-site scripting."
    )
    DESC_MISSING_FRAME_PROTECTION = (
        "The response from '{url}' does not include X-Frame-Options or "
        "a Content-Security-Policy with frame-ancestors directive. "
        "An attacker can embed this page in an iframe and trick users "
        "into clicking hidden elements (clickjacking)."
    )
    DESC_MISSING_CSP = (
        "The response from '{url}' does not include a "
        "Content-Security-Policy header. CSP restricts which resources "
        "(scripts, styles, images) the browser is allowed to load, "
        "significantly reducing the impact of XSS attacks."
    )
    DESC_MISSING_PERMISSIONS_POLICY = (
        "The response from '{url}' does not include a Permissions-Policy "
        "(formerly Feature-Policy) header. This header controls which "
        "browser features (camera, microphone, geolocation) can be used "
        "by the page and embedded iframes."
    )
    DESC_MISSING_REFERRER_POLICY = (
        "The response from '{url}' does not include a Referrer-Policy "
        "header. Without it, the browser may send full URL information "
        "in the Referer header to external sites, potentially leaking "
        "sensitive data in query parameters or path segments."
    )
    DESC_SERVER_VERSION_DISCLOSURE = (
        "The response from '{url}' includes a Server header with version "
        "information: '{server_value}'. Exposing the server software and "
        "version helps attackers identify known vulnerabilities for that "
        "specific version."
    )
    DESC_X_POWERED_BY_PRESENT = (
        "The response from '{url}' includes an X-Powered-By header: "
        "'{powered_by_value}'. This reveals the application framework, "
        "helping attackers target framework-specific vulnerabilities.\n\n"
        "**Fix:** In Express: `app.disable('x-powered-by')` (one line). "
        "In nginx: `proxy_hide_header X-Powered-By;`. This is a 30-second fix."
    )

    # --- Error messages ---
    ERROR_SCAN_FAILED = (
        "Security headers scan failed for {url}: {error}"
    )


class CORSConfig:
    """Configuration for CORS misconfiguration scanning."""

    SCANNER_NAME = "cors_scanner"
    HTTP_TIMEOUT_SECONDS = SharedPatterns.DEFAULT_HTTP_TIMEOUT_SECONDS
    MAX_CONCURRENT = SharedPatterns.DEFAULT_MAX_CONCURRENT
    PROBE_DELAY = SharedPatterns.DEFAULT_PROBE_DELAY
    MAX_ENDPOINTS_TO_TEST = 5
    PATH_PREFIX_DEPTH = 2

    # CORS response header names
    HEADER_ALLOW_ORIGIN = "access-control-allow-origin"
    HEADER_ALLOW_CREDENTIALS = "access-control-allow-credentials"

    # Sentinel values
    WILDCARD_ORIGIN = "*"
    NULL_ORIGIN = "null"
    CREDENTIALS_TRUE_VALUE = "true"

    # Origin probes: (origin_value, label)
    # {target} is replaced with the actual target hostname at runtime
    ORIGIN_PROBES = (
        ("https://evil.com", "arbitrary_origin"),
        ("null", "null_origin"),
        ("https://{target}.evil.com", "subdomain_bypass"),
    )

    # Confidence levels
    CONFIDENCE_WILDCARD_CREDS = 0.95
    CONFIDENCE_ORIGIN_REFLECTED = 0.90
    CONFIDENCE_NULL_ORIGIN = 0.85
    CONFIDENCE_WILDCARD_NO_CREDS = 0.70

    # --- Titles ---
    TITLE_WILDCARD_CREDENTIALS = (
        "CORS allows wildcard origin with credentials"
    )
    TITLE_ORIGIN_REFLECTED = (
        "CORS reflects arbitrary Origin header"
    )
    TITLE_NULL_ORIGIN = (
        "CORS allows null origin"
    )
    TITLE_WILDCARD_NO_CREDS = (
        "CORS allows wildcard origin (data leakage risk)"
    )

    # --- Descriptions ---
    DESC_WILDCARD_CREDENTIALS = (
        "The endpoint {url} returns Access-Control-Allow-Origin: * with "
        "Access-Control-Allow-Credentials: true. This is a critical "
        "misconfiguration that allows any website to make authenticated "
        "cross-origin requests and steal user credentials or session data."
    )
    DESC_ORIGIN_REFLECTED = (
        "The endpoint {url} reflects the request Origin header '{origin}' "
        "in Access-Control-Allow-Origin. An attacker can make cross-origin "
        "requests from any domain and read the response, potentially "
        "exfiltrating sensitive data."
    )
    DESC_NULL_ORIGIN = (
        "The endpoint {url} allows Origin: null in its CORS policy. "
        "Sandboxed iframes, local file:// pages, and certain redirects "
        "send Origin: null, enabling attackers to bypass CORS protections."
    )
    DESC_WILDCARD_NO_CREDS = (
        "The endpoint {url} returns Access-Control-Allow-Origin: * without "
        "credentials. While credentials cannot be sent, any website can "
        "read the response data, which may leak non-public information."
    )

    # --- Error messages ---
    ERROR_CORS_SCAN_FAILED = "CORS scan failed for {endpoint}: {error}"


class OpenRedirectConfig:
    """Configuration for open redirect vulnerability scanning."""

    SCANNER_NAME = "open_redirect_scanner"
    HTTP_TIMEOUT_SECONDS = SharedPatterns.DEFAULT_HTTP_TIMEOUT_SECONDS
    MAX_CONCURRENT = SharedPatterns.DEFAULT_MAX_CONCURRENT
    PROBE_DELAY = SharedPatterns.DEFAULT_PROBE_DELAY

    # Default param to test when an endpoint matches a redirect path
    DEFAULT_REDIRECT_PARAM = "redirect"

    # Location header name
    HEADER_LOCATION = "location"

    # URL schemes
    SCHEME_HTTP = "http"
    SCHEME_HTTPS = "https"

    # Parameters that commonly control redirects
    REDIRECT_PARAM_NAMES = (
        "redirect", "url", "next", "return", "returnto",
        "continue", "goto", "dest", "destination", "redir",
        "redirect_uri", "callback",
    )

    # Common redirect endpoint paths
    REDIRECT_PATH_INDICATORS = (
        "/login", "/logout", "/auth/callback",
        "/oauth/authorize", "/sso", "/signin", "/signout",
    )

    # Redirect payloads: (payload, label)
    REDIRECT_PAYLOADS = (
        ("https://evil.com", "absolute_url"),
        ("//evil.com", "protocol_relative"),
        ("/\\/evil.com", "path_confusion"),
        ("https://evil.com%00.target.com", "null_byte"),
    )

    # Patterns that indicate JavaScript or meta-based redirects in response body
    BODY_REDIRECT_PATTERNS = (
        r'window\.location\s*=\s*["\']https?://evil\.com',
        r'window\.location\.href\s*=\s*["\']https?://evil\.com',
        r'window\.location\.replace\s*\(\s*["\']https?://evil\.com',
        r'<meta\s+http-equiv\s*=\s*["\']refresh["\'][^>]*url\s*=\s*https?://evil\.com',
    )

    # Indicators in the hostname that confirm external redirect
    EVIL_DOMAIN_INDICATORS = ("evil.com",)

    # Confidence levels
    CONFIDENCE_HEADER_REDIRECT = 0.90
    CONFIDENCE_BODY_REDIRECT = 0.75

    # --- Titles ---
    TITLE_HEADER_REDIRECT = "Open redirect via HTTP Location header"
    TITLE_BODY_REDIRECT = (
        "Open redirect via JavaScript/meta refresh in response body"
    )

    # --- Descriptions ---
    DESC_HEADER_REDIRECT = (
        "The parameter '{param}' on endpoint {url} redirects to an "
        "external domain when set to '{payload}'. The server responded "
        "with Location: {location}. Attackers can use this to redirect "
        "users to phishing pages while leveraging the trusted domain."
    )
    DESC_BODY_REDIRECT = (
        "The parameter '{param}' on endpoint {url} triggers a "
        "client-side redirect when set to '{payload}'. The response body "
        "contains a JavaScript or meta-refresh redirect to an external "
        "domain, which can be used for phishing attacks."
    )

    # --- Error messages ---
    ERROR_REDIRECT_SCAN_FAILED = (
        "Open redirect scan failed for {endpoint}: {error}"
    )


class AuthBypassConfig:
    """Configuration for the authentication bypass scanner."""

    SCANNER_NAME = "auth_bypass_scanner"
    HTTP_TIMEOUT_SECONDS = 10
    PROBE_DELAY_SECONDS = 0.5
    RESPONSE_BODY_PREVIEW_LENGTH = 500

    # Maximum protected endpoints to test for auth header bypass
    MAX_AUTH_BYPASS_ENDPOINTS = 5

    # Lockout testing
    LOCKOUT_ATTEMPT_COUNT = 10
    LOCKOUT_PROBE_DELAY_SECONDS = 0.2

    # Delay between default credential attempts (rate limiting)
    CREDENTIAL_TEST_DELAY_SECONDS = 0.5

    # Timing-based username enumeration threshold (seconds)
    TIMING_DELTA_THRESHOLD_SECONDS = 0.5

    # --- Endpoint indicators ---
    LOGIN_ENDPOINT_INDICATORS = (
        "/login", "/signin", "/sign-in", "/auth/login",
        "/api/auth", "/api/login", "/api/signin",
    )

    RESET_ENDPOINT_INDICATORS = (
        "/forgot-password", "/forgot", "/reset-password",
        "/api/auth/forgot", "/api/forgot-password",
        "/api/reset-password", "/password-reset",
    )

    SIGNUP_ENDPOINT_INDICATORS = (
        "/signup", "/sign-up", "/register", "/api/signup",
        "/api/register",
    )

    AUTH_REQUIRED_INDICATORS = (
        "/api/user", "/api/account", "/api/profile",
        "/api/settings", "/api/admin", "/dashboard/api",
        "/api/me",
    )

    # --- Test credentials ---
    TEST_USERNAME_NONEXISTENT = "nonexistent_user_test_00@test.invalid"
    TEST_USERNAME_VALID_LOOKING = "admin@test.com"
    TEST_PASSWORD_WRONG = "definitely_wrong_password_12345!"

    # Default credential pairs: (username, password)
    DEFAULT_CREDENTIAL_PAIRS = (
        ("admin@admin.com", "admin"),
        ("admin@admin.com", "password"),
        ("admin@admin.com", "admin123"),
        ("test@test.com", "test"),
        ("root@root.com", "root"),
        ("admin@admin.com", "changeme"),
        ("user@user.com", "password123"),
    )

    # --- Differential error message pairs ---
    # Each pair: (phrase indicating user not found, phrase indicating wrong password)
    DIFFERENTIAL_ERROR_PAIRS = (
        ("user not found", "invalid password"),
        ("user not found", "wrong password"),
        ("no account", "incorrect password"),
        ("does not exist", "invalid credentials"),
        ("email not found", "password incorrect"),
        ("unknown user", "bad password"),
        ("no user", "invalid password"),
        ("not registered", "wrong password"),
    )

    # --- Token leak indicators ---
    TOKEN_LEAK_INDICATORS = (
        "reset_token", "resettoken", "token=",
        "reset-token", "password_reset_token",
        "verification_token", "verify_token",
    )

    # --- Auth success indicators in response body ---
    AUTH_SUCCESS_INDICATORS = (
        "access_token", "accesstoken", "auth_token",
        "jwt", "bearer", "session_id", "sessionid",
        '"token"', "'token'",
    )

    # --- Auth header bypass test labels ---
    BYPASS_LABEL_NO_HEADER = "no Authorization header"
    BYPASS_LABEL_EMPTY_BEARER = "empty Bearer token"
    BYPASS_LABEL_BASIC_ADMIN = "Basic admin:admin"

    # Base64 of admin:admin
    BASIC_AUTH_ADMIN_HEADER = "Basic YWRtaW46YWRtaW4="

    # --- Confidence values ---
    CONFIDENCE_USERNAME_ENUM_MESSAGE = 0.85
    CONFIDENCE_USERNAME_ENUM_TIMING = 0.65
    CONFIDENCE_USERNAME_ENUM_STATUS = 0.70
    CONFIDENCE_RESET_TOKEN_LEAK = 0.90
    CONFIDENCE_NO_LOCKOUT = 0.60
    CONFIDENCE_DEFAULT_CREDS = 0.95
    CONFIDENCE_AUTH_BYPASS = 0.85

    # --- Finding titles ---
    TITLE_USERNAME_ENUMERATION_MESSAGE = (
        "Username enumeration via differential error messages"
    )
    TITLE_USERNAME_ENUMERATION_TIMING = (
        "Possible username enumeration via response timing"
    )
    TITLE_USERNAME_ENUMERATION_STATUS = (
        "Username enumeration via different HTTP status codes"
    )
    TITLE_RESET_TOKEN_LEAK = "Password reset token exposed in response"
    TITLE_NO_ACCOUNT_LOCKOUT = "No account lockout after failed login attempts"
    TITLE_DEFAULT_CREDENTIALS = "Default credentials accepted"
    TITLE_AUTH_HEADER_BYPASS = (
        "Authentication bypass — endpoint accessible without valid credentials"
    )

    # --- Finding descriptions ---
    DESC_USERNAME_ENUMERATION_MESSAGE = (
        "The login endpoint {url} returns different error messages depending "
        "on whether a username exists. This allows attackers to enumerate "
        "valid usernames before attempting password attacks."
    )
    DESC_USERNAME_ENUMERATION_TIMING = (
        "The login endpoint {url} shows a response time difference of "
        "{delta_ms}ms between valid and invalid usernames. Attackers can "
        "use timing analysis to enumerate valid accounts."
    )
    DESC_USERNAME_ENUMERATION_STATUS = (
        "The login endpoint {url} returns different HTTP status codes for "
        "invalid users ({status_invalid}) vs valid users with wrong "
        "passwords ({status_valid}). This enables username enumeration."
    )
    DESC_RESET_TOKEN_LEAK = (
        "The password reset endpoint {url} exposes the reset token in the "
        "{location}. An attacker can intercept or observe the token to "
        "reset any user's password without accessing their email."
    )
    DESC_NO_ACCOUNT_LOCKOUT = (
        "The login endpoint {url} accepted {attempts} consecutive failed "
        "login attempts without locking the account. Without lockout, "
        "attackers can perform unlimited brute-force password attacks."
    )
    DESC_DEFAULT_CREDENTIALS = (
        "The login endpoint {url} accepted default credentials for user "
        "'{username}'. Default credentials are widely known and allow "
        "immediate unauthorized access."
    )
    DESC_AUTH_HEADER_BYPASS = (
        "The endpoint {url} returned a successful response when accessed "
        "with {bypass_method}. Protected endpoints should return 401 or "
        "403 when proper authentication is not provided."
    )

    # --- Error messages ---
    ERROR_SCAN_FAILED = (
        "Auth bypass scan ({phase}) failed for {endpoint}: {error}"
    )


class HTTPProbeConfig:
    """Configuration for HTTP configuration probe scanner."""

    SCANNER_NAME = "http_probe_scanner"

    MAX_ENDPOINTS_TO_TEST = 5
    MAX_CONCURRENT = 3
    PROBE_DELAY = 0.2
    MAX_METHOD_TEST_ENDPOINTS = 3

    # --- Method tampering ---
    DANGEROUS_METHODS = ("TRACE", "CONNECT")

    CONFIDENCE_METHOD_TAMPERING = 0.80
    CONFIDENCE_TRACE = 0.90

    TITLE_DANGEROUS_METHOD = "Dangerous HTTP method {method} enabled on {url}"
    DESC_DANGEROUS_METHOD = (
        "The endpoint {url} allows the {method} HTTP method "
        "(Allow: {allow_header}). TRACE enables cross-site tracing attacks "
        "that can steal credentials from HTTP headers."
    )

    TITLE_TRACE_ENABLED = "TRACE method echoes request on {url}"
    DESC_TRACE_ENABLED = (
        "The endpoint {url} responds to TRACE requests by echoing the "
        "request back, including headers. This enables cross-site tracing "
        "(XST) attacks that can steal HttpOnly cookies and auth tokens."
    )

    # --- Host header injection ---
    FORGED_HOST = "evil-host-injection-test.com"
    HOST_HEADERS = ("Host", "X-Forwarded-Host")

    CONFIDENCE_HOST_INJECTION = 0.85

    TITLE_HOST_INJECTION = "Host header injection via {header}"
    DESC_HOST_INJECTION = (
        "The endpoint {url} reflects the forged {header}: {host} in its "
        "response. This can enable password reset poisoning, cache "
        "poisoning, and routing-based attacks."
    )

    # --- CRLF / Header injection ---
    CRLF_CANARY_HEADER = "X-CRLF-Test"
    CRLF_CANARY_VALUE = "crlf_injected"
    CRLF_PAYLOADS = (
        "\r\nX-CRLF-Test: crlf_injected",
        "%0d%0aX-CRLF-Test:%20crlf_injected",
        "\r\n\r\n<script>alert(1)</script>",
    )
    CRLF_PARAM_NAMES = (
        "url", "redirect", "next", "return", "callback",
        "path", "ref", "location", "goto",
    )

    CONFIDENCE_CRLF = 0.90

    TITLE_CRLF_INJECTION = "CRLF injection — response header injection via '{param}'"
    DESC_CRLF_INJECTION = (
        "The endpoint {url} is vulnerable to CRLF injection via the "
        "'{param}' parameter. By injecting \\r\\n characters, an attacker "
        "can insert arbitrary HTTP response headers.\n\n"
        "**Impact:** Session fixation (inject Set-Cookie), cache "
        "poisoning (inject Cache-Control), or XSS via injected "
        "Content-Type + HTML body."
    )

    # --- Verbose error pages ---
    ERROR_TRIGGER_PATHS = (
        "/nonexistent-path-security-probe-12345",
        "/api/nonexistent-security-probe",
        "/%00",
        "/'" + "A" * 500,
    )

    ERROR_LEAK_PATTERNS = (
        r"at\s+Object\.\<anonymous\>",
        r"at\s+\w+\s+\(",
        r"Traceback\s+\(most\s+recent",
        r"Exception\s+in\s+thread",
        r"Stack\s+Trace:",
        r"/usr/\w+/",
        r"/home/\w+/",
        r"C:\\\\",
        r"/var/www/",
        r"node_modules/",
        r"\.py\",\s+line\s+\d+",
        r"\.java:\d+\)",
    )

    CONFIDENCE_VERBOSE_ERROR = 0.80

    TITLE_VERBOSE_ERROR = "Verbose error page at {url}"
    DESC_VERBOSE_ERROR = (
        "The endpoint {url} returned a {status} error response containing "
        "internal details such as stack traces, file paths, or framework "
        "information. This aids attacker reconnaissance."
    )

    # --- Directory listing / sensitive files ---
    # (path, check_type, indicator)
    SENSITIVE_PATHS = (
        ("/.git/HEAD", "content", "ref:"),
        ("/.env", "content", "="),
        ("/.env.local", "content", "="),
        ("/robots.txt", "content", "Disallow"),
        ("/api/", "listing", ""),
        ("/static/", "listing", ""),
        ("/assets/", "listing", ""),
        ("/backup/", "listing", ""),
        ("/backups/", "listing", ""),
    )

    DIRECTORY_LISTING_INDICATORS = (
        "Index of /",
        "Directory listing for",
        "<title>Directory:",
        "Parent Directory",
    )

    CONFIDENCE_SENSITIVE_FILE = 0.90
    CONFIDENCE_DIRECTORY_LISTING = 0.80

    TITLE_SENSITIVE_FILE = "Sensitive file exposed: {path}"
    DESC_SENSITIVE_FILE = (
        "The file at {url} is publicly accessible. If this contains "
        "secrets, credentials, or source code metadata, it should be "
        "blocked by the web server."
    )

    TITLE_DIRECTORY_LISTING = "Directory listing enabled: {path}"
    DESC_DIRECTORY_LISTING = (
        "The directory at {url} has directory listing enabled, exposing "
        "its contents to anyone. This may reveal internal file structure "
        "and sensitive resources."
    )

    ERROR_PROBE_FAILED = "HTTP probe failed for {url}: {error}"


class TemplateInjectionConfig:
    """Configuration for server-side template injection (SSTI) checks."""

    # (payload, expected_output, engine_hint)
    SSTI_PAYLOADS = (
        ("{{7*7}}", "49", "Jinja2/Twig/Nunjucks"),
        ("${7*7}", "49", "Freemarker/Velocity/Groovy"),
        ("<%= 7*7 %>", "49", "ERB/EJS"),
        ("#{7*7}", "49", "Pug/Jade"),
        ("{{7*'7'}}", "7777777", "Jinja2 string multiplication"),
    )

    MAX_ENDPOINTS_TO_TEST = 10
    MAX_PARAMS_PER_ENDPOINT = 3

    CONFIDENCE_SSTI = 0.90

    TITLE_SSTI = (
        "Server-side template injection ({engine}) in {param} at {url}"
    )
    DESC_SSTI = (
        "The parameter '{param}' at {url} evaluates template expressions. "
        "The payload '{payload}' produced '{expected}' in the response. "
        "SSTI often leads to remote code execution (RCE)."
    )


class GuidedDASTConfig:
    """Configuration for SAST-guided DAST test generation and execution."""

    # Execution limits
    MAX_CONCURRENT = 3
    PROBE_DELAY = 0.3
    MAX_TEST_CASES = 50
    HTTP_TIMEOUT = 15
    RACE_CONCURRENT_REQUESTS = 5

    # Confidence
    CONFIDENCE_CONFIRMED = 0.95

    # Scanner identity
    SCANNER_NAME = "sast_guided_dast"
    USER_AGENT = "BrandifAI-GuidedDAST/1.0"

    # Test type identifiers
    TEST_TYPE_AUTH_BYPASS = "auth_bypass"
    TEST_TYPE_IDOR = "idor_targeted"
    TEST_TYPE_MASS_ASSIGNMENT = "mass_assignment"
    TEST_TYPE_RACE_CONDITION = "race_condition"
    TEST_TYPE_SQLI = "sqli_targeted"
    TEST_TYPE_XSS = "xss_targeted"
    TEST_TYPE_RLS_BYPASS = "rls_bypass"

    # Descriptions
    DESC_AUTH_BYPASS = (
        "Testing unauthenticated {method} access to {url} — "
        "SAST found missing auth check in code"
    )
    DESC_IDOR = (
        "Testing IDOR by swapping parameter '{param}' at {url} — "
        "SAST found missing ownership check"
    )
    DESC_MASS_ASSIGNMENT = (
        "Testing mass assignment of privileged fields ({fields}) at {url} — "
        "schema exposes sensitive columns"
    )
    DESC_RACE_CONDITION = (
        "Race condition probe {batch}/{total} to {url} — "
        "LLM review identified TOCTOU risk"
    )
    DESC_INJECTION = (
        "{injection_type} probe targeting parameter '{param}' at {url} — "
        "SAST found unsanitized input"
    )
    DESC_RLS_BYPASS = (
        "Direct Supabase REST query to table '{table}' with anon key — "
        "SAST found missing RLS policy"
    )

    # Expected behaviors
    EXPECTED_AUTH_BYPASS = "Should return 401 or 403 if auth is enforced"
    EXPECTED_IDOR = "Should return 403 or empty result if ownership is checked"
    EXPECTED_MASS_ASSIGNMENT = "Privileged fields should be ignored or rejected"
    EXPECTED_RACE_CONDITION = "Only one of concurrent requests should succeed"
    EXPECTED_INJECTION = "Should return error or sanitized response, not raw data"
    EXPECTED_RLS_BYPASS = "Should return empty array or 401 if RLS is enabled"

    # Finding output
    FINDING_TITLE = "SAST-guided {test_type} confirmed at {url}"
    FINDING_EVIDENCE = "{method} {url} returned HTTP {status}"
    EVIDENCE_RACE_CONDITION = (
        "{count}/{total} concurrent requests succeeded — race condition likely"
    )

    # Progress / logging messages
    MSG_NO_TESTS = "No SAST-guided DAST test cases generated"
    MSG_EXECUTING = "Executing {count} SAST-guided DAST test cases"
    MSG_COMPLETED = (
        "SAST-guided DAST complete: {confirmed} confirmed out of {total} tests"
    )
    MSG_STRATEGY_FAILED = (
        "Strategy {strategy} failed: {error}"
    )
    MSG_DRY_RUN = "Skipping dry-run test for payment endpoint: {url}"
    MSG_PROBE_ERROR = "Probe failed for {url}: {error}"
    MSG_PHASE = "Running SAST-guided DAST..."
    PROGRESS_GUIDED_DAST = 96


class ProbeCaptureConfig:
    """Configuration for DAST probe request/response capture."""

    MAX_RESPONSE_BODY_CAPTURE = 5000  # chars
    MAX_REQUEST_BODY_CAPTURE = 2000  # chars
    SENSITIVE_HEADERS = ("authorization", "cookie", "x-api-key", "apikey")
    REDACT_AFTER_CHARS = 10
    REDACT_PLACEHOLDER = "...REDACTED"


class ProbeAnalyzerConfig:
    """Configuration for cross-probe DAST analysis."""

    SCANNER_NAME = "probe_analyzer"

    # Response size anomaly thresholds
    RESPONSE_SIZE_MULTIPLIER = 5.0
    RESPONSE_SIZE_MIN_BYTES = 10_000  # 10 KB

    # Timing anomaly thresholds
    TIMING_MULTIPLIER = 3.0
    TIMING_MIN_MS = 2_000.0  # 2 seconds

    # Cookie analysis
    MIN_SESSION_TOKEN_LENGTH = 16

    # Sensitive data exposure
    MIN_UNIQUE_EMAILS_TO_FLAG = 3

    # Confidence values per analysis type
    CONFIDENCE_HEADER_LEAK = 0.80
    CONFIDENCE_COOKIE_ISSUES = 0.70
    CONFIDENCE_RESPONSE_SIZE = 0.60
    CONFIDENCE_TIMING = 0.50
    CONFIDENCE_ERROR_FINGERPRINT = 0.70
    CONFIDENCE_SENSITIVE_EMAILS = 0.70
    CONFIDENCE_SENSITIVE_API_KEY = 0.90
    CONFIDENCE_SENSITIVE_JWT = 0.80

    # Internal IP patterns (RFC 1918 + link-local)
    INTERNAL_IP_PATTERN = (
        r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
        r'|192\.168\.\d{1,3}\.\d{1,3})'
    )

    # Internal hostname patterns
    INTERNAL_HOSTNAME_PATTERN = r'[\w.-]+\.(?:internal|local|corp)\b'

    # Debug headers that should not be exposed
    DEBUG_HEADERS = ("x-debug-token", "x-debug-id")

    # Backend framework disclosure headers
    FRAMEWORK_HEADERS = (
        "x-aspnet-version",
        "x-runtime",
        "x-django-debug",
        "x-powered-by",
    )

    # Cookie header name
    SET_COOKIE_HEADER = "set-cookie"

    # Session cookie name patterns
    SESSION_COOKIE_NAMES = ("session", "sid", "token", "auth", "jwt")

    # API key prefixes in response bodies
    API_KEY_PREFIXES = ("sk_live_", "AKIA", "ghp_", "glpat-")

    # Email regex
    EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

    # JWT pattern in response bodies
    JWT_BODY_PATTERN = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'

    # Technology fingerprints in error responses
    TECH_FINGERPRINTS = {
        "Express": (r"Cannot\s+(?:GET|POST|PUT|DELETE)", r"express"),
        "Django": (r"(?:Django|CSRF verification failed)", r"django"),
        "Rails": (r"(?:ActionController|ActiveRecord)", r"rails"),
        "ASP.NET": (r"(?:System\.Web|__VIEWSTATE|aspnet)", r"asp\.net"),
        "PHP": (r"(?:Fatal error|Warning:.*\bPHP\b)", r"php"),
        "Spring": (r"(?:Whitelabel Error Page|spring)", r"spring"),
        "Tomcat": (r"(?:Apache Tomcat|org\.apache)", r"tomcat"),
    }

    # Finding titles
    TITLE_HEADER_LEAK = "Information leakage via HTTP response headers"
    TITLE_COOKIE_ISSUES = "Cookie security weaknesses detected"
    TITLE_RESPONSE_SIZE = "Anomalous response size at {url}"
    TITLE_TIMING = "Timing anomalies detected across DAST probes"
    TITLE_ERROR_FINGERPRINT = "Backend technology disclosed via error responses"
    TITLE_SENSITIVE_EMAILS = "Email addresses exposed in responses"
    TITLE_SENSITIVE_API_KEY = "API key exposed in response body"
    TITLE_SENSITIVE_JWT = "JWT token exposed in response body"

    # Finding descriptions
    DESC_HEADER_LEAK = (
        "Cross-probe analysis found information leakage in HTTP response "
        "headers: {details}"
    )
    DESC_COOKIE_ISSUES = (
        "Cross-probe cookie analysis found security weaknesses: {details}"
    )
    DESC_RESPONSE_SIZE = (
        "Response from {url} is {size} bytes, which is {ratio:.1f}x the "
        "mean response size of {mean} bytes — may indicate data over-exposure"
    )
    DESC_TIMING = (
        "The following endpoints had response times significantly above "
        "the mean ({mean_ms:.0f}ms): {details}"
    )
    DESC_ERROR_FINGERPRINT = (
        "Error responses reveal backend technology stack: {techs}. "
        "This aids attackers in targeting known vulnerabilities."
    )
    DESC_SENSITIVE_EMAILS = (
        "{count} unique email addresses found across DAST response bodies"
    )
    DESC_SENSITIVE_API_KEY = (
        "API key with prefix '{prefix}' found in response body from {url}"
    )
    DESC_SENSITIVE_JWT = (
        "JWT token found in response body from {url}, potentially "
        "allowing session hijacking"
    )
