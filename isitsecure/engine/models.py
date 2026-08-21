"""Domain models for the Deep Security Scan Agent."""

from enum import Enum
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field, computed_field

from isitsecure.engine.enums import (
    EndpointCategory,
    EndpointMethod,
    IDORRiskLevel,
    IDORTestType,
    ImpactCategory,
    LikelihoodLevel,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel


class DASTProbeCaptureEntry(BaseModel):
    """A single captured HTTP request/response pair from DAST probing."""

    timestamp: str = ""  # ISO8601
    scanner_name: str = ""

    # Request
    request_method: str = ""
    request_url: str = ""
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""

    # Response
    response_status: int = 0
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    response_time_ms: float = 0.0

    # Curl command for replay
    curl_command: str = ""


class DiscoveredEndpoint(BaseModel):
    """An API endpoint discovered from client-side JavaScript."""

    url: str
    method: EndpointMethod = EndpointMethod.GET
    source_pattern: str = ""
    has_path_params: bool = False
    path_param_names: list[str] = Field(default_factory=list)
    query_param_names: list[str] = Field(default_factory=list)
    category: EndpointCategory = EndpointCategory.UNKNOWN
    requires_auth: Optional[bool] = None

    @property
    def has_id_params(self) -> bool:
        """Whether this endpoint has any ID-like parameters."""
        return self.has_path_params or len(self.query_param_names) > 0


class IDORProbeResult(BaseModel):
    """Result of a single IDOR probe against an endpoint."""

    original_url: str
    probed_url: str
    test_type: IDORTestType
    original_status: Optional[int] = None
    probed_status: Optional[int] = None
    original_body_preview: str = ""
    probed_body_preview: str = ""
    response_differs: bool = False
    data_returned: bool = False
    error: Optional[str] = None


class IDORTestResult(BaseModel):
    """Aggregated result of IDOR testing on a single endpoint."""

    endpoint: DiscoveredEndpoint
    risk_level: IDORRiskLevel
    probes: list[IDORProbeResult] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    summary: str = ""


class InterceptedRequest(BaseModel):
    """A network request intercepted during authenticated crawling."""

    url: str
    method: str
    response_status: int
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    response_body_preview: str = ""
    response_content_type: str = ""
    resource_ids_found: list[str] = Field(default_factory=list)


class AuthenticatedCrawlResult(BaseModel):
    """Result of crawling as an authenticated user."""

    pages_visited: int = 0
    pages_discovered: list[str] = Field(default_factory=list)
    intercepted_requests: list[InterceptedRequest] = Field(default_factory=list)
    discovered_endpoints: list[DiscoveredEndpoint] = Field(default_factory=list)
    owned_resource_ids: dict[str, list[str]] = Field(
        default_factory=dict
    )  # table/path -> [id1, id2]
    supabase_queries: list[InterceptedRequest] = Field(default_factory=list)
    tables_discovered: list[str] = Field(default_factory=list)
    auth_headers: dict[str, str] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class BrowserSignupResult(BaseModel):
    """Outcome of a browser-driven self-registration (``AuthenticatedCrawler.signup``).

    The pentest ``provision_account`` browser fallback drives a real browser to read a
    SPA's register form, submit it, and capture the real signup endpoint from the
    resulting XHR. This is the structured result it reads back:

    - ``success`` — the register form submitted and produced a 2xx signup API call.
    - ``signup_endpoint`` — the path of the intercepted signup POST (e.g. ``/api/Users``),
      the non-standard endpoint that path-probing could not find.
    - ``email``/``password``/``username`` — the agent-owned credentials it registered with.
    - ``status_code`` — the signup API call's status (``None`` when none was captured).
    - ``error`` — why signup could not complete (no register page, no XHR, submit failed).
    - ``blocked_reason`` — a real-world wall (CAPTCHA / email- / SMS-verification) that was
      *detected and reported*, never defeated (the honest boundary). Mutually the reason
      ``success`` is False without an ``error``.
    """

    success: bool = False
    signup_endpoint: str = ""
    email: str = ""
    password: str = ""
    username: str = ""
    status_code: int | None = None
    error: str = ""
    blocked_reason: str = ""


class FormField(BaseModel):
    """One fillable control perceived on a register/signup form.

    Captured by ``AuthenticatedCrawler._perceive_form`` for the LLM form-comprehension
    path (the "read and understand the app, don't guess" signup). ``locator`` is a stable
    CSS selector the executor can target (a stamped index attribute), so the plan the LLM
    returns can drive each control deterministically. ``options`` enumerates the choices of a
    native ``<select>`` OR a custom dropdown (``mat-select`` / ``[role="combobox"]`` /
    ``[role="listbox"]``) so the LLM can pick one of the REAL options rather than guessing.

    ``control_kind`` is the CANONICAL, framework-agnostic taxonomy the perception classifies
    every control into — one of ``"text"`` (text/email/password/number/tel/url/search/
    textarea), ``"single_select"``, ``"multi_select"``, ``"radio_group"``, ``"checkbox"``,
    ``"toggle"``, or ``"other"``. Perception detects the kind across native HTML, Angular
    Material, and React/ARIA variants; the executor has ONE driver per kind that handles the
    per-framework mechanics, and the LLM plans at this semantic level (this is a single-choice
    with these options → pick one). ``"other"`` (the default) means "unclassified — infer from
    tag/type/action", preserving backward compatibility for callers that build a field by hand.
    """

    locator: str
    tag: str = ""
    type: str = ""
    name: str = ""
    id: str = ""
    label: str = ""
    placeholder: str = ""
    aria_label: str = ""
    required: bool = False
    value: str = ""
    options: list[str] = Field(default_factory=list)
    control_kind: str = "other"


class FormPerception(BaseModel):
    """A structured perception of a register/signup form: every fillable control (with its
    dropdown options), a bounded screenshot (base64 PNG), the page URL, and the submit
    control's locator. The input to the LLM form-comprehension step."""

    fields: list[FormField] = Field(default_factory=list)
    screenshot_b64: str = ""
    page_url: str = ""
    submit_locator: str = ""


class FormFillAction(BaseModel):
    """One step of a fill plan, driving one control of a canonical ``control_kind``:

    - ``type`` text into a ``text`` control (``value``);
    - ``select`` one option of a ``single_select`` (``value`` — one of the field's enumerated
      ``options``);
    - ``select_multi`` several options of a ``multi_select`` (``values`` — a subset of the
      enumerated ``options``);
    - ``choose`` one option of a ``radio_group`` (``value``);
    - ``check`` / ``uncheck`` a ``checkbox`` (``value`` a boolean, or the verb itself);
    - ``toggle`` a ``toggle`` on/off (``value`` a boolean).

    Single-value actions use ``value``; ``select_multi`` uses ``values``. ``locator`` targets
    the control (a perceived field's stable selector). The legacy verbs ``type``/``select``/
    ``check`` remain valid so older plans keep working."""

    locator: str
    # "type" | "select" | "select_multi" | "choose" | "check" | "uncheck" | "toggle"
    action: str = "type"
    value: str = ""
    values: list[str] = Field(default_factory=list)


class FormFillPlan(BaseModel):
    """The LLM's plan for filling a perceived form — an ordered list of fill actions.
    Privilege/role actions are stripped before execution (never self-escalate)."""

    actions: list[FormFillAction] = Field(default_factory=list)


class CrossUserIDORResult(BaseModel):
    """Result of a cross-user IDOR test on a single resource."""

    table_or_endpoint: str
    resource_id: str
    owner_user_id: str
    attacker_user_id: str
    read_accessible: bool = False
    write_accessible: bool = False
    delete_accessible: bool = False
    full_table_readable: bool = False
    evidence: list[IDORProbeResult] = Field(default_factory=list)
    risk_level: IDORRiskLevel = IDORRiskLevel.SAFE
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)


class AppEntity(BaseModel):
    """One data entity the target app exposes (e.g. ``User``, ``Product``) with its
    inferred ID scheme and the endpoints that expose it.

    Part of the :class:`AppModel` the LLM analyst builds from the GROUNDED knowledge
    store. ``id_scheme`` is evidence-grounded — inferred from the observed id VALUES
    (all-numeric-sequential → ``sequential_int``, UUIDs → ``uuid``), one of
    ``sequential_int``/``uuid``/``slug``/``unknown``; a value outside that set is
    normalised to ``unknown`` at parse time. ``endpoints`` are real captured
    ``METHOD path_template`` refs, never guesses."""

    name: str = ""
    id_scheme: str = "unknown"  # sequential_int | uuid | slug | unknown
    endpoints: list[str] = Field(default_factory=list)


class StateChangingOp(BaseModel):
    """A mutating operation the app exposes — the write surface worth attacking
    (mass-assignment, broken-authz-on-write). ``path_template`` is a real captured
    template (``POST /api/Users/{id}``), never a guess."""

    method: str = ""
    path_template: str = ""


class AppModel(BaseModel):
    """A structured, bounded model of the target app, produced by the LLM analyst
    (``LLMPlanner.build_app_model``) from the GROUNDED knowledge store — the observed
    endpoint inventory — so the planner reasons from an *understanding* of the app
    (its entities, id scheme, tenancy/roles, and auth mechanism) instead of guessing
    attacks opportunistically.

    Every field is optional/defaulted so a THIN model — or the conservative empty model
    a malformed LLM response parses to — is valid and never raises. Conservative and
    evidence-grounded: ``id_scheme`` is inferred from observed id VALUES,
    ``auth_mechanism`` from captured auth-header/token SHAPE (a ``_loot_structure``-style
    descriptor, never a raw secret), and ``confidence`` (0–1) reflects how much the
    observed surface actually supports the model."""

    app_type: str = ""
    entities: list[AppEntity] = Field(default_factory=list)
    tenancy: str = "unknown"  # e.g. "multi-user, per-user objects" | "multi-tenant" | ...
    roles: list[str] = Field(default_factory=list)
    auth_mechanism: str = "unknown"  # e.g. "JWT (RS256) in Authorization header" | ...
    state_changing_ops: list[StateChangingOp] = Field(default_factory=list)
    interesting_params: list[str] = Field(default_factory=list)
    notes: str = ""
    confidence: float = 0.0


class FindingSource(str, Enum):
    """Where the finding was discovered."""

    DAST_URL = "dast_url"
    DAST_AUTHENTICATED = "dast_auth"
    SAST_CODE = "sast_code"
    SAST_GIT_HISTORY = "sast_git"
    SAST_GUIDED_DAST = "sast_guided_dast"
    CROSS_REFERENCED = "cross_ref"


class CodeLocation(BaseModel):
    """Exact location in source code for SAST findings."""

    file_path: str
    line_number: int | None = None
    line_end: int | None = None
    code_snippet: str = ""
    github_url: str = ""


class DeepFinding(BaseModel):
    """Unified finding from any scanner (DAST or SAST).

    This is the single output format for ALL scanners in the deep scan agent.
    Both DASTScannerProtocol and CodeScannerProtocol produce DeepFindings.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    source: FindingSource
    category: FindingCategory
    severity: SeverityLevel
    title: str
    description: str
    technical_detail: str = ""
    evidence: str = ""
    confidence: float = Field(ge=0.0, le=1.0)
    scanner_name: str

    # Priority model (filled by triage layer)
    impact: ImpactCategory | None = None
    likelihood: LikelihoodLevel | None = None
    priority: int | None = None  # 1 (highest) to 4 (lowest)
    remediation_guidance: str = ""

    # DAST-specific fields
    endpoint_url: str | None = None
    http_method: str | None = None
    request_payload: str | None = None
    response_preview: str | None = None
    # Baseline (safe-value) response, for differential findings (the NoSQL size
    # oracle and error-based SQLi). Lets the LLM injection adjudicator compare
    # baseline vs. injected instead of guessing from the injected response alone
    # (#5, #125).
    baseline_response_preview: str | None = None

    # SAST-specific fields
    code_location: CodeLocation | None = None

    # Theme grouping (filled by triage layer)
    theme_id: str = ""

    # DAST probe captures (request/response pairs for review)
    probe_captures: list[DASTProbeCaptureEntry] = Field(default_factory=list)

    # Cross-reference
    related_finding_ids: list[str] = Field(default_factory=list)

    @computed_field  # serialized so users can copy it into `.isitsecureignore`
    @property
    def fingerprint(self) -> str:
        """Stable cross-scan identity (#38). Derived, never stored, so it can't
        drift from the finding's content. See ``engine/identity.py``."""
        from isitsecure.engine.identity import finding_fingerprint
        return finding_fingerprint(self)

    def to_customer_dict(self) -> dict:
        """Serialize for customer-facing report (excludes fix_code)."""
        return self.model_dump(mode="json")


class RemediationPhase(BaseModel):
    """A phase in the remediation plan for the owner summary."""

    phase_number: int
    title: str
    description: str
    priority: int = 1  # 1-4
    finding_count: int = 0


class OwnerSummary(BaseModel):
    """Non-technical summary for the site/app owner.

    Written in plain language for an SMB owner who may not be
    technical.  No code, no file paths, no jargon.
    """

    grade: str = ""  # A-F
    grade_label: str = ""
    risk_summary: str = ""
    key_risks: list[str] = Field(default_factory=list)
    remediation_phases: list[RemediationPhase] = Field(default_factory=list)
    scope_disclaimer: str = ""
    what_this_report_is_not: str = ""


class SecurityTheme(BaseModel):
    """A thematic grouping of related security findings.

    Themes cluster findings by the underlying security concern
    (e.g., "Payment Processing Integrity", "Missing Row-Level Security")
    rather than by scanner or severity.
    """

    theme_id: str  # short slug, e.g. "payment-integrity"
    title: str  # human-readable, e.g. "Payment Processing Integrity"
    description: str  # 2-3 sentence summary of the theme
    severity: str = ""  # overall theme severity (highest among findings)
    finding_count: int = 0
    finding_ids: list[str] = Field(default_factory=list)


class ScanTokenUsage(BaseModel):
    """Token usage and estimated cost for a scan."""

    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    llm_calls: int = 0
    estimated_cost_usd: float = 0.0
    model: str = ""


class DeepScanReport(BaseModel):
    """Complete report from a deep security scan.

    Contains both an owner-friendly summary and detailed technical
    findings.  The ``findings`` field is kept for backward compatibility.
    """

    target_url: str | None = None
    repo_url: str | None = None
    repo_branch: str = ""
    repo_commit_hash: str = ""
    framework: str = ""
    backend: str = ""
    scan_mode: str = ""

    # Discovery
    total_endpoints_discovered: int = 0
    endpoints_with_ids: int = 0
    endpoints_tested: int = 0
    routes_in_code: int = 0
    tables_discovered: int = 0

    # Owner summary (non-technical)
    owner_summary: OwnerSummary | None = None

    # All findings unified (technical)
    findings: list[DeepFinding] = Field(default_factory=list)

    # Legacy (keep for backward compat with existing IDOR scan)
    discovered_endpoints: list[DiscoveredEndpoint] = Field(default_factory=list)
    idor_results: list[IDORTestResult] = Field(default_factory=list)

    scan_duration_seconds: float = 0.0
    scanners_run: list[str] = Field(default_factory=list)

    # Thematic grouping of findings
    themes: list[SecurityTheme] = Field(default_factory=list)

    # Token usage tracking
    token_usage: ScanTokenUsage | None = None

    @property
    def critical_count(self) -> int:
        """Count findings with CRITICAL severity."""
        return sum(1 for f in self.findings if f.severity == SeverityLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count findings with HIGH severity."""
        return sum(1 for f in self.findings if f.severity == SeverityLevel.HIGH)

    @property
    def medium_count(self) -> int:
        """Count findings with MEDIUM severity."""
        return sum(1 for f in self.findings if f.severity == SeverityLevel.MEDIUM)

    @property
    def dast_findings(self) -> list["DeepFinding"]:
        """Filter to DAST-only findings."""
        return [
            f for f in self.findings
            if f.source in (FindingSource.DAST_URL, FindingSource.DAST_AUTHENTICATED)
        ]

    @property
    def sast_findings(self) -> list["DeepFinding"]:
        """Filter to SAST-only findings."""
        return [
            f for f in self.findings
            if f.source in (FindingSource.SAST_CODE, FindingSource.SAST_GIT_HISTORY)
        ]

    @property
    def cross_referenced_findings(self) -> list["DeepFinding"]:
        """Filter to cross-referenced findings."""
        return [
            f for f in self.findings
            if f.source == FindingSource.CROSS_REFERENCED
        ]

    # Legacy IDOR convenience properties (backward compat)
    @property
    def confirmed_idor_count(self) -> int:
        """Count confirmed IDOR results (legacy)."""
        return sum(
            1 for r in self.idor_results
            if r.risk_level == IDORRiskLevel.CONFIRMED
        )

    @property
    def likely_idor_count(self) -> int:
        """Count likely IDOR results (legacy)."""
        return sum(
            1 for r in self.idor_results
            if r.risk_level == IDORRiskLevel.LIKELY
        )

    @property
    def possible_idor_count(self) -> int:
        """Count possible IDOR results (legacy)."""
        return sum(
            1 for r in self.idor_results
            if r.risk_level == IDORRiskLevel.POSSIBLE
        )
