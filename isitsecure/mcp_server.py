"""Local stdio MCP server exposing isitsecure's ``scan`` tool (#58).

Hosted nowhere: the user's AI coding tool (Cursor, Claude Code, Claude Desktop)
spawns ``isitsecure mcp`` as a subprocess and speaks MCP over stdio. This is the
day-one thin slice — a single ``scan`` tool that runs a fast **code-only (SAST)**
scan on a local repo and returns trimmed, agent-friendly findings enriched with
the plain-English layer (what it is / what an attacker could do / how to fix).

The heavy ``mcp`` SDK is an optional dependency; import failures surface as a
clear "install isitsecure[mcp]" message rather than a traceback.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

# Pydantic (used by FastMCP to build the tool's output schema) requires
# typing_extensions.TypedDict, not typing.TypedDict, on Python < 3.12.
from typing_extensions import TypedDict

logger = logging.getLogger(__name__)


class McpFinding(TypedDict):
    """One trimmed, agent-facing finding (part of the tool's output schema)."""

    id: str
    severity: str
    category: str
    title: str
    file: str | None
    line: int | None
    priority: int | None
    what_it_is: str
    attacker_could: str
    fix: str


class GradeStepDict(TypedDict):
    """One rung on the climb to a better grade."""

    grade: str
    requires: str
    clear_at_least: int


class ThemeSummary(TypedDict):
    """A root-cause grouping of related findings."""

    theme_id: str
    title: str
    severity: str
    finding_count: int


class ScanResult(TypedDict):
    """The `scan` tool's structured result — drives the MCP output schema."""

    scan_id: str
    grade: str
    grade_label: str
    safe_to_launch: bool
    verdict: str
    counts: dict[str, int]
    total_findings: int
    returned_findings: int
    min_severity: str
    path_to_next_grade: list[GradeStepDict]
    themes: list[ThemeSummary]
    findings: list[McpFinding]


class FindingDetail(TypedDict):
    """Deep dive on one finding — the `explain` tool's output schema.

    Leads with the finding's OWN generated text (description / technical detail /
    evidence / the vulnerable snippet) so it's specific to this finding, not the
    category-level blurb the `scan` list carries.
    """

    id: str
    severity: str
    category: str
    title: str
    file: str | None
    line: int | None
    code_snippet: str | None
    description: str
    technical_detail: str
    evidence: str
    what_it_is: str
    attacker_could: str
    business_impact: str
    remediation: str
    stack_remediation: str
    walkthrough: list[str]


class FixProposal(TypedDict):
    """A proposed fix for one finding — the `fix` tool's output schema.

    The MCP does NOT write files: it returns the change for the host LLM to
    apply with its own editor (see docs/mcp.md "Who applies the fix"). Carries a
    unified diff AND the full fixed file so the agent can apply either way.
    """

    finding_id: str
    file: str
    title: str
    category: str
    severity: str
    diff: str
    fixed_file: str
    explanation: str
    applied: bool
    next_step: str


MCP_MISSING_MSG = (
    "The MCP server needs the optional 'mcp' dependency.\n"
    "Install it with:  pip install 'isitsecure[mcp]'   (or 'isitsecure[all]')."
)

# Surfaced to the host LLM in the MCP initialize response so it knows *when* to
# reach for these tools on its own — users say "run a security audit", not
# "call the isitsecure scan tool".
_SERVER_INSTRUCTIONS = (
    "isitsecure runs a security review of the user's own code. Reach for the "
    "`scan` tool whenever the user wants to check their code for security "
    "problems — e.g. \"run a security audit\", \"scan for vulnerabilities\", "
    "\"is this safe to ship/launch\", \"review my code for security issues\", "
    "\"any security bugs?\", or before a release — even when they don't name "
    "isitsecure. It runs a local static analysis (SAST) on a repository path and "
    "returns a letter grade, a launch verdict, findings with plain-English "
    "explanations, and what it takes to reach a better grade. Prefer it over "
    "reading the code yourself for security posture. Do NOT use it for general "
    "code review, style, or non-security bugs. After a scan, use `explain` with "
    "the scan_id and a finding's id to dig into a specific finding (\"explain the "
    "SQL injection one\", \"why does this matter\"). Use `fix` with the scan_id "
    "and a finding's id to get a proposed patch (\"fix the SQL injection\", \"patch "
    "finding X\") — it returns a diff for YOU to apply with your editor; the MCP "
    "does not write files."
)

# Severity ranking for the min-severity filter and result ordering.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

@dataclass(frozen=True)
class _CachedScan:
    """A cached scan: the full report plus the local path that was scanned.

    The path lets `fix`/`verify` read the actual source files a finding refers to
    (findings carry a repo-relative path, not file contents).
    """

    report: Any
    repo_path: str | None


# In-process cache of scans, keyed by scan_id, so later tools (explain/fix/
# verify) can resolve a finding — and its source file — from a *prior* scan
# within the same session. The `scan` tool returns only trimmed findings, but
# these keep the full report. Bounded to the most recent scans to cap memory.
_SCAN_CACHE: "OrderedDict[str, _CachedScan]" = OrderedDict()
_SCAN_CACHE_MAX = 20


def _cache_report(report, repo_path: str | None = None) -> str:
    """Store a scan under a fresh scan_id; evict oldest past the cap.

    Synchronous with no ``await`` inside, so insert+evict is atomic w.r.t. other
    coroutines on the event loop — keep it that way (an ``async`` refactor would
    reintroduce an interleaving race on the shared cache).
    """
    scan_id = uuid4().hex[:12]
    _SCAN_CACHE[scan_id] = _CachedScan(report=report, repo_path=repo_path)
    while len(_SCAN_CACHE) > _SCAN_CACHE_MAX:
        _SCAN_CACHE.popitem(last=False)
    return scan_id


def get_cached_report(scan_id: str):
    """Return the full DeepScanReport for a scan_id, or None if unknown/evicted."""
    entry = _SCAN_CACHE.get(scan_id)
    return entry.report if entry else None


def get_scan_path(scan_id: str) -> str | None:
    """Return the local path that was scanned for a scan_id, or None."""
    entry = _SCAN_CACHE.get(scan_id)
    return entry.repo_path if entry else None


def get_finding(scan_id: str, finding_id: str):
    """Resolve a single finding from a prior scan (for explain/fix/verify).

    Returns None if the scan_id is unknown/evicted or the finding_id isn't in it.
    """
    entry = _SCAN_CACHE.get(scan_id)
    if entry is None:
        return None
    return next((f for f in entry.report.findings if f.id == finding_id), None)


def _require_fastmcp():
    """Return the FastMCP class, or raise a friendly error if uninstalled."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - exercised via CLI message
        raise RuntimeError(MCP_MISSING_MSG) from exc
    return FastMCP


def _maybe_llm_client():
    """Build an LLM client if a key is configured, else None.

    Code-only SAST runs entirely on rule-based scanners, so the MCP scan works
    with no API key; a configured key just adds the LLM review pass.
    """
    try:
        from isitsecure.config import load_api_key

        api_key = load_api_key("anthropic")
        if not api_key:
            return None
        from isitsecure.llm.adapters import create_llm_client

        return create_llm_client("anthropic", api_key)
    except Exception as exc:
        # Best-effort: fall back to rule-based SAST, but leave a breadcrumb on
        # stderr so a real misconfig (bad key, import break) is diagnosable.
        logger.debug("LLM client unavailable, running rule-based only: %s", exc)
        return None


async def _run_scan_silent(path: Path, scan_mode) -> Any:
    """Run a scan to completion, discarding progress events, returning report."""
    from isitsecure.engine.factory import (
        create_deep_security_scan_agent,
        create_repo_ingestion_service,
    )
    from isitsecure.engine.models import DeepScanReport

    llm_client = _maybe_llm_client()
    agent = create_deep_security_scan_agent(
        llm_client=llm_client,
        judgment_llm_client=llm_client,
        repo_ingestion_service=create_repo_ingestion_service(),
    )

    report = None
    async for event in agent.scan(repo_url=str(path), scan_mode=scan_mode):
        data = getattr(event, "data", None) or {}
        if "report" in data:
            report = DeepScanReport.model_validate(data["report"])
    return report


def _trim_report(report, min_severity: str, scan_id: str) -> ScanResult:
    """Collapse a full DeepScanReport into a compact, agent-friendly payload."""
    from isitsecure.engine.reporting.plain_english import (
        calculate_grade,
        explain_finding,
        grade_path,
        launch_verdict,
    )

    threshold = _SEVERITY_RANK.get(min_severity.lower(), _SEVERITY_RANK["medium"])

    # Count every severity so the buckets reconcile with total_findings.
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in report.findings:
        sev = finding.severity.value.lower()
        if sev in counts:
            counts[sev] += 1

    findings_out: list[dict] = []
    for finding in report.findings:
        sev = finding.severity.value.lower()
        if _SEVERITY_RANK.get(sev, 0) < threshold:
            continue
        explanation = explain_finding(finding)
        loc = finding.code_location
        findings_out.append(
            {
                "id": finding.id,
                "severity": sev,
                "category": finding.category.value,
                "title": finding.title,
                "file": loc.file_path if loc else None,
                "line": loc.line_number if loc else None,
                "priority": finding.priority,
                "what_it_is": explanation.what_it_is,
                "attacker_could": explanation.attacker_could,
                "fix": explanation.what_to_do,
            }
        )

    findings_out.sort(key=lambda f: -_SEVERITY_RANK.get(f["severity"], 0))

    grade = calculate_grade(
        counts["critical"], counts["high"], counts["medium"], counts["low"]
    )
    verdict = launch_verdict(counts["critical"], counts["high"], counts["medium"])

    # What it takes to climb to each better grade — so an assistant can answer
    # "what gets me to a C?" without reading isitsecure's grader (#68).
    path = [
        {"grade": s.grade, "requires": s.requires, "clear_at_least": s.clear_at_least}
        for s in grade_path(
            counts["critical"], counts["high"], counts["medium"], counts["low"]
        )
    ]
    themes = [
        {
            "theme_id": t.theme_id,
            "title": t.title,
            "severity": t.severity,
            "finding_count": t.finding_count,
        }
        for t in (report.themes or [])
    ]

    return {
        "scan_id": scan_id,
        "grade": grade.grade,
        "grade_label": grade.label,
        "safe_to_launch": verdict.ready,
        "verdict": verdict.headline,
        "counts": counts,
        "total_findings": len(report.findings),
        "returned_findings": len(findings_out),
        "min_severity": min_severity,
        "path_to_next_grade": path,
        "themes": themes,
        "findings": findings_out,
    }


def _finding_detail(finding, report) -> FindingDetail:
    """Build the deep-dive payload for one finding (the `explain` tool core)."""
    from isitsecure.engine.reporting.plain_english import (
        business_impact,
        explain_finding,
        remediation_detail,
        walkthrough_for,
    )

    explanation = explain_finding(finding)
    loc = finding.code_location
    walkthrough = walkthrough_for(finding.category)

    # Stack-tailored category guidance (#47/#48), using the scan's detected stack.
    stack_remediation = remediation_detail(
        finding.category,
        framework=getattr(report, "framework", None) or None,
        backend=getattr(report, "backend", None) or None,
    )
    # Prefer this finding's OWN generated remediation when present; else the
    # stack-tailored category guidance.
    finding_specific = (finding.remediation_guidance or "").strip()

    return {
        "id": finding.id,
        "severity": finding.severity.value.lower(),
        "category": finding.category.value,
        "title": finding.title,
        "file": loc.file_path if loc else None,
        "line": loc.line_number if loc else None,
        "code_snippet": (loc.code_snippet if loc else None) or None,
        "description": finding.description or "",
        "technical_detail": finding.technical_detail or "",
        "evidence": finding.evidence or "",
        "what_it_is": explanation.what_it_is,
        "attacker_could": explanation.attacker_could,
        "business_impact": business_impact(finding.category),
        "remediation": finding_specific or stack_remediation,
        "stack_remediation": stack_remediation,
        "walkthrough": list(walkthrough.steps) if walkthrough else [],
    }


def _resolve_scan_and_finding(scan_id: str, finding_id: str):
    """Resolve (report, finding) from the cache, or raise a ToolError.

    Shared by explain/fix so the two distinct not-found errors (unknown scan vs
    unknown finding) stay identical and DRY.
    """
    from mcp.server.fastmcp.exceptions import ToolError

    report = get_cached_report(scan_id)
    if report is None:
        raise ToolError(
            f"Unknown scan_id '{scan_id}'. Run a scan first — its result "
            "includes the scan_id to pass here."
        )
    finding = next((f for f in report.findings if f.id == finding_id), None)
    if finding is None:
        raise ToolError(
            f"No finding '{finding_id}' in scan '{scan_id}'. Use a finding "
            "id from that scan's results."
        )
    return report, finding


def _read_finding_file(finding, repo_path: str | None) -> str:
    """Read the source file a finding points at, guarding against traversal.

    Raises ValueError with an actionable message when the path is unknown or the
    file can't be read.
    """
    loc = finding.code_location
    rel = loc.file_path if loc else ""
    if not rel:
        raise ValueError("This finding has no source file to fix.")
    if not repo_path:
        raise ValueError(
            "The scanned path is no longer known for this scan_id — re-run scan, "
            "then fix using the new scan_id."
        )
    root = Path(repo_path).resolve()
    target = (root / rel).resolve()
    if target != root and root not in target.parents:
        raise ValueError(f"Refusing to read a path outside the scanned repo: {rel}")
    if not target.is_file():
        raise ValueError(f"Source file not found: {rel}")
    # Size-guard before reading (shares FixGenerator's threshold so they can't
    # drift), and never let a raw OS error escape with the absolute path.
    from isitsecure.engine.fixes.fix_generator import FixGenerator

    if target.stat().st_size > FixGenerator.MAX_FILE_SIZE:
        raise ValueError(f"Source file too large to fix: {rel}")
    try:
        return target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"Could not read source file: {rel}") from exc


def _fix_proposal(finding, result) -> FixProposal:
    """Map a FixResult into the agent-facing FixProposal (the host applies it)."""
    return {
        "finding_id": finding.id,
        "file": result.file_path,
        "title": finding.title,
        "category": finding.category.value,
        "severity": finding.severity.value.lower(),
        "diff": result.diff,
        "fixed_file": result.fixed_code,
        "explanation": result.explanation,
        "applied": False,
        "next_step": (
            "Review the diff and apply it with your editor (the MCP does not "
            "write files). Then re-scan to confirm the finding is resolved."
        ),
    }


async def scan_repo(
    path: str, mode: str = "code-only", min_severity: str = "medium"
) -> dict:
    """Scan a local repo and return a trimmed, structured result.

    Async because FastMCP invokes tools inside its own running event loop —
    calling ``asyncio.run`` from there raises "event loop already running", so we
    ``await`` the scan directly instead. Returns ``{"error": ...}`` on bad input
    rather than raising, so the calling agent gets an actionable message.
    """
    from isitsecure.engine.enums import ScanMode

    resolved = Path(path).expanduser()
    if not resolved.exists() or not resolved.is_dir():
        return {"error": f"Path not found or not a directory: {path}"}

    mode_map = {
        "code-only": ScanMode.CODE_ONLY,
        "full": ScanMode.FULL,
        "url-only": ScanMode.URL_ONLY,
    }
    scan_mode = mode_map.get(mode, ScanMode.CODE_ONLY)

    report = await _run_scan_silent(resolved, scan_mode)
    if report is None:
        return {"error": "Scan completed but produced no report."}
    # Cache the full report + scanned path so explain/fix/verify can resolve
    # findings (and their source files) by (scan_id, finding_id) later (#69).
    scan_id = _cache_report(report, repo_path=str(resolved))
    return _trim_report(report, min_severity, scan_id)


def build_server():
    """Construct the FastMCP server exposing the ``scan`` tool."""
    FastMCP = _require_fastmcp()
    server = FastMCP("isitsecure", instructions=_SERVER_INSTRUCTIONS)

    @server.tool()
    async def scan(path: str, min_severity: str = "medium") -> ScanResult:
        """Security audit / vulnerability scan of a local code repository (SAST).

        Use this whenever the user asks to check, audit, scan, or review their
        code for security issues or vulnerabilities, or asks whether their app is
        safe to ship or launch — not only when they name isitsecure. Runs fast
        static analysis on the given path; no network or running app needed.

        Args:
            path: Path to the local repo/directory to scan.
            min_severity: Only return findings at or above this severity
                (critical | high | medium | low). Default: medium.

        Returns a security grade, a go/no-go launch verdict, severity counts,
        the steps to reach a better grade (`path_to_next_grade`), root-cause
        themes, and a list of findings — each with a plain-English explanation of
        what it is, what an attacker could do, and how to fix it. Raises a tool
        error if the path does not exist or is not a directory.
        """
        from mcp.server.fastmcp.exceptions import ToolError

        result = await scan_repo(path, mode="code-only", min_severity=min_severity)
        if "error" in result:
            raise ToolError(result["error"])
        return result  # type: ignore[return-value]  # shape matches ScanResult

    @server.tool()
    async def explain(scan_id: str, finding_id: str) -> FindingDetail:
        """Deep dive on one finding from a prior scan.

        Use after a scan when the user wants to understand a specific finding —
        "explain the SQL injection one", "tell me more about that", "why does
        this matter", "how do I fix finding X". Pass the `scan_id` from the scan
        result and the finding's `id`. Returns the finding's own description,
        technical detail, evidence, and vulnerable code, plus business impact and
        step-by-step remediation (stack-tailored when the framework is known).
        """
        report, finding = _resolve_scan_and_finding(scan_id, finding_id)
        return _finding_detail(finding, report)

    @server.tool()
    async def fix(scan_id: str, finding_id: str) -> FixProposal:
        """Propose a fix for one finding — returns a diff for YOU (the host) to apply.

        Use after a scan when the user wants to fix a specific finding ("fix the
        SQL injection", "fix finding X", "patch this"). Pass the `scan_id` and the
        finding's `id`. Returns a unified diff, the full fixed file, and an
        explanation. The MCP does NOT write files — apply the change with your own
        editor, then re-scan to confirm the finding is resolved.
        """
        from mcp.server.fastmcp.exceptions import ToolError

        _, finding = _resolve_scan_and_finding(scan_id, finding_id)

        llm_client = _maybe_llm_client()
        if llm_client is None:
            raise ToolError(
                "Generating a fix needs an LLM API key. Set ANTHROPIC_API_KEY or "
                "run `isitsecure setup`."
            )
        try:
            file_content = _read_finding_file(finding, get_scan_path(scan_id))
        except ValueError as exc:
            raise ToolError(str(exc))

        from isitsecure.engine.fixes.fix_generator import FixGenerator

        result = await FixGenerator(llm_client).generate_fix(finding, file_content)
        if not result.success:
            raise ToolError(
                f"Couldn't generate a fix: {result.error or 'unknown error'}"
            )
        return _fix_proposal(finding, result)

    return server


def run_stdio() -> None:
    """Entry point for ``isitsecure mcp`` — serve over stdio until the client exits."""
    build_server().run(transport="stdio")
