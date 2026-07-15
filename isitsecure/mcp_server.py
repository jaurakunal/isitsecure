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
from pathlib import Path
from typing import Any

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
    what_it_is: str
    attacker_could: str
    fix: str


class ScanResult(TypedDict):
    """The `scan` tool's structured result — drives the MCP output schema."""

    grade: str
    grade_label: str
    safe_to_launch: bool
    verdict: str
    counts: dict[str, int]
    total_findings: int
    returned_findings: int
    min_severity: str
    findings: list[McpFinding]


MCP_MISSING_MSG = (
    "The MCP server needs the optional 'mcp' dependency.\n"
    "Install it with:  pip install 'isitsecure[mcp]'   (or 'isitsecure[all]')."
)

# Severity ranking for the min-severity filter and result ordering.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


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


def _trim_report(report, min_severity: str) -> ScanResult:
    """Collapse a full DeepScanReport into a compact, agent-friendly payload."""
    from isitsecure.engine.reporting.plain_english import (
        calculate_grade,
        explain_finding,
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

    return {
        "grade": grade.grade,
        "grade_label": grade.label,
        "safe_to_launch": verdict.ready,
        "verdict": verdict.headline,
        "counts": counts,
        "total_findings": len(report.findings),
        "returned_findings": len(findings_out),
        "min_severity": min_severity,
        "findings": findings_out,
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
    return _trim_report(report, min_severity)


def build_server():
    """Construct the FastMCP server exposing the ``scan`` tool."""
    FastMCP = _require_fastmcp()
    server = FastMCP("isitsecure")

    @server.tool()
    async def scan(path: str, min_severity: str = "medium") -> ScanResult:
        """Run a fast code-only (SAST) security scan on a local repository.

        Args:
            path: Path to the local repo/directory to scan.
            min_severity: Only return findings at or above this severity
                (critical | high | medium | low). Default: medium.

        Returns a security grade, a go/no-go launch verdict, severity counts, and
        a list of findings — each with a plain-English explanation of what it is,
        what an attacker could do, and how to fix it. Raises a tool error if the
        path does not exist or is not a directory.
        """
        from mcp.server.fastmcp.exceptions import ToolError

        result = await scan_repo(path, mode="code-only", min_severity=min_severity)
        if "error" in result:
            raise ToolError(result["error"])
        return result  # type: ignore[return-value]  # shape matches ScanResult

    return server


def run_stdio() -> None:
    """Entry point for ``isitsecure mcp`` — serve over stdio until the client exits."""
    build_server().run(transport="stdio")
