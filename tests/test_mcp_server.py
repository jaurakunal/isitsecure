"""Tests for the local MCP server thin slice (#58).

Covered without running a full scan (fast + deterministic):
- the `scan` tool is registered with the expected schema
- bad input returns a structured error instead of raising
- `_trim_report` produces the compact, agent-friendly payload, honours the
  min-severity filter, orders by severity, and carries plain-English fields
- a missing optional `mcp` dependency yields a friendly install message
"""

import asyncio
import builtins

import pytest

from isitsecure.engine.models import (
    CodeLocation,
    DeepFinding,
    DeepScanReport,
    FindingSource,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure import mcp_server


def _finding(severity, category, title, *, file="app/api/x.ts", line=10):
    return DeepFinding(
        source=FindingSource.SAST_CODE,
        category=category,
        severity=severity,
        title=title,
        description=f"{title} — details",
        confidence=0.9,
        scanner_name="test_scanner",
        code_location=CodeLocation(file_path=file, line_number=line),
    )


def _report(findings):
    return DeepScanReport(findings=findings)


def test_scan_tool_registered_with_schema():
    server = mcp_server.build_server()
    tools = asyncio.run(server.list_tools())
    assert [t.name for t in tools] == ["scan"]
    props = tools[0].inputSchema.get("properties", {})
    assert "path" in props and "min_severity" in props


async def test_bad_path_returns_error_dict_not_raise():
    result = await mcp_server.scan_repo("/definitely/not/a/real/dir")
    assert "error" in result
    assert "not a directory" in result["error"].lower()


async def test_scan_tool_runs_inside_running_event_loop():
    """Regression: FastMCP dispatches tools inside its own running event loop.

    A sync tool that called asyncio.run() blew up here with "event loop already
    running" — passing unit tests but failing the real MCP protocol. Invoke the
    tool via the server (bad path → fast, no real scan): it must raise a proper
    tool error about the path, NOT the asyncio loop error.
    """
    server = mcp_server.build_server()
    with pytest.raises(Exception) as exc:
        await server.call_tool(
            "scan", {"path": "/definitely/not/a/real/dir", "min_severity": "low"}
        )
    msg = str(exc.value).lower()
    assert "not a directory" in msg            # the tool actually ran
    assert "event loop" not in msg              # and did NOT hit the asyncio bug


async def test_scan_tool_declares_output_schema():
    """The tool advertises a typed output schema so clients get structuredContent."""
    server = mcp_server.build_server()
    tools = await server.list_tools()
    assert tools[0].outputSchema is not None


def test_trim_report_shape_and_plain_english():
    report = _report([
        _finding(SeverityLevel.CRITICAL, FindingCategory.INJECTION_RISK, "SQL injection via id"),
    ])
    out = mcp_server._trim_report(report, "medium")

    # Top-level summary fields
    assert out["grade"]  # F for a critical
    assert out["safe_to_launch"] is False
    assert out["counts"]["critical"] == 1
    assert out["total_findings"] == 1
    assert out["returned_findings"] == 1

    # Each finding carries the trimmed + plain-English fields, no raw bloat.
    f = out["findings"][0]
    assert set(f) == {
        "id", "severity", "category", "title",
        "file", "line", "what_it_is", "attacker_could", "fix",
    }
    assert f["severity"] == "critical"
    assert f["category"] == "injection_risk"
    assert f["file"] == "app/api/x.ts" and f["line"] == 10
    assert f["what_it_is"] and f["fix"]  # plain-English populated


def test_min_severity_filter_excludes_lower():
    report = _report([
        _finding(SeverityLevel.CRITICAL, FindingCategory.INJECTION_RISK, "crit"),
        _finding(SeverityLevel.LOW, FindingCategory.MISSING_HEADERS, "low"),
    ])
    out = mcp_server._trim_report(report, "high")
    # counts reflect ALL findings; returned list only those >= high
    assert out["counts"]["critical"] == 1 and out["counts"]["low"] == 1
    assert out["returned_findings"] == 1
    assert out["findings"][0]["title"] == "crit"


def test_info_severity_counted_and_totals_reconcile():
    report = _report([
        _finding(SeverityLevel.CRITICAL, FindingCategory.INJECTION_RISK, "crit"),
        _finding(SeverityLevel.INFO, FindingCategory.INFO_DISCLOSURE, "informational"),
    ])
    out = mcp_server._trim_report(report, "low")
    # info is bucketed (not lost) and counts reconcile with total_findings
    assert out["counts"]["info"] == 1
    assert sum(out["counts"].values()) == out["total_findings"] == 2
    # info sits below the 'low' threshold, so it's not returned
    assert out["returned_findings"] == 1


def test_min_severity_boundary_is_inclusive():
    report = _report([
        _finding(SeverityLevel.MEDIUM, FindingCategory.INFO_DISCLOSURE, "med"),
    ])
    out = mcp_server._trim_report(report, "medium")  # exactly at threshold
    assert out["returned_findings"] == 1


def test_findings_ordered_by_severity():
    report = _report([
        _finding(SeverityLevel.MEDIUM, FindingCategory.INFO_DISCLOSURE, "med"),
        _finding(SeverityLevel.CRITICAL, FindingCategory.INJECTION_RISK, "crit"),
        _finding(SeverityLevel.HIGH, FindingCategory.IDOR, "high"),
    ])
    out = mcp_server._trim_report(report, "low")
    assert [f["severity"] for f in out["findings"]] == ["critical", "high", "medium"]


def test_missing_mcp_dependency_gives_friendly_message(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("mcp.server") or name == "mcp":
            raise ImportError("No module named 'mcp'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(RuntimeError) as exc:
        mcp_server._require_fastmcp()
    assert "isitsecure[mcp]" in str(exc.value)
