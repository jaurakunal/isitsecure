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
from collections import OrderedDict

import pytest

from isitsecure.engine.models import (
    CodeLocation,
    DeepFinding,
    DeepScanReport,
    FindingSource,
    SecurityTheme,
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


def test_tools_registered_with_schema():
    server = mcp_server.build_server()
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    assert set(tools) == {"scan", "explain", "fix"}
    assert set(tools["scan"].inputSchema.get("properties", {})) >= {"path", "min_severity"}
    assert set(tools["explain"].inputSchema.get("properties", {})) == {"scan_id", "finding_id"}
    assert set(tools["fix"].inputSchema.get("properties", {})) == {"scan_id", "finding_id"}


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
    out = mcp_server._trim_report(report, "medium", "sid")

    # Top-level summary fields
    assert out["scan_id"] == "sid"
    assert out["grade"]  # F for a critical
    assert out["safe_to_launch"] is False
    assert out["counts"]["critical"] == 1
    assert out["total_findings"] == 1
    assert out["returned_findings"] == 1

    # Each finding carries the trimmed + plain-English fields, no raw bloat.
    f = out["findings"][0]
    assert set(f) == {
        "id", "severity", "category", "title", "file", "line",
        "priority", "what_it_is", "attacker_could", "fix",
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
    out = mcp_server._trim_report(report, "high", "sid")
    # counts reflect ALL findings; returned list only those >= high
    assert out["counts"]["critical"] == 1 and out["counts"]["low"] == 1
    assert out["returned_findings"] == 1
    assert out["findings"][0]["title"] == "crit"


def test_info_severity_counted_and_totals_reconcile():
    report = _report([
        _finding(SeverityLevel.CRITICAL, FindingCategory.INJECTION_RISK, "crit"),
        _finding(SeverityLevel.INFO, FindingCategory.INFO_DISCLOSURE, "informational"),
    ])
    out = mcp_server._trim_report(report, "low", "sid")
    # info is bucketed (not lost) and counts reconcile with total_findings
    assert out["counts"]["info"] == 1
    assert sum(out["counts"].values()) == out["total_findings"] == 2
    # info sits below the 'low' threshold, so it's not returned
    assert out["returned_findings"] == 1


def test_min_severity_boundary_is_inclusive():
    report = _report([
        _finding(SeverityLevel.MEDIUM, FindingCategory.INFO_DISCLOSURE, "med"),
    ])
    out = mcp_server._trim_report(report, "medium", "sid")  # exactly at threshold
    assert out["returned_findings"] == 1


def test_findings_ordered_by_severity():
    report = _report([
        _finding(SeverityLevel.MEDIUM, FindingCategory.INFO_DISCLOSURE, "med"),
        _finding(SeverityLevel.CRITICAL, FindingCategory.INJECTION_RISK, "crit"),
        _finding(SeverityLevel.HIGH, FindingCategory.IDOR, "high"),
    ])
    out = mcp_server._trim_report(report, "low", "sid")
    assert [f["severity"] for f in out["findings"]] == ["critical", "high", "medium"]


def test_path_to_next_grade_in_output():
    # 1 critical → grade F; the first step up is D by clearing that critical.
    report = _report([
        _finding(SeverityLevel.CRITICAL, FindingCategory.INJECTION_RISK, "crit"),
    ])
    out = mcp_server._trim_report(report, "low", "sid")
    path = out["path_to_next_grade"]
    assert path[0]["grade"] == "D"
    assert path[0]["clear_at_least"] == 1
    assert path[-1]["grade"] == "A"          # ladder tops out at A
    assert "critical" in path[0]["requires"]


def test_themes_surfaced_in_output():
    report = DeepScanReport(
        findings=[_finding(SeverityLevel.HIGH, FindingCategory.IDOR, "x")],
        themes=[SecurityTheme(
            theme_id="payment-integrity", title="Payment Processing Integrity",
            description="…", severity="critical", finding_count=3,
            finding_ids=["a", "b", "c"],
        )],
    )
    out = mcp_server._trim_report(report, "low", "sid")
    assert out["themes"][0]["theme_id"] == "payment-integrity"
    assert out["themes"][0]["finding_count"] == 3


@pytest.fixture
def isolated_cache(monkeypatch):
    """Run against a fresh scan cache so these tests can't leak the module global."""
    monkeypatch.setattr(mcp_server, "_SCAN_CACHE", OrderedDict())


def test_scan_cache_roundtrip_and_finding_identity(isolated_cache):
    report = _report([_finding(SeverityLevel.HIGH, FindingCategory.IDOR, "x")])
    fid = report.findings[0].id
    sid = mcp_server._cache_report(report)
    assert mcp_server.get_cached_report(sid) is report
    assert mcp_server.get_finding(sid, fid).id == fid          # resolves
    assert mcp_server.get_finding(sid, "no-such-finding") is None
    assert mcp_server.get_finding("no-such-scan", fid) is None


def test_scan_cache_evicts_oldest_past_cap(isolated_cache):
    ids = [
        mcp_server._cache_report(_report([]))
        for _ in range(mcp_server._SCAN_CACHE_MAX + 3)
    ]
    assert mcp_server.get_cached_report(ids[0]) is None        # oldest evicted
    assert mcp_server.get_cached_report(ids[-1]) is not None   # newest kept
    assert len(mcp_server._SCAN_CACHE) == mcp_server._SCAN_CACHE_MAX


def test_finding_detail_surfaces_finding_specific_text(isolated_cache):
    f = DeepFinding(
        source=FindingSource.SAST_CODE,
        category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.CRITICAL,
        title="SQL injection in getById",
        description="Concatenates req.params.id into a raw SQL string.",
        technical_detail="Line 67 builds `SELECT * FROM t WHERE id=${id}`.",
        evidence="const q = `SELECT ... ${id}`",
        confidence=0.9,
        scanner_name="llm_code_reviewer",
        remediation_guidance="Use a parameterized query: db.query('... WHERE id=$1', [id]).",
        code_location=CodeLocation(
            file_path="src/lib/db.ts", line_number=67, code_snippet="const q = `... ${id}`",
        ),
    )
    report = DeepScanReport(findings=[f], framework="nextjs")
    detail = mcp_server._finding_detail(f, report)

    # The finding's OWN generated text is surfaced (not the category blurb)
    assert detail["description"].startswith("Concatenates")
    assert detail["technical_detail"] and detail["evidence"]
    assert detail["code_snippet"]
    # remediation prefers the finding-specific guidance
    assert "parameterized" in detail["remediation"].lower()
    # full deep-dive schema present
    assert set(detail) >= {
        "id", "severity", "category", "title", "file", "line", "code_snippet",
        "description", "technical_detail", "evidence", "what_it_is",
        "attacker_could", "business_impact", "remediation", "stack_remediation",
        "walkthrough",
    }


async def test_explain_tool_resolves_cached_finding(isolated_cache):
    f = _finding(SeverityLevel.HIGH, FindingCategory.IDOR, "IDOR on tasks")
    sid = mcp_server._cache_report(_report([f]))
    server = mcp_server.build_server()
    result = await server.call_tool("explain", {"scan_id": sid, "finding_id": f.id})
    assert "idor" in str(result).lower()          # resolved and returned the finding


async def test_explain_tool_raises_on_unknown_scan(isolated_cache):
    server = mcp_server.build_server()
    with pytest.raises(Exception) as exc:
        await server.call_tool("explain", {"scan_id": "nope", "finding_id": "x"})
    assert "scan_id" in str(exc.value).lower()


async def test_explain_tool_raises_on_unknown_finding(isolated_cache):
    sid = mcp_server._cache_report(_report([
        _finding(SeverityLevel.HIGH, FindingCategory.IDOR, "x"),
    ]))
    server = mcp_server.build_server()
    with pytest.raises(Exception) as exc:
        await server.call_tool("explain", {"scan_id": sid, "finding_id": "no-such"})
    assert "no finding" in str(exc.value).lower()


def test_fix_proposal_maps_result_and_never_marks_applied():
    from isitsecure.engine.fixes.fix_generator import FixResult

    f = _finding(SeverityLevel.CRITICAL, FindingCategory.INJECTION_RISK, "SQLi", file="db.ts")
    result = FixResult(
        finding_id=f.id, file_path="db.ts", success=True,
        original_code="raw", fixed_code="parameterized",
        diff="--- a/db.ts\n+++ b/db.ts\n", explanation="Parameterized the query.",
    )
    p = mcp_server._fix_proposal(f, result)
    assert p["applied"] is False                       # MCP never writes
    assert p["diff"].startswith("--- a/db.ts")
    assert p["fixed_file"] == "parameterized"
    assert "Parameterized" in p["explanation"]
    assert set(p) == {
        "finding_id", "file", "title", "category", "severity",
        "diff", "fixed_file", "explanation", "applied", "next_step",
    }


def _f_file(name):  # a finding pointing at a given relative file
    return _finding(SeverityLevel.HIGH, FindingCategory.INJECTION_RISK, "x", file=name)


def test_read_finding_file_reads_and_guards(tmp_path):
    (tmp_path / "app.js").write_text("const x = 1;\n")
    (tmp_path / "src" / "lib").mkdir(parents=True)
    (tmp_path / "src" / "lib" / "db.ts").write_text("const q = 1;\n")

    # legit top-level and nested paths read fine
    assert "const x" in mcp_server._read_finding_file(_f_file("app.js"), str(tmp_path))
    assert "const q" in mcp_server._read_finding_file(_f_file("src/lib/db.ts"), str(tmp_path))

    # escapes are refused: parent traversal AND absolute paths
    with pytest.raises(ValueError):
        mcp_server._read_finding_file(_f_file("../secret"), str(tmp_path))
    with pytest.raises(ValueError):
        mcp_server._read_finding_file(_f_file("/etc/passwd"), str(tmp_path))

    # missing file / unknown scanned path
    with pytest.raises(ValueError):
        mcp_server._read_finding_file(_f_file("nope.js"), str(tmp_path))
    with pytest.raises(ValueError):
        mcp_server._read_finding_file(_f_file("app.js"), None)


def test_read_finding_file_rejects_too_large(tmp_path):
    from isitsecure.engine.fixes.fix_generator import FixGenerator
    (tmp_path / "big.js").write_text("x" * (FixGenerator.MAX_FILE_SIZE + 1))
    with pytest.raises(ValueError):
        mcp_server._read_finding_file(_f_file("big.js"), str(tmp_path))


async def test_fix_tool_returns_proposal(isolated_cache, tmp_path, monkeypatch):
    from isitsecure.engine.fixes import fix_generator as fg

    (tmp_path / "db.ts").write_text("const q = `SELECT ... ${id}`;\n")
    f = _finding(SeverityLevel.CRITICAL, FindingCategory.INJECTION_RISK, "SQLi in getById", file="db.ts")
    sid = mcp_server._cache_report(_report([f]), repo_path=str(tmp_path))

    async def fake_generate_fix(self, finding, content):
        return fg.FixResult(
            finding_id=finding.id, file_path="db.ts", success=True,
            fixed_code="const q = db.query('... WHERE id=$1', [id]);",
            diff="--- a/db.ts\n+++ b/db.ts\n", explanation="Parameterized the query.",
        )

    monkeypatch.setattr(fg.FixGenerator, "generate_fix", fake_generate_fix)
    monkeypatch.setattr(mcp_server, "_maybe_llm_client", lambda: object())

    server = mcp_server.build_server()
    res = await server.call_tool("fix", {"scan_id": sid, "finding_id": f.id})
    assert "parameterized" in str(res).lower()


async def test_fix_tool_needs_llm_key(isolated_cache, tmp_path, monkeypatch):
    (tmp_path / "db.ts").write_text("x")
    f = _finding(SeverityLevel.CRITICAL, FindingCategory.INJECTION_RISK, "x", file="db.ts")
    sid = mcp_server._cache_report(_report([f]), repo_path=str(tmp_path))
    monkeypatch.setattr(mcp_server, "_maybe_llm_client", lambda: None)
    server = mcp_server.build_server()
    with pytest.raises(Exception) as exc:
        await server.call_tool("fix", {"scan_id": sid, "finding_id": f.id})
    assert "api key" in str(exc.value).lower() or "llm" in str(exc.value).lower()


async def test_fix_tool_unknown_scan_raises(isolated_cache):
    server = mcp_server.build_server()
    with pytest.raises(Exception) as exc:
        await server.call_tool("fix", {"scan_id": "nope", "finding_id": "x"})
    assert "scan_id" in str(exc.value).lower()


async def test_fix_tool_unknown_finding_raises(isolated_cache):
    sid = mcp_server._cache_report(
        _report([_finding(SeverityLevel.HIGH, FindingCategory.IDOR, "x")])
    )
    server = mcp_server.build_server()
    with pytest.raises(Exception) as exc:
        await server.call_tool("fix", {"scan_id": sid, "finding_id": "no-such"})
    assert "no finding" in str(exc.value).lower()


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
