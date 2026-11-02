"""F1 x F2 integration: MCP verify honesty, atomic write_source_file, CLI verify errors."""

from __future__ import annotations

import json
import os
import stat

from typer.testing import CliRunner

from isitsecure import mcp_server
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.fixes import fix_generator as FG
from isitsecure.engine.models import CodeLocation, DeepFinding, DeepScanReport, FindingSource


def _finding(scanner: str, title: str = "SQL injection") -> DeepFinding:
    return DeepFinding(
        source=FindingSource.SAST_CODE,
        title=title,
        severity=SeverityLevel.HIGH,
        category=FindingCategory.EXPOSED_SECRETS,
        description="d",
        confidence=0.9,
        scanner_name=scanner,
        code_location=CodeLocation(file_path="app/db.py", line_number=3),
    )


def test_mcp_verify_does_not_resolve_findings_of_a_failed_scanner() -> None:
    old = DeepScanReport(findings=[_finding("semgrep_taint"), _finding("secret_scanner", "Key")])
    # Re-scan produced no findings, but semgrep_taint did not actually run.
    new = DeepScanReport(findings=[], scanner_errors=["semgrep_taint: semgrep not installed"])
    r = mcp_server._verify_result(old, new, "sid")
    assert r["resolved"] == ["Key"]
    assert r["resolved_count"] == 1
    assert r["unverifiable_count"] == 1
    # the unconfirmed finding keeps counting against the grade
    assert r["counts"]["high"] == 1


def test_mcp_verify_unmapped_scanner_error_resolves_nothing() -> None:
    old = DeepScanReport(findings=[_finding("semgrep_taint")])
    new = DeepScanReport(findings=[], scanner_errors=["something odd happened"])
    r = mcp_server._verify_result(old, new, "sid")
    assert r["resolved_count"] == 0
    assert r["unverifiable_count"] == 1


def test_mcp_verify_resolves_when_scanners_ran() -> None:
    old = DeepScanReport(findings=[_finding("semgrep_taint")])
    r = mcp_server._verify_result(old, DeepScanReport(findings=[]), "sid")
    assert r["resolved_count"] == 1 and r["unverifiable_count"] == 0


def test_write_source_file_is_atomic_and_keeps_mode(tmp_path) -> None:
    f = tmp_path / "a.py"
    f.write_bytes(b"x = 1\r\n")
    os.chmod(f, 0o755)
    inode = f.stat().st_ino
    FG.write_source_file(str(tmp_path), "a.py", "x = 2\r\n")
    assert f.read_bytes() == b"x = 2\r\n"
    assert stat.S_IMODE(f.stat().st_mode) == 0o755
    assert f.stat().st_ino != inode  # replaced via rename, not truncated in place
    assert [p.name for p in tmp_path.iterdir()] == ["a.py"]  # no temp litter


def test_cli_verify_malformed_report_is_a_clear_error(tmp_path) -> None:
    from isitsecure.cli import app

    bad = tmp_path / "r.json"
    bad.write_text(json.dumps({"findings": [{"title": 1}]}))
    res = CliRunner().invoke(app, ["verify", "--report", str(bad)])
    assert res.exit_code == 2
    assert "not a valid scan report" in " ".join(res.output.split())
    assert "Traceback" not in res.output
