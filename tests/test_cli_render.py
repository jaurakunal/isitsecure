"""Tests for the CLI's report renderers.

These had no coverage at all until the `cli` package split moved them into
`render.py` — five pure-ish functions that turn a scan report into the thing a
user or another tool actually consumes. A regression in any of them (a broken
SARIF document, an unrenderable table) would have reached users with nothing
to catch it, so they get pinned here.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import pytest

from isitsecure.cli.render import (
    _generate_badge_svg,
    _generate_fixes,
    _generate_html_report,
    _generate_sarif_report,
    _print_report_table,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import (
    CodeLocation,
    DeepFinding,
    DeepScanReport,
    FindingSource,
)


def _finding(
    severity: SeverityLevel = SeverityLevel.HIGH,
    category: FindingCategory = FindingCategory.INJECTION_RISK,
    title: str = "SQL injection in user lookup",
    *,
    file: str | None = "src/db.ts",
) -> DeepFinding:
    return DeepFinding(
        source=FindingSource.SAST_CODE,
        category=category,
        severity=severity,
        title=title,
        description="User input reaches a SQL query unsanitised.",
        confidence=0.9,
        scanner_name="semgrep_taint",
        code_location=(
            CodeLocation(file_path=file, line_number=42) if file else None
        ),
    )


def _report(findings: list[DeepFinding] | None = None) -> DeepScanReport:
    return DeepScanReport(
        target_url="https://example.com",
        scan_mode="code-only",
        findings=findings if findings is not None else [],
        scanners_run=["semgrep_taint"],
        scan_duration_seconds=12.0,
        total_endpoints_discovered=3,
    )


# ---------------------------------------------------------------------------
# _generate_badge_svg
# ---------------------------------------------------------------------------


class TestBadgeSVG:
    def test_is_well_formed_xml(self) -> None:
        root = ET.fromstring(_generate_badge_svg("A", 0, 0, 0))
        assert root.tag.endswith("svg")

    @pytest.mark.parametrize(
        "grade, colour",
        [("A", "#4c1"), ("B", "#97ca00"), ("C", "#dfb317"),
         ("D", "#fe7d37"), ("F", "#e05d44")],
    )
    def test_colour_per_grade(self, grade: str, colour: str) -> None:
        assert colour in _generate_badge_svg(grade, 0, 0, 0)

    @pytest.mark.parametrize("grade", ["A+", "A-", "C+", "B-"])
    def test_granular_grades_colour_by_their_base_letter(self, grade: str) -> None:
        """Grades are A+/A-/C+/… — the colour comes from the first character."""
        expected = _generate_badge_svg(grade[0], 0, 0, 0)
        rendered = _generate_badge_svg(grade, 0, 0, 0)
        colour = {"A": "#4c1", "B": "#97ca00", "C": "#dfb317"}[grade[0]]
        assert colour in rendered and colour in expected

    def test_unknown_grade_falls_back_to_grey(self) -> None:
        assert "#9f9f9f" in _generate_badge_svg("?", 0, 0, 0)

    def test_finding_count_shown_only_when_there_are_findings(self) -> None:
        assert "(7 findings)" in _generate_badge_svg("C", 1, 2, 7)
        assert "findings" not in _generate_badge_svg("A", 0, 0, 0)

    def test_width_grows_with_the_label(self) -> None:
        """A fixed width would clip the longer text."""
        narrow = ET.fromstring(_generate_badge_svg("A", 0, 0, 0))
        wide = ET.fromstring(_generate_badge_svg("F", 9, 9, 1234))
        assert float(wide.get("width")) > float(narrow.get("width"))

    def test_grade_is_readable_by_assistive_tech(self) -> None:
        svg = _generate_badge_svg("D", 1, 1, 4)
        assert 'aria-label="security: D (4 findings)"' in svg


# ---------------------------------------------------------------------------
# _generate_sarif_report
# ---------------------------------------------------------------------------


class TestSARIF:
    def test_is_valid_sarif_2_1_0(self) -> None:
        doc = json.loads(_generate_sarif_report(_report([_finding()])))
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"]) == 1

    def test_every_finding_becomes_a_result(self) -> None:
        report = _report([_finding(), _finding(title="XSS in search")])
        doc = json.loads(_generate_sarif_report(report))
        assert len(doc["runs"][0]["results"]) == 2

    def test_clean_report_is_still_a_valid_document(self) -> None:
        """GitHub code-scanning rejects a malformed upload; zero findings is
        the case most likely to be uploaded unattended from CI."""
        doc = json.loads(_generate_sarif_report(_report()))
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# _generate_html_report
# ---------------------------------------------------------------------------


class TestHTML:
    def test_is_a_self_contained_document(self) -> None:
        html = _generate_html_report(_report([_finding()]))
        assert html.lstrip().startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_findings_reach_the_page(self) -> None:
        html = _generate_html_report(
            _report([_finding(title="SQL injection in user lookup")])
        )
        assert "SQL injection in user lookup" in html

    def test_clean_report_renders(self) -> None:
        assert "<!DOCTYPE html>" in _generate_html_report(_report())


# ---------------------------------------------------------------------------
# _print_report_table
# ---------------------------------------------------------------------------


class TestReportTable:
    def test_leads_with_the_launch_verdict_and_grade(self, capsys) -> None:
        _print_report_table(_report([_finding(SeverityLevel.CRITICAL)]))
        out = capsys.readouterr().out
        assert "Launch Readiness" in out
        assert "Grade:" in out

    def test_findings_are_listed(self, capsys) -> None:
        _print_report_table(_report([_finding(title="SQL injection in user lookup")]))
        out = capsys.readouterr().out
        assert "Findings" in out

    def test_clean_report_says_so_instead_of_an_empty_table(self, capsys) -> None:
        _print_report_table(_report())
        out = capsys.readouterr().out
        assert "No vulnerabilities found" in out

    def test_a_finding_without_a_code_location_still_renders(self, capsys) -> None:
        """DAST findings carry no file path; the table must not assume one."""
        _print_report_table(_report([_finding(file=None)]))
        assert "Findings" in capsys.readouterr().out

    @pytest.mark.parametrize(
        "severity",
        [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM,
         SeverityLevel.LOW, SeverityLevel.INFO],
    )
    def test_every_severity_renders(self, severity, capsys) -> None:
        _print_report_table(_report([_finding(severity)]))
        assert "Findings" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# _generate_fixes
# ---------------------------------------------------------------------------


class TestGenerateFixes:
    @pytest.mark.asyncio
    async def test_no_fixable_findings_needs_no_llm(self) -> None:
        """Only SAST findings with a file path and critical/high severity are
        fixable — anything else must short-circuit before an API call."""
        plan = await _generate_fixes(_report(), llm_client=None, repo_url=None)
        assert "No critical or high findings" in plan

    @pytest.mark.asyncio
    async def test_low_severity_alone_is_not_fixable(self) -> None:
        plan = await _generate_fixes(
            _report([_finding(SeverityLevel.LOW)]), llm_client=None, repo_url=None
        )
        assert "No critical or high findings" in plan

    @pytest.mark.asyncio
    async def test_finding_without_a_file_is_not_fixable(self) -> None:
        plan = await _generate_fixes(
            _report([_finding(SeverityLevel.CRITICAL, file=None)]),
            llm_client=None,
            repo_url=None,
        )
        assert "No critical or high findings" in plan
