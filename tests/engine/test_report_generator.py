"""Tests for the Deep Security Scan report generator and HTML renderer."""

import pytest

from isitsecure.engine.constants import ReportConfig
from isitsecure.engine.models import (
    CodeLocation,
    DeepFinding,
    DeepScanReport,
    FindingSource,
    OwnerSummary,
    RemediationPhase,
    SecurityTheme,
)
from isitsecure.engine.reporting.html_renderer import HTMLReportRenderer
from isitsecure.engine.reporting.report_generator import ReportGenerator
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    severity: SeverityLevel = SeverityLevel.MEDIUM,
    category: FindingCategory = FindingCategory.MISSING_HEADERS,
    source: FindingSource = FindingSource.DAST_URL,
    title: str = "Test Finding",
    scanner: str = "test_scanner",
    remediation_guidance: str = "",
    endpoint_url: str | None = None,
    code_location: CodeLocation | None = None,
) -> DeepFinding:
    """Create a DeepFinding with sensible defaults for testing."""
    return DeepFinding(
        source=source,
        category=category,
        severity=severity,
        title=title,
        description=f"Description for {title}",
        confidence=0.9,
        scanner_name=scanner,
        remediation_guidance=remediation_guidance,
        endpoint_url=endpoint_url,
        code_location=code_location,
    )


def _make_report(findings: list[DeepFinding] | None = None, **kwargs) -> DeepScanReport:
    """Create a DeepScanReport with sensible defaults for testing."""
    defaults = {
        "target_url": "https://example.com",
        "scan_mode": "full",
        "scanners_run": ["idor_scanner", "rls_scanner"],
        "total_endpoints_discovered": 15,
        "scan_duration_seconds": 42.5,
    }
    defaults.update(kwargs)
    if findings is not None:
        defaults["findings"] = findings
    return DeepScanReport(**defaults)


# ---------------------------------------------------------------------------
# ReportGenerator tests
# ---------------------------------------------------------------------------

class TestReportGenerator:
    """Tests for ReportGenerator."""

    def setup_method(self) -> None:
        self.generator = ReportGenerator()

    def test_grade_a_when_clean(self) -> None:
        """No findings -> grade A (A+ is reserved for hardened results)."""
        report = _make_report(findings=[])
        result = self.generator.generate(report)
        assert result["grade"] == "A"
        assert result["grade_base"] == "A"
        assert result["grade_legend"]  # legend present (#43)

    def test_grade_d_on_any_high(self) -> None:
        """Any high (no critical) -> grade D."""
        report = _make_report(findings=[
            _make_finding(severity=SeverityLevel.HIGH, title="High 1"),
            _make_finding(severity=SeverityLevel.HIGH, title="High 2"),
        ])
        result = self.generator.generate(report)
        assert result["grade"] == "D"

    def test_grade_c_on_three_medium(self) -> None:
        """3+ medium (no critical/high) -> grade C."""
        findings = [
            _make_finding(severity=SeverityLevel.MEDIUM, title=f"Med {i}")
            for i in range(3)
        ]
        report = _make_report(findings=findings)
        result = self.generator.generate(report)
        assert result["grade"] == "C"

    def test_grade_f_on_any_critical(self) -> None:
        """Any critical -> grade F, with the new plain-language label."""
        from isitsecure.engine.reporting import plain_english

        findings = [
            _make_finding(severity=SeverityLevel.CRITICAL, title=f"Crit {i}")
            for i in range(3)
        ] + [
            _make_finding(severity=SeverityLevel.HIGH, title=f"High {i}")
            for i in range(12)
        ]
        report = _make_report(findings=findings)
        result = self.generator.generate(report)
        assert result["grade"] == "F"
        assert result["grade_label"] == plain_english.GRADE_LADDER_LABELS["F"]

    def test_format_findings(self) -> None:
        """Findings should include all required fields."""
        code_loc = CodeLocation(
            file_path="src/api/route.ts",
            line_number=42,
            code_snippet="const secret = process.env.SECRET;",
        )
        finding = _make_finding(
            severity=SeverityLevel.HIGH,
            source=FindingSource.SAST_CODE,
            endpoint_url="https://example.com/api/users",
            code_location=code_loc,
        )
        report = _make_report(findings=[finding])
        result = self.generator.generate(report)

        high_findings = result["high_findings"]
        assert len(high_findings) == 1

        f = high_findings[0]
        assert f["severity"] == "high"
        assert f["source"] == FindingSource.SAST_CODE.value
        assert f["endpoint_url"] == "https://example.com/api/users"
        assert f["remediation_guidance"] == ""  # filled by triage layer, empty by default
        assert f["confidence"] == 0.9
        assert f["code_location"]["file"] == "src/api/route.ts"
        assert f["code_location"]["line"] == 42
        assert f["code_location"]["snippet"] == "const secret = process.env.SECRET;"

    def test_remediation_checklist(self) -> None:
        """Should produce prioritized checklist grouped by category."""
        findings = [
            _make_finding(
                severity=SeverityLevel.LOW,
                category=FindingCategory.MISSING_HEADERS,
                title="Missing X-Frame-Options",
            ),
            _make_finding(
                severity=SeverityLevel.CRITICAL,
                category=FindingCategory.EXPOSED_SECRETS,
                title="Exposed API key",
            ),
            _make_finding(
                severity=SeverityLevel.HIGH,
                category=FindingCategory.IDOR,
                title="IDOR in user endpoint",
            ),
        ]
        report = _make_report(findings=findings)
        result = self.generator.generate(report)
        checklist = result["remediation_checklist"]

        assert len(checklist) == 3
        # First item should be the critical finding
        assert checklist[0]["severity"] == "critical"
        assert checklist[0]["category"] == FindingCategory.EXPOSED_SECRETS.value
        assert checklist[0]["priority"] == 1
        # fix_available is False when remediation_guidance is empty (default)
        assert checklist[0]["fix_available"] is False

        # Second should be high
        assert checklist[1]["severity"] == "high"
        assert checklist[1]["priority"] == 2

        # Third should be low
        assert checklist[2]["severity"] == "low"
        assert checklist[2]["priority"] == 3
        assert checklist[2]["fix_available"] is False

    def test_empty_report(self) -> None:
        """Empty report -> grade A, empty sections."""
        report = _make_report(findings=[])
        result = self.generator.generate(report)

        assert result["grade"] == "A"
        assert result["finding_counts"]["total"] == 0
        assert result["finding_counts"]["critical"] == 0
        assert result["critical_findings"] == []
        assert result["high_findings"] == []
        assert result["medium_findings"] == []
        assert result["low_findings"] == []
        assert result["dast_findings"] == []
        assert result["sast_findings"] == []
        assert result["cross_referenced_findings"] == []
        assert result["remediation_checklist"] == []

    def test_finding_counts(self) -> None:
        """Should correctly count by severity and source."""
        findings = [
            _make_finding(severity=SeverityLevel.CRITICAL, source=FindingSource.DAST_URL),
            _make_finding(severity=SeverityLevel.HIGH, source=FindingSource.DAST_AUTHENTICATED),
            _make_finding(severity=SeverityLevel.HIGH, source=FindingSource.SAST_CODE),
            _make_finding(severity=SeverityLevel.MEDIUM, source=FindingSource.SAST_GIT_HISTORY),
            _make_finding(severity=SeverityLevel.MEDIUM, source=FindingSource.CROSS_REFERENCED),
            _make_finding(severity=SeverityLevel.LOW, source=FindingSource.DAST_URL),
        ]
        report = _make_report(findings=findings)
        result = self.generator.generate(report)
        counts = result["finding_counts"]

        assert counts["total"] == 6
        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["medium"] == 2
        assert counts["dast"] == 3  # 2 DAST_URL + 1 DAST_AUTHENTICATED
        assert counts["sast"] == 2  # SAST_CODE + SAST_GIT_HISTORY
        assert counts["cross_referenced"] == 1

    def test_executive_summary(self) -> None:
        """Should produce non-empty summary string."""
        report = _make_report(findings=[
            _make_finding(severity=SeverityLevel.HIGH),
        ])
        result = self.generator.generate(report)

        summary = result["summary"]
        assert isinstance(summary, str)
        assert len(summary) > 0
        assert "https://example.com" in summary

    def test_executive_summary_uses_repo_url_when_no_target(self) -> None:
        """Summary should use repo_url if target_url is None."""
        report = _make_report(
            target_url=None,
            repo_url="https://github.com/user/repo",
            findings=[],
        )
        result = self.generator.generate(report)
        assert "github.com/user/repo" in result["summary"]

    def test_report_metadata(self) -> None:
        """Report should include scan metadata."""
        report = _make_report(findings=[])
        result = self.generator.generate(report)

        assert result["title"] == ReportConfig.REPORT_TITLE
        assert result["scan_mode"] == "full"
        assert result["target_url"] == "https://example.com"
        assert result["duration_seconds"] == 42.5
        assert result["scanners_run"] == ["idor_scanner", "rls_scanner"]
        assert result["endpoints_discovered"] == 15

    def test_findings_with_none_code_location(self) -> None:
        """Findings without code_location should serialize as None."""
        finding = _make_finding(code_location=None)
        report = _make_report(findings=[finding])
        result = self.generator.generate(report)

        formatted = result["medium_findings"][0]
        assert formatted["code_location"] is None

    def test_duplicate_category_in_checklist(self) -> None:
        """Remediation checklist should only list each category once."""
        findings = [
            _make_finding(
                severity=SeverityLevel.HIGH,
                category=FindingCategory.IDOR,
                title="IDOR 1",
            ),
            _make_finding(
                severity=SeverityLevel.MEDIUM,
                category=FindingCategory.IDOR,
                title="IDOR 2",
            ),
            _make_finding(
                severity=SeverityLevel.LOW,
                category=FindingCategory.MISSING_HEADERS,
                title="Missing header",
            ),
        ]
        report = _make_report(findings=findings)
        result = self.generator.generate(report)
        checklist = result["remediation_checklist"]

        assert len(checklist) == 2
        categories = [item["category"] for item in checklist]
        assert FindingCategory.IDOR.value in categories
        assert FindingCategory.MISSING_HEADERS.value in categories

        # IDOR should show finding_count=2
        idor_item = next(
            i for i in checklist if i["category"] == FindingCategory.IDOR.value
        )
        assert idor_item["finding_count"] == 2


# ---------------------------------------------------------------------------
# HTMLReportRenderer tests
# ---------------------------------------------------------------------------

class TestHTMLRenderer:
    """Tests for HTMLReportRenderer."""

    def setup_method(self) -> None:
        self.generator = ReportGenerator()
        self.renderer = HTMLReportRenderer()

    def _generate_and_render(self, findings: list[DeepFinding] | None = None, **kwargs) -> str:
        """Helper: generate report then render to HTML."""
        report = _make_report(findings=findings or [], **kwargs)
        report_data = self.generator.generate(report)
        return self.renderer.render(report_data)

    def test_renders_html(self) -> None:
        """Should produce valid HTML string."""
        html = self._generate_and_render()
        assert html.startswith("<!DOCTYPE html>")
        assert "<html" in html
        assert "</html>" in html
        assert "<body>" in html
        assert "</body>" in html

    def test_includes_grade(self) -> None:
        """HTML should contain the grade."""
        html = self._generate_and_render(findings=[
            _make_finding(severity=SeverityLevel.HIGH),
            _make_finding(severity=SeverityLevel.HIGH),
        ])
        assert ">B<" in html or "grade" in html.lower()

    def test_includes_findings(self) -> None:
        """HTML should contain finding titles."""
        html = self._generate_and_render(findings=[
            _make_finding(severity=SeverityLevel.CRITICAL, title="SQL Injection in /api/users"),
        ])
        assert "SQL Injection in /api/users" in html

    def test_includes_severity_badges(self) -> None:
        """HTML should contain severity badges with correct colors."""
        html = self._generate_and_render(findings=[
            _make_finding(severity=SeverityLevel.CRITICAL, title="Crit"),
        ])
        assert ReportConfig.HTML_SEVERITY_COLORS["critical"] in html
        assert "CRITICAL" in html

    def test_includes_remediation_table(self) -> None:
        """HTML should contain remediation checklist table."""
        html = self._generate_and_render(findings=[
            _make_finding(severity=SeverityLevel.HIGH, title="Fix this"),
        ])
        assert ReportConfig.SECTION_REMEDIATION in html
        assert "<table" in html

    def test_empty_report_renders(self) -> None:
        """Empty report should render without errors."""
        html = self._generate_and_render(findings=[])
        assert "<!DOCTYPE html>" in html
        assert ReportConfig.HTML_NO_FINDINGS_MESSAGE in html

    def test_includes_code_snippet(self) -> None:
        """HTML should render code snippets when present."""
        code_loc = CodeLocation(
            file_path="src/db.ts",
            line_number=10,
            code_snippet="const query = `SELECT * FROM ${input}`;",
        )
        html = self._generate_and_render(findings=[
            _make_finding(
                severity=SeverityLevel.HIGH,
                source=FindingSource.SAST_CODE,
                code_location=code_loc,
            ),
        ])
        assert "src/db.ts" in html
        assert "code-snippet" in html

    def test_escapes_html_in_findings(self) -> None:
        """HTML special characters in findings should be escaped."""
        html = self._generate_and_render(findings=[
            _make_finding(
                severity=SeverityLevel.HIGH,
                title="<script>alert('xss')</script>",
            ),
        ])
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_includes_executive_summary(self) -> None:
        """HTML should include the executive summary section."""
        html = self._generate_and_render(findings=[])
        assert ReportConfig.SECTION_EXECUTIVE_SUMMARY in html

    def test_includes_footer_with_endpoints(self) -> None:
        """HTML should include footer with endpoint count."""
        html = self._generate_and_render(
            findings=[],
            total_endpoints_discovered=42,
        )
        assert "Endpoints discovered: 42" in html

    def test_grade_a_color(self) -> None:
        """Grade A should use the correct green color."""
        html = self._generate_and_render(findings=[])
        assert ReportConfig.HTML_GRADE_COLORS["A"] in html

    def test_remediation_rendered(self) -> None:
        """Remediation guidance should appear in the HTML output."""
        html = self._generate_and_render(findings=[
            _make_finding(
                severity=SeverityLevel.HIGH,
                remediation_guidance="Add helmet middleware for security headers",
            ),
        ])
        assert "Remediation" in html
        assert "Add helmet middleware" in html


# ---------------------------------------------------------------------------
# Owner summary (risk summary) tests
# ---------------------------------------------------------------------------

_RISK_TEXT = (
    "Anyone on the internet can read data from your 'predictions' table "
    "without logging in."
)


def _make_owner_summary(**kwargs) -> OwnerSummary:
    """Create an OwnerSummary with a plain-English risk summary."""
    defaults = {
        "grade": "F",
        "grade_label": "Critical",
        "risk_summary": _RISK_TEXT,
        "key_risks": ["Unauthenticated data access", "Payments can be forged"],
        "remediation_phases": [
            RemediationPhase(
                phase_number=1,
                title="Lock down public data access",
                description="Require login before returning prediction data.",
                priority=1,
                finding_count=3,
            ),
        ],
        "scope_disclaimer": "This scan covered your public web app only.",
        "what_this_report_is_not": "This is not a full penetration test.",
    }
    defaults.update(kwargs)
    return OwnerSummary(**defaults)


class TestOwnerSummaryGeneration:
    """ReportGenerator should surface owner_summary and themes."""

    def setup_method(self) -> None:
        self.generator = ReportGenerator()

    def test_owner_summary_surfaced(self) -> None:
        report = _make_report(findings=[], owner_summary=_make_owner_summary())
        result = self.generator.generate(report)

        owner = result["owner_summary"]
        assert owner is not None
        assert owner["risk_summary"] == _RISK_TEXT
        assert owner["key_risks"] == [
            "Unauthenticated data access",
            "Payments can be forged",
        ]
        assert owner["remediation_phases"][0]["title"] == (
            "Lock down public data access"
        )
        assert owner["remediation_phases"][0]["finding_count"] == 3

    def test_owner_summary_none_when_absent(self) -> None:
        report = _make_report(findings=[], owner_summary=None)
        result = self.generator.generate(report)
        assert result["owner_summary"] is None

    def test_owner_summary_none_when_empty(self) -> None:
        """An OwnerSummary with no usable content is surfaced as None."""
        report = _make_report(findings=[], owner_summary=OwnerSummary())
        result = self.generator.generate(report)
        assert result["owner_summary"] is None

    def test_themes_surfaced(self) -> None:
        theme = SecurityTheme(
            theme_id="payment-integrity",
            title="Payment Processing Integrity",
            description="Payment amounts can be tampered with client-side.",
            severity="critical",
            finding_count=2,
        )
        report = _make_report(findings=[], themes=[theme])
        result = self.generator.generate(report)

        assert len(result["themes"]) == 1
        assert result["themes"][0]["title"] == "Payment Processing Integrity"
        assert result["themes"][0]["finding_count"] == 2

    def test_themes_empty_by_default(self) -> None:
        report = _make_report(findings=[])
        result = self.generator.generate(report)
        assert result["themes"] == []


class TestRiskSummaryRendering:
    """HTMLReportRenderer should render the Risk Summary callout."""

    def setup_method(self) -> None:
        self.generator = ReportGenerator()
        self.renderer = HTMLReportRenderer()

    def _render(self, **kwargs) -> str:
        report = _make_report(findings=[], **kwargs)
        return self.renderer.render(self.generator.generate(report))

    def test_risk_summary_appears_when_present(self) -> None:
        html = self._render(owner_summary=_make_owner_summary())
        # Text appears; apostrophes are HTML-escaped by the renderer.
        assert "Anyone on the internet can read data from your" in html
        assert "table without logging in." in html
        # The callout div (not just the CSS rule) is emitted.
        assert '<div class="risk-callout">' in html
        assert "What This Means for You" in html
        # Owner-friendly extras render too.
        assert "Unauthenticated data access" in html
        assert "Lock down public data access" in html
        assert "This is not a full penetration test." in html

    def test_risk_summary_omitted_when_absent(self) -> None:
        """No owner_summary -> no callout box, no crash, report still complete."""
        html = self._render(owner_summary=None)
        assert '<div class="risk-callout">' not in html
        assert "What This Means for You" not in html
        # Report remains complete with technical sections.
        assert ReportConfig.SECTION_EXECUTIVE_SUMMARY in html
        assert ReportConfig.SECTION_REMEDIATION in html

    def test_risk_summary_omitted_when_empty(self) -> None:
        html = self._render(owner_summary=OwnerSummary())
        assert '<div class="risk-callout">' not in html

    def test_risk_summary_escapes_html(self) -> None:
        malicious = "<script>alert('xss')</script>"
        html = self._render(
            owner_summary=_make_owner_summary(risk_summary=malicious)
        )
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_themes_rendered_when_present(self) -> None:
        theme = SecurityTheme(
            theme_id="payment-integrity",
            title="Payment Processing Integrity",
            description="Payment amounts can be tampered with client-side.",
            severity="critical",
            finding_count=2,
        )
        html = self._render(themes=[theme])
        assert "Security Themes" in html
        assert "Payment Processing Integrity" in html

    def test_themes_omitted_when_absent(self) -> None:
        html = self._render()
        assert "Security Themes" not in html


# ---------------------------------------------------------------------------
# Wave 1: vibe-coder readiness (rule-based, no LLM)
# ---------------------------------------------------------------------------

class TestVibeCoderReadiness:
    """ReportGenerator surfaces the rule-based plain-English layer (#41-#57)."""

    def setup_method(self) -> None:
        self.generator = ReportGenerator()
        self.renderer = HTMLReportRenderer()

    def test_launch_verdict_blocks_on_critical(self) -> None:
        report = _make_report(findings=[
            _make_finding(severity=SeverityLevel.CRITICAL, title="Crit"),
        ])
        result = self.generator.generate(report)
        verdict = result["launch_verdict"]
        assert verdict["ready"] is False
        assert "Not safe to launch" in verdict["headline"]
        assert verdict["line"]  # combined line present

    def test_launch_verdict_clean_is_ready(self) -> None:
        result = self.generator.generate(_make_report(findings=[]))
        assert result["launch_verdict"]["ready"] is True

    def test_grade_is_granular_and_has_legend(self) -> None:
        # Two mediums -> C+ on the new ladder.
        report = _make_report(findings=[
            _make_finding(severity=SeverityLevel.MEDIUM, title="M1"),
            _make_finding(severity=SeverityLevel.MEDIUM, title="M2"),
        ])
        result = self.generator.generate(report)
        assert result["grade"] == "C+"
        assert result["grade_base"] == "C"
        assert result["grade_legend"]

    def test_findings_carry_plain_explanation_and_impact(self) -> None:
        report = _make_report(findings=[
            _make_finding(
                severity=SeverityLevel.CRITICAL,
                category=FindingCategory.IDOR,
                title="IDOR in orders",
            ),
        ])
        result = self.generator.generate(report)
        f = result["critical_findings"][0]
        assert set(f["plain_explanation"]) == {
            "what_it_is", "attacker_could", "what_to_do",
        }
        assert f["business_impact"].strip()
        # Glossary picks up IDOR from the title.
        assert "idor" in f["glossary"]

    def test_checklist_leads_with_business_impact(self) -> None:
        report = _make_report(findings=[
            _make_finding(
                severity=SeverityLevel.CRITICAL,
                category=FindingCategory.RLS_MISCONFIGURATION,
                title="RLS disabled on predictions",
            ),
        ])
        result = self.generator.generate(report)
        item = result["remediation_checklist"][0]
        assert item["business_impact"].strip()
        assert item["what_to_do"].strip()

    def test_html_renders_verdict_and_plain_english(self) -> None:
        report = _make_report(findings=[
            _make_finding(
                severity=SeverityLevel.CRITICAL,
                category=FindingCategory.IDOR,
                title="IDOR in orders",
            ),
        ])
        html = self.renderer.render(self.generator.generate(report))
        # #57 verdict banner at the top.
        assert 'class="verdict' in html
        assert "Not safe to launch" in html
        # #43 legend.
        assert "safe to ship" in html
        # #41 plain-English block.
        assert "plain-explain" in html
        assert "What an attacker could do" in html
        # #42 glossary tooltip.
        assert "glossary-term" in html

    def test_html_verdict_go_when_clean(self) -> None:
        html = self.renderer.render(self.generator.generate(_make_report(findings=[])))
        assert 'class="verdict go"' in html

    def test_html_grade_color_uses_base_letter(self) -> None:
        """Granular grade C+ should still color using the C base color."""
        report = _make_report(findings=[
            _make_finding(severity=SeverityLevel.MEDIUM, title="M1"),
            _make_finding(severity=SeverityLevel.MEDIUM, title="M2"),
        ])
        html = self.renderer.render(self.generator.generate(report))
        assert ReportConfig.HTML_GRADE_COLORS["C"] in html
        assert ">C+<" in html
