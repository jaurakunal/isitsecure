"""Tests for new model fields and new models in deep security scan."""

import pytest

from isitsecure.engine.enums import ImpactCategory, LikelihoodLevel
from isitsecure.engine.models import (
    CodeLocation,
    DeepFinding,
    DeepScanReport,
    FindingSource,
    OwnerSummary,
    RemediationPhase,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel


def _make_finding(**kwargs: object) -> DeepFinding:
    """Helper to build a DeepFinding with sensible defaults."""
    defaults = {
        "source": FindingSource.DAST_URL,
        "category": FindingCategory.IDOR,
        "severity": SeverityLevel.HIGH,
        "title": "Test finding",
        "description": "Test description",
        "confidence": 0.9,
        "scanner_name": "test_scanner",
    }
    defaults.update(kwargs)
    return DeepFinding(**defaults)


class TestDeepFindingNewFields:
    """Tests for the new priority model fields on DeepFinding."""

    def test_impact_defaults_to_none(self) -> None:
        """impact should default to None when not provided."""
        finding = _make_finding()
        assert finding.impact is None

    def test_likelihood_defaults_to_none(self) -> None:
        """likelihood should default to None when not provided."""
        finding = _make_finding()
        assert finding.likelihood is None

    def test_priority_defaults_to_none(self) -> None:
        """priority should default to None when not provided."""
        finding = _make_finding()
        assert finding.priority is None

    def test_remediation_guidance_defaults_empty(self) -> None:
        """remediation_guidance should default to empty string."""
        finding = _make_finding()
        assert finding.remediation_guidance == ""

    def test_setting_impact_and_likelihood(self) -> None:
        """Should accept ImpactCategory and LikelihoodLevel enums."""
        finding = _make_finding(
            impact=ImpactCategory.DATA_BREACH,
            likelihood=LikelihoodLevel.ACTIVELY_EXPLOITABLE,
        )
        assert finding.impact == ImpactCategory.DATA_BREACH
        assert finding.likelihood == LikelihoodLevel.ACTIVELY_EXPLOITABLE

    def test_to_customer_dict_excludes_nothing(self) -> None:
        """to_customer_dict should return a clean dict with all fields."""
        finding = _make_finding(
            impact=ImpactCategory.FINANCIAL,
            likelihood=LikelihoodLevel.REQUIRES_AUTH,
            priority=2,
            remediation_guidance="Use parameterized queries.",
        )
        data = finding.to_customer_dict()
        assert isinstance(data, dict)
        assert data["impact"] == "financial"
        assert data["likelihood"] == "requires_auth"
        assert data["priority"] == 2
        assert data["remediation_guidance"] == "Use parameterized queries."
        # All standard fields should be present
        assert "id" in data
        assert "source" in data
        assert "category" in data
        assert "severity" in data

    def test_finding_with_all_new_fields(self) -> None:
        """Should create a finding with all new priority model fields set."""
        finding = _make_finding(
            impact=ImpactCategory.LEGAL,
            likelihood=LikelihoodLevel.THEORETICAL,
            priority=4,
            remediation_guidance="Review compliance requirements.",
        )
        assert finding.impact == ImpactCategory.LEGAL
        assert finding.likelihood == LikelihoodLevel.THEORETICAL
        assert finding.priority == 4
        assert finding.remediation_guidance == "Review compliance requirements."


class TestOwnerSummary:
    """Tests for the OwnerSummary model."""

    def test_defaults(self) -> None:
        """Default OwnerSummary should have empty fields."""
        summary = OwnerSummary()
        assert summary.grade == ""
        assert summary.grade_label == ""
        assert summary.risk_summary == ""
        assert summary.key_risks == []
        assert summary.remediation_phases == []
        assert summary.scope_disclaimer == ""
        assert summary.what_this_report_is_not == ""

    def test_with_all_fields(self) -> None:
        """Should accept all fields correctly."""
        summary = OwnerSummary(
            grade="B",
            grade_label="Good",
            risk_summary="Moderate risk exposure detected.",
            key_risks=["Missing CSRF protection", "Weak password policy"],
            scope_disclaimer="This scan covers only the public-facing site.",
            what_this_report_is_not="This is not a penetration test.",
        )
        assert summary.grade == "B"
        assert summary.grade_label == "Good"
        assert summary.risk_summary == "Moderate risk exposure detected."
        assert len(summary.key_risks) == 2
        assert summary.scope_disclaimer == "This scan covers only the public-facing site."
        assert summary.what_this_report_is_not == "This is not a penetration test."

    def test_with_remediation_phases(self) -> None:
        """Should accept remediation phases list."""
        phases = [
            RemediationPhase(
                phase_number=1,
                title="Critical Fixes",
                description="Fix SQL injection and exposed secrets.",
                priority=1,
                finding_count=3,
            ),
            RemediationPhase(
                phase_number=2,
                title="Security Headers",
                description="Add missing security headers.",
                priority=2,
                finding_count=5,
            ),
        ]
        summary = OwnerSummary(
            grade="C",
            grade_label="Needs Improvement",
            remediation_phases=phases,
        )
        assert len(summary.remediation_phases) == 2
        assert summary.remediation_phases[0].title == "Critical Fixes"
        assert summary.remediation_phases[1].finding_count == 5

    def test_serialization(self) -> None:
        """Should serialize to dict correctly."""
        summary = OwnerSummary(
            grade="A",
            grade_label="Excellent",
            key_risks=["Minor issues only"],
            remediation_phases=[
                RemediationPhase(
                    phase_number=1,
                    title="Polish",
                    description="Minor improvements.",
                )
            ],
        )
        data = summary.model_dump()
        assert data["grade"] == "A"
        assert data["grade_label"] == "Excellent"
        assert len(data["key_risks"]) == 1
        assert len(data["remediation_phases"]) == 1
        assert data["remediation_phases"][0]["title"] == "Polish"


class TestRemediationPhase:
    """Tests for the RemediationPhase model."""

    def test_creation(self) -> None:
        """Should create with all required and optional fields."""
        phase = RemediationPhase(
            phase_number=1,
            title="Immediate Fixes",
            description="Address critical vulnerabilities first.",
            priority=1,
            finding_count=7,
        )
        assert phase.phase_number == 1
        assert phase.title == "Immediate Fixes"
        assert phase.description == "Address critical vulnerabilities first."
        assert phase.priority == 1
        assert phase.finding_count == 7

    def test_defaults(self) -> None:
        """Optional fields should have correct defaults."""
        phase = RemediationPhase(
            phase_number=3,
            title="Long-term",
            description="Ongoing monitoring.",
        )
        assert phase.priority == 1
        assert phase.finding_count == 0


class TestDeepScanReportWithOwnerSummary:
    """Tests for DeepScanReport owner_summary integration."""

    def test_report_includes_owner_summary(self) -> None:
        """Should store an OwnerSummary on the report."""
        summary = OwnerSummary(
            grade="D",
            grade_label="Poor",
            risk_summary="Significant vulnerabilities found.",
            key_risks=["SQL injection", "Missing auth", "Exposed secrets"],
        )
        report = DeepScanReport(
            target_url="https://example.com",
            owner_summary=summary,
        )
        assert report.owner_summary is not None
        assert report.owner_summary.grade == "D"
        assert len(report.owner_summary.key_risks) == 3

    def test_report_owner_summary_defaults_none(self) -> None:
        """owner_summary should default to None."""
        report = DeepScanReport()
        assert report.owner_summary is None

    def test_report_serializes_with_owner_summary(self) -> None:
        """Full report with owner_summary should serialize cleanly."""
        finding = _make_finding(
            impact=ImpactCategory.OPERATIONAL,
            likelihood=LikelihoodLevel.REQUIRES_ADMIN,
            priority=3,
        )
        summary = OwnerSummary(
            grade="B",
            grade_label="Good",
            remediation_phases=[
                RemediationPhase(
                    phase_number=1,
                    title="Quick Wins",
                    description="Easy fixes with high impact.",
                    priority=1,
                    finding_count=2,
                ),
            ],
        )
        report = DeepScanReport(
            target_url="https://example.com",
            findings=[finding],
            owner_summary=summary,
            scanners_run=["xss", "secrets"],
        )
        data = report.model_dump(mode="json")
        assert data["owner_summary"]["grade"] == "B"
        assert len(data["owner_summary"]["remediation_phases"]) == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["impact"] == "operational"
        assert data["findings"][0]["priority"] == 3
