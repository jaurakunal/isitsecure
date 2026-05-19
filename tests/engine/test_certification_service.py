"""Tests for security certification and badge service."""

from datetime import UTC, datetime, timedelta

import pytest

from isitsecure.engine.constants import CertificationConfig
from isitsecure.engine.enums import PlanTier
from isitsecure.engine.models import DeepFinding, DeepScanReport
from isitsecure.engine.models import FindingSource
from isitsecure.engine.projects.certification_service import (
    CertificationService,
    SecurityCertification,
)
from isitsecure.engine.projects.models import Project
from isitsecure.engine.enums import FindingCategory, SeverityLevel


def _make_report(
    critical: int = 0, high: int = 0, medium: int = 0,
) -> DeepScanReport:
    """Helper to create a report with specified finding counts."""
    findings: list[DeepFinding] = []
    for _ in range(critical):
        findings.append(
            DeepFinding(
                source=FindingSource.DAST_URL,
                category=FindingCategory.INJECTION_RISK,
                severity=SeverityLevel.CRITICAL,
                title="Critical finding",
                description="Test",
                confidence=0.9,
                scanner_name="test",
            )
        )
    for _ in range(high):
        findings.append(
            DeepFinding(
                source=FindingSource.DAST_URL,
                category=FindingCategory.AUTH_WEAKNESS,
                severity=SeverityLevel.HIGH,
                title="High finding",
                description="Test",
                confidence=0.8,
                scanner_name="test",
            )
        )
    for _ in range(medium):
        findings.append(
            DeepFinding(
                source=FindingSource.DAST_URL,
                category=FindingCategory.MISSING_HEADERS,
                severity=SeverityLevel.MEDIUM,
                title="Medium finding",
                description="Test",
                confidence=0.7,
                scanner_name="test",
            )
        )
    return DeepScanReport(
        target_url="https://example.com",
        findings=findings,
        scan_duration_seconds=30.0,
    )


def _make_project() -> Project:
    """Helper to create a test project."""
    return Project(
        name="Test App",
        owner_id="owner-1",
        target_url="https://example.com",
        plan_tier=PlanTier.CERTIFICATION,
    )


class TestCertificationService:
    """Tests for CertificationService."""

    def setup_method(self) -> None:
        self.service = CertificationService()
        self.project = _make_project()

    def test_is_eligible_pass(self) -> None:
        report = _make_report(medium=2)
        eligible, reason = self.service.is_eligible(report, "A")
        assert eligible
        assert reason == ""

    def test_is_eligible_fail_critical(self) -> None:
        report = _make_report(critical=1)
        eligible, reason = self.service.is_eligible(report, "A")
        assert not eligible
        assert "critical" in reason

    def test_is_eligible_fail_grade(self) -> None:
        report = _make_report()
        eligible, reason = self.service.is_eligible(report, "C")
        assert not eligible
        assert "below minimum" in reason

    def test_issue_certification(self) -> None:
        report = _make_report(medium=1)
        cert = self.service.issue_certification(
            project=self.project,
            scan_id="scan-1",
            report=report,
            grade="A",
        )
        assert cert.project_id == self.project.id
        assert cert.grade == "A"
        assert cert.scan_id == "scan-1"
        assert cert.is_valid
        assert cert.findings_at_certification == 1

    def test_issue_not_eligible(self) -> None:
        report = _make_report(critical=1)
        with pytest.raises(ValueError, match="Not eligible"):
            self.service.issue_certification(
                project=self.project,
                scan_id="scan-1",
                report=report,
                grade="A",
            )

    def test_get_certification(self) -> None:
        report = _make_report()
        cert = self.service.issue_certification(
            project=self.project,
            scan_id="scan-1",
            report=report,
            grade="A",
        )
        found = self.service.get_certification(cert.id)
        assert found is not None
        assert found.id == cert.id

        not_found = self.service.get_certification("nonexistent")
        assert not_found is None

    def test_get_active_certification(self) -> None:
        report = _make_report()
        self.service.issue_certification(
            project=self.project,
            scan_id="scan-1",
            report=report,
            grade="B",
        )
        cert2 = self.service.issue_certification(
            project=self.project,
            scan_id="scan-2",
            report=report,
            grade="A",
        )
        active = self.service.get_active_certification(self.project.id)
        assert active is not None
        assert active.id == cert2.id

    def test_expired_certification(self) -> None:
        report = _make_report()
        cert = self.service.issue_certification(
            project=self.project,
            scan_id="scan-1",
            report=report,
            grade="A",
        )
        # Manually expire the certification
        cert.expires_at = datetime.now(UTC) - timedelta(days=1)
        assert not cert.is_valid

        active = self.service.get_active_certification(self.project.id)
        assert active is None

    def test_render_badge_svg(self) -> None:
        report = _make_report()
        cert = self.service.issue_certification(
            project=self.project,
            scan_id="scan-1",
            report=report,
            grade="A",
        )
        svg = self.service.render_badge_svg(cert)
        assert "<svg" in svg
        assert "Grade A" in svg
        assert CertificationConfig.GRADE_COLORS["A"] in svg

    def test_render_badge_html(self) -> None:
        report = _make_report()
        cert = self.service.issue_certification(
            project=self.project,
            scan_id="scan-1",
            report=report,
            grade="A",
        )
        html = self.service.render_badge_html(cert)
        assert cert.verify_url in html
        assert cert.badge_url in html
        assert CertificationConfig.TITLE_CERTIFIED in html

    def test_badge_contains_grade(self) -> None:
        report = _make_report()
        cert = self.service.issue_certification(
            project=self.project,
            scan_id="scan-1",
            report=report,
            grade="B",
        )
        svg = self.service.render_badge_svg(cert)
        assert "Grade B" in svg

    def test_verify_url(self) -> None:
        report = _make_report()
        cert = self.service.issue_certification(
            project=self.project,
            scan_id="scan-1",
            report=report,
            grade="A",
        )
        assert cert.verify_url.startswith(CertificationConfig.VERIFY_BASE_URL)
        assert cert.id in cert.verify_url


class TestSecurityCertification:
    """Tests for SecurityCertification model."""

    def test_model_defaults(self) -> None:
        cert = SecurityCertification(
            project_id="proj-1", grade="A", scan_id="scan-1",
        )
        assert cert.id is not None
        assert cert.issued_at is not None
        assert cert.expires_at is not None
        assert cert.reviewer == ""

    def test_is_valid(self) -> None:
        cert = SecurityCertification(
            project_id="proj-1", grade="A", scan_id="scan-1",
        )
        assert cert.is_valid

        cert.expires_at = datetime.now(UTC) - timedelta(days=1)
        assert not cert.is_valid

    def test_auto_urls(self) -> None:
        cert = SecurityCertification(
            project_id="proj-1", grade="A", scan_id="scan-1",
        )
        assert cert.badge_url.startswith(CertificationConfig.BADGE_BASE_URL)
        assert cert.verify_url.startswith(CertificationConfig.VERIFY_BASE_URL)
        assert cert.id in cert.badge_url
        assert cert.id in cert.verify_url
