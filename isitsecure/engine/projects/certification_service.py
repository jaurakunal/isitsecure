"""Security certification and badge service.

Issues verifiable security certificates for apps that pass deep scans.
Certificates include an embeddable SVG badge and a verification URL.
"""

import logging
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from pydantic import BaseModel, Field

from isitsecure.engine.constants import CertificationConfig
from isitsecure.engine.models import DeepScanReport
from isitsecure.engine.projects.models import Project

logger = logging.getLogger(__name__)


class SecurityCertification(BaseModel):
    """A security certification issued after a passing scan."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    project_id: str
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
        + timedelta(days=CertificationConfig.CERTIFICATION_VALIDITY_DAYS)
    )
    grade: str
    scan_id: str
    reviewer: str = ""
    badge_url: str = ""
    verify_url: str = ""
    findings_at_certification: int = 0
    target_url: str | None = None

    @property
    def is_valid(self) -> bool:
        """Whether the certification has not expired."""
        return datetime.now(UTC) < self.expires_at

    def model_post_init(self, __context: object) -> None:
        """Set badge and verify URLs if not provided."""
        if not self.badge_url:
            self.badge_url = f"{CertificationConfig.BADGE_BASE_URL}/{self.id}"
        if not self.verify_url:
            self.verify_url = f"{CertificationConfig.VERIFY_BASE_URL}/{self.id}"


class CertificationService:
    """Issues and manages security certifications."""

    # Grade ordering from worst to best for eligibility checks
    GRADE_ORDER = ["F", "D", "C", "B", "A"]

    def __init__(self) -> None:
        self._certifications: dict[str, SecurityCertification] = {}

    def is_eligible(
        self, report: DeepScanReport, grade: str,
    ) -> tuple[bool, str]:
        """Check if a scan result is eligible for certification.

        Returns (eligible, reason).
        """
        if report.critical_count > CertificationConfig.MAX_CRITICAL_FOR_CERTIFICATION:
            return (
                False,
                f"{report.critical_count} critical findings "
                f"(max {CertificationConfig.MAX_CRITICAL_FOR_CERTIFICATION})",
            )

        if report.high_count > CertificationConfig.MAX_HIGH_FOR_CERTIFICATION:
            return (
                False,
                f"{report.high_count} high findings "
                f"(max {CertificationConfig.MAX_HIGH_FOR_CERTIFICATION})",
            )

        min_grade = CertificationConfig.MIN_GRADE_FOR_CERTIFICATION
        min_idx = (
            self.GRADE_ORDER.index(min_grade)
            if min_grade in self.GRADE_ORDER
            else len(self.GRADE_ORDER) - 2
        )
        grade_clean = grade.rstrip("+-")
        current_idx = (
            self.GRADE_ORDER.index(grade_clean)
            if grade_clean in self.GRADE_ORDER
            else 0
        )

        if current_idx < min_idx:
            return (
                False,
                f"Grade {grade} below minimum {min_grade}",
            )

        return True, ""

    def issue_certification(
        self,
        project: Project,
        scan_id: str,
        report: DeepScanReport,
        grade: str,
        reviewer: str = "",
    ) -> SecurityCertification:
        """Issue a new certification for a project."""
        eligible, reason = self.is_eligible(report, grade)
        if not eligible:
            raise ValueError(
                CertificationConfig.ERROR_NOT_ELIGIBLE.format(reason=reason)
            )

        cert = SecurityCertification(
            project_id=project.id,
            grade=grade,
            scan_id=scan_id,
            reviewer=reviewer,
            target_url=project.target_url,
            findings_at_certification=len(report.findings),
        )
        self._certifications[cert.id] = cert
        return cert

    def get_certification(self, cert_id: str) -> SecurityCertification | None:
        """Get a certification by ID."""
        return self._certifications.get(cert_id)

    def get_active_certification(
        self, project_id: str,
    ) -> SecurityCertification | None:
        """Get the most recent valid certification for a project."""
        project_certs = [
            c
            for c in self._certifications.values()
            if c.project_id == project_id and c.is_valid
        ]
        if not project_certs:
            return None
        return max(project_certs, key=lambda c: c.issued_at)

    def render_badge_svg(self, cert: SecurityCertification) -> str:
        """Render the certification badge as SVG."""
        color = CertificationConfig.GRADE_COLORS.get(
            cert.grade.rstrip("+-"), "#95a5a6",
        )
        return CertificationConfig.BADGE_SVG_TEMPLATE.format(
            color=color,
            grade=f"Grade {cert.grade}",
        )

    def render_badge_html(self, cert: SecurityCertification) -> str:
        """Render HTML embed code for the badge."""
        return (
            f'<a href="{cert.verify_url}" target="_blank" rel="noopener">'
            f'<img src="{cert.badge_url}.svg" '
            f'alt="{CertificationConfig.TITLE_CERTIFIED}" />'
            f"</a>"
        )
