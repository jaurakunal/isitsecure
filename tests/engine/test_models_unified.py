"""Tests for unified deep security scan models."""

import pytest

from isitsecure.engine.models import (
    CodeLocation,
    DeepFinding,
    DeepScanReport,
    FindingSource,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel


def _make_finding(
    source: FindingSource = FindingSource.DAST_URL,
    category: FindingCategory = FindingCategory.IDOR,
    severity: SeverityLevel = SeverityLevel.HIGH,
    **kwargs: object,
) -> DeepFinding:
    """Helper to build a DeepFinding with sensible defaults."""
    defaults = {
        "source": source,
        "category": category,
        "severity": severity,
        "title": "Test finding",
        "description": "Test description",
        "confidence": 0.9,
        "scanner_name": "test_scanner",
    }
    defaults.update(kwargs)
    return DeepFinding(**defaults)


class TestDeepFinding:
    """Tests for the DeepFinding model."""

    def test_create_dast_finding(self) -> None:
        """Should create a DAST finding with endpoint fields."""
        finding = _make_finding(
            source=FindingSource.DAST_URL,
            endpoint_url="https://example.com/api/users/1",
            http_method="GET",
            response_preview='{"id": 1, "email": "user@example.com"}',
        )
        assert finding.source == FindingSource.DAST_URL
        assert finding.endpoint_url == "https://example.com/api/users/1"
        assert finding.http_method == "GET"
        assert finding.code_location is None

    def test_create_sast_finding(self) -> None:
        """Should create a SAST finding with code location."""
        location = CodeLocation(
            file_path="src/api/users.ts",
            line_number=42,
            line_end=45,
            code_snippet="const secret = 'hardcoded'",
        )
        finding = _make_finding(
            source=FindingSource.SAST_CODE,
            category=FindingCategory.EXPOSED_SECRETS,
            code_location=location,
            fix_code="const secret = process.env.SECRET",
        )
        assert finding.source == FindingSource.SAST_CODE
        assert finding.code_location is not None
        assert finding.code_location.file_path == "src/api/users.ts"
        assert finding.code_location.line_number == 42
        assert finding.endpoint_url is None

    def test_finding_serialization(self) -> None:
        """Should serialize to JSON correctly."""
        finding = _make_finding()
        data = finding.model_dump()
        assert data["source"] == "dast_url"
        assert data["category"] == "idor"
        assert data["severity"] == "high"
        assert isinstance(data["id"], str)
        assert len(data["id"]) > 0

    def test_auto_generated_id(self) -> None:
        """Each finding should get a unique ID."""
        f1 = _make_finding()
        f2 = _make_finding()
        assert f1.id != f2.id

    def test_confidence_bounds(self) -> None:
        """Confidence must be between 0.0 and 1.0."""
        finding = _make_finding(confidence=0.0)
        assert finding.confidence == 0.0

        finding = _make_finding(confidence=1.0)
        assert finding.confidence == 1.0

        with pytest.raises(ValueError):
            _make_finding(confidence=1.5)

        with pytest.raises(ValueError):
            _make_finding(confidence=-0.1)

    def test_related_finding_ids_default_empty(self) -> None:
        """related_finding_ids should default to empty list."""
        finding = _make_finding()
        assert finding.related_finding_ids == []

    def test_related_finding_ids_populated(self) -> None:
        """Should accept related finding IDs."""
        finding = _make_finding(related_finding_ids=["abc-123", "def-456"])
        assert len(finding.related_finding_ids) == 2


class TestDeepScanReport:
    """Tests for the updated DeepScanReport model."""

    def _make_report(self, findings: list[DeepFinding] | None = None) -> DeepScanReport:
        return DeepScanReport(findings=findings or [])

    def test_critical_count(self) -> None:
        """Should count CRITICAL findings correctly."""
        findings = [
            _make_finding(severity=SeverityLevel.CRITICAL),
            _make_finding(severity=SeverityLevel.CRITICAL),
            _make_finding(severity=SeverityLevel.HIGH),
        ]
        report = self._make_report(findings)
        assert report.critical_count == 2

    def test_high_count(self) -> None:
        """Should count HIGH findings correctly."""
        findings = [
            _make_finding(severity=SeverityLevel.HIGH),
            _make_finding(severity=SeverityLevel.MEDIUM),
        ]
        report = self._make_report(findings)
        assert report.high_count == 1

    def test_medium_count(self) -> None:
        """Should count MEDIUM findings correctly."""
        findings = [
            _make_finding(severity=SeverityLevel.MEDIUM),
            _make_finding(severity=SeverityLevel.MEDIUM),
            _make_finding(severity=SeverityLevel.LOW),
        ]
        report = self._make_report(findings)
        assert report.medium_count == 2

    def test_dast_findings_filter(self) -> None:
        """Should filter to DAST-only findings."""
        findings = [
            _make_finding(source=FindingSource.DAST_URL),
            _make_finding(source=FindingSource.DAST_AUTHENTICATED),
            _make_finding(source=FindingSource.SAST_CODE),
        ]
        report = self._make_report(findings)
        assert len(report.dast_findings) == 2

    def test_sast_findings_filter(self) -> None:
        """Should filter to SAST-only findings."""
        findings = [
            _make_finding(source=FindingSource.DAST_URL),
            _make_finding(source=FindingSource.SAST_CODE),
            _make_finding(source=FindingSource.SAST_GIT_HISTORY),
        ]
        report = self._make_report(findings)
        assert len(report.sast_findings) == 2

    def test_cross_ref_filter(self) -> None:
        """Should filter to cross-referenced findings."""
        findings = [
            _make_finding(source=FindingSource.DAST_URL),
            _make_finding(source=FindingSource.CROSS_REFERENCED),
        ]
        report = self._make_report(findings)
        assert len(report.cross_referenced_findings) == 1
        assert report.cross_referenced_findings[0].source == FindingSource.CROSS_REFERENCED

    def test_empty_report(self) -> None:
        """Empty report should have 0 counts."""
        report = self._make_report()
        assert report.critical_count == 0
        assert report.high_count == 0
        assert report.medium_count == 0
        assert len(report.dast_findings) == 0
        assert len(report.sast_findings) == 0
        assert len(report.cross_referenced_findings) == 0
        assert report.findings == []
        assert report.scanners_run == []

    def test_backward_compat_fields(self) -> None:
        """Legacy fields should still be present."""
        report = self._make_report()
        assert report.discovered_endpoints == []
        assert report.idor_results == []
        assert report.target_url is None

    def test_new_metadata_fields(self) -> None:
        """Should support new metadata fields."""
        report = DeepScanReport(
            target_url="https://example.com",
            repo_url="https://github.com/org/repo",
            framework="nextjs",
            backend="supabase",
            scan_mode="full",
            scanners_run=["idor", "xss", "secrets"],
        )
        assert report.framework == "nextjs"
        assert report.backend == "supabase"
        assert report.scan_mode == "full"
        assert len(report.scanners_run) == 3


class TestCodeLocation:
    """Tests for the CodeLocation model."""

    def test_create_with_line_number(self) -> None:
        """Should create with line number range."""
        loc = CodeLocation(
            file_path="src/api/route.ts",
            line_number=10,
            line_end=15,
            code_snippet="const key = 'secret'",
        )
        assert loc.file_path == "src/api/route.ts"
        assert loc.line_number == 10
        assert loc.line_end == 15

    def test_create_without_line_number(self) -> None:
        """Should allow creation without line numbers."""
        loc = CodeLocation(file_path="package.json")
        assert loc.line_number is None
        assert loc.line_end is None
        assert loc.code_snippet == ""

    def test_github_url(self) -> None:
        """Should store GitHub URL for linking."""
        url = "https://github.com/org/repo/blob/main/src/api/route.ts#L10-L15"
        loc = CodeLocation(
            file_path="src/api/route.ts",
            line_number=10,
            github_url=url,
        )
        assert loc.github_url == url
