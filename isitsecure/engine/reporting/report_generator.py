"""Generates structured reports from DeepScanReport.

SRP: This class is responsible only for transforming a DeepScanReport
into a serializable dict. HTML rendering is delegated to HTMLReportRenderer.
"""

from isitsecure.engine.constants import ReportConfig
from isitsecure.engine.models import DeepFinding, DeepScanReport
from isitsecure.engine.enums import SeverityLevel


class ReportGenerator:
    """Generates human-readable reports from scan results.

    Produces:
    1. Security grade (A-F)
    2. Executive summary
    3. Findings grouped by severity and source
    4. Remediation checklist
    """

    # Severity sort order (lower = more severe)
    _SEVERITY_ORDER = {
        SeverityLevel.CRITICAL: 0,
        SeverityLevel.HIGH: 1,
        SeverityLevel.MEDIUM: 2,
        SeverityLevel.LOW: 3,
        SeverityLevel.INFO: 4,
    }

    # Default order for unknown severities
    _DEFAULT_SEVERITY_ORDER = 5

    def generate(self, report: DeepScanReport) -> dict:
        """Generate a structured report dict from scan results.

        Args:
            report: The completed DeepScanReport with all findings.

        Returns:
            A JSON-serializable dict containing the full report data.
        """
        grade = self._calculate_grade(report)

        return {
            "title": ReportConfig.REPORT_TITLE,
            "grade": grade,
            "grade_label": ReportConfig.GRADE_LABELS.get(grade, ""),
            "scan_mode": report.scan_mode,
            "target_url": report.target_url,
            "repo_url": report.repo_url,
            "duration_seconds": report.scan_duration_seconds,
            "scanners_run": report.scanners_run,
            "summary": self._build_executive_summary(report, grade),
            "owner_summary": self._build_owner_summary(report),
            "themes": self._build_themes(report),
            "finding_counts": self._build_finding_counts(report),
            "critical_findings": self._format_findings(
                [f for f in report.findings if f.severity == SeverityLevel.CRITICAL]
            ),
            "high_findings": self._format_findings(
                [f for f in report.findings if f.severity == SeverityLevel.HIGH]
            ),
            "medium_findings": self._format_findings(
                [f for f in report.findings if f.severity == SeverityLevel.MEDIUM]
            ),
            "low_findings": self._format_findings(
                [f for f in report.findings if f.severity == SeverityLevel.LOW]
            ),
            "dast_findings": self._format_findings(report.dast_findings),
            "sast_findings": self._format_findings(report.sast_findings),
            "cross_referenced_findings": self._format_findings(
                report.cross_referenced_findings
            ),
            "endpoints_discovered": report.total_endpoints_discovered,
            "remediation_checklist": self._build_remediation_checklist(report),
        }

    def _calculate_grade(self, report: DeepScanReport) -> str:
        """Calculate security grade A-F based on finding severity counts.

        Grade logic:
        - A: 0 critical, 0 high
        - B: 0 critical, <= GRADE_B high
        - C: 0 critical, <= GRADE_C high
        - D: <= 1 critical, <= GRADE_D high
        - F: Everything else
        """
        critical = report.critical_count
        high = report.high_count

        if critical == 0 and high == 0:
            return "A"
        if critical == 0 and high <= ReportConfig.GRADE_B:
            return "B"
        if critical == 0 and high <= ReportConfig.GRADE_C:
            return "C"
        if critical <= 1 and high <= ReportConfig.GRADE_D:
            return "D"
        return "F"

    def _build_executive_summary(self, report: DeepScanReport, grade: str) -> str:
        """Build executive summary text based on grade and findings.

        Args:
            report: The scan report.
            grade: The calculated letter grade.

        Returns:
            A human-readable summary string.
        """
        target = report.target_url or report.repo_url or "the target"
        scanners = len(report.scanners_run)
        total = len(report.findings)
        critical = report.critical_count
        high = report.high_count

        summary_map = {
            "A": ReportConfig.SUMMARY_EXCELLENT,
            "B": ReportConfig.SUMMARY_GOOD,
            "C": ReportConfig.SUMMARY_FAIR,
            "D": ReportConfig.SUMMARY_POOR,
            "F": ReportConfig.SUMMARY_CRITICAL,
        }

        template = summary_map.get(grade, ReportConfig.SUMMARY_CRITICAL)
        return template.format(
            target=target,
            total=total,
            scanners=scanners,
            critical=critical,
            high=high,
        )

    def _build_owner_summary(self, report: DeepScanReport) -> dict | None:
        """Surface the non-technical owner summary for rendering.

        Returns a plain dict of owner-friendly fields, or None when the
        report has no owner_summary (e.g. ``--llm none`` scans) or the
        summary carries no meaningful content.

        Args:
            report: The scan report.

        Returns:
            A dict with owner-facing fields, or None if unavailable/empty.
        """
        owner = report.owner_summary
        if owner is None:
            return None

        # Treat a summary with no usable content as absent so the renderer
        # can gracefully omit the section rather than show an empty box.
        has_content = bool(
            owner.risk_summary.strip()
            or owner.key_risks
            or owner.remediation_phases
            or owner.scope_disclaimer.strip()
            or owner.what_this_report_is_not.strip()
        )
        if not has_content:
            return None

        return {
            "grade": owner.grade,
            "grade_label": owner.grade_label,
            "risk_summary": owner.risk_summary,
            "key_risks": list(owner.key_risks),
            "remediation_phases": [
                {
                    "phase_number": phase.phase_number,
                    "title": phase.title,
                    "description": phase.description,
                    "priority": phase.priority,
                    "finding_count": phase.finding_count,
                }
                for phase in owner.remediation_phases
            ],
            "scope_disclaimer": owner.scope_disclaimer,
            "what_this_report_is_not": owner.what_this_report_is_not,
        }

    def _build_themes(self, report: DeepScanReport) -> list[dict]:
        """Surface thematic groupings of findings for rendering.

        Args:
            report: The scan report.

        Returns:
            List of theme dicts (empty when no themes are present).
        """
        return [
            {
                "theme_id": theme.theme_id,
                "title": theme.title,
                "description": theme.description,
                "severity": theme.severity,
                "finding_count": theme.finding_count,
            }
            for theme in report.themes
        ]

    def _build_finding_counts(self, report: DeepScanReport) -> dict:
        """Build finding count summary dict."""
        return {
            "total": len(report.findings),
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "dast": len(report.dast_findings),
            "sast": len(report.sast_findings),
            "cross_referenced": len(report.cross_referenced_findings),
        }

    def _format_findings(self, findings: list[DeepFinding]) -> list[dict]:
        """Format findings for report output.

        Args:
            findings: List of DeepFinding objects to format.

        Returns:
            List of JSON-serializable finding dicts.
        """
        return [
            {
                "id": f.id,
                "severity": f.severity.value,
                "category": f.category.value,
                "title": f.title,
                "description": f.description,
                "scanner": f.scanner_name,
                "source": f.source.value,
                "endpoint_url": f.endpoint_url,
                "code_location": {
                    "file": f.code_location.file_path,
                    "line": f.code_location.line_number,
                    "snippet": f.code_location.code_snippet,
                }
                if f.code_location
                else None,
                "remediation_guidance": f.remediation_guidance,
                "confidence": f.confidence,
            }
            for f in findings
        ]

    def _build_remediation_checklist(self, report: DeepScanReport) -> list[dict]:
        """Build prioritized remediation checklist.

        Groups findings by category, sorted by severity (most severe first).
        Each category appears only once with its highest-severity finding.

        Args:
            report: The scan report.

        Returns:
            Ordered list of remediation action dicts.
        """
        checklist: list[dict] = []
        seen_categories: set[str] = set()

        sorted_findings = sorted(
            report.findings,
            key=lambda f: self._severity_order(f.severity),
        )

        for finding in sorted_findings:
            category_value = finding.category.value
            if category_value not in seen_categories:
                seen_categories.add(category_value)
                checklist.append(
                    {
                        "priority": len(checklist) + 1,
                        "category": category_value,
                        "severity": finding.severity.value,
                        "action": finding.title,
                        "finding_count": sum(
                            1
                            for f in report.findings
                            if f.category == finding.category
                        ),
                        "fix_available": bool(finding.remediation_guidance),
                    }
                )

        return checklist

    def _severity_order(self, severity: SeverityLevel) -> int:
        """Return sort order for a severity level (lower = more severe)."""
        return self._SEVERITY_ORDER.get(severity, self._DEFAULT_SEVERITY_ORDER)
