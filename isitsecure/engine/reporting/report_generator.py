"""Generates structured reports from DeepScanReport.

SRP: This class is responsible only for transforming a DeepScanReport
into a serializable dict. HTML rendering is delegated to HTMLReportRenderer.
"""

from isitsecure.engine.constants import ReportConfig
from isitsecure.engine.models import DeepFinding, DeepScanReport
from isitsecure.engine.enums import SeverityLevel
from isitsecure.engine.reporting import plain_english


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
        grade_result = self._grade_result(report)
        grade = grade_result.grade
        verdict = plain_english.launch_verdict(
            report.critical_count, report.high_count, report.medium_count
        )

        return {
            "title": ReportConfig.REPORT_TITLE,
            "grade": grade,
            # Base letter (A-F) drives coloring so A+/A/A- share a color.
            "grade_base": plain_english.grade_base_letter(grade),
            "grade_label": grade_result.label,
            "grade_legend": grade_result.legend,
            # #57 — launch-readiness verdict for the top of the report.
            "launch_verdict": {
                "ready": verdict.ready,
                "headline": verdict.headline,
                "detail": verdict.detail,
                "line": verdict.as_line(),
            },
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

    def _low_count(self, report: DeepScanReport) -> int:
        """Count findings with LOW severity."""
        return sum(
            1 for f in report.findings if f.severity == SeverityLevel.LOW
        )

    def _grade_result(self, report: DeepScanReport) -> "plain_english.GradeResult":
        """Compute the granular grade (A+/A/A-/B+/B/C+/C/D/F) for a report.

        Delegates to the rule-based ladder in ``plain_english`` so the CLI
        and HTML report share one source of truth. Works with ``--llm none``.
        """
        return plain_english.calculate_grade(
            critical=report.critical_count,
            high=report.high_count,
            medium=report.medium_count,
            low=self._low_count(report),
        )

    def _calculate_grade(self, report: DeepScanReport) -> str:
        """Return the granular security grade string for a report.

        Kept as the public entry point used by the CLI badge command and
        tests. See ``plain_english.calculate_grade`` for the thresholds.
        """
        return self._grade_result(report).grade

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

        # Granular grades (A+, A-, C+, ...) collapse to their base letter
        # so the executive-summary template lookup still resolves.
        base = plain_english.grade_base_letter(grade)
        template = summary_map.get(base, ReportConfig.SUMMARY_CRITICAL)
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
        formatted = []
        for f in findings:
            # #41 — rule-based, LLM-free plain-English explanation.
            explanation = plain_english.explain_finding(f)
            formatted.append({
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
                # #41 — three-part jargon-free explanation.
                "plain_explanation": explanation.as_dict(),
                # #44 — consequence-first, owner-facing one-liner.
                "business_impact": plain_english.business_impact(f.category),
                # #42 — glossary terms present in the title (for tooltips).
                "glossary": self._glossary_for(f),
            })
        return formatted

    @staticmethod
    def _glossary_for(finding: DeepFinding) -> dict[str, str]:
        """Return {term: definition} for glossary terms in a finding's title.

        Powers inline tooltips / parentheticals in the report renderers.
        """
        import re

        text = f"{finding.title} {finding.category.value}"
        lowered = text.lower()
        found: dict[str, str] = {}
        for term, definition in plain_english.GLOSSARY.items():
            if re.search(rf"\b{re.escape(term)}\b", lowered):
                found[term] = definition
        return found

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
                explanation = plain_english.explain_finding(finding)
                checklist.append(
                    {
                        "priority": len(checklist) + 1,
                        "category": category_value,
                        "severity": finding.severity.value,
                        "action": finding.title,
                        # #44 — lead each checklist row with the consequence
                        # to the owner, not the technical category label.
                        "business_impact": plain_english.business_impact(
                            finding.category
                        ),
                        "what_to_do": explanation.what_to_do,
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
