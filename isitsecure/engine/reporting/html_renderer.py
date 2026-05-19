"""Renders scan report as HTML.

SRP: This class is responsible only for converting a structured report dict
(produced by ReportGenerator) into an HTML string with inline CSS,
suitable for PDF generation.
"""

from html import escape

from isitsecure.engine.constants import ReportConfig


class HTMLReportRenderer:
    """Renders a structured report dict as HTML for PDF generation.

    Uses inline CSS for PDF compatibility (no external stylesheets).
    All dynamic content is HTML-escaped to prevent XSS in rendered output.
    """

    # Layout constants
    _MAX_SNIPPET_DISPLAY_LENGTH = 500
    _TABLE_HEADER_BG = "#f3f4f6"
    _BORDER_COLOR = "#e5e7eb"
    _BODY_BG = "#ffffff"
    _TEXT_COLOR = "#111827"
    _MUTED_TEXT_COLOR = "#6b7280"

    def render(self, report_data: dict) -> str:
        """Render report dict to HTML string.

        Args:
            report_data: Structured report dict from ReportGenerator.generate().

        Returns:
            Complete HTML document string with inline CSS.
        """
        grade = report_data.get("grade", "?")
        grade_color = ReportConfig.HTML_GRADE_COLORS.get(grade, self._MUTED_TEXT_COLOR)

        sections = [
            self._render_header(report_data, grade, grade_color),
            self._render_executive_summary(report_data),
            self._render_finding_counts(report_data),
            self._render_findings_section(
                ReportConfig.SECTION_CRITICAL_FINDINGS,
                report_data.get("critical_findings", [])
                + report_data.get("high_findings", []),
            ),
            self._render_findings_section(
                ReportConfig.SECTION_DAST_RESULTS,
                report_data.get("dast_findings", []),
            ),
            self._render_findings_section(
                ReportConfig.SECTION_SAST_RESULTS,
                report_data.get("sast_findings", []),
            ),
            self._render_findings_section(
                ReportConfig.SECTION_CROSS_REF,
                report_data.get("cross_referenced_findings", []),
            ),
            self._render_remediation_checklist(report_data),
            self._render_footer(report_data),
        ]

        body = "\n".join(sections)
        return self._wrap_html(body)

    def _wrap_html(self, body: str) -> str:
        """Wrap body content in a full HTML document with inline styles."""
        return (
            "<!DOCTYPE html>\n"
            "<html lang=\"en\">\n"
            "<head>\n"
            "  <meta charset=\"UTF-8\">\n"
            f"  <title>{escape(ReportConfig.HTML_TITLE)}</title>\n"
            "  <style>\n"
            f"    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', "
            f"Roboto, sans-serif; color: {self._TEXT_COLOR}; background: {self._BODY_BG}; "
            f"margin: 0; padding: 20px; font-size: 14px; line-height: 1.6; }}\n"
            f"    h1 {{ font-size: 24px; margin-bottom: 4px; }}\n"
            f"    h2 {{ font-size: 18px; border-bottom: 2px solid {self._BORDER_COLOR}; "
            f"padding-bottom: 6px; margin-top: 32px; }}\n"
            f"    .grade-badge {{ display: inline-block; font-size: 48px; font-weight: bold; "
            f"width: 80px; height: 80px; line-height: 80px; text-align: center; "
            f"border-radius: 12px; color: white; }}\n"
            f"    .summary {{ background: #f9fafb; border-left: 4px solid {self._BORDER_COLOR}; "
            f"padding: 12px 16px; margin: 16px 0; }}\n"
            f"    table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}\n"
            f"    th, td {{ border: 1px solid {self._BORDER_COLOR}; padding: 8px 12px; "
            f"text-align: left; }}\n"
            f"    th {{ background: {self._TABLE_HEADER_BG}; font-weight: 600; }}\n"
            f"    .severity-badge {{ display: inline-block; padding: 2px 8px; "
            f"border-radius: 4px; color: white; font-size: 12px; font-weight: 600; }}\n"
            f"    .finding-card {{ border: 1px solid {self._BORDER_COLOR}; border-radius: 8px; "
            f"padding: 12px 16px; margin: 8px 0; }}\n"
            f"    .code-snippet {{ background: #1e1e1e; color: #d4d4d4; padding: 8px 12px; "
            f"border-radius: 4px; font-family: 'Courier New', monospace; font-size: 12px; "
            f"overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}\n"
            f"    .muted {{ color: {self._MUTED_TEXT_COLOR}; }}\n"
            f"    .counts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, "
            f"minmax(120px, 1fr)); gap: 12px; margin: 16px 0; }}\n"
            f"    .count-card {{ text-align: center; padding: 12px; border-radius: 8px; "
            f"border: 1px solid {self._BORDER_COLOR}; }}\n"
            f"    .count-number {{ font-size: 28px; font-weight: bold; }}\n"
            f"    .count-label {{ font-size: 12px; color: {self._MUTED_TEXT_COLOR}; }}\n"
            "  </style>\n"
            "</head>\n"
            f"<body>\n{body}\n</body>\n"
            "</html>"
        )

    def _render_header(self, report_data: dict, grade: str, grade_color: str) -> str:
        """Render report header with title and grade badge."""
        title = escape(report_data.get("title", ReportConfig.REPORT_TITLE))
        grade_label = escape(report_data.get("grade_label", ""))
        target = escape(report_data.get("target_url", "") or "")
        scan_mode = escape(report_data.get("scan_mode", ""))
        duration = report_data.get("duration_seconds", 0)
        scanners = report_data.get("scanners_run", [])

        scanners_str = escape(", ".join(scanners)) if scanners else "N/A"

        return (
            f"<h1>{title}</h1>\n"
            f"<div style=\"display: flex; align-items: center; gap: 16px; margin: 16px 0;\">\n"
            f"  <div class=\"grade-badge\" style=\"background: {grade_color};\">"
            f"{escape(grade)}</div>\n"
            f"  <div>\n"
            f"    <div style=\"font-size: 16px; font-weight: 600;\">{grade_label}</div>\n"
            f"    <div class=\"muted\">Target: {target}</div>\n"
            f"    <div class=\"muted\">Mode: {scan_mode} | "
            f"Duration: {duration:.1f}s | Scanners: {scanners_str}</div>\n"
            f"  </div>\n"
            f"</div>"
        )

    def _render_executive_summary(self, report_data: dict) -> str:
        """Render executive summary section."""
        summary = escape(report_data.get("summary", ""))
        return (
            f"<h2>{escape(ReportConfig.SECTION_EXECUTIVE_SUMMARY)}</h2>\n"
            f"<div class=\"summary\">{summary}</div>"
        )

    def _render_finding_counts(self, report_data: dict) -> str:
        """Render finding count summary cards."""
        counts = report_data.get("finding_counts", {})
        cards = []

        count_items = [
            ("Total", counts.get("total", 0), self._TEXT_COLOR),
            ("Critical", counts.get("critical", 0), ReportConfig.HTML_SEVERITY_COLORS.get("critical", "")),
            ("High", counts.get("high", 0), ReportConfig.HTML_SEVERITY_COLORS.get("high", "")),
            ("Medium", counts.get("medium", 0), ReportConfig.HTML_SEVERITY_COLORS.get("medium", "")),
            ("DAST", counts.get("dast", 0), self._TEXT_COLOR),
            ("SAST", counts.get("sast", 0), self._TEXT_COLOR),
            ("Cross-Ref", counts.get("cross_referenced", 0), self._TEXT_COLOR),
        ]

        for label, count, color in count_items:
            cards.append(
                f"<div class=\"count-card\">"
                f"<div class=\"count-number\" style=\"color: {color};\">{count}</div>"
                f"<div class=\"count-label\">{escape(label)}</div>"
                f"</div>"
            )

        return (
            f"<div class=\"counts-grid\">{''.join(cards)}</div>"
        )

    def _render_findings_section(self, title: str, findings: list[dict]) -> str:
        """Render a section of findings as cards."""
        header = f"<h2>{escape(title)}</h2>\n"

        if not findings:
            return header + f"<p class=\"muted\">{escape(ReportConfig.HTML_NO_FINDINGS_MESSAGE)}</p>"

        cards = []
        for finding in findings:
            cards.append(self._render_finding_card(finding))

        return header + "\n".join(cards)

    def _render_finding_card(self, finding: dict) -> str:
        """Render a single finding as an HTML card."""
        severity = finding.get("severity", "info")
        severity_color = ReportConfig.HTML_SEVERITY_COLORS.get(
            severity, self._MUTED_TEXT_COLOR
        )
        title = escape(finding.get("title", ""))
        description = escape(finding.get("description", ""))
        scanner = escape(finding.get("scanner", ""))
        source = escape(finding.get("source", ""))
        endpoint = finding.get("endpoint_url")
        code_loc = finding.get("code_location")
        remediation = finding.get("remediation_guidance")
        confidence = finding.get("confidence", 0)

        parts = [
            f"<div class=\"finding-card\">",
            f"  <div style=\"display: flex; align-items: center; gap: 8px; margin-bottom: 8px;\">",
            f"    <span class=\"severity-badge\" style=\"background: {severity_color};\">"
            f"{escape(severity.upper())}</span>",
            f"    <strong>{title}</strong>",
            f"    <span class=\"muted\" style=\"margin-left: auto;\">"
            f"{scanner} ({source}) | conf: {confidence:.0%}</span>",
            f"  </div>",
            f"  <p>{description}</p>",
        ]

        if endpoint:
            parts.append(
                f"  <p class=\"muted\">Endpoint: {escape(endpoint)}</p>"
            )

        if code_loc:
            file_path = escape(code_loc.get("file", ""))
            line = code_loc.get("line")
            snippet = code_loc.get("snippet", "")
            location_str = f"{file_path}"
            if line is not None:
                location_str += f":{line}"
            parts.append(f"  <p class=\"muted\">Location: {location_str}</p>")
            if snippet:
                truncated = snippet[: self._MAX_SNIPPET_DISPLAY_LENGTH]
                parts.append(
                    f"  <div class=\"code-snippet\">{escape(truncated)}</div>"
                )

        if remediation:
            parts.append(
                f"  <p><strong>Remediation:</strong></p>"
                f"  <p>{escape(remediation)}</p>"
            )

        parts.append("</div>")
        return "\n".join(parts)

    def _render_remediation_checklist(self, report_data: dict) -> str:
        """Render remediation checklist as a table."""
        header = f"<h2>{escape(ReportConfig.SECTION_REMEDIATION)}</h2>\n"
        checklist = report_data.get("remediation_checklist", [])

        if not checklist:
            return header + f"<p class=\"muted\">{escape(ReportConfig.HTML_NO_FINDINGS_MESSAGE)}</p>"

        rows = []
        for item in checklist:
            severity = item.get("severity", "info")
            severity_color = ReportConfig.HTML_SEVERITY_COLORS.get(
                severity, self._MUTED_TEXT_COLOR
            )
            fix_icon = "Yes" if item.get("fix_available") else "No"
            rows.append(
                f"<tr>"
                f"<td>{item.get('priority', '')}</td>"
                f"<td><span class=\"severity-badge\" style=\"background: {severity_color};\">"
                f"{escape(severity.upper())}</span></td>"
                f"<td>{escape(item.get('category', ''))}</td>"
                f"<td>{escape(item.get('action', ''))}</td>"
                f"<td>{item.get('finding_count', 0)}</td>"
                f"<td>{fix_icon}</td>"
                f"</tr>"
            )

        return (
            header
            + "<table>\n"
            + "<tr><th>#</th><th>Severity</th><th>Category</th>"
            + "<th>Action</th><th>Findings</th><th>Fix Available</th></tr>\n"
            + "\n".join(rows)
            + "\n</table>"
        )

    def _render_footer(self, report_data: dict) -> str:
        """Render report footer with metadata."""
        endpoints = report_data.get("endpoints_discovered", 0)
        return (
            f"<hr style=\"margin-top: 32px; border: none; "
            f"border-top: 1px solid {self._BORDER_COLOR};\">\n"
            f"<p class=\"muted\" style=\"font-size: 12px;\">"
            f"Endpoints discovered: {endpoints} | "
            f"Generated by BrandifAI Deep Security Scanner</p>"
        )
