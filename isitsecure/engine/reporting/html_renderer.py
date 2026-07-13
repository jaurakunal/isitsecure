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

    # Risk Summary callout styling (owner-friendly, non-technical section)
    _RISK_CALLOUT_BG = "#eff6ff"
    _RISK_CALLOUT_BORDER = "#bfdbfe"
    _RISK_CALLOUT_ACCENT = "#1d4ed8"

    # Section titles owned by the renderer (owner-facing sections)
    _SECTION_RISK_SUMMARY = "What This Means for You"
    _SECTION_KEY_RISKS = "Your Biggest Risks"
    _SECTION_ACTION_PLAN = "Recommended Action Plan"
    _SECTION_THEMES = "Security Themes"

    def render(self, report_data: dict) -> str:
        """Render report dict to HTML string.

        Args:
            report_data: Structured report dict from ReportGenerator.generate().

        Returns:
            Complete HTML document string with inline CSS.
        """
        grade = report_data.get("grade", "?")
        # Granular grades (A+, A-, C+, ...) share the color of their base
        # letter (A-F), so look up the color by the base letter.
        grade_base = report_data.get("grade_base", grade)
        grade_color = ReportConfig.HTML_GRADE_COLORS.get(
            grade_base, self._MUTED_TEXT_COLOR
        )

        sections = [
            # #57 — launch-readiness verdict is the very first thing shown.
            self._render_launch_verdict(report_data),
            self._render_header(report_data, grade, grade_color),
            self._render_risk_summary(report_data),
            self._render_executive_summary(report_data),
            self._render_finding_counts(report_data),
            self._render_themes(report_data),
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
            f"    .risk-callout {{ background: {self._RISK_CALLOUT_BG}; "
            f"border: 1px solid {self._RISK_CALLOUT_BORDER}; "
            f"border-left: 6px solid {self._RISK_CALLOUT_ACCENT}; border-radius: 8px; "
            f"padding: 16px 20px; margin: 20px 0; }}\n"
            f"    .risk-callout h2 {{ border: none; margin: 0 0 8px 0; padding: 0; "
            f"font-size: 18px; color: {self._RISK_CALLOUT_ACCENT}; }}\n"
            f"    .risk-callout .risk-text {{ font-size: 15px; line-height: 1.7; }}\n"
            f"    .risk-callout h3 {{ font-size: 14px; margin: 16px 0 6px 0; }}\n"
            f"    .risk-callout ul {{ margin: 6px 0 0 0; padding-left: 20px; }}\n"
            f"    .risk-callout li {{ margin: 4px 0; }}\n"
            f"    .phase-card {{ background: {self._BODY_BG}; "
            f"border: 1px solid {self._RISK_CALLOUT_BORDER}; border-radius: 6px; "
            f"padding: 10px 14px; margin: 8px 0; }}\n"
            f"    .phase-num {{ display: inline-block; min-width: 22px; height: 22px; "
            f"line-height: 22px; text-align: center; border-radius: 50%; "
            f"background: {self._RISK_CALLOUT_ACCENT}; color: white; font-size: 12px; "
            f"font-weight: 600; margin-right: 8px; }}\n"
            f"    .disclaimer {{ font-size: 12px; color: {self._MUTED_TEXT_COLOR}; "
            f"margin-top: 12px; }}\n"
            f"    .theme-card {{ border: 1px solid {self._BORDER_COLOR}; border-radius: 8px; "
            f"padding: 12px 16px; margin: 8px 0; }}\n"
            # #57 — launch-readiness verdict banner (go = green, no-go = red).
            f"    .verdict {{ border-radius: 10px; padding: 16px 20px; margin: 0 0 20px 0; "
            f"font-size: 17px; font-weight: 600; display: flex; align-items: baseline; "
            f"gap: 10px; flex-wrap: wrap; }}\n"
            f"    .verdict.go {{ background: #ecfdf5; border: 1px solid #a7f3d0; "
            f"color: #065f46; }}\n"
            f"    .verdict.nogo {{ background: #fef2f2; border: 1px solid #fecaca; "
            f"color: #991b1b; }}\n"
            f"    .verdict .verdict-detail {{ font-weight: 400; font-size: 14px; }}\n"
            # #43 — plain-language grade legend under the grade badge.
            f"    .grade-legend {{ font-size: 12px; color: {self._MUTED_TEXT_COLOR}; "
            f"margin-top: 4px; }}\n"
            # #44 — business-impact-first line on each finding card.
            f"    .impact-line {{ font-weight: 600; margin: 0 0 8px 0; }}\n"
            # #41 — three-part plain-English explanation block.
            f"    .plain-explain {{ background: #f9fafb; border-radius: 6px; "
            f"padding: 10px 14px; margin: 8px 0; }}\n"
            f"    .plain-explain dt {{ font-weight: 600; font-size: 12px; "
            f"text-transform: uppercase; letter-spacing: .02em; "
            f"color: {self._MUTED_TEXT_COLOR}; margin-top: 6px; }}\n"
            f"    .plain-explain dt:first-child {{ margin-top: 0; }}\n"
            f"    .plain-explain dd {{ margin: 2px 0 0 0; }}\n"
            # #42 — inline glossary tooltip (dotted underline + hover title).
            f"    .glossary-term {{ border-bottom: 1px dotted {self._MUTED_TEXT_COLOR}; "
            f"cursor: help; }}\n"
            f"    .glossary-list {{ font-size: 12px; color: {self._MUTED_TEXT_COLOR}; "
            f"margin: 6px 0 0 0; }}\n"
            "  </style>\n"
            "</head>\n"
            f"<body>\n{body}\n</body>\n"
            "</html>"
        )

    def _render_launch_verdict(self, report_data: dict) -> str:
        """Render the go/no-go launch-readiness banner at the top (#57).

        Returns an empty string when no verdict is present so the report
        still renders (older report dicts, or partial data).
        """
        verdict = report_data.get("launch_verdict")
        if not verdict:
            return ""

        headline = escape(verdict.get("headline", ""))
        if not headline:
            return ""
        detail = escape(verdict.get("detail", "") or "")
        css_class = "go" if verdict.get("ready") else "nogo"

        detail_html = (
            f"<span class=\"verdict-detail\">{detail}</span>" if detail else ""
        )
        return (
            f"<div class=\"verdict {css_class}\">"
            f"<span>{headline}</span>{detail_html}"
            f"</div>"
        )

    def _render_header(self, report_data: dict, grade: str, grade_color: str) -> str:
        """Render report header with title and grade badge."""
        title = escape(report_data.get("title", ReportConfig.REPORT_TITLE))
        grade_label = escape(report_data.get("grade_label", ""))
        grade_legend = escape(report_data.get("grade_legend", ""))
        target = escape(report_data.get("target_url", "") or "")
        scan_mode = escape(report_data.get("scan_mode", ""))
        duration = report_data.get("duration_seconds", 0)
        scanners = report_data.get("scanners_run", [])

        scanners_str = escape(", ".join(scanners)) if scanners else "N/A"

        legend_html = (
            f"    <div class=\"grade-legend\">{grade_legend}</div>\n"
            if grade_legend
            else ""
        )

        return (
            f"<h1>{title}</h1>\n"
            f"<div style=\"display: flex; align-items: center; gap: 16px; margin: 16px 0;\">\n"
            f"  <div class=\"grade-badge\" style=\"background: {grade_color};\">"
            f"{escape(grade)}</div>\n"
            f"  <div>\n"
            f"    <div style=\"font-size: 16px; font-weight: 600;\">{grade_label}</div>\n"
            f"{legend_html}"
            f"    <div class=\"muted\">Target: {target}</div>\n"
            f"    <div class=\"muted\">Mode: {scan_mode} | "
            f"Duration: {duration:.1f}s | Scanners: {scanners_str}</div>\n"
            f"  </div>\n"
            f"</div>"
        )

    def _render_risk_summary(self, report_data: dict) -> str:
        """Render the plain-English owner risk summary as a callout box.

        Rendered prominently near the top of the report for non-technical
        readers. Returns an empty string when no owner summary is present
        (e.g. ``--llm none`` scans) so the section degrades gracefully.
        """
        owner = report_data.get("owner_summary")
        if not owner:
            return ""

        parts = ["<div class=\"risk-callout\">"]
        parts.append(f"  <h2>{escape(self._SECTION_RISK_SUMMARY)}</h2>")

        risk_summary = owner.get("risk_summary", "")
        if risk_summary and risk_summary.strip():
            parts.append(
                f"  <div class=\"risk-text\">{escape(risk_summary)}</div>"
            )

        key_risks = owner.get("key_risks") or []
        if key_risks:
            parts.append(f"  <h3>{escape(self._SECTION_KEY_RISKS)}</h3>")
            parts.append("  <ul>")
            for risk in key_risks:
                parts.append(f"    <li>{escape(str(risk))}</li>")
            parts.append("  </ul>")

        phases = owner.get("remediation_phases") or []
        if phases:
            parts.append(f"  <h3>{escape(self._SECTION_ACTION_PLAN)}</h3>")
            for phase in phases:
                number = escape(str(phase.get("phase_number", "")))
                title = escape(phase.get("title", ""))
                description = escape(phase.get("description", ""))
                count = phase.get("finding_count", 0)
                count_str = (
                    f" <span class=\"muted\">({count} finding"
                    f"{'s' if count != 1 else ''})</span>"
                    if count
                    else ""
                )
                parts.append(
                    f"  <div class=\"phase-card\">"
                    f"<span class=\"phase-num\">{number}</span>"
                    f"<strong>{title}</strong>{count_str}"
                    f"<div style=\"margin-top: 4px;\">{description}</div>"
                    f"</div>"
                )

        disclaimer_bits = []
        scope = owner.get("scope_disclaimer", "")
        if scope and scope.strip():
            disclaimer_bits.append(escape(scope))
        not_report = owner.get("what_this_report_is_not", "")
        if not_report and not_report.strip():
            disclaimer_bits.append(escape(not_report))
        if disclaimer_bits:
            parts.append(
                f"  <div class=\"disclaimer\">{' '.join(disclaimer_bits)}</div>"
            )

        parts.append("</div>")
        return "\n".join(parts)

    def _render_themes(self, report_data: dict) -> str:
        """Render thematic groupings of findings, if present.

        Returns an empty string when no themes are available so the
        section is omitted entirely rather than showing an empty heading.
        """
        themes = report_data.get("themes") or []
        if not themes:
            return ""

        cards = [f"<h2>{escape(self._SECTION_THEMES)}</h2>"]
        for theme in themes:
            title = escape(theme.get("title", ""))
            description = escape(theme.get("description", ""))
            severity = theme.get("severity", "") or ""
            count = theme.get("finding_count", 0)

            badge = ""
            if severity:
                severity_color = ReportConfig.HTML_SEVERITY_COLORS.get(
                    severity.lower(), self._MUTED_TEXT_COLOR
                )
                badge = (
                    f"<span class=\"severity-badge\" style=\"background: "
                    f"{severity_color};\">{escape(severity.upper())}</span> "
                )

            count_str = (
                f"<span class=\"muted\" style=\"margin-left: auto;\">"
                f"{count} finding{'s' if count != 1 else ''}</span>"
                if count
                else ""
            )
            cards.append(
                f"<div class=\"theme-card\">"
                f"<div style=\"display: flex; align-items: center; gap: 8px; "
                f"margin-bottom: 6px;\">{badge}<strong>{title}</strong>"
                f"{count_str}</div>"
                f"<p>{description}</p>"
                f"</div>"
            )

        return "\n".join(cards)

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
        impact = finding.get("business_impact", "")
        explanation = finding.get("plain_explanation") or {}
        glossary = finding.get("glossary") or {}

        parts = [
            f"<div class=\"finding-card\">",
            f"  <div style=\"display: flex; align-items: center; gap: 8px; margin-bottom: 8px;\">",
            f"    <span class=\"severity-badge\" style=\"background: {severity_color};\">"
            f"{escape(severity.upper())}</span>",
            f"    <strong>{title}</strong>",
            f"    <span class=\"muted\" style=\"margin-left: auto;\">"
            f"{scanner} ({source}) | conf: {confidence:.0%}</span>",
            f"  </div>",
        ]

        # #44 — lead the card with the plain-English business impact.
        if impact:
            parts.append(f"  <p class=\"impact-line\">{escape(impact)}</p>")

        # #41 — three-part rule-based plain-English explanation.
        if explanation:
            parts.append(self._render_plain_explanation(explanation))

        parts.append(f"  <p class=\"muted\">{description}</p>")

        # #42 — inline glossary definitions for jargon in this finding.
        if glossary:
            terms = "; ".join(
                f"<span class=\"glossary-term\" title=\"{escape(defn)}\">"
                f"{escape(term.upper())}</span> — {escape(defn)}"
                for term, defn in glossary.items()
            )
            parts.append(f"  <p class=\"glossary-list\">{terms}</p>")

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

    def _render_plain_explanation(self, explanation: dict) -> str:
        """Render the three-part plain-English explanation block (#41)."""
        rows = [
            ("What it is", explanation.get("what_it_is", "")),
            ("What an attacker could do", explanation.get("attacker_could", "")),
            ("What to do", explanation.get("what_to_do", "")),
        ]
        items = []
        for label, text in rows:
            if not text:
                continue
            items.append(
                f"<dt>{escape(label)}</dt><dd>{escape(text)}</dd>"
            )
        if not items:
            return ""
        return f"  <dl class=\"plain-explain\">{''.join(items)}</dl>"

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
            # #44 — lead the row with the owner-facing consequence, and keep
            # the technical category as a muted secondary label beneath it.
            impact = escape(item.get("business_impact", ""))
            category = escape(item.get("category", ""))
            what_cell = impact or escape(item.get("action", ""))
            rows.append(
                f"<tr>"
                f"<td>{item.get('priority', '')}</td>"
                f"<td><span class=\"severity-badge\" style=\"background: {severity_color};\">"
                f"{escape(severity.upper())}</span></td>"
                f"<td>{what_cell}"
                f"<div class=\"muted\" style=\"font-size:12px;\">{category}</div></td>"
                f"<td>{item.get('finding_count', 0)}</td>"
                f"<td>{fix_icon}</td>"
                f"</tr>"
            )

        return (
            header
            + "<table>\n"
            + "<tr><th>#</th><th>Severity</th><th>What this means for you</th>"
            + "<th>Findings</th><th>Fix Available</th></tr>\n"
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
            f"Generated by isitsecure — https://isitsecure.ai</p>"
        )
