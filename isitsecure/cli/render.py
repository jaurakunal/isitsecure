"""Turning a scan report into something to look at or hand to another tool.

Table, HTML, SARIF, badge SVG and the LLM fix plan — all pure rendering, with
no scanning and no command wiring, so each output format can be exercised on a
report object alone.
"""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table

from isitsecure.cli._io import console

async def _generate_fixes(report, llm_client, repo_url: str | None) -> str:
    """Generate LLM-powered fixes for critical and high findings."""
    from isitsecure.engine.fixes.fix_generator import FixGenerator
    from isitsecure.engine.fixes.markdown_exporter import FixPlanMarkdownExporter

    # Filter to fixable findings (SAST with code locations)
    fixable = [
        f for f in report.findings
        if f.code_location and f.code_location.file_path
        and f.severity.value in ("critical", "high")
    ]

    if not fixable:
        return "# isitsecure Fix Plan\n\nNo critical or high findings with source code locations to fix."

    # Build file content map from the report's findings
    # If we have a local repo, read the files directly
    file_contents: dict[str, str] = {}
    if repo_url and repo_url.startswith("file://"):
        import os
        repo_path = repo_url.replace("file://", "").rstrip("/")
        for finding in fixable:
            fp = finding.code_location.file_path
            if fp not in file_contents:
                full_path = os.path.join(repo_path, fp)
                if os.path.isfile(full_path):
                    try:
                        file_contents[fp] = open(full_path).read()
                    except Exception:
                        pass

    # Fall back to code snippets from findings if we can't read files
    for finding in fixable:
        fp = finding.code_location.file_path
        if fp not in file_contents and finding.code_location.code_snippet:
            file_contents[fp] = finding.code_location.code_snippet

    console.print(f"  Generating fixes for {len(fixable)} findings across {len(file_contents)} files...")

    generator = FixGenerator(llm_client)
    plan = await generator.generate_fix_plan(fixable, file_contents)

    exporter = FixPlanMarkdownExporter()
    return exporter.export(plan)


def _generate_sarif_report(report) -> str:
    """Generate a SARIF 2.1.0 report from a DeepScanReport."""
    from isitsecure.engine.reporting.sarif_renderer import SARIFRenderer

    renderer = SARIFRenderer()
    return renderer.render(report)


def _generate_html_report(report) -> str:
    """Generate a self-contained HTML report from a DeepScanReport."""
    from isitsecure.engine.reporting.report_generator import ReportGenerator
    from isitsecure.engine.reporting.html_renderer import HTMLReportRenderer

    generator = ReportGenerator()
    renderer = HTMLReportRenderer()
    report_data = generator.generate(report)
    return renderer.render(report_data)


def _print_report_table(report) -> None:
    """Print a summary table of the scan report.

    Leads with a rule-based, LLM-free launch-readiness verdict and a
    granular grade so a non-technical user gets a clear go/no-go up top,
    then a business-impact-first findings table with plain-English framing.
    """
    from isitsecure.engine.reporting import plain_english

    # #43 — granular grade (A+/A/A-/.../F) + plain-language legend.
    grade_result = plain_english.calculate_grade(
        critical=report.critical_count,
        high=report.high_count,
        medium=report.medium_count,
        low=sum(
            1 for f in report.findings
            if (f.severity.value if hasattr(f.severity, "value") else f.severity)
            == "low"
        ),
    )
    grade = grade_result.grade

    # #57 — go/no-go launch verdict, rendered first and most prominently.
    verdict = plain_english.launch_verdict(
        report.critical_count, report.high_count, report.medium_count
    )
    console.print()
    console.print(Panel(
        f"[bold]{verdict.headline}[/bold]"
        + (f"\n{verdict.detail}" if verdict.detail else ""),
        title="Launch Readiness",
        border_style="green" if verdict.ready else "red",
    ))

    console.print(Panel(
        f"[bold]Grade: {grade}[/bold] — {grade_result.label}\n"
        f"[dim]{grade_result.legend}[/dim]\n\n"
        f"Critical: {report.critical_count}  |  "
        f"High: {report.high_count}  |  "
        f"Medium: {report.medium_count}  |  "
        f"Endpoints: {report.total_endpoints_discovered}  |  "
        f"Scanners: {len(report.scanners_run)}  |  "
        f"Duration: {report.scan_duration_seconds:.0f}s",
        title="Results",
        border_style="bright_magenta",
    ))

    if not report.findings:
        console.print("[green]No vulnerabilities found![/green]")
        return

    # Findings table — business-impact-first (#44), with plain-English
    # framing and inline glossary (#41, #42).
    table = Table(title="Findings", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Severity", width=9)
    table.add_column("What this means for you", width=48)
    table.add_column("Category", width=18)
    table.add_column("Detail", width=40)

    severity_colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    # Order most-severe first so the biggest risks are read first.
    severity_order = {
        "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
    }

    def _sev(f):
        return f.severity.value if hasattr(f.severity, "value") else str(f.severity)

    ordered = sorted(report.findings, key=lambda f: severity_order.get(_sev(f), 5))

    seen_glossary: set[str] = set()
    for i, finding in enumerate(ordered, 1):
        sev = _sev(finding)
        color = severity_colors.get(sev, "white")
        category = finding.category.value if hasattr(finding.category, "value") else str(finding.category)

        # #44 — consequence-first summary column.
        impact = plain_english.business_impact(finding.category)
        # #42 — expand each acronym once on first use (parenthetical).
        detail = finding.title[:40]
        for term, definition in plain_english.GLOSSARY.items():
            if term in seen_glossary:
                continue
            import re as _re
            if _re.search(rf"\b{_re.escape(term)}\b", f"{finding.title} {category}".lower()):
                detail = f"{detail}\n[dim]{term.upper()}: {definition}[/dim]"
                seen_glossary.add(term)
                break

        # Stable fingerprint so the user can `--suppress` this finding (#38/#51).
        detail = f"{detail}\n[dim]fp {finding.fingerprint}[/dim]"

        table.add_row(
            str(i),
            f"[{color}]{sev.upper()}[/{color}]",
            impact,
            category,
            detail,
        )

    console.print(table)

    # #49 — step-by-step walkthroughs for the top-4 fixes, as numbered lists.
    # One walkthrough per category present (deduped), so a repo with several
    # IDOR findings shows the "add an ownership check" steps once.
    seen_walkthroughs: set[str] = set()
    for finding in ordered:
        walkthrough = plain_english.walkthrough_for(finding.category)
        if walkthrough is None:
            continue
        cat = finding.category.value if hasattr(finding.category, "value") else str(finding.category)
        if cat in seen_walkthroughs:
            continue
        seen_walkthroughs.add(cat)
        steps = "\n".join(
            f"[bold]{i}.[/bold] {step}"
            for i, step in enumerate(walkthrough.steps, 1)
        )
        console.print()
        console.print(Panel(
            steps,
            title=f"How to fix, step by step: {walkthrough.title}",
            border_style="cyan",
        ))

    # Owner summary (LLM layer, if present) — layers on top of the baseline.
    if report.owner_summary and report.owner_summary.risk_summary:
        console.print()
        console.print(Panel(
            report.owner_summary.risk_summary,
            title="Risk Summary",
            border_style="yellow",
        ))


def _generate_badge_svg(grade: str, critical: int, high: int, total: int) -> str:
    """Generate a shields.io-style SVG badge for the security grade."""
    GRADE_COLORS = {
        "A": "#4c1",      # Green
        "B": "#97ca00",   # Yellow-green
        "C": "#dfb317",   # Yellow
        "D": "#fe7d37",   # Orange
        "F": "#e05d44",   # Red
    }
    # Grades are now granular (A+, A-, C+, ...); color by the base letter.
    color = GRADE_COLORS.get(grade[:1], "#9f9f9f")

    label = "security"
    value = grade
    if total > 0:
        value = f"{grade} ({total} findings)"

    label_width = len(label) * 6.5 + 10
    value_width = len(value) * 6.5 + 10
    total_width = label_width + value_width

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{label}: {value}">
  <title>{label}: {value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text aria-hidden="true" x="{label_width/2}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
    <text x="{label_width/2}" y="14">{label}</text>
    <text aria-hidden="true" x="{label_width + value_width/2}" y="15" fill="#010101" fill-opacity=".3">{value}</text>
    <text x="{label_width + value_width/2}" y="14">{value}</text>
  </g>
</svg>'''
