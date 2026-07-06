"""isitsecure CLI - AI-powered security scanner for modern web apps.

Usage:
    isitsecure scan https://myapp.com                          # URL-only DAST scan
    isitsecure scan --repo github.com/me/app --mode code-only  # SAST only
    isitsecure scan https://myapp.com --repo github.com/me/app --mode full  # Full scan
    isitsecure launch                                          # Open web UI
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from isitsecure import __version__

app = typer.Typer(
    name="isitsecure",
    help="AI-powered security scanner for modern web apps. SAST + DAST + LLM review.",
    no_args_is_help=True,
)
console = Console()


# ---------------------------------------------------------------------------
# Config management
# ---------------------------------------------------------------------------

from isitsecure.config import CONFIG_DIR, CONFIG_FILE, load_api_key


def _ensure_config_dir() -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return CONFIG_DIR


def _load_api_key(provider: str) -> str | None:
    """Load API key from env, .env file, or config (see isitsecure.config)."""
    return load_api_key(provider)


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@app.command()
def scan(
    target_url: Optional[str] = typer.Argument(None, help="URL to scan (DAST)"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="GitHub repo URL (SAST)"),
    branch: str = typer.Option("main", "--branch", "-b", help="Git branch"),
    github_token: Optional[str] = typer.Option(None, "--github-token", envvar="GITHUB_TOKEN"),
    mode: str = typer.Option("auto", "--mode", "-m", help="Scan mode: auto|url-only|code-only|authenticated|full"),
    auth_email: Optional[str] = typer.Option(None, "--auth-email", help="Auth email for authenticated scanning"),
    auth_password: Optional[str] = typer.Option(None, "--auth-password", help="Auth password"),
    auth_provider: str = typer.Option("supabase", "--auth-provider", help="Auth provider: supabase|firebase|browser|token"),
    llm_provider: str = typer.Option("anthropic", "--llm", help="LLM provider: anthropic|google|none"),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table|json|html|sarif|fixes"),
    output_file: Optional[str] = typer.Option(None, "--output-file", "-f", help="Write report to file"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run a security scan against a web application."""
    if not target_url and not repo:
        console.print("[red]Error: provide a target URL, a --repo, or both.[/red]")
        raise typer.Exit(1)

    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    # Resolve LLM client
    llm_client = None
    judgment_llm_client = None
    if llm_provider != "none":
        api_key = _load_api_key(llm_provider)
        if not api_key:
            console.print(
                f"[yellow]No API key found for {llm_provider}. "
                f"Set {llm_provider.upper()}_API_KEY in your environment or .env file.\n"
                f"Running without LLM review (reduced accuracy).[/yellow]"
            )
        else:
            from isitsecure.llm.adapters import create_llm_client
            llm_client = create_llm_client(llm_provider, api_key)
            judgment_llm_client = create_llm_client(llm_provider, api_key, judgment=True)

    # Build scanner
    from isitsecure.engine.factory import (
        create_deep_security_scan_agent,
        create_repo_ingestion_service,
    )

    repo_service = create_repo_ingestion_service() if repo else None
    agent = create_deep_security_scan_agent(
        llm_client=llm_client,
        judgment_llm_client=judgment_llm_client,
        repo_ingestion_service=repo_service,
    )

    # Build credentials
    credentials_a = None
    if auth_email and auth_password:
        from isitsecure.engine.auth.protocols import AuthCredentials
        from isitsecure.engine.enums import AuthProvider as AuthProviderEnum
        credentials_a = AuthCredentials(
            provider=AuthProviderEnum(auth_provider),
            email=auth_email,
            password=auth_password,
        )

    # Resolve scan mode
    from isitsecure.engine.enums import ScanMode
    scan_mode_map = {
        "url-only": ScanMode.URL_ONLY,
        "code-only": ScanMode.CODE_ONLY,
        "authenticated": ScanMode.AUTHENTICATED,
        "full": ScanMode.FULL,
    }
    resolved_mode = scan_mode_map.get(mode) if mode != "auto" else None

    # Run scan with progress display
    console.print(Panel(
        f"[bold]isitsecure v{__version__}[/bold]\n"
        f"Target: {target_url or 'N/A'}  |  Repo: {repo or 'N/A'}  |  LLM: {llm_provider}",
        title="Security Scan",
        border_style="bright_magenta",
    ))

    report = asyncio.run(_run_scan(
        agent=agent,
        target_url=target_url,
        repo_url=repo,
        github_token=github_token,
        credentials_a=credentials_a,
        scan_mode=resolved_mode,
    ))

    # Output results
    if output == "json":
        result_json = report.model_dump_json(indent=2)
        if output_file:
            Path(output_file).write_text(result_json)
            console.print(f"[green]Report written to {output_file}[/green]")
        else:
            console.print(result_json)
    elif output == "html":
        html_content = _generate_html_report(report)
        out_path = output_file or "isitsecure-report.html"
        Path(out_path).write_text(html_content)
        console.print(f"[green]HTML report written to {out_path}[/green]")
    elif output == "sarif":
        sarif_content = _generate_sarif_report(report)
        out_path = output_file or "isitsecure-results.sarif"
        Path(out_path).write_text(sarif_content)
        console.print(f"[green]SARIF report written to {out_path}[/green]")
        console.print(
            "[dim]Upload to GitHub: gh api repos/OWNER/REPO/code-scanning/sarifs "
            f"-f 'sarif=@{out_path}' -f commit_sha=$(git rev-parse HEAD)[/dim]"
        )
    elif output == "fixes":
        if not llm_client:
            console.print("[red]Fix generation requires an LLM API key. Set ANTHROPIC_API_KEY or use --llm anthropic.[/red]")
            raise typer.Exit(1)
        _print_report_table(report)
        console.print("\n[bold]Generating fixes...[/bold]")
        fix_md = asyncio.run(_generate_fixes(report, llm_client, repo))
        out_path = output_file or "isitsecure-fixes.md"
        Path(out_path).write_text(fix_md)
        console.print(f"\n[green]Fix plan written to {out_path}[/green]")
        console.print("[dim]Paste into Cursor or Claude Code: 'Apply all the security fixes in this document'[/dim]")
    elif output == "table":
        _print_report_table(report)
        if output_file:
            Path(output_file).write_text(report.model_dump_json(indent=2))
            console.print(f"\n[green]Full report written to {output_file}[/green]")
    else:
        console.print(f"[yellow]Output format '{output}' not yet implemented. Using table.[/yellow]")
        _print_report_table(report)


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


async def _run_scan(agent, **kwargs):
    """Run the scan and display progress."""
    report = None

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Initializing...", total=100)

        async for event in agent.scan(**kwargs):
            phase = getattr(event, "phase", "")
            message = getattr(event, "message", "")
            pct = getattr(event, "progress", 0)
            data = getattr(event, "data", None)

            description = message or phase or "Scanning..."
            if len(description) > 60:
                description = description[:57] + "..."
            progress.update(task, completed=pct, description=description)

            # The final COMPLETE event carries the report as a JSON dict
            # under data["report"]; reconstruct the model from it.
            if isinstance(data, dict) and "report" in data:
                from isitsecure.engine.models import DeepScanReport

                report = DeepScanReport.model_validate(data["report"])

    if report is None:
        console.print("[red]Scan completed but no report was generated.[/red]")
        raise typer.Exit(1)

    return report


def _print_report_table(report) -> None:
    """Print a summary table of the scan report."""
    # Grade
    grade = "N/A"
    if report.owner_summary:
        grade = report.owner_summary.grade

    console.print()
    console.print(Panel(
        f"[bold]Grade: {grade}[/bold]  |  "
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

    # Findings table
    table = Table(title="Findings", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Category", width=20)
    table.add_column("Title", width=50)
    table.add_column("Scanner", width=20)
    table.add_column("Source", width=12)

    severity_colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for i, finding in enumerate(report.findings, 1):
        sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        color = severity_colors.get(sev, "white")
        table.add_row(
            str(i),
            f"[{color}]{sev.upper()}[/{color}]",
            str(finding.category.value if hasattr(finding.category, "value") else finding.category),
            finding.title[:50],
            finding.scanner_name or "",
            str(finding.source.value if hasattr(finding.source, "value") else finding.source),
        )

    console.print(table)

    # Owner summary
    if report.owner_summary and report.owner_summary.risk_summary:
        console.print()
        console.print(Panel(
            report.owner_summary.risk_summary,
            title="Risk Summary",
            border_style="yellow",
        ))


# ---------------------------------------------------------------------------
# launch command (web UI)
# ---------------------------------------------------------------------------

@app.command()
def launch(
    port: int = typer.Option(3000, "--port", "-p", help="Port for the web UI"),
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to"),
) -> None:
    """Launch the isitsecure web UI in your browser."""
    import webbrowser

    import uvicorn

    console.print(Panel(
        f"[bold]isitsecure v{__version__}[/bold]\n"
        f"Starting web UI at http://{host}:{port}",
        title="Web UI",
        border_style="bright_magenta",
    ))

    webbrowser.open(f"http://{host}:{port}")
    uvicorn.run(
        "isitsecure.server.app:app",
        host=host,
        port=port,
        log_level="warning",
    )


# ---------------------------------------------------------------------------
# fix command — scan + generate fixes + apply them
# ---------------------------------------------------------------------------

@app.command()
def fix(
    repo: str = typer.Option(..., "--repo", "-r", help="Path to local repo to fix"),
    llm_provider: str = typer.Option("anthropic", "--llm", help="LLM provider: anthropic|google"),
    api_key: Optional[str] = typer.Option(None, "--api-key", envvar="ANTHROPIC_API_KEY"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show fixes without applying them"),
    severity: str = typer.Option("critical,high", "--severity", help="Severities to fix: critical,high,medium"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Scan, generate AI fixes, and apply them to your code in one command."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    # Resolve API key
    resolved_key = api_key or _load_api_key(llm_provider)
    if not resolved_key:
        console.print(
            f"[red]Fix generation requires an API key. "
            f"Set {llm_provider.upper()}_API_KEY or pass --api-key.[/red]"
        )
        raise typer.Exit(1)

    from isitsecure.llm.adapters import create_llm_client
    llm_client = create_llm_client(llm_provider, resolved_key)

    # Resolve repo path
    import os
    repo_path = os.path.abspath(repo.replace("file://", ""))
    if not os.path.isdir(repo_path):
        console.print(f"[red]Repository path not found: {repo_path}[/red]")
        raise typer.Exit(1)

    repo_url = f"file://{repo_path}"

    # Step 1: Scan
    console.print(Panel(
        f"[bold]isitsecure fix[/bold]\n"
        f"Repo: {repo_path}  |  LLM: {llm_provider}  |  {'Dry run' if dry_run else 'Will apply fixes'}",
        title="Auto-Fix",
        border_style="bright_magenta",
    ))

    from isitsecure.engine.factory import create_deep_security_scan_agent, create_repo_ingestion_service
    repo_service = create_repo_ingestion_service()
    agent = create_deep_security_scan_agent(
        llm_client=llm_client,
        judgment_llm_client=llm_client,
        repo_ingestion_service=repo_service,
    )

    console.print("\n[bold]Step 1/3:[/bold] Scanning for vulnerabilities...")
    report = asyncio.run(_run_scan(agent=agent, repo_url=repo_url, scan_mode=None))
    _print_report_table(report)

    # Step 2: Generate fixes
    target_severities = {s.strip().lower() for s in severity.split(",")}
    fixable = [
        f for f in report.findings
        if f.code_location and f.code_location.file_path
        and (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) in target_severities
    ]

    if not fixable:
        console.print("\n[green]No fixable findings at the selected severity levels.[/green]")
        raise typer.Exit(0)

    console.print(f"\n[bold]Step 2/3:[/bold] Generating fixes for {len(fixable)} findings...")

    # Read file contents
    file_contents: dict[str, str] = {}
    for finding in fixable:
        fp = finding.code_location.file_path
        if fp not in file_contents:
            full_path = os.path.join(repo_path, fp)
            if os.path.isfile(full_path):
                try:
                    file_contents[fp] = open(full_path).read()
                except Exception:
                    pass

    fix_plan = asyncio.run(_run_fix_generation(llm_client, fixable, file_contents))

    if not fix_plan.files:
        console.print("\n[yellow]No fixes could be generated.[/yellow]")
        if fix_plan.skipped:
            for reason in fix_plan.skipped:
                console.print(f"  [dim]Skipped: {reason}[/dim]")
        raise typer.Exit(0)

    # Step 3: Apply fixes — one final version per file. Multiple findings in
    # the same file are chained into a single rewrite (no clobbering).
    from difflib import unified_diff
    n_files = len(fix_plan.files)
    console.print(
        f"\n[bold]Step 3/3:[/bold] {'Previewing' if dry_run else 'Applying'} "
        f"fixes for {fix_plan.fixed_count} findings across {n_files} file(s)..."
    )

    applied = 0
    failed = 0
    for path, fixed_content in fix_plan.files.items():
        console.print(f"\n  [bold]{path}[/bold]")
        if dry_run:
            original = file_contents.get(path, "")
            diff = "\n".join(unified_diff(
                original.splitlines(), fixed_content.splitlines(),
                fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="",
            ))
            console.print(f"  [dim]{diff[:800]}[/dim]")
            applied += 1
        else:
            full_path = os.path.join(repo_path, path)
            try:
                with open(full_path, "w") as f:
                    f.write(fixed_content)
                console.print(f"  [green]Applied[/green]")
                applied += 1
            except Exception as e:
                console.print(f"  [red]Failed to write: {e}[/red]")
                failed += 1

    # Summary
    console.print()
    action = "previewed" if dry_run else "applied"
    console.print(Panel(
        f"[bold]{fix_plan.fixed_count} findings fixed across {applied} file(s) {action}[/bold]  |  "
        f"{failed} failed  |  "
        f"{len(fix_plan.skipped)} skipped  |  "
        f"{fix_plan.total_findings} total findings",
        title="Fix Summary",
        border_style="green" if failed == 0 else "yellow",
    ))

    if not dry_run and applied > 0:
        # Re-scan the fixed code to confirm the findings are actually gone.
        from isitsecure.engine.fixes.verifier import verify_findings_resolved
        fixed_findings = [
            f for f in fixable
            if f.code_location and f.code_location.file_path in fix_plan.files
        ]
        console.print("\n[bold]Verifying fixes (re-scanning)...[/bold]")
        vr = asyncio.run(verify_findings_resolved(repo_path, fixed_findings))
        if vr.checked:
            console.print(
                f"  [green]{vr.resolved} of {vr.checked} findings confirmed resolved "
                f"by re-scan[/green]"
            )
            if vr.still_present:
                console.print(
                    f"  [yellow]{vr.still_present} still flagged — this can be a partial "
                    f"fix, or a valid fix the scanner can't confirm. Review the diff:[/yellow]"
                )
                for t in vr.still_present_titles:
                    console.print(f"    [yellow]• {t}[/yellow]")
        if vr.unverifiable:
            console.print(
                f"  [dim]{vr.unverifiable} finding(s) can't be auto-verified "
                f"(business-logic/DAST) — review manually[/dim]"
            )

        console.print("\n[bold]Next steps:[/bold]")
        console.print("  1. Review changes: [dim]git diff[/dim]")
        console.print("  2. Run your tests")
        console.print("  3. Add isitsecure to CI so it can't regress "
                      "([dim]see examples/github-action.yml[/dim])")
    elif dry_run:
        console.print(f"\n[dim]Run without --dry-run to apply fixes: isitsecure fix --repo {repo}[/dim]")


async def _run_fix_generation(llm_client, findings, file_contents):
    """Run fix generation, chaining multiple findings per file (no clobbering)."""
    from isitsecure.engine.fixes.fix_generator import FixGenerator

    generator = FixGenerator(llm_client)
    return await generator.generate_file_fixes(findings, file_contents)


# ---------------------------------------------------------------------------
# badge command — generate security grade badge SVG
# ---------------------------------------------------------------------------

@app.command()
def badge(
    repo: str = typer.Option(..., "--repo", "-r", help="Path to local repo to scan"),
    output_file: str = typer.Option("isitsecure-badge.svg", "--output", "-o", help="Output SVG file"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Generate a security grade badge SVG from a scan."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    import os
    repo_path = os.path.abspath(repo.replace("file://", ""))
    repo_url = f"file://{repo_path}"

    from isitsecure.engine.factory import create_deep_security_scan_agent, create_repo_ingestion_service
    repo_service = create_repo_ingestion_service()
    agent = create_deep_security_scan_agent(
        llm_client=None,
        judgment_llm_client=None,
        repo_ingestion_service=repo_service,
    )

    console.print("[bold]Scanning for security grade...[/bold]")
    report = asyncio.run(_run_scan(agent=agent, repo_url=repo_url, scan_mode=None))

    # Calculate grade
    from isitsecure.engine.reporting.report_generator import ReportGenerator
    gen = ReportGenerator()
    grade = gen._calculate_grade(report)

    svg = _generate_badge_svg(grade, report.critical_count, report.high_count, len(report.findings))
    Path(output_file).write_text(svg)

    console.print(f"[green]Badge written to {output_file}[/green]")
    console.print(f"Grade: [bold]{grade}[/bold]  |  {len(report.findings)} findings")
    console.print(f"\nAdd to your README:")
    console.print(f'  [dim]![Security: {grade}](./{output_file})[/dim]')


def _generate_badge_svg(grade: str, critical: int, high: int, total: int) -> str:
    """Generate a shields.io-style SVG badge for the security grade."""
    GRADE_COLORS = {
        "A": "#4c1",      # Green
        "B": "#97ca00",   # Yellow-green
        "C": "#dfb317",   # Yellow
        "D": "#fe7d37",   # Orange
        "F": "#e05d44",   # Red
    }
    color = GRADE_COLORS.get(grade, "#9f9f9f")

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


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------

@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"isitsecure v{__version__}")


# ---------------------------------------------------------------------------
# setup command
# ---------------------------------------------------------------------------

@app.command()
def setup() -> None:
    """Interactive first-time setup - configure API keys and install browsers."""
    _ensure_config_dir()

    console.print(Panel(
        "[bold]isitsecure setup[/bold]\n"
        "Configure API keys and install browser for DAST scanning.",
        border_style="bright_magenta",
    ))

    # API key
    console.print("\n[bold]1. LLM API Key[/bold]")
    console.print("   For full scanning (business logic review, triage, semantic analysis)")
    console.print("   Set ANTHROPIC_API_KEY or GOOGLE_API_KEY in your .env file")
    console.print("   Or enter it now to save to ~/.isitsecure/config.toml\n")

    key = typer.prompt("Anthropic API key (or press Enter to skip)", default="", show_default=False)
    if key:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(
            f'[llm]\nanthropic_api_key = "{key}"\n'
        )
        console.print("[green]Saved to ~/.isitsecure/config.toml[/green]")

    # Playwright
    console.print("\n[bold]2. Browser for DAST scanning[/bold]")
    install_browser = typer.confirm("Install Chromium for dynamic testing?", default=True)
    if install_browser:
        import subprocess
        console.print("Installing Chromium...")
        result = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            console.print("[green]Chromium installed successfully[/green]")
        else:
            console.print(f"[red]Failed to install Chromium: {result.stderr}[/red]")
            console.print("You can install it later: python -m playwright install chromium")

    console.print("\n[green bold]Setup complete![/green bold]")
    console.print("Run: isitsecure scan https://your-app.com")
