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
from rich.panel import Panel
from rich.table import Table

from isitsecure import __version__

app = typer.Typer(
    name="isitsecure",
    help="AI-powered security scanner for modern web apps. SAST + DAST + LLM review.",
    no_args_is_help=True,
)
console = Console()
# Decorative output (welcome banner, scan progress) goes to stderr so stdout
# stays clean for piped data (JSON/SARIF/report bodies).
err_console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Welcome banner
# ---------------------------------------------------------------------------

# 5-row block font — only the glyphs in "isitsecure" are defined.
_BANNER_FONT = {
    "i": ["████", " ██ ", " ██ ", " ██ ", "████"],
    "s": ["████", "█   ", "████", "   █", "████"],
    "t": ["████", " ██ ", " ██ ", " ██ ", " ██ "],
    "e": ["████", "█   ", "███ ", "█   ", "████"],
    "c": ["████", "█   ", "█   ", "█   ", "████"],
    "u": ["█  █", "█  █", "█  █", "█  █", "████"],
    "r": ["███ ", "█  █", "███ ", "█ █ ", "█  █"],
}

_WELCOME_SHOWN = False


def _print_welcome() -> None:
    """Print the framed isitsecure welcome banner (once per process, to stderr).

    The wordmark scales to the terminal width, coloured by a diagonal pink→purple
    wave. On an interactive terminal a one-time shimmer sweeps across it on load.
    """
    global _WELCOME_SHOWN
    if _WELCOME_SHOWN:
        return
    _WELCOME_SHOWN = True

    import math
    import time

    word = "isitsecure"
    pink, purple = (255, 106, 193), (168, 107, 255)
    out = err_console.file          # stderr
    tty = err_console.is_terminal   # colour + animate only on a real terminal
    m = "bright_magenta"

    # --- scale the block font toward the terminal width ---
    term_w = err_console.width or 80
    base_w = len(" ".join(_BANNER_FONT[c][0] for c in word))  # unscaled width
    hscale = max(1, min(4, (term_w - 12) // base_w))
    vscale = (hscale + 1) // 2

    rows: list[str] = []
    for r in range(5):
        raw = " ".join(_BANNER_FONT[c][r] for c in word)
        wide = "".join(ch * hscale for ch in raw)
        rows.extend([wide] * vscale)
    n_rows = len(rows)
    wm_w = len(rows[0])
    pad = "     "  # inner left padding for the wordmark

    def _cell(col: int, ri: int, glint) -> str:
        if not tty:
            return ""
        t = (math.sin(col * (2 * math.pi / (24 * hscale)) - ri * 0.85) + 1) / 2
        r, g, b = (pink[i] + (purple[i] - pink[i]) * t for i in range(3))
        if glint is not None:
            d = (col - glint) / (5 * hscale)
            boost = math.exp(-d * d) * 0.9
            r, g, b = (v + (255 - v) * boost for v in (r, g, b))
        return f"\033[38;2;{round(r)};{round(g)};{round(b)}m"

    def _wordmark(glint=None) -> list[str]:
        reset = "\033[0m" if tty else ""
        return [
            pad + "".join(_cell(i, ri, glint) + ch for i, ch in enumerate(rowstr)) + reset
            for ri, rowstr in enumerate(rows)
        ]

    frame_w = min(term_w - 3, wm_w + len(pad) + 4)
    top = f"[{m}]┌[/{m}]" + " " * (frame_w - 2) + f"[{m}]┐[/{m}]"
    bot = f"[{m}]└[/{m}]" + " " * (frame_w - 2) + f"[{m}]┘[/{m}]"

    # header
    err_console.print()
    err_console.print(f"  {top}")
    err_console.print(f"  {pad}[dim]Welcome to[/dim]")

    # wordmark — resting frame, then (on a tty) a single shimmer sweep
    for line in _wordmark():
        out.write("  " + line + "\n")
    out.flush()
    if tty:
        frames = 20
        span = wm_w + 20 * hscale
        for k in range(1, frames + 1):
            glint = -10 * hscale + span * k / frames
            out.write(f"\033[{n_rows}A")
            for line in _wordmark(glint):
                out.write("\033[2K  " + line + "\n")
            out.flush()
            time.sleep(0.025)
        out.write(f"\033[{n_rows}A")
        for line in _wordmark():
            out.write("\033[2K  " + line + "\n")
        out.flush()

    # footer
    err_console.print()
    err_console.print(f"[dim]{('CLI  ·  v' + __version__).rjust(frame_w)}[/dim]")
    err_console.print(f"  {bot}")
    err_console.print()
    err_console.print(
        f"  {pad}[dim]Scan your web app for security issues right from your terminal —[/dim]"
    )
    err_console.print(f"  {pad}[dim]SAST + DAST + LLM review in one command.[/dim]")
    err_console.print()
    err_console.print(
        f"  {pad}[{m}]●[/{m}] 44 rule-based scanners [dim](+ optional AI review)[/dim]"
    )
    err_console.print(
        f"  {pad}[{m}]●[/{m}] Quick by default  [dim]· run[/dim] --depth deep "
        "[dim]for the full arsenal[/dim]"
    )
    err_console.print()


@app.callback()
def _main() -> None:
    """AI-powered security scanner. Runs before every command."""
    _print_welcome()


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
    depth: str = typer.Option("quick", "--depth", help="Scan depth: quick (fast, default) | deep (adds time-based SQLi, active XSS, and other slow/aggressive probes)"),
    auth_email: Optional[str] = typer.Option(None, "--auth-email", help="Auth email/username for authenticated scanning (user A)"),
    auth_password: Optional[str] = typer.Option(None, "--auth-password", help="Auth password (user A)"),
    auth_email_b: Optional[str] = typer.Option(None, "--auth-email-b", help="Second user's email/username — enables cross-user IDOR testing"),
    auth_password_b: Optional[str] = typer.Option(None, "--auth-password-b", help="Second user's password"),
    auth_provider: str = typer.Option("supabase", "--auth-provider", help="Auth provider: supabase|firebase|browser|token (use token for a plain REST login)"),
    login_url: Optional[str] = typer.Option(None, "--login-url", help="Explicit login endpoint (else auto-discovered)"),
    llm_provider: str = typer.Option("anthropic", "--llm", help="LLM provider: anthropic|google|none"),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table|json|html|sarif|fixes"),
    output_file: Optional[str] = typer.Option(None, "--output-file", "-f", help="Write report to file"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run a security scan against a web application."""
    if not target_url and not repo:
        err_console.print(
            "[red]I need either your website's address (to test it live) or your "
            "code (to scan it). You gave neither.[/red]\n"
            "[dim]Try one of:[/dim]\n"
            "  isitsecure scan https://your-app.com\n"
            "  isitsecure scan --repo github.com/you/your-app"
        )
        raise typer.Exit(1)

    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    # Smart first-run (#56): if the user didn't pick a mode, choose it from what
    # they gave us and tell them, in plain language, what we're about to do.
    has_auth = bool(auth_email and auth_password)
    resolved_mode_name = mode if mode != "auto" else _auto_select_mode(
        target_url, repo, has_auth
    )

    # Resolve LLM client
    llm_client = None
    judgment_llm_client = None
    has_api_key = False
    if llm_provider != "none":
        api_key = _load_api_key(llm_provider)
        has_api_key = bool(api_key)
        if api_key:
            from isitsecure.llm.adapters import create_llm_client
            llm_client = create_llm_client(llm_provider, api_key)
            judgment_llm_client = create_llm_client(llm_provider, api_key, judgment=True)

    # Pre-flight (#54): surface missing prerequisites up front, before we spend
    # minutes scanning. Only checks what the chosen mode actually needs.
    if output not in ("json", "sarif"):
        _explain_mode(resolved_mode_name)
    _preflight_checks(resolved_mode_name, llm_provider, has_api_key)

    # Build scanner
    from isitsecure.engine.factory import (
        create_deep_security_scan_agent,
        create_repo_ingestion_service,
    )

    from isitsecure.engine.enums import ScanDepth
    scan_depth = ScanDepth.DEEP if depth.lower() == "deep" else ScanDepth.QUICK

    repo_service = create_repo_ingestion_service() if repo else None
    agent = create_deep_security_scan_agent(
        llm_client=llm_client,
        judgment_llm_client=judgment_llm_client,
        repo_ingestion_service=repo_service,
        depth=scan_depth,
    )

    # Build credentials
    credentials_a = None
    credentials_b = None
    if auth_email and auth_password:
        from isitsecure.engine.auth.protocols import AuthCredentials
        from isitsecure.engine.enums import AuthProvider as AuthProviderEnum
        credentials_a = AuthCredentials(
            provider=AuthProviderEnum(auth_provider),
            email=auth_email,
            password=auth_password,
            login_url=login_url,
        )
        if auth_email_b and auth_password_b:
            credentials_b = AuthCredentials(
                provider=AuthProviderEnum(auth_provider),
                email=auth_email_b,
                password=auth_password_b,
                login_url=login_url,
            )

    # Resolve scan mode — resolved_mode_name was decided up front (#56); map it
    # to the engine enum so the CLI and engine always agree on what runs.
    from isitsecure.engine.enums import ScanMode
    scan_mode_map = {
        "url-only": ScanMode.URL_ONLY,
        "code-only": ScanMode.CODE_ONLY,
        "authenticated": ScanMode.AUTHENTICATED,
        "full": ScanMode.FULL,
    }
    resolved_mode = scan_mode_map.get(resolved_mode_name)

    # Scan header (to stderr so it never pollutes piped JSON/SARIF).
    if output not in ("json", "sarif"):
        err_console.print(Panel(
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
        credentials_b=credentials_b,
        scan_mode=resolved_mode,
    ))

    # Output results
    if output == "json":
        result_json = report.model_dump_json(indent=2)
        if output_file:
            Path(output_file).write_text(result_json)
            err_console.print(f"[green]Report written to {output_file}[/green]")
        else:
            # Write raw — never through Rich, which would word-wrap and corrupt
            # the JSON (inserting newlines mid-string) when stdout isn't a TTY.
            sys.stdout.write(result_json + "\n")
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
            err_console.print(
                "[red]Writing fix suggestions needs the AI review turned on, and I "
                "couldn't find an API key.[/red]\n"
                "[bold]Fix:[/bold] run [dim]isitsecure setup[/dim] to add one "
                "(or set ANTHROPIC_API_KEY)."
            )
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
        # Always leave the user a browseable HTML report they can open.
        try:
            html_path = Path("isitsecure-report.html")
            html_path.write_text(_generate_html_report(report))
            console.print(
                f"\n[bold]📄 HTML report:[/bold] {html_path.resolve()}"
                f"\n[dim]   open it in a browser to explore the findings[/dim]"
            )
        except Exception as exc:
            logging.getLogger(__name__).debug("HTML report generation failed: %s", exc)
    else:
        err_console.print(
            f"[yellow]I don't recognize the output format '{output}', so I'll show "
            "the results as a table.[/yellow]\n"
            "[dim]Valid options for --output are: table, json, html, sarif, fixes.[/dim]"
        )
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
    """Run the scan, narrating each step as a live scrolling log.

    The tool "speaks" what it's doing — a phase header for each stage and an
    indented line as each scanner finishes — so a long scan visibly progresses
    instead of freezing on a single bar.
    """
    import time

    report = None
    t0 = time.monotonic()
    last_phase = None
    err_console.print()

    async for event in agent.scan(**kwargs):
        phase = getattr(event, "phase", "")
        phase_val = getattr(phase, "value", phase)
        message = getattr(event, "message", "") or "Scanning..."
        data = getattr(event, "data", None) or {}
        elapsed = time.monotonic() - t0
        stamp = f"[dim]{elapsed:6.1f}s[/dim]"

        # The final COMPLETE event carries the report; capture it, don't log it.
        if "report" in data:
            from isitsecure.engine.models import DeepScanReport
            report = DeepScanReport.model_validate(data["report"])
            continue

        status = data.get("status")
        if status == "start":
            # Scanner launched — show it's in flight.
            err_console.print(f"{stamp}    [cyan]→[/cyan] [dim]{data['scanner']}…[/dim]")
        elif status == "done":
            # Scanner finished — detail line.
            count = data.get("findings", 0)
            if count:
                err_console.print(
                    f"{stamp}    [green]✓[/green] {data['scanner']} "
                    f"[yellow]— {count} finding(s)[/yellow]"
                )
            else:
                err_console.print(
                    f"{stamp}    [green]✓[/green] [dim]{data['scanner']} — clean[/dim]"
                )
        elif phase_val != last_phase:
            # New phase — header line.
            err_console.print(f"{stamp} [bold cyan]▶[/bold cyan] {message}")
            last_phase = phase_val
        else:
            # A sub-step within the current phase (emitted by a scanner).
            err_console.print(f"{stamp}      [dim]· {message}[/dim]")

    if report is None:
        err_console.print(
            "[red]The scan finished but didn't produce any results — something went "
            "wrong along the way.[/red]\n"
            "[dim]Try re-running with -v (verbose) to see what happened, or check "
            "that your website address / code path is correct.[/dim]"
        )
        raise typer.Exit(1)

    err_console.print(
        f"[dim]{time.monotonic() - t0:6.1f}s[/dim] [green]✓ Scan complete[/green]\n"
    )

    return report


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

        table.add_row(
            str(i),
            f"[{color}]{sev.upper()}[/{color}]",
            impact,
            category,
            detail,
        )

    console.print(table)

    # Owner summary (LLM layer, if present) — layers on top of the baseline.
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

    # UI users start the UI from a terminal — offer the deeper-analysis setup
    # here so they get it too (interactive, one-time, skippable).
    _lsp_offer()

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
    technical: bool = typer.Option(
        False, "--technical",
        help="Show the git details (backup ref, diff/test commands) instead of the plain-language summary",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Scan your code, fix the issues, and re-check — in plain language.

    By default this is a git-free experience: fixes are written straight to your
    files (with your original safely backed up under the hood) and the result is
    reported in plain English. Pass --technical for the git details.
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)

    # Resolve API key
    resolved_key = api_key or _load_api_key(llm_provider)
    if not resolved_key:
        err_console.print(
            "[red]Auto-fixing your code needs the AI turned on, and I couldn't "
            "find an API key.[/red]\n"
            "[bold]Fix:[/bold] run [dim]isitsecure setup[/dim] to add one "
            f"(or set {llm_provider.upper()}_API_KEY, or pass --api-key)."
        )
        raise typer.Exit(1)

    from isitsecure.llm.adapters import create_llm_client
    llm_client = create_llm_client(llm_provider, resolved_key)

    # Resolve repo path
    import os
    repo_path = os.path.abspath(repo.replace("file://", ""))
    if not os.path.isdir(repo_path):
        err_console.print(
            f"[red]I couldn't find your code at:[/red] {repo_path}\n"
            "[dim]Double-check the path — --repo should point to a folder on your "
            "computer (e.g. --repo ./my-app or --repo /Users/you/my-app).[/dim]"
        )
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

    # --- Dry run: just preview the diffs, change nothing. ---
    if dry_run:
        console.print(
            f"\n[bold]Step 3/3:[/bold] Previewing fixes for {fix_plan.fixed_count} "
            f"findings across {n_files} file(s)..."
        )
        for path, fixed_content in fix_plan.files.items():
            console.print(f"\n  [bold]{path}[/bold]")
            original = file_contents.get(path, "")
            diff = "\n".join(unified_diff(
                original.splitlines(), fixed_content.splitlines(),
                fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="",
            ))
            console.print(f"  [dim]{diff[:800]}[/dim]")
        console.print(
            f"\n[dim]Run without --dry-run to apply these fixes: "
            f"isitsecure fix --repo {repo}[/dim]"
        )
        raise typer.Exit(0)

    # --- Apply for real: take a safety net first, then write files in place. ---
    console.print(
        f"\n[bold]Step 3/3:[/bold] Applying fixes for {fix_plan.fixed_count} "
        f"findings across {n_files} file(s)..."
    )

    from isitsecure.engine.fixes.safety_net import create_safety_net
    from isitsecure.engine.shared.safe_path import resolve_within

    net = create_safety_net(repo_path, list(fix_plan.files.keys()))

    applied = 0
    failed = 0
    for path, fixed_content in fix_plan.files.items():
        try:
            full_path = resolve_within(repo_path, path)
            with open(full_path, "w") as f:
                f.write(fixed_content)
            applied += 1
        except Exception as e:
            console.print(f"  [red]Couldn't update {path}: {e}[/red]")
            failed += 1

    # Re-scan the fixed code to confirm the findings are actually gone.
    from isitsecure.engine.fixes.verifier import verify_findings_resolved
    from isitsecure.engine.fixes import plain_results

    fixed_findings = [
        f for f in fixable
        if f.code_location and f.code_location.file_path in fix_plan.files
    ]
    console.print("[bold]Re-checking your code...[/bold]")
    vr = asyncio.run(verify_findings_resolved(repo_path, fixed_findings))

    # Fold everything into the three plain-language buckets. "couldn't fix" =
    # findings we tried but produced no fix for (failed generation + write
    # failures).
    fix_failed = (len(fixable) - fix_plan.fixed_count) + failed
    counts = plain_results.classify_verification(
        attempted=len(fixable),
        fix_failed=fix_failed,
        verification=vr.to_dict(),
    )

    console.print()
    console.print(Panel(
        f"[bold]{plain_results.summarize(counts)}[/bold]",
        title="Done",
        border_style="green" if counts.needs_review == 0 and counts.couldnt_fix == 0 else "yellow",
    ))

    hint = plain_results.next_step_hint(counts, saved_hint=net.restore_hint)
    if hint:
        console.print(f"\n[dim]{hint}[/dim]")

    if counts.needs_review and vr.still_present_titles:
        console.print("\n[bold]Worth a look:[/bold]")
        for t in vr.still_present_titles:
            console.print(f"  [yellow]•[/yellow] {t}")

    # --- Power-user / technical view: the git mechanics, on request. ---
    if technical:
        console.print("\n[bold]Technical details:[/bold]")
        if net.kind == "git":
            console.print(
                f"  Backup ref: [dim]{net.location}[/dim] "
                f"[dim](restore original: git checkout {net.location} -- .)[/dim]"
            )
        elif net.kind == "copy":
            console.print(f"  Backup copy: [dim]{net.location}[/dim]")
        console.print("  1. Review changes: [dim]git diff[/dim]")
        console.print("  2. Run your tests")
        console.print(
            "  3. Add isitsecure to CI so it can't regress "
            "([dim]see examples/github-action.yml[/dim])"
        )


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
    # Only prefix "./" for relative paths; an absolute -o path would otherwise
    # render as ".//abs/path".
    badge_ref = output_file if Path(output_file).is_absolute() else f"./{output_file}"
    console.print(f'  [dim]![Security: {grade}]({badge_ref})[/dim]')


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

# ---------------------------------------------------------------------------
# Language-server (LSP) setup
# ---------------------------------------------------------------------------

# The scan auto-detects each language server via shutil.which; this table drives
# `setup` installing/verifying them. `needs` is the tool that must be on PATH to
# run `cmd` (None = uses the current interpreter's pip, always available).
_LSP_SPECS = [
    {
        "lang": "Python",
        "bins": ("pylsp", "pyright-langserver", "basedpyright-langserver"),
        "runtime": (),
        "needs": None,
        "cmd": [sys.executable, "-m", "pip", "install", "python-lsp-server"],
        "hint": "pip install python-lsp-server",
    },
    {
        "lang": "TypeScript / JavaScript",
        "bins": ("typescript-language-server",),
        "runtime": ("node",),
        "needs": "npm",
        "cmd": ["npm", "install", "-g", "typescript-language-server", "typescript"],
        "hint": {
            "macos": "install Node.js (`brew install node`), then re-run `isitsecure setup --lsp`",
            "windows": "install Node.js (`winget install OpenJS.NodeJS` or nodejs.org), then re-run `isitsecure setup --lsp`",
            "linux": "install Node.js (your package manager or nodejs.org), then re-run `isitsecure setup --lsp`",
        },
    },
    {
        "lang": "Java / Kotlin",
        "bins": ("jdtls", "jdt-language-server"),
        "runtime": ("java",),
        "needs": "brew",
        "cmd": ["brew", "install", "jdtls"],
        "hint": {
            "macos": "install a JDK (`brew install openjdk`) + jdtls — https://github.com/eclipse-jdtls/eclipse.jdt.ls#installation",
            "windows": "install a JDK (`winget install Microsoft.OpenJDK`) + jdtls — https://github.com/eclipse-jdtls/eclipse.jdt.ls#installation",
            "linux": "install a JDK + jdtls — https://github.com/eclipse-jdtls/eclipse.jdt.ls#installation",
        },
    },
]


def _os_key() -> str:
    import os
    if os.name == "nt":
        return "windows"
    return "macos" if sys.platform == "darwin" else "linux"


def _os_hint(spec) -> str:
    """The install hint for this OS (specs use a str or a per-OS dict)."""
    hint = spec["hint"]
    return hint if isinstance(hint, str) else hint.get(_os_key(), next(iter(hint.values())))


def _resolve_install_cmd(cmd):
    """Make an install command launchable across platforms.

    Resolves argv[0] to its real path (so PATHEXT lookups like npm.cmd resolve),
    and on Windows launches .cmd/.bat shims via ``cmd /c`` — CreateProcess can't
    run those directly, which is why a bare ["npm", ...] fails on Windows.
    """
    import os
    import shutil
    exe = shutil.which(cmd[0]) or cmd[0]
    if os.name == "nt" and exe.lower().endswith((".cmd", ".bat")):
        return ["cmd", "/c", exe, *cmd[1:]]
    return [exe, *cmd[1:]]


def _first_which(bins) -> Optional[str]:
    import shutil
    for b in bins:
        if shutil.which(b):
            return b
    return None


def _chromium_installed() -> bool:
    """True if Playwright's Chromium is installed (best effort, no launch)."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            return bool(p.chromium.executable_path) and Path(p.chromium.executable_path).exists()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Smart first-run: pick the scan mode from what the user gave us (issue #56)
# ---------------------------------------------------------------------------

def _auto_select_mode(
    target_url: Optional[str],
    repo: Optional[str],
    has_auth: bool,
) -> str:
    """Pick a scan mode from the inputs the user provided.

    A beginner shouldn't have to know the mode names — if they give a website
    we test it live, if they give code we scan it, if they give both we do the
    full scan. Mirrors the engine's own detection so ``--mode auto`` and this
    explanation always agree.
    """
    if target_url and repo:
        return "full"
    if target_url and has_auth:
        return "authenticated"
    if repo:
        return "code-only"
    return "url-only"


# Plain-language, one-line "here's what I'm doing" per resolved mode.
_MODE_EXPLANATIONS = {
    "url-only": "Testing your live website for security issues (no code needed).",
    "authenticated": "Logging into your live website and testing it as a real user "
                     "would see it.",
    "code-only": "Scanning your code for security issues (no live site needed).",
    "full": "Scanning your code AND testing your live website — the most thorough scan.",
}


def _explain_mode(resolved_mode: str) -> None:
    """Print a friendly one-liner telling the user what the scan will do."""
    explanation = _MODE_EXPLANATIONS.get(resolved_mode)
    if explanation:
        err_console.print(f"[bright_magenta]▸[/bright_magenta] {explanation}")


# ---------------------------------------------------------------------------
# Pre-flight checks: catch missing prerequisites BEFORE the scan runs (#54)
# ---------------------------------------------------------------------------

def _preflight_checks(
    resolved_mode: str,
    llm_provider: str,
    has_api_key: bool,
) -> None:
    """Warn about missing prerequisites *before* a long scan starts.

    Only checks what the chosen mode actually needs, so a code-only scan never
    nags about a browser. Each warning names the exact fix command and what is
    degraded if left unaddressed. Warnings only — a scan can still run degraded,
    so we never hard-exit here.
    """
    import shutil

    needs_live_site = resolved_mode in ("url-only", "authenticated", "full")
    needs_code_analysis = resolved_mode in ("code-only", "full")

    warnings: list[str] = []

    # (a) Chromium / Playwright — required to test a live site.
    if needs_live_site and not _chromium_installed():
        warnings.append(
            "The browser used to test your live website isn't installed yet.\n"
            "    [dim]→ Live-site testing will be skipped until you install it.[/dim]\n"
            "    [bold]Fix:[/bold] isitsecure setup"
        )

    # (b) Language servers — deeper code analysis for code/full scans.
    if needs_code_analysis:
        missing = [
            s["lang"] for s in _LSP_SPECS
            if not _first_which(s["bins"])
            or any(not shutil.which(r) for r in s["runtime"])
        ]
        if missing:
            warnings.append(
                "Deeper code analysis isn't fully set up "
                f"([dim]{', '.join(missing)}[/dim]).\n"
                "    [dim]→ Code scanning still runs, but may miss some issues and "
                "flag more false alarms.[/dim]\n"
                "    [bold]Fix:[/bold] isitsecure setup --lsp"
            )

    # (c) LLM API key — only if the user asked for an LLM provider.
    if llm_provider != "none" and not has_api_key:
        warnings.append(
            f"No {llm_provider} API key found, so the AI review is off.\n"
            "    [dim]→ You'll still get findings, but without plain-English "
            "explanations or fix suggestions.[/dim]\n"
            "    [bold]Fix:[/bold] isitsecure setup  [dim](or set "
            f"{llm_provider.upper()}_API_KEY)[/dim]"
        )

    if warnings:
        err_console.print()
        err_console.print("[yellow bold]Before we start — a couple of things to know:[/yellow bold]")
        for w in warnings:
            err_console.print(f"  [yellow]•[/yellow] {w}")
        err_console.print("[dim]The scan will still run with what's available.[/dim]")
        err_console.print()


def _print_status_report() -> None:
    """`setup --check`: report what's configured without changing anything."""
    import shutil
    console.print("\n[bold]isitsecure environment[/bold]")

    key = _load_api_key("anthropic") or _load_api_key("google")
    mark = "[green]✓[/green]" if key else "[yellow]•[/yellow]"
    console.print(f"  {mark} LLM API key: "
                  + ("configured" if key else "[dim]not set — rule-based scanning only[/dim]"))

    browser = _chromium_installed()
    mark = "[green]✓[/green]" if browser else "[yellow]•[/yellow]"
    console.print(f"  {mark} DAST browser (Chromium): "
                  + ("installed" if browser else "[dim]not installed — run `isitsecure setup`[/dim]"))

    console.print("\n  [dim]Language servers (deeper code analysis, fewer false positives):[/dim]")
    for spec in _LSP_SPECS:
        found = _first_which(spec["bins"])
        missing_rt = [r for r in spec["runtime"] if not shutil.which(r)]
        if found and not missing_rt:
            console.print(f"  [green]✓[/green] {spec['lang']}: [dim]{found}[/dim]")
        elif found and missing_rt:
            console.print(f"  [yellow]![/yellow] {spec['lang']}: {found} found, but "
                          f"[dim]{', '.join(missing_rt)}[/dim] not on PATH to run it")
        else:
            console.print(f"  [yellow]•[/yellow] {spec['lang']}: [dim]not installed[/dim]")
    console.print("\n[dim]Install missing language servers with:[/dim] isitsecure setup --lsp")


def _setup_lsps() -> None:
    """Install any missing language servers we can, guide for the rest."""
    import shutil
    import subprocess
    console.print("\n[bold]Language servers (LSP)[/bold] "
                  "[dim]— trace auth flows, reduce false positives on code scans[/dim]")
    for spec in _LSP_SPECS:
        found = _first_which(spec["bins"])
        if found:
            console.print(f"  [green]✓[/green] {spec['lang']}: already installed [dim]({found})[/dim]")
            continue
        needs = spec["needs"]
        if needs is not None and not shutil.which(needs):
            console.print(f"  [yellow]•[/yellow] {spec['lang']}: [dim]{_os_hint(spec)}[/dim]")
            continue
        console.print(f"  [cyan]→[/cyan] {spec['lang']}: installing…")
        try:
            res = subprocess.run(
                _resolve_install_cmd(spec["cmd"]),
                capture_output=True, text=True, timeout=600,
            )
        except Exception as exc:
            console.print(f"  [red]✗[/red] {spec['lang']}: {exc}")
            console.print(f"      [dim]{_os_hint(spec)}[/dim]")
            continue
        if res.returncode == 0 and _first_which(spec["bins"]):
            console.print(f"  [green]✓[/green] {spec['lang']}: installed")
        else:
            tail = (res.stderr or res.stdout or "install did not complete").strip().splitlines()
            console.print(f"  [yellow]![/yellow] {spec['lang']}: {(tail[-1] if tail else '')[:120]}")
            console.print(f"      [dim]{_os_hint(spec)}[/dim]")
        missing_rt = [r for r in spec["runtime"] if not shutil.which(r)]
        if missing_rt:
            console.print(f"      [dim](also needs {', '.join(missing_rt)} on PATH to run)[/dim]")


def _lsp_offer() -> None:
    """Offer, once, to install missing language servers.

    Used by ``launch`` so UI users — who start the UI from a terminal — get the
    same deeper-analysis setup. No-op when everything is ready, when running
    non-interactively, or after the user has declined once.
    """
    missing = [s for s in _LSP_SPECS if not _first_which(s["bins"])]
    if not missing or not sys.stdin.isatty():
        return
    marker = CONFIG_DIR / ".lsp_dismissed"
    try:
        if marker.exists():
            return
    except OSError:
        pass

    console.print(
        "\n[bold]Enable deeper code analysis?[/bold] [dim](recommended)[/dim]\n"
        "  isitsecure can trace how your code actually enforces login and\n"
        "  permissions — catching more real issues and cutting false alarms on\n"
        "  code scans. It installs a small language-analysis helper.\n"
        f"  [dim]Not set up yet: {', '.join(s['lang'] for s in missing)}[/dim]"
    )
    if typer.confirm("Set it up now?", default=True):
        _setup_lsps()
    else:
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            marker.write_text("")  # remember the decline; don't nag on relaunch
        except OSError:
            pass
        console.print(
            "[dim]Skipped — set up any time with `isitsecure setup --lsp`.[/dim]"
        )


@app.command()
def setup(
    lsp: bool = typer.Option(
        False, "--lsp", help="Only install/verify the code-analysis language servers"),
    check: bool = typer.Option(
        False, "--check", help="Report what's installed (API key, browser, LSP) — installs nothing"),
) -> None:
    """First-time setup — API key, DAST browser, and code-analysis language servers."""
    _ensure_config_dir()

    if check:
        _print_status_report()
        return

    if lsp:
        _setup_lsps()
        console.print("\n[green]Language-server setup done.[/green]")
        return

    console.print(Panel(
        "[bold]isitsecure setup[/bold]\n"
        "Configure API keys, install the DAST browser, and set up language servers.",
        border_style="bright_magenta",
    ))

    # API key
    console.print("\n[bold]1. AI review key (optional, but recommended)[/bold]")
    console.print("   With an AI key, isitsecure turns the report into plain English you")
    console.print("   can actually read and gives you specific fix suggestions. Without")
    console.print("   one, scans still run — you just get the raw findings.")
    console.print("   [dim]Get a key at console.anthropic.com. It saves to "
                  "~/.isitsecure/config.toml.[/dim]\n")

    key = typer.prompt("Paste your Anthropic API key (or press Enter to skip)", default="", show_default=False)
    if key:
        import os
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        # Escape for a TOML basic string so a stray quote/backslash in the key
        # can't corrupt the file.
        safe_key = key.replace("\\", "\\\\").replace('"', '\\"')
        CONFIG_FILE.write_text(f'[llm]\nanthropic_api_key = "{safe_key}"\n')
        # The file holds a secret — restrict it to the owner.
        try:
            os.chmod(CONFIG_DIR, 0o700)
            os.chmod(CONFIG_FILE, 0o600)
        except OSError:
            pass
        console.print("[green]Saved to ~/.isitsecure/config.toml (perms 0600)[/green]")

    # Playwright
    console.print("\n[bold]2. Browser for live-site testing[/bold]")
    console.print("   isitsecure opens your website in a real browser to test it the way")
    console.print("   an attacker would. This installs that browser (Chromium).")
    install_browser = typer.confirm("Install it now?", default=True)
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
            console.print(
                "[red]The browser download didn't finish.[/red] "
                "[dim]Live-site testing won't work until it's installed.[/dim]"
            )
            console.print("You can try again any time with: python -m playwright install chromium")
            if result.stderr:
                console.print(f"[dim]Details: {result.stderr.strip().splitlines()[-1][:200]}[/dim]")

    # Language servers
    console.print("\n[bold]3. Language servers (deeper code analysis)[/bold]")
    console.print("   Let the scanner trace auth flows through your code and cut false")
    console.print("   positives. Optional — scans still work with regex-based detection.")
    if typer.confirm("Install/verify language servers now?", default=True):
        _setup_lsps()

    console.print("\n[green bold]Setup complete![/green bold]")
    console.print("Run: isitsecure scan https://your-app.com")
