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

CONFIG_DIR = Path.home() / ".isitsecure"
CONFIG_FILE = CONFIG_DIR / "config.toml"


def _ensure_config_dir() -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return CONFIG_DIR


def _load_api_key(provider: str) -> str | None:
    """Load API key from env, .env file, or config."""
    import os

    # 1. Environment variable
    env_keys = {
        "anthropic": "ANTHROPIC_API_KEY",
        "google": "GOOGLE_API_KEY",
    }
    env_key = env_keys.get(provider, "")
    val = os.environ.get(env_key)
    if val:
        return val

    # 2. .env file in current directory
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith(f"{env_key}="):
                return line.split("=", 1)[1].strip().strip("\"'")

    # 3. Config file
    if CONFIG_FILE.exists():
        try:
            import tomllib
            with open(CONFIG_FILE, "rb") as f:
                config = tomllib.load(f)
            return config.get("llm", {}).get(f"{provider}_api_key")
        except Exception:
            pass

    return None


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

            if data and hasattr(data, "findings"):
                report = data

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
