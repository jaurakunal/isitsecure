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
from rich.panel import Panel
from rich.table import Table

from isitsecure import __version__

from isitsecure.cli._app import app
from isitsecure.cli._io import console, err_console
from isitsecure.cli.render import (
    _generate_badge_svg,
    _generate_fixes,
    _generate_html_report,
    _generate_sarif_report,
    _print_report_table,
)
from isitsecure.cli.run import _run_scan
from isitsecure.cli.environment import (
    _LSP_SPECS,
    _chromium_installed,
    _first_which,
)



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
def _main(ctx: typer.Context) -> None:
    """AI-powered security scanner. Runs before every command."""
    # The MCP server speaks JSON-RPC over stdio; the banner already goes to
    # stderr (stdout stays clean), but MCP clients pipe stderr into their logs,
    # so skip the decorative banner for `mcp` to keep those logs quiet.
    if ctx.invoked_subcommand != "mcp":
        _print_welcome()


# ---------------------------------------------------------------------------
# Config management
# ---------------------------------------------------------------------------

from isitsecure.cli.config import _load_api_key


def _drop_findings_from_themes(report, hidden_ids: set) -> None:
    """Remove hidden findings from the report's thematic grouping so suppressed
    or baseline-known findings don't resurface there (#51/#52)."""
    if not hidden_ids or not report.themes:
        return
    kept = []
    for theme in report.themes:
        theme.finding_ids = [i for i in theme.finding_ids if i not in hidden_ids]
        theme.finding_count = len(theme.finding_ids)
        if theme.finding_ids:
            kept.append(theme)
    report.themes = kept


def _apply_trust_filters(
    report, *, output: str, target_url, repo,
    suppress, suppress_reason: str, suppress_file, show_suppressed: bool,
    baseline: bool, baseline_accept: bool, baseline_file,
) -> None:
    """Apply suppression (#51) then baseline (#52) to ``report.findings`` in place.

    Suppression runs first, so the baseline never records or diffs a suppressed
    finding. Mutates ``report.findings`` (and themes) so every output format sees
    the same filtered set; emits progress to stderr. Extracted from ``scan`` so
    the composition can be unit-tested directly.
    """
    from isitsecure.engine import baseline as _baseline
    from isitsecure.engine import suppression as _suppression

    # --- Suppression -----------------------------------------------------
    ignore_path = Path(suppress_file) if suppress_file else _suppression.default_ignore_path()
    if suppress:
        newly = _suppression.add_suppressions(
            ignore_path, report.findings, suppress, suppress_reason
        )
        if newly:
            err_console.print(
                f"[green]Suppressed {len(newly)} finding(s)[/green] in [dim]{ignore_path}[/dim]"
            )
        unmatched = set(suppress) - {f.fingerprint for f in report.findings}
        if unmatched:
            err_console.print(
                f"[yellow]No finding in this scan matched: {', '.join(sorted(unmatched))}[/yellow]"
            )
    active, hidden = _suppression.partition(
        report.findings, _suppression.load_suppressed_fingerprints(ignore_path)
    )
    if show_suppressed:
        report.findings = hidden
        if output not in ("json", "sarif"):
            err_console.print(
                f"[dim]Showing {len(hidden)} suppressed finding(s) from {ignore_path.name}[/dim]"
            )
    else:
        report.findings = active
        _drop_findings_from_themes(report, {f.id for f in hidden})
        if hidden and output not in ("json", "sarif"):
            err_console.print(
                f"[dim]{len(hidden)} finding(s) suppressed via {ignore_path.name} "
                f"(use --show-suppressed to view)[/dim]"
            )

    # --- Baseline --------------------------------------------------------
    if baseline_accept and show_suppressed:
        err_console.print(
            "[yellow]--baseline-accept is ignored with --show-suppressed "
            "(refusing to baseline the suppressed set).[/yellow]"
        )
    if not (baseline or baseline_accept) or show_suppressed:
        return
    bl_path = Path(baseline_file) if baseline_file else _baseline.baseline_path(target_url, repo)
    if baseline_accept:
        n = _baseline.save_baseline(
            bl_path, report.findings, target_url=target_url, repo_url=repo,
            commit=report.repo_commit_hash,
        )
        err_console.print(
            f"[green]Baseline accepted[/green] — {n} finding(s) recorded in [dim]{bl_path}[/dim]"
        )
    if not baseline:
        return
    known_baseline = _baseline.load_baseline(bl_path)
    if known_baseline is None:  # missing OR corrupt — distinguish for an honest message
        if bl_path.exists():
            err_console.print(
                f"[yellow]Baseline at {bl_path} is unreadable/corrupt — showing all findings.[/yellow]"
            )
        elif not baseline_accept:
            err_console.print(
                "[yellow]No baseline accepted yet for this project — showing all findings. "
                "Run once with --baseline-accept first.[/yellow]"
            )
        return
    new, known = _baseline.partition_new(report.findings, known_baseline)
    report.findings = new
    _drop_findings_from_themes(report, {f.id for f in known})
    if known and output not in ("json", "sarif"):
        err_console.print(
            f"[dim]{len(known)} known finding(s) hidden by baseline; showing {len(new)} new.[/dim]"
        )


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@app.command()
def scan(
    target_url: Optional[str] = typer.Argument(None, help="URL to scan (DAST)"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="GitHub repo URL (SAST)"),
    branch: Optional[str] = typer.Option(
        None, "--branch", "-b",
        help="Git branch to scan (default: the repository's own default branch)"),
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
    suppress: Optional[list[str]] = typer.Option(None, "--suppress", help="Fingerprint to add to .isitsecureignore (repeatable)"),
    suppress_reason: str = typer.Option("", "--suppress-reason", help="Reason recorded next to --suppress entries"),
    suppress_file: Optional[str] = typer.Option(None, "--suppress-file", help="Ignore file path (default ./.isitsecureignore)"),
    show_suppressed: bool = typer.Option(False, "--show-suppressed", help="List suppressed findings instead of hiding them"),
    baseline: bool = typer.Option(False, "--baseline", help="Show only findings new since the accepted baseline"),
    baseline_accept: bool = typer.Option(False, "--baseline-accept", help="Record the current findings as the baseline"),
    baseline_file: Optional[str] = typer.Option(None, "--baseline-file", help="Baseline path (default ~/.isitsecure/baselines/<project>.json)"),
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
        repo_branch=branch,
    ))

    # Suppression (#51) + baseline (#52): filter the findings once, so every
    # output format sees the same set. Extracted for direct testing.
    _apply_trust_filters(
        report, output=output, target_url=target_url, repo=repo,
        suppress=suppress, suppress_reason=suppress_reason,
        suppress_file=suppress_file, show_suppressed=show_suppressed,
        baseline=baseline, baseline_accept=baseline_accept, baseline_file=baseline_file,
    )

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

    # Something we were asked to scan couldn't be read. The findings above are
    # real but partial, so don't let a green exit code say otherwise (#147).
    if report.ingestion_errors:
        err_console.print()
        for problem in report.ingestion_errors:
            err_console.print(f"  [red]•[/red] {problem}")
        err_console.print(
            "[yellow]Your code was not scanned — the results above cover only "
            "the live site.[/yellow]"
        )
        raise typer.Exit(1)












# ---------------------------------------------------------------------------
# verify command (#53 — re-check specific findings: fixed or still present)
# ---------------------------------------------------------------------------

@app.command()
def verify(
    target_url: Optional[str] = typer.Argument(None, help="Target URL to re-probe DAST findings against"),
    report: str = typer.Option(..., "--report", help="Previous scan JSON (from scan --output json)"),
    fingerprint: Optional[list[str]] = typer.Option(None, "--fingerprint", help="Only verify these fingerprints (repeatable; default: all)"),
    repo: Optional[str] = typer.Option(None, "--repo", "-r", help="Local repo path for re-checking SAST findings"),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table|json"),
) -> None:
    """Re-check whether findings from a previous scan are fixed now.

    SAST findings are re-checked against a local --repo; DAST findings are
    re-probed against the target URL. Exits non-zero if any finding is still
    present (CI-friendly).
    """
    import asyncio as _asyncio

    from isitsecure.engine.models import DeepFinding
    from isitsecure.engine.reverify import VerifyStatus, reverify_findings

    report_path = Path(report)
    if not report_path.exists():
        err_console.print(f"[red]Report not found: {report}[/red]")
        raise typer.Exit(2)
    try:
        data = json.loads(report_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        err_console.print(f"[red]Could not read report {report}: {exc}[/red]")
        raise typer.Exit(2) from exc

    findings = [DeepFinding.model_validate(d) for d in data.get("findings", [])]
    unknown: set[str] = set()
    if fingerprint:
        wanted = set(fingerprint)
        findings = [f for f in findings if f.fingerprint in wanted]
        unknown = wanted - {f.fingerprint for f in findings}
        if unknown:
            err_console.print(
                f"[yellow]Not in report: {', '.join(sorted(unknown))}[/yellow]"
            )
    if not findings:
        # Nothing verified — an inconclusive gate must not read as "green".
        err_console.print("[yellow]No matching findings to verify.[/yellow]")
        raise typer.Exit(2 if unknown else 0)

    verdicts = _asyncio.run(reverify_findings(findings, target_url=target_url, repo_path=repo))

    still = [v for v in verdicts if v.status == VerifyStatus.STILL_PRESENT]
    fixed = [v for v in verdicts if v.status == VerifyStatus.FIXED]
    inconclusive = [v for v in verdicts
                    if v.status in (VerifyStatus.UNVERIFIABLE, VerifyStatus.ERROR)]

    if output == "json":
        sys.stdout.write(json.dumps({
            "verdicts": [
                {"fingerprint": v.finding.fingerprint, "status": v.status.value,
                 "title": v.finding.title, "detail": v.detail}
                for v in verdicts
            ],
            "fixed": len(fixed), "still_present": len(still),
        }, indent=2) + "\n")
    else:
        _status_style = {
            VerifyStatus.FIXED: "[green]FIXED[/green]",
            VerifyStatus.STILL_PRESENT: "[red]STILL PRESENT[/red]",
            VerifyStatus.UNVERIFIABLE: "[dim]unverifiable[/dim]",
            VerifyStatus.ERROR: "[yellow]error[/yellow]",
        }
        table = Table(title="Re-verification", show_lines=False)
        table.add_column("Status", width=16)
        table.add_column("Finding", width=52)
        table.add_column("Fingerprint", style="dim", width=16)
        for v in verdicts:
            table.add_row(_status_style[v.status], v.finding.title[:52], v.finding.fingerprint)
        console.print(table)
        console.print(
            f"\n[green]{len(fixed)} fixed[/green] · "
            f"[red]{len(still)} still present[/red] · "
            f"[dim]{len(inconclusive)} unverifiable/error[/dim]"
        )

    # Exit codes for CI: 1 = a regression is still present; 2 = inconclusive
    # (something couldn't be verified, or a requested fingerprint wasn't found) —
    # so a typo or a missing target never reads as a green gate; 0 = all fixed.
    if still:
        raise typer.Exit(1)
    if inconclusive or unknown:
        raise typer.Exit(2)
    raise typer.Exit(0)


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
    # Imported here, not at module scope: `setup_lsp` registers the `setup`
    # command, and importing it before this module's own commands are defined
    # would reorder them in `--help`.
    from isitsecure.cli.setup_lsp import _lsp_offer

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




# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------

@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"isitsecure v{__version__}")


@app.command()
def mcp() -> None:
    """Run the local MCP server (stdio) so AI coding tools can call `scan`.

    Point Cursor / Claude Code / Claude Desktop at this command in their MCP
    config; the tool spawns it as a subprocess and talks to it over stdio.
    Nothing is hosted or exposed on the network.

        {"mcpServers": {"isitsecure": {"command": "isitsecure", "args": ["mcp"]}}}
    """
    from isitsecure.mcp_server import run_stdio

    try:
        run_stdio()
    except RuntimeError as exc:
        # Missing optional 'mcp' dependency — surface the install hint, not a trace.
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# setup command
# ---------------------------------------------------------------------------

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
        elif shutil.which("typescript-language-server"):
            # The server being installed isn't enough: it needs a TypeScript
            # 5.x runtime to start at all, and scans never provide one from
            # the scanned tree itself (issue #145).
            from isitsecure.engine.code_analysis.lsp.tsserver_locator import (
                find_tsserver_js,
            )
            if not find_tsserver_js():
                warnings.append(
                    "The TypeScript language server has no TypeScript runtime "
                    "to run, so it can't start.\n"
                    "    [dim]→ Auth-flow tracing is skipped; code scanning "
                    "falls back to regex-only analysis.[/dim]\n"
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


