"""The ``fix`` command: scan, generate fixes, apply them or open PRs."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import typer
from rich.panel import Panel

from isitsecure.cli._app import app
from isitsecure.cli._io import console, err_console
from isitsecure.cli.config import _load_api_key
from isitsecure.cli.render import _print_report_table
from isitsecure.cli.run import _run_scan

@app.command()
def fix(
    repo: str = typer.Option(..., "--repo", "-r", help="Local repo path, OR a remote GitHub URL to open PRs against"),
    llm_provider: str = typer.Option("anthropic", "--llm", help="LLM provider: anthropic|google"),
    api_key: Optional[str] = typer.Option(None, "--api-key", envvar="ANTHROPIC_API_KEY"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show fixes without applying them"),
    severity: str = typer.Option("critical,high", "--severity", help="Severities to fix: critical,high,medium"),
    technical: bool = typer.Option(
        False, "--technical",
        help="Show the git details (backup ref, diff/test commands) instead of the plain-language summary",
    ),
    github_token: Optional[str] = typer.Option(None, "--github-token", envvar="GITHUB_TOKEN", help="GitHub token for remote-repo pull requests (never stored/logged)"),
    pr_strategy: str = typer.Option("per-category", "--pr-strategy", help="Group PRs by: per-category|per-file|per-finding|single"),
    max_prs: int = typer.Option(8, "--max-prs", help="Cap on PRs; excess low-severity categories batch into one PR"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Scan your code, fix the issues, and re-check — in plain language.

    A local ``--repo`` path gets fixes applied in place, git-free by default —
    your original is safely backed up under the hood; pass --technical for the
    git details. A remote GitHub ``--repo`` URL (with ``--github-token``) is
    cloned and gets per-category pull requests opened instead.
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

    # Remote GitHub URL → clone + per-category pull requests.
    from isitsecure.engine.fixes.pr_flow import is_remote_url
    if is_remote_url(repo):
        _run_remote_pr_fix(
            repo_url=repo,
            llm_client=llm_client,
            llm_provider=llm_provider,
            github_token=github_token,
            severity=severity,
            pr_strategy=pr_strategy,
            max_prs=max_prs,
            dry_run=dry_run,
        )
        return

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
            console.print(
                f"  Backup copy: [dim]{net.location}[/dim] "
                f"[dim](restore original: cp -a {net.location}/. .)[/dim]"
            )
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


def _run_remote_pr_fix(
    *,
    repo_url: str,
    llm_client,
    llm_provider: str,
    github_token: Optional[str],
    severity: str,
    pr_strategy: str,
    max_prs: int,
    dry_run: bool,
) -> None:
    """Scan a REMOTE GitHub repo and open per-category pull requests with fixes."""
    from isitsecure.engine.fixes.pr_flow import (
        parse_github_url,
        group_findings,
        PRFlow,
    )

    # Parse + guard the host up front so we fail clearly before scanning.
    try:
        ref = parse_github_url(repo_url)
    except ValueError as exc:
        err_console.print(f"[red]Couldn't parse that repo URL:[/red] {exc}")
        raise typer.Exit(1)

    if not ref.is_github:
        err_console.print(
            f"[yellow]{ref.host} pull requests aren't supported yet — GitHub only.[/yellow]\n"
            "[dim]Scan locally and run 'isitsecure fix --repo <path>' to apply fixes in place.[/dim]"
        )
        raise typer.Exit(1)

    if not github_token:
        err_console.print(
            "[red]Opening pull requests on a remote repo needs a GitHub token.[/red]\n"
            "[bold]Fix:[/bold] pass [dim]--github-token[/dim] (or set GITHUB_TOKEN). "
            "It's used only for the push + PR and is never stored or logged."
        )
        raise typer.Exit(1)

    console.print(Panel(
        f"[bold]isitsecure fix (remote)[/bold]\n"
        f"Repo: {ref.slug}  |  LLM: {llm_provider}  |  Strategy: {pr_strategy}  |  Max PRs: {max_prs}",
        title="Remote Auto-Fix → Pull Requests",
        border_style="bright_magenta",
    ))

    # Step 1: Scan the remote repo (SAST — code-only).
    from isitsecure.engine.factory import (
        create_deep_security_scan_agent,
        create_repo_ingestion_service,
    )
    repo_service = create_repo_ingestion_service()
    agent = create_deep_security_scan_agent(
        llm_client=llm_client,
        judgment_llm_client=llm_client,
        repo_ingestion_service=repo_service,
    )

    console.print("\n[bold]Step 1/2:[/bold] Scanning the remote repo for vulnerabilities...")
    from isitsecure.engine.enums import ScanMode
    report = asyncio.run(
        _run_scan(agent=agent, repo_url=repo_url, scan_mode=ScanMode.CODE_ONLY)
    )
    _print_report_table(report)

    target_severities = {s.strip().lower() for s in severity.split(",")}
    fixable = [
        f for f in report.findings
        if f.code_location and f.code_location.file_path
        and (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) in target_severities
    ]
    if not fixable:
        console.print("\n[green]No fixable findings at the selected severity levels.[/green]")
        raise typer.Exit(0)

    if dry_run:
        # Show the PR plan without cloning/pushing.
        groups = group_findings(fixable, strategy=pr_strategy, max_prs=max_prs)
        console.print(f"\n[bold]Dry run — would open {len(groups)} pull request(s):[/bold]")
        for g in groups:
            label = "low-severity cleanup" if g.is_low_batch else g.title_label
            console.print(f"  • [cyan]isitsecure/fix-{g.branch_suffix}[/cyan] — {label} "
                          f"({len(g.findings)} finding(s))")
        console.print("\n[dim]Run without --dry-run to clone, push branches, and open the PRs.[/dim]")
        raise typer.Exit(0)

    # Step 2: Clone → fix → group → push → open PRs.
    console.print(f"\n[bold]Step 2/2:[/bold] Generating fixes and opening pull requests...")

    from isitsecure.engine.fixes.fix_generator import FixGenerator

    async def _emit(event: dict) -> None:
        msg = event.get("message", "")
        if msg:
            console.print(f"  [dim]{msg}[/dim]")

    async def _go():
        flow = PRFlow(FixGenerator(llm_client))
        return await flow.run(
            repo_url=repo_url,
            findings=fixable,
            github_token=github_token,
            strategy=pr_strategy,
            max_prs=max_prs,
            emit=_emit,
        )

    try:
        result = asyncio.run(_go())
    except ValueError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    # Report
    console.print()
    if result.opened_prs:
        console.print("[bold green]Pull requests opened:[/bold green]")
        for pr in result.opened_prs:
            console.print(f"  • {pr.title}")
            console.print(f"    [cyan]{pr.url}[/cyan]")
    console.print(Panel(
        f"[bold]{result.summary}[/bold]\n"
        f"{result.fixed_count} finding(s) fixed  |  "
        f"{len(result.skipped)} skipped  |  {len(result.errors)} error(s)",
        title="Remote Fix Summary",
        border_style="green" if not result.errors else "yellow",
    ))
    if result.errors:
        for e in result.errors:
            console.print(f"  [yellow]• {e}[/yellow]")
    if result.skipped and logging.getLogger().isEnabledFor(logging.DEBUG):
        for s in result.skipped:
            console.print(f"  [dim]Skipped: {s}[/dim]")
