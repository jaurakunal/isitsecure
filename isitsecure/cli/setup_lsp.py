"""The ``setup`` command: install and report on scan prerequisites.

Acts on what ``environment`` detects — API key, DAST browser, language servers,
and the TypeScript runtime the TS language server needs to start at all.
"""

from __future__ import annotations

import sys

import typer
from rich.panel import Panel

from isitsecure.cli._app import app
from isitsecure.cli._io import console
from isitsecure.cli.environment import (
    _LSP_SPECS,
    _chromium_installed,
    _first_which,
    _os_hint,
    _resolve_install_cmd,
)
from isitsecure.cli.config import (
    CONFIG_DIR,
    CONFIG_FILE,
    _ensure_config_dir,
    _load_api_key,
)

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

    if _first_which(("typescript-language-server",)):
        from isitsecure.engine.code_analysis.lsp.tsserver_locator import (
            find_tsserver_js,
        )
        tsserver = find_tsserver_js()
        if tsserver:
            console.print("  [green]✓[/green] TypeScript runtime (tsserver.js): "
                          f"[dim]{tsserver}[/dim]")
        else:
            console.print("  [yellow]•[/yellow] TypeScript runtime (tsserver.js): "
                          "[dim]missing — the TS language server can't start; "
                          "run `isitsecure setup --lsp`[/dim]")
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

    _ensure_tsserver_runtime()


def _ensure_tsserver_runtime() -> None:
    """Make sure the TypeScript language server has a TypeScript to run.

    typescript-language-server ships no TypeScript of its own and resolves it
    from the workspace — but scans run against an ingested copy with no
    ``node_modules``, so there is never one to find and the server refuses to
    start. We install a private TypeScript 5.x under ``~/.isitsecure/lsp`` and
    pass it as ``tsserver.path``; 5.x specifically, because ``typescript@latest``
    is now the Go rewrite with no ``lib/tsserver.js`` (issue #145).
    """
    import shutil
    import subprocess

    from isitsecure.engine.code_analysis.lsp.tsserver_locator import (
        PROVISIONED_ROOT,
        TYPESCRIPT_PACKAGE_SPEC,
        find_tsserver_js,
    )

    if not _first_which(("typescript-language-server",)):
        return  # nothing to feed — the server itself isn't installed

    found = find_tsserver_js()
    if found:
        console.print(f"  [green]✓[/green] TypeScript runtime: [dim]{found}[/dim]")
        return

    if not shutil.which("npm"):
        console.print("  [yellow]![/yellow] TypeScript runtime: [dim]npm not on PATH — "
                      f"install {TYPESCRIPT_PACKAGE_SPEC} and set "
                      "ISITSECURE_TSSERVER_PATH to its lib/tsserver.js[/dim]")
        return

    console.print(f"  [cyan]→[/cyan] TypeScript runtime: installing {TYPESCRIPT_PACKAGE_SPEC}…")
    try:
        PROVISIONED_ROOT.mkdir(parents=True, exist_ok=True)
        res = subprocess.run(
            _resolve_install_cmd([
                "npm", "install", "--prefix", str(PROVISIONED_ROOT),
                TYPESCRIPT_PACKAGE_SPEC, "--no-audit", "--no-fund",
            ]),
            capture_output=True, text=True, timeout=600,
        )
    except Exception as exc:
        console.print(f"  [red]✗[/red] TypeScript runtime: {exc}")
        return

    found = find_tsserver_js()
    if res.returncode == 0 and found:
        console.print("  [green]✓[/green] TypeScript runtime: installed "
                      f"[dim]({found})[/dim]")
    else:
        tail = (res.stderr or res.stdout or "install did not complete").strip().splitlines()
        console.print("  [yellow]![/yellow] TypeScript runtime: "
                      f"{(tail[-1] if tail else '')[:120]}")
        console.print("      [dim]Auth-flow tracing will fall back to regex-only analysis.[/dim]")


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
