"""Driving a scan and narrating it.

Shared by the ``scan`` and ``fix`` commands, which both need to run the engine
and show progress; it lives apart from either so neither has to import the
other.
"""

from __future__ import annotations

import typer

from isitsecure.cli._io import err_console

async def _run_scan(agent, **kwargs):
    """Run the scan, narrating each step as a live scrolling log.

    The tool "speaks" what it's doing — a phase header for each stage and an
    indented line as each scanner finishes — so a long scan visibly progresses
    instead of freezing on a single bar.
    """
    import time

    report = None
    failure: str | None = None
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

        # Keep the reason a phase gave up, so a scan that ends without a
        # report can explain itself instead of shrugging (#147).
        if data.get("error") and message:
            failure = message

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
        if failure:
            err_console.print(f"\n[red]{failure}[/red]")
        else:
            err_console.print(
                "[red]The scan finished but didn't produce any results — something "
                "went wrong along the way.[/red]"
            )
        err_console.print(
            "[dim]Try re-running with -v (verbose) to see what happened, or check "
            "that your website address / code path is correct.[/dim]"
        )
        raise typer.Exit(1)

    err_console.print(
        f"[dim]{time.monotonic() - t0:6.1f}s[/dim] [green]✓ Scan complete[/green]\n"
    )

    return report
