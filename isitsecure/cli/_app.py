"""The Typer application object.

Its own module to break a cycle: command modules need ``app`` to register
themselves with ``@app.command()``, and ``cli/__init__`` needs to import those
command modules for the registration to happen. Importing ``app`` from here
lets both sides do that without importing each other.
"""

from __future__ import annotations

import typer

app = typer.Typer(
    name="isitsecure",
    help="AI-powered security scanner for modern web apps. SAST + DAST + LLM review.",
    no_args_is_help=True,
)
