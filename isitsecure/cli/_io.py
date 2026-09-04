"""The CLI's two Rich consoles.

Kept in their own module so every command module shares one pair rather than
constructing its own. Neither is given an explicit ``file``: Rich resolves
``sys.stdout``/``sys.stderr`` at write time, which is what lets Typer's
``CliRunner`` and pytest's ``capsys`` capture CLI output without either of
them being rebound.
"""

from __future__ import annotations

from rich.console import Console

console = Console()
# Decorative output (welcome banner, scan progress) goes to stderr so stdout
# stays clean for piped data (JSON/SARIF/report bodies).
err_console = Console(stderr=True)
