"""Formatting for JSON-RPC error responses from language servers.

DRY: every LSP client reads the same wire format, so the one place that turns
an ``{"error": {...}}`` payload into a human sentence lives here.

Why it matters (issue #145): the clients used to collapse an error response to
``None``, which made a precise, actionable server message ("Could not find a
valid TypeScript installation…") surface as "initialize returned None.
Stderr: (empty)" — pointing the user at the wrong problem entirely.
"""

from __future__ import annotations

from typing import Any


def format_rpc_error(message: Any) -> str | None:
    """Render the ``error`` member of a JSON-RPC message, if it has one.

    Returns ``None`` for successful responses and for anything that isn't a
    JSON-RPC message, so callers can use it as the "did this fail?" test.
    """
    if not isinstance(message, dict):
        return None
    error = message.get("error")
    if error is None:
        return None
    if not isinstance(error, dict):
        return str(error)

    text = str(error.get("message", "")).strip() or "unknown error"
    code = error.get("code")
    rendered = f"[{code}] {text}" if code is not None else text

    data = error.get("data")
    if data not in (None, "", {}, []):
        rendered = f"{rendered} ({data})"
    return rendered
