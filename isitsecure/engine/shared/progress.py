"""Ambient progress reporting so scanners can narrate long-running work.

A scanner deep in a loop can call ``emit("probing /api/x")`` and the message
surfaces in the agent's event stream — and thus the live CLI log — without the
scanner holding a reference to the agent or changing its return type. When no
reporter is active (unit tests, direct scanner calls), ``emit`` is a cheap
no-op.

The agent installs a :class:`ProgressReporter` for the duration of a scan via
``use_reporter`` and drains its queue between/around ``await`` points, turning
each emitted message into a ``DeepScanEvent``. Because ``asyncio`` tasks capture
the current context at creation time, scanner tasks launched by the agent
inherit the active reporter automatically.
"""

from __future__ import annotations

import asyncio
import contextvars
import logging

logger = logging.getLogger(__name__)

_current: contextvars.ContextVar = contextvars.ContextVar(
    "isitsecure_progress_reporter", default=None
)


class ProgressReporter:
    """Collects progress messages emitted anywhere during a scan."""

    def __init__(self) -> None:
        self.queue: asyncio.Queue = asyncio.Queue()

    def post(self, message: str, data: dict) -> None:
        self.queue.put_nowait((message, data))


def emit(message: str, **data) -> None:
    """Report a progress message from inside a scan. No-op if none is active."""
    reporter = _current.get()
    if reporter is None:
        return
    try:
        reporter.post(message, data)
    except Exception as exc:  # never let progress reporting break a scan
        logger.debug("progress emit failed: %s", exc)


def use_reporter(reporter: ProgressReporter | None):
    """Install ``reporter`` as the ambient one; returns a token for reset."""
    return _current.set(reporter)


def reset_reporter(token) -> None:
    """Restore the previous ambient reporter."""
    _current.reset(token)
