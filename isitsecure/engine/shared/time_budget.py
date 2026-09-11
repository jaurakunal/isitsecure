"""Cooperative time budget for bounded DAST scanners.

Scanners run under an external hard timeout (`run_scanner_safe`) that
CANCELS the coroutine on expiry — which discards every finding accumulated
so far. A scanner that tests endpoints in priority order should instead stop
*cooperatively* and RETURN what it found before that hard cancel fires.

Usage:

    budget = TimeBudget(ScannerTimeouts.INJECTION_ACTIVE_SECONDS)
    for ep in ranked_endpoints[:CAP]:
        if budget.expired():
            logger.info("stopping early — budget spent")
            break
        ...

The internal deadline is set slightly before the external timeout (safety
margin) so the scanner returns cleanly instead of being cancelled.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from contextvars import ContextVar

# The deadline `run_scanner_safe` is enforcing, published so a scanner can
# stop itself just before the cancel lands. Ambient rather than passed down,
# because the alternative is threading a timeout through every scanner's
# constructor and every call site to fix a problem none of them caused.
_deadline: ContextVar[float | None] = ContextVar("scanner_deadline", default=None)

DEFAULT_SAFETY_MARGIN = 0.15


@contextmanager
def scanner_deadline(
    total_seconds: float, safety_margin: float = DEFAULT_SAFETY_MARGIN
):
    """Publish the deadline a scanner is running under.

    Set by the runner around the hard timeout. `TimeBudget()` with no
    argument picks it up, so a scanner opts into graceful degradation with
    two lines and no knowledge of what its own timeout is.
    """
    usable = max(0.0, total_seconds * (1.0 - safety_margin))
    token = _deadline.set(time.monotonic() + usable)
    try:
        yield
    finally:
        _deadline.reset(token)


class TimeBudget:
    """Tracks a cooperative deadline, set inside a scanner's hard timeout."""

    def __init__(
        self,
        total_seconds: float | None = None,
        safety_margin: float = DEFAULT_SAFETY_MARGIN,
    ) -> None:
        """
        Args:
            total_seconds: The scanner's external timeout budget. Omit it to
                inherit the deadline the runner published, which is the
                normal case — a scanner rarely knows its own timeout, and
                hardcoding one is how the two drift apart.
            safety_margin: Fraction of the budget reserved so the scanner
                returns before the external timeout cancels it.
        """
        if total_seconds is None:
            ambient = _deadline.get()
            # Unbounded outside a scanner run — a directly-invoked scanner
            # should not stop early because nobody set a deadline.
            self._deadline = ambient if ambient is not None else float("inf")
            return
        usable = max(0.0, total_seconds * (1.0 - safety_margin))
        self._deadline = time.monotonic() + usable

    def expired(self) -> bool:
        return time.monotonic() >= self._deadline

    def remaining(self) -> float:
        return max(0.0, self._deadline - time.monotonic())
