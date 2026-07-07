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


class TimeBudget:
    """Tracks a cooperative deadline, set inside a scanner's hard timeout."""

    def __init__(self, total_seconds: float, safety_margin: float = 0.15) -> None:
        """
        Args:
            total_seconds: The scanner's external timeout budget.
            safety_margin: Fraction of the budget reserved so the scanner
                returns before the external timeout cancels it.
        """
        usable = max(0.0, total_seconds * (1.0 - safety_margin))
        self._deadline = time.monotonic() + usable

    def expired(self) -> bool:
        return time.monotonic() >= self._deadline

    def remaining(self) -> float:
        return max(0.0, self._deadline - time.monotonic())
