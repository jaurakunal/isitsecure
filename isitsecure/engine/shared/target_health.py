"""Per-host liveness tracker: stop sending into a target that stopped answering.

A DAST probe that drives the server into unbounded work (or a target that simply
fell over) turns every later request into a full client timeout. Scanners that
keep sending only wedge the server further and burn the scan budget.

The tracker counts CONSECUTIVE transport failures per host (timeouts and
connection errors -- never an HTTP status; a 5xx is an answer). Once
``UNRESPONSIVE_STREAK`` are seen in a row the host is "unresponsive": callers
should stop sending, except for one probe every ``PROBE_INTERVAL_SECONDS`` so a
recovery is noticed. It never aborts a scan: it only answers "should I send?"
and records how many requests it suppressed.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from urllib.parse import urlparse

# One timeout is a slow endpoint; three in a row with nothing answering between
# them is a server that stopped.
UNRESPONSIVE_STREAK = 3
# While unresponsive, allow a single probe this often to detect recovery.
PROBE_INTERVAL_SECONDS = 15.0


class TargetHealth:
    """Consecutive-transport-failure ledger, keyed by host."""

    def __init__(
        self,
        streak_limit: int = UNRESPONSIVE_STREAK,
        probe_interval: float = PROBE_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = streak_limit
        self._probe_interval = probe_interval
        self._clock = clock
        self._streaks: dict[str, int] = {}
        self._last_probe: dict[str, float] = {}
        self.suppressed = 0  # requests we declined to send

    @staticmethod
    def host_of(url: str) -> str:
        try:
            return urlparse(url).netloc.lower()
        except ValueError:
            return ""

    def is_unresponsive(self, url: str) -> bool:
        return self._streaks.get(self.host_of(url), 0) >= self._limit

    def should_send(self, url: str) -> bool:
        """True when a request to ``url`` may go out.

        An unresponsive host is refused (and counted in ``suppressed``) except
        for one liveness probe per probe interval.
        """
        host = self.host_of(url)
        if self._streaks.get(host, 0) < self._limit:
            return True
        now = self._clock()
        last = self._last_probe.get(host)
        if last is None or now - last >= self._probe_interval:
            self._last_probe[host] = now
            return True
        self.suppressed += 1
        return False

    def note_success(self, url: str) -> None:
        """The host ANSWERED (any HTTP status): the streak ends."""
        host = self.host_of(url)
        self._streaks.pop(host, None)
        self._last_probe.pop(host, None)

    def note_failure(self, url: str) -> bool:
        """The host did not answer. Returns True when this tips it unresponsive."""
        host = self.host_of(url)
        count = self._streaks.get(host, 0) + 1
        self._streaks[host] = count
        return count == self._limit
