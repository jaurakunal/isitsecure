# ---------------------------------------------------------------------------
# Ambient deadline — graceful degradation under the runner's hard timeout
# ---------------------------------------------------------------------------

import asyncio

import pytest

from isitsecure.engine.shared.time_budget import TimeBudget, scanner_deadline


class TestAmbientDeadline:
    """A scanner should stop itself and return, not be cancelled holding
    findings.

    http_probe_scanner ran 901s against a 900s timeout with four real
    findings — an exposed /.env among them — and `run_scanner_safe` discarded
    every one. Cancellation cannot return partial results, so the scanner has
    to stop first.
    """

    def test_no_deadline_means_unbounded(self) -> None:
        """A scanner invoked directly, outside a run, must not stop early
        because nobody published a deadline."""
        assert TimeBudget().remaining() == float("inf")
        assert not TimeBudget().expired()

    def test_a_published_deadline_is_inherited(self) -> None:
        with scanner_deadline(100):
            assert TimeBudget().remaining() == pytest.approx(85, abs=1)

    def test_the_margin_leaves_room_to_return(self) -> None:
        """The cooperative deadline has to land before the hard one, or the
        scanner is cancelled while tidying up."""
        with scanner_deadline(100):
            assert TimeBudget().remaining() < 100

    def test_an_explicit_budget_still_wins(self) -> None:
        """Scanners that know their own budget keep it."""
        with scanner_deadline(1000):
            assert TimeBudget(10).remaining() == pytest.approx(8.5, abs=0.5)

    def test_the_deadline_does_not_leak_out_of_the_block(self) -> None:
        with scanner_deadline(100):
            pass
        assert TimeBudget().remaining() == float("inf")

    @pytest.mark.asyncio
    async def test_it_crosses_the_task_boundary(self) -> None:
        """`run_scanner_safe` wraps the scanner in `wait_for`, which runs it
        in a new Task. A Task copies the context at creation, so a deadline
        set beforehand is visible inside — this pins that."""

        async def inside() -> float:
            return TimeBudget().remaining()

        with scanner_deadline(100):
            remaining = await asyncio.wait_for(inside(), timeout=100)
        assert remaining == pytest.approx(85, abs=1)

    def test_an_expired_deadline_reports_expired(self) -> None:
        with scanner_deadline(0):
            assert TimeBudget().expired()


class TestRunnerPublishesTheDeadline:
    """The end-to-end behaviour: partial results survive, cancellation does
    not return them."""

    @pytest.mark.asyncio
    async def test_a_scanner_that_stops_early_keeps_its_findings(self) -> None:
        """The regression this guards. Without a published deadline the
        scanner never stops, `wait_for` cancels it, and everything it found
        is thrown away."""
        from isitsecure.engine.shared.scanner_runner import run_scanner_safe

        found = []

        async def scanner():
            budget = TimeBudget()
            for i in range(1000):
                if budget.expired():
                    break
                found.append(i)
                await asyncio.sleep(0.01)
            return found

        results = await run_scanner_safe("test_scanner", scanner(), timeout_seconds=0.5)

        assert results, "a scanner that stopped on the deadline must return"
        assert results is found

    @pytest.mark.asyncio
    async def test_a_scanner_that_ignores_the_deadline_still_returns_nothing(
        self,
    ) -> None:
        """Cancellation cannot recover state, so the hard timeout remains
        all-or-nothing. That is the reason to stop cooperatively, and why the
        runner logs loudly when it has to cancel."""
        from isitsecure.engine.shared.scanner_runner import run_scanner_safe

        async def stubborn():
            await asyncio.sleep(5)
            return ["never reached"]

        results = await run_scanner_safe("stubborn", stubborn(), timeout_seconds=0.3)
        assert results == []
