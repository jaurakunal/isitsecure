"""Tests for the safe scanner runner."""

import asyncio

import pytest

from isitsecure.engine.models import (
    DeepFinding,
    FindingSource,
)
from isitsecure.engine.shared.scanner_runner import (
    ScannerTimeouts,
    run_scanner_safe,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel


def _make_finding(**kwargs: object) -> DeepFinding:
    """Helper to build a test finding."""
    defaults = {
        "source": FindingSource.DAST_URL,
        "category": FindingCategory.IDOR,
        "severity": SeverityLevel.HIGH,
        "title": "Test",
        "description": "Test description",
        "confidence": 0.9,
        "scanner_name": "test",
    }
    defaults.update(kwargs)
    return DeepFinding(**defaults)


class TestRunScannerSafe:
    """Tests for run_scanner_safe."""

    @pytest.mark.asyncio
    async def test_returns_results_on_success(self) -> None:
        """Should return scanner results normally."""
        expected = [_make_finding(), _make_finding()]

        async def scanner() -> list[DeepFinding]:
            return expected

        results = await run_scanner_safe("test_scanner", scanner())
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_returns_empty_on_timeout(self) -> None:
        """Should return [] when scanner times out."""

        async def slow_scanner() -> list[DeepFinding]:
            await asyncio.sleep(10)
            return [_make_finding()]

        results = await run_scanner_safe(
            "slow_scanner", slow_scanner(), timeout_seconds=0.1
        )
        assert results == []

    @pytest.mark.asyncio
    async def test_returns_empty_on_exception(self) -> None:
        """Should return [] when scanner raises."""

        async def broken_scanner() -> list[DeepFinding]:
            raise ValueError("Something went wrong")

        results = await run_scanner_safe("broken_scanner", broken_scanner())
        assert results == []

    @pytest.mark.asyncio
    async def test_does_not_propagate_exception(self) -> None:
        """Exception in one scanner should not affect others."""

        async def failing() -> list[DeepFinding]:
            raise RuntimeError("Boom")

        async def succeeding() -> list[DeepFinding]:
            return [_make_finding()]

        # Run both — failing one should not prevent succeeding one
        r1 = await run_scanner_safe("failing", failing())
        r2 = await run_scanner_safe("succeeding", succeeding())

        assert r1 == []
        assert len(r2) == 1

    @pytest.mark.asyncio
    async def test_uses_default_timeout(self) -> None:
        """Should use ScannerTimeouts.DEFAULT_SECONDS when not specified."""
        async def fast_scanner() -> list[DeepFinding]:
            return [_make_finding()]

        # Just verify it works with default timeout (no timeout_seconds arg)
        results = await run_scanner_safe("fast", fast_scanner())
        assert len(results) == 1


class TestScannerTimeouts:
    """Tests for ScannerTimeouts constants."""

    def test_default_timeout_value(self) -> None:
        """Default timeout should be 60 seconds."""
        assert ScannerTimeouts.DEFAULT_SECONDS == 60

    def test_llm_timeout_is_longest(self) -> None:
        """LLM code review should have the longest timeout."""
        assert ScannerTimeouts.LLM_CODE_REVIEW_SECONDS >= ScannerTimeouts.DEFAULT_SECONDS
        assert (
            ScannerTimeouts.LLM_CODE_REVIEW_SECONDS
            >= ScannerTimeouts.AUTHENTICATED_CRAWLER_SECONDS
        )
