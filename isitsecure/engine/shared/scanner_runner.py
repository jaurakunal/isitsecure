"""Safe scanner execution with timeout and error isolation."""

import asyncio
import logging
from typing import Any, Coroutine

from isitsecure.engine.models import DeepFinding
from isitsecure.engine.shared.progress import emit
from isitsecure.engine.shared.time_budget import scanner_deadline

logger = logging.getLogger(__name__)


class ScannerTimeouts:
    """Per-scanner timeout configuration.

    These are now the *only* bound on how much of an application a scanner
    covers: the endpoint caps that used to stop work after the first 20 or 30
    endpoints are gone, because probing costs HTTP requests rather than
    tokens and a cap of 30 against 77 endpoints was a coin flip about which
    half got examined.

    They are correspondingly generous. A scan that takes an hour and finishes
    is worth more than one that takes ten minutes and quietly skipped two
    thirds of the surface — provided it says what it is doing, which is what
    `progress.emit` is for. Timing out is now a real failure signal rather
    than the normal way a scanner ends.
    """

    DEFAULT_SECONDS = 600
    AUTHENTICATED_CRAWLER_SECONDS = 900  # Browser login + BFS crawl of 50 pages
    IDOR_CROSS_USER_SECONDS = 1800
    PRIVILEGE_ESCALATION_SECONDS = 1800  # 8 tests: differential, mutation replay, object write, etc.
    GIT_SECRET_SCAN_SECONDS = 90
    SEMGREP_TAINT_SECONDS = 150  # above SemgrepAnalyzer's own 120s subprocess timeout
    LLM_CODE_REVIEW_SECONDS = 900  # 15 min — reviews in parallel batches (includes import-graph files)
    LSP_VALIDATION_SECONDS = 600   # 2 min — LSP init + auth flow tracing
    TRIAGE_SECONDS = 900           # 15 min — batched LLM triage + themes + owner summary
    INJECTION_ADJUDICATOR_SECONDS = 240  # 4 min — batched LLM genuine-vs-benign injection review (#5)
    XSS_ACTIVE_SECONDS = 3600       # 10 min — 20 endpoints × 5 params × 3 probe stages (deep)
    XSS_QUICK_SECONDS = 900        # 2 min — reflected + POST-body only, no DOM pass (quick, #118)
    INJECTION_ACTIVE_SECONDS = 5400  # 15 min — 30 endpoints × 5 params, time-based SQLi (3s sleeps)
    AUTH_BYPASS_SECONDS = 1800       # 5 min — multiple login attempts + timing measurements
    RATE_LIMIT_SECONDS = 900        # 5 min — 100+ burst requests
    HTTP_PROBE_SECONDS = 900        # 3 min — TRACE, host injection, directory listing, CRLF
    PROBE_ANALYZER_SECONDS = 30     # Pure data analysis, no HTTP requests
    GUIDED_DAST_SECONDS = 1800       # 10 min — SAST-guided test cases
    DOM_XSS_SECONDS = 1800           # 15 min — Playwright: navigate + hook sinks on up to 30 pages
    OOB_POLL_SECONDS = 30           # OOB callback poll (just HTTP calls, no scanning)


async def run_scanner_safe(
    scanner_name: str,
    scan_coro: Coroutine[Any, Any, list[DeepFinding]],
    timeout_seconds: float = ScannerTimeouts.DEFAULT_SECONDS,
) -> list[DeepFinding]:
    """Run a scanner coroutine with timeout and error isolation.

    A single scanner failure MUST NOT kill the entire scan.
    Returns empty list on timeout or error.

    Args:
        scanner_name: Name of the scanner (for logging).
        scan_coro: The coroutine to execute.
        timeout_seconds: Maximum time to wait before cancelling.

    Returns:
        List of findings, or empty list on failure.
    """
    try:
        # Publish the deadline so the scanner can stop itself and RETURN what
        # it found. A cancel here discards everything: http_probe_scanner ran
        # 901s against a 900s timeout holding four real findings — an exposed
        # /.env among them — and reported none of them.
        with scanner_deadline(timeout_seconds):
            return await asyncio.wait_for(scan_coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning(
            "Scanner '%s' timed out after %ss — findings discarded. It did "
            "not stop on the cooperative deadline, which means either it has "
            "no TimeBudget or it blocked between checks.",
            scanner_name, timeout_seconds,
        )
        emit(
            f"{scanner_name}: hard timeout at {timeout_seconds}s, "
            "findings lost"
        )
        return []
    except Exception as e:
        logger.error("Scanner '%s' failed: %s", scanner_name, e, exc_info=True)
        return []
