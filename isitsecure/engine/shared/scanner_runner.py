"""Safe scanner execution with timeout and error isolation."""

import asyncio
import logging
from typing import Any, Coroutine

from isitsecure.engine.models import DeepFinding

logger = logging.getLogger(__name__)


class ScannerTimeouts:
    """Per-scanner timeout configuration."""

    DEFAULT_SECONDS = 60
    AUTHENTICATED_CRAWLER_SECONDS = 300  # Browser login + BFS crawl of 50 pages
    IDOR_CROSS_USER_SECONDS = 120
    PRIVILEGE_ESCALATION_SECONDS = 180  # 8 tests: differential, mutation replay, object write, etc.
    GIT_SECRET_SCAN_SECONDS = 90
    LLM_CODE_REVIEW_SECONDS = 900  # 15 min — reviews in parallel batches (includes import-graph files)
    LSP_VALIDATION_SECONDS = 120   # 2 min — LSP init + auth flow tracing
    TRIAGE_SECONDS = 900           # 15 min — batched LLM triage + themes + owner summary
    XSS_ACTIVE_SECONDS = 600       # 10 min — 20 endpoints × 5 params × 3 probe stages
    INJECTION_ACTIVE_SECONDS = 900  # 15 min — 30 endpoints × 5 params, time-based SQLi (3s sleeps)
    AUTH_BYPASS_SECONDS = 300       # 5 min — multiple login attempts + timing measurements
    RATE_LIMIT_SECONDS = 300        # 5 min — 100+ burst requests
    HTTP_PROBE_SECONDS = 180        # 3 min — TRACE, host injection, directory listing, CRLF
    PROBE_ANALYZER_SECONDS = 30     # Pure data analysis, no HTTP requests
    GUIDED_DAST_SECONDS = 600       # 10 min — SAST-guided test cases
    DOM_XSS_SECONDS = 900           # 15 min — Playwright: navigate + hook sinks on up to 30 pages
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
        return await asyncio.wait_for(scan_coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning(
            "Scanner '%s' timed out after %ss", scanner_name, timeout_seconds
        )
        return []
    except Exception as e:
        logger.error("Scanner '%s' failed: %s", scanner_name, e, exc_info=True)
        return []
