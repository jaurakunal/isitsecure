"""Safe scanner execution with timeout and error isolation."""

import asyncio
import contextvars
import logging
from typing import Any, Coroutine

from isitsecure.engine.models import DeepFinding
from isitsecure.engine.shared.progress import emit
from isitsecure.engine.shared.time_budget import scanner_deadline

logger = logging.getLogger(__name__)


# Ambient list that run_scanner_safe appends "name: timed out/failed" to. The
# agent installs one per scan; tasks inherit it by reference.
_scanner_failures: contextvars.ContextVar = contextvars.ContextVar(
    "isitsecure_scanner_failures", default=None
)


def use_failure_log(log: list[str]) -> contextvars.Token:
    """Record scanner failures into ``log`` for the current context."""
    return _scanner_failures.set(log)


def reset_failure_log(token: contextvars.Token) -> None:
    try:
        _scanner_failures.reset(token)
    except ValueError:  # generator closed from a different context
        _scanner_failures.set(None)


def record_scanner_failure(scanner_name: str, reason: str) -> None:
    log = _scanner_failures.get()
    if log is not None:
        entry = f"{scanner_name}: {reason}"
        if entry not in log:
            log.append(entry)


def record_skipped_work(scanner_name: str, scanner: Any) -> None:
    """Surface work a scanner skipped without failing, into the failure log.

    Scanners record ``skipped_files`` / ``skipped_steps`` (``(item, reason)``
    pairs) and ``unchecked_packages`` (a count) when an LLM or network call
    degraded. Nothing else reads those, so a partial review looked complete.
    Read defensively (any scanner may lack them) and append one concise line
    per kind so it reaches ``DeepScanReport.scanner_errors``.
    """
    for attr, noun in (("skipped_files", "file(s) not reviewed"),
                       ("skipped_steps", "step(s) skipped")):
        items = getattr(scanner, attr, None)
        if isinstance(items, (list, tuple)) and items:
            reasons = sorted({
                str(i[1]) if isinstance(i, (list, tuple)) and len(i) > 1 else "unknown"
                for i in items
            })
            record_scanner_failure(
                scanner_name, f"{len(items)} {noun} ({', '.join(reasons[:3])})"
            )
    count = getattr(scanner, "unchecked_packages", None)
    if not isinstance(count, int) or isinstance(count, bool) or count <= 0:
        count = getattr(scanner, "_unchecked_packages", 0)
    if isinstance(count, int) and not isinstance(count, bool) and count > 0:
        record_scanner_failure(scanner_name, f"{count} package(s) not checked")


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
    IDOR_CROSS_USER_SECONDS = 1800   # 30 min
    PRIVILEGE_ESCALATION_SECONDS = 1800  # 30 min — 8 tests: differential, mutation replay, object write, etc.
    GIT_SECRET_SCAN_SECONDS = 90
    SEMGREP_TAINT_SECONDS = 150  # above SemgrepAnalyzer's own 120s subprocess timeout
    LLM_CODE_REVIEW_SECONDS = 900  # 15 min — reviews in parallel batches (includes import-graph files)
    LSP_VALIDATION_SECONDS = 600   # 10 min — LSP init + auth flow tracing
    TRIAGE_SECONDS = 900           # 15 min — batched LLM triage + themes + owner summary
    INJECTION_ADJUDICATOR_SECONDS = 240  # 4 min — batched LLM genuine-vs-benign injection review (#5)
    XSS_ACTIVE_SECONDS = 3600       # 60 min — every endpoint × 5 params × 3 probe stages (deep)
    XSS_QUICK_SECONDS = 900        # 15 min — reflected + POST-body only, no DOM pass (quick, #118)
    INJECTION_ACTIVE_SECONDS = 5400  # 90 min — every endpoint × 5 params, time-based SQLi (3s sleeps).
    # The largest single budget by far, and the one that decides how long a
    # full scan takes: any wall-clock cap below this cannot fit one scan.
    AUTH_BYPASS_SECONDS = 1800       # 30 min — multiple login attempts + timing measurements
    RATE_LIMIT_SECONDS = 900        # 15 min — 100+ burst requests
    HTTP_PROBE_SECONDS = 900        # 15 min — TRACE, host injection, directory listing, CRLF
    PROBE_ANALYZER_SECONDS = 30     # Pure data analysis, no HTTP requests
    GUIDED_DAST_SECONDS = 1800       # 30 min — SAST-guided test cases
    DOM_XSS_SECONDS = 1800           # 30 min — Playwright: navigate + hook sinks on up to 30 pages
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
        record_scanner_failure(scanner_name, "timed out")
        return []
    except Exception as e:
        logger.error("Scanner '%s' failed: %s", scanner_name, e, exc_info=True)
        record_scanner_failure(scanner_name, "failed")
        return []
