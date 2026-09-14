"""Cooperative TimeBudget guards on the DAST scanners.

`run_scanner_safe` wraps each scanner in `scanner_deadline(timeout)`, publishing
an ambient deadline. A scanner adopts graceful degradation by creating a no-arg
`TimeBudget()` (which inherits that deadline) and checking `budget.expired()` at
the top of its endpoint loop, so it RETURNS the findings gathered so far instead
of being hard-cancelled (which discards all of them).

These tests pin that behaviour for a representative scanner of each loop shape:
- a RateLimitedClient-wrapped single loop (SSRF, mass-assignment),
- a helper-method loop (security headers).

The contract: with an already-expired ambient deadline, the per-endpoint work
method is NEVER entered; without one, it is. That proves the guard reads the
ambient deadline and short-circuits before any network call.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.scanners.ssrf_scanner import SSRFScanner
from isitsecure.engine.scanners.mass_assignment_scanner import MassAssignmentScanner
from isitsecure.engine.scanners.security_headers_scanner import SecurityHeadersScanner
from isitsecure.engine.shared.time_budget import scanner_deadline


def _patch_client(module_path: str):
    """Patch a scanner module's RateLimitedClient with an async-cm no-op."""
    rc = patch(f"{module_path}.RateLimitedClient")
    return rc


@pytest.mark.asyncio
async def test_ssrf_stops_before_probing_when_deadline_expired() -> None:
    """An expired ambient deadline stops SSRF before the first param probe."""
    ep = DiscoveredEndpoint(
        url="https://ex.com/api/fetch?url=https://google.com",
        method=EndpointMethod.GET,
        query_param_names=["url"],
    )
    scanner = SSRFScanner()
    with patch.object(
        scanner, "_test_endpoint_param", new=AsyncMock(return_value=[])
    ) as probe, _patch_client("isitsecure.engine.scanners.ssrf_scanner") as rc:
        rc.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
        rc.return_value.__aexit__ = AsyncMock(return_value=False)
        with scanner_deadline(0.0):  # already expired
            findings = await scanner.scan([ep], snapshot=None)
    assert findings == []
    probe.assert_not_called()


@pytest.mark.asyncio
async def test_ssrf_probes_when_deadline_is_live() -> None:
    """The same endpoint IS probed when the deadline has not passed."""
    ep = DiscoveredEndpoint(
        url="https://ex.com/api/fetch?url=https://google.com",
        method=EndpointMethod.GET,
        query_param_names=["url"],
    )
    scanner = SSRFScanner()
    with patch.object(
        scanner, "_test_endpoint_param", new=AsyncMock(return_value=[])
    ) as probe, _patch_client("isitsecure.engine.scanners.ssrf_scanner") as rc:
        rc.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
        rc.return_value.__aexit__ = AsyncMock(return_value=False)
        with scanner_deadline(3600.0):  # plenty of time
            await scanner.scan([ep], snapshot=None)
    probe.assert_called_once()


@pytest.mark.asyncio
async def test_mass_assignment_stops_when_deadline_expired() -> None:
    """An expired ambient deadline stops mass-assignment before any endpoint."""
    ep = DiscoveredEndpoint(
        url="https://ex.com/api/users/1",
        method=EndpointMethod.PUT,
        query_param_names=[],
    )
    scanner = MassAssignmentScanner()
    with patch.object(
        scanner, "_test_endpoint", new=AsyncMock(return_value=[])
    ) as probe, _patch_client(
        "isitsecure.engine.scanners.mass_assignment_scanner"
    ) as rc:
        rc.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
        rc.return_value.__aexit__ = AsyncMock(return_value=False)
        with scanner_deadline(0.0):
            findings = await scanner.scan([ep], snapshot=None)
    assert findings == []
    probe.assert_not_called()


@pytest.mark.asyncio
async def test_mass_assignment_tests_endpoint_when_deadline_is_live() -> None:
    """Guards against a trivially-passing expired test: the same endpoint IS
    tested when the deadline is live, proving it reaches the guarded loop."""
    ep = DiscoveredEndpoint(
        url="https://ex.com/api/users/1",
        method=EndpointMethod.PUT,
        query_param_names=[],
    )
    scanner = MassAssignmentScanner()
    with patch.object(
        scanner, "_test_endpoint", new=AsyncMock(return_value=[])
    ) as probe, _patch_client(
        "isitsecure.engine.scanners.mass_assignment_scanner"
    ) as rc:
        rc.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
        rc.return_value.__aexit__ = AsyncMock(return_value=False)
        with scanner_deadline(3600.0):
            await scanner.scan([ep], snapshot=None)
    probe.assert_called_once()


@pytest.mark.asyncio
async def test_security_headers_stops_when_deadline_expired() -> None:
    """An expired ambient deadline stops the header loop before any request."""
    ep = DiscoveredEndpoint(url="https://ex.com", method=EndpointMethod.GET)
    scanner = SecurityHeadersScanner()
    with patch.object(
        scanner, "_check_single_endpoint", new=AsyncMock(return_value=[])
    ) as probe, _patch_client(
        "isitsecure.engine.scanners.security_headers_scanner"
    ) as rc:
        rc.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
        rc.return_value.__aexit__ = AsyncMock(return_value=False)
        with scanner_deadline(0.0):
            findings = await scanner.scan([ep], snapshot=None)
    assert findings == []
    probe.assert_not_called()


@pytest.mark.asyncio
async def test_security_headers_checks_when_deadline_is_live() -> None:
    """The header check runs when the deadline is live (guard is not a no-op)."""
    ep = DiscoveredEndpoint(url="https://ex.com", method=EndpointMethod.GET)
    scanner = SecurityHeadersScanner()
    with patch.object(
        scanner, "_check_single_endpoint", new=AsyncMock(return_value=[])
    ) as probe, _patch_client(
        "isitsecure.engine.scanners.security_headers_scanner"
    ) as rc:
        rc.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
        rc.return_value.__aexit__ = AsyncMock(return_value=False)
        with scanner_deadline(3600.0):
            await scanner.scan([ep], snapshot=None)
    probe.assert_called_once()
