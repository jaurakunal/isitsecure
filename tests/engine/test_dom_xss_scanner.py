"""Tests for DOMXSSScanner — browser-based DOM XSS detection via Playwright."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from isitsecure.engine.constants import DOMXSSConfig
from isitsecure.engine.models import FindingSource
from isitsecure.engine.scanners.dom_xss_scanner import (
    DOMXSSScanner,
    _SINK_HOOK_SCRIPT,
)
from isitsecure.engine.shared.url_utils import inject_query_param
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scanner() -> DOMXSSScanner:
    return DOMXSSScanner()


def _make_mock_page(findings: list[dict] | None = None) -> MagicMock:
    """Build a mock Playwright Page that returns sink findings from evaluate."""
    page = AsyncMock()
    page.goto = AsyncMock()
    page.wait_for_load_state = AsyncMock()
    page.add_init_script = AsyncMock()

    # page.evaluate returns the hook findings list then clears it
    page.evaluate = AsyncMock(return_value=findings or [])

    return page


# ---------------------------------------------------------------------------
# Unit Tests: Finding builder
# ---------------------------------------------------------------------------


class TestBuildFinding:
    """Test _build_finding produces correct DeepFinding fields."""

    def test_query_param_finding(self, scanner: DOMXSSScanner) -> None:
        hit = {
            "sink": "innerHTML",
            "canary": "DOMXSS_CANARY_abc12345",
            "value": "<div>DOMXSS_CANARY_abc12345</div>",
            "url": "https://example.com/page?q=DOMXSS_CANARY_abc12345",
        }
        finding = scanner._build_finding(
            "https://example.com/page", hit, "query_param", "q", "DOMXSS_CANARY_abc12345",
        )

        assert finding.severity == SeverityLevel.HIGH
        assert finding.category == FindingCategory.INJECTION_RISK
        assert finding.source == FindingSource.DAST_AUTHENTICATED
        assert finding.confidence == DOMXSSConfig.CONFIDENCE_CONFIRMED
        assert finding.scanner_name == DOMXSSConfig.SCANNER_NAME
        assert "innerHTML" in finding.title
        assert "query parameter 'q'" in finding.description
        assert "DOMXSS_CANARY_abc12345" in finding.technical_detail

    def test_hash_finding(self, scanner: DOMXSSScanner) -> None:
        hit = {
            "sink": "location.assign",
            "canary": "DOMXSS_CANARY_def67890",
            "value": "javascript:DOMXSS_CANARY_def67890",
            "url": "https://example.com/page#DOMXSS_CANARY_def67890",
        }
        finding = scanner._build_finding(
            "https://example.com/page", hit, "hash_fragment", "#", "DOMXSS_CANARY_def67890",
        )

        assert "location.assign" in finding.title
        assert "hash fragment" in finding.description

    def test_postmessage_finding(self, scanner: DOMXSSScanner) -> None:
        hit = {
            "sink": "eval",
            "canary": "DOMXSS_CANARY_ghi11111",
            "value": "DOMXSS_CANARY_ghi11111",
            "url": "https://example.com/page",
        }
        finding = scanner._build_finding(
            "https://example.com/page", hit, "postMessage", "message", "DOMXSS_CANARY_ghi11111",
        )

        assert "eval" in finding.title
        assert "postMessage" in finding.description


# ---------------------------------------------------------------------------
# Unit Tests: URL helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_inject_query_param_empty_query(self) -> None:
        """Uses shared inject_query_param from url_utils (DRY)."""
        result = inject_query_param(
            "https://example.com/page", "q", "test",
        )
        assert "q=test" in result

    def test_inject_query_param_existing_query(self) -> None:
        result = inject_query_param(
            "https://example.com/page?a=1", "q", "test",
        )
        assert "a=1" in result
        assert "q=test" in result

    def test_generate_canary_format(self, scanner: DOMXSSScanner) -> None:
        canary = scanner._generate_canary()
        assert canary.startswith("DOMXSS_CANARY_")
        assert len(canary) == len("DOMXSS_CANARY_") + 8


# ---------------------------------------------------------------------------
# Integration Tests: scan_with_page
# ---------------------------------------------------------------------------


class TestScanWithPage:
    """Test the scan_with_page flow using a mock Playwright page."""

    @pytest.mark.asyncio
    async def test_confirmed_dom_xss_via_query_param(self, scanner: DOMXSSScanner) -> None:
        """Simulate a sink hit on the first query param injection."""

        canary_holder = {}

        async def mock_evaluate(script: str) -> list[dict]:
            # Return a finding on the first collection call, then empty
            if "window.__domxss_findings" in script:
                if canary_holder.get("returned"):
                    return []
                canary_holder["returned"] = True
                return [
                    {
                        "sink": "innerHTML",
                        "canary": canary_holder.get("canary", "DOMXSS_CANARY_aaaaaaaa"),
                        "value": f"<b>{canary_holder.get('canary', 'DOMXSS_CANARY_aaaaaaaa')}</b>",
                        "url": "https://example.com/page?q=...",
                    }
                ]
            return []

        page = AsyncMock()
        page.goto = AsyncMock()
        page.wait_for_load_state = AsyncMock()
        page.evaluate = AsyncMock(side_effect=mock_evaluate)

        # Patch _generate_canary to track what canary is used
        original_gen = scanner._generate_canary
        def patched_gen():
            c = original_gen()
            canary_holder["canary"] = c
            return c
        scanner._generate_canary = patched_gen

        findings = await scanner.scan_with_page(
            page, ["https://example.com/page"],
        )

        assert len(findings) >= 1
        assert findings[0].severity == SeverityLevel.HIGH
        assert "innerHTML" in findings[0].title
        assert findings[0].scanner_name == DOMXSSConfig.SCANNER_NAME

    @pytest.mark.asyncio
    async def test_no_findings_when_sinks_not_reached(self, scanner: DOMXSSScanner) -> None:
        """No findings when canary never reaches a sink."""
        page = AsyncMock()
        page.goto = AsyncMock()
        page.wait_for_load_state = AsyncMock()
        page.evaluate = AsyncMock(return_value=[])

        findings = await scanner.scan_with_page(
            page, ["https://example.com/page"],
        )

        assert findings == []

    @pytest.mark.asyncio
    async def test_empty_pages_list(self, scanner: DOMXSSScanner) -> None:
        """Empty page list produces no findings."""
        page = AsyncMock()
        findings = await scanner.scan_with_page(page, [])
        assert findings == []

    @pytest.mark.asyncio
    async def test_max_pages_respected(self, scanner: DOMXSSScanner) -> None:
        """Scanner respects MAX_PAGES_TO_TEST limit."""
        page = AsyncMock()
        page.goto = AsyncMock()
        page.wait_for_load_state = AsyncMock()
        page.evaluate = AsyncMock(return_value=[])

        many_pages = [f"https://example.com/page{i}" for i in range(100)]

        # Patch wait to zero for speed
        with patch(
            "isitsecure.engine.scanners.dom_xss_scanner.asyncio.sleep",
            new_callable=AsyncMock,
        ):
            await scanner.scan_with_page(page, many_pages)

        # Should have navigated at most MAX_PAGES_TO_TEST * num_vectors times
        # (each page tests multiple vectors but stops early on no findings)
        assert page.goto.call_count <= DOMXSSConfig.MAX_PAGES_TO_TEST * (
            len(DOMXSSConfig.INJECTION_PARAMS) + 2  # +2 for hash + postMessage
        )


# ---------------------------------------------------------------------------
# Integration Tests: standalone scan (mocked Playwright)
# ---------------------------------------------------------------------------


class TestStandaloneScan:
    """Test the standalone scan() method that launches its own browser."""

    @pytest.mark.asyncio
    async def test_scan_returns_empty_without_playwright(self, scanner: DOMXSSScanner) -> None:
        """Graceful degradation when Playwright is not installed."""
        with patch(
            "isitsecure.engine.scanners.dom_xss_scanner.async_playwright",
            None,
        ):
            findings = await scanner.scan(["https://example.com"])
            assert findings == []

    @pytest.mark.asyncio
    async def test_scan_returns_empty_with_no_pages(self, scanner: DOMXSSScanner) -> None:
        findings = await scanner.scan([])
        assert findings == []


# ---------------------------------------------------------------------------
# Constants validation
# ---------------------------------------------------------------------------


class TestDOMXSSConfig:
    """Verify config constants are sane."""

    def test_scanner_name(self) -> None:
        assert DOMXSSConfig.SCANNER_NAME == "dom_xss_scanner"

    def test_confidence_is_high(self) -> None:
        assert DOMXSSConfig.CONFIDENCE_CONFIRMED >= 0.9

    def test_injection_params_non_empty(self) -> None:
        assert len(DOMXSSConfig.INJECTION_PARAMS) > 0

    def test_postmessage_payloads_contain_placeholder(self) -> None:
        for payload in DOMXSSConfig.POSTMESSAGE_PAYLOADS:
            assert "{canary}" in payload


class TestSinkHookScript:
    """Verify the injected JS hook script is well-formed."""

    def test_script_is_non_empty(self) -> None:
        assert len(_SINK_HOOK_SCRIPT) > 100

    def test_script_contains_canary_regex(self) -> None:
        assert "DOMXSS_CANARY_" in _SINK_HOOK_SCRIPT

    def test_script_hooks_innerhtml(self) -> None:
        assert "innerHTML" in _SINK_HOOK_SCRIPT

    def test_script_hooks_eval(self) -> None:
        assert "origEval" in _SINK_HOOK_SCRIPT

    def test_script_hooks_document_write(self) -> None:
        assert "document.write" in _SINK_HOOK_SCRIPT

    def test_script_hooks_location_assign(self) -> None:
        assert "location.assign" in _SINK_HOOK_SCRIPT

    def test_script_hooks_postmessage_sinks(self) -> None:
        # setTimeout and setInterval with string args are postMessage attack vectors
        assert "origSetTimeout" in _SINK_HOOK_SCRIPT
        assert "origSetInterval" in _SINK_HOOK_SCRIPT
