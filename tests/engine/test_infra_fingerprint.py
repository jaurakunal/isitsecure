"""Tests for the header-based infrastructure fingerprint helper and the
url-only anon RLS scan wiring in the orchestrator."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from isitsecure.engine.agent import DeepScanEvent, DeepSecurityScanAgent
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.shared.infra_fingerprint import detect_providers


# ---------------------------------------------------------------------------
# detect_providers
# ---------------------------------------------------------------------------

class TestDetectProviders:
    def test_cloudflare_via_cf_ray(self) -> None:
        assert detect_providers({"cf-ray": "abc123-SJC"}) == ["Cloudflare"]

    def test_cloudflare_via_server_header(self) -> None:
        assert detect_providers({"Server": "cloudflare"}) == ["Cloudflare"]

    def test_case_insensitive_header_names(self) -> None:
        assert detect_providers({"CF-RAY": "abc"}) == ["Cloudflare"]

    def test_vercel_detected(self) -> None:
        assert detect_providers({"x-vercel-id": "iad1::xyz"}) == ["Vercel"]

    def test_netlify_detected(self) -> None:
        assert detect_providers({"x-nf-request-id": "01H..."}) == ["Netlify"]

    def test_multiple_providers(self) -> None:
        result = detect_providers(
            {"cf-ray": "abc-SJC", "x-vercel-id": "iad1::xyz"}
        )
        assert "Cloudflare" in result
        assert "Vercel" in result

    def test_no_providers_detected(self) -> None:
        assert detect_providers({"server": "nginx", "content-type": "text/html"}) == []

    def test_empty_headers(self) -> None:
        assert detect_providers({}) == []

    def test_none_headers(self) -> None:
        assert detect_providers(None) == []

    def test_no_duplicate_provider_when_multiple_signals_match(self) -> None:
        # Both cf-ray and cf-cache-status match Cloudflare -> reported once.
        result = detect_providers(
            {"cf-ray": "abc", "cf-cache-status": "HIT", "server": "cloudflare"}
        )
        assert result == ["Cloudflare"]


# ---------------------------------------------------------------------------
# _resolve_backend
# ---------------------------------------------------------------------------

class TestResolveBackend:
    def _agent(self) -> DeepSecurityScanAgent:
        return DeepSecurityScanAgent(
            ingestion_service=AsyncMock(),
            endpoint_scanner=AsyncMock(),
        )

    def _snapshot(self, raw_headers: dict[str, str]) -> MagicMock:
        snap = MagicMock()
        snap.headers.raw_headers = raw_headers
        return snap

    def test_supabase_only(self) -> None:
        agent = self._agent()
        backend = agent._resolve_backend(
            None, self._snapshot({}), "https://xyz.supabase.co"
        )
        assert backend == "Supabase"

    def test_cloudflare_plus_supabase(self) -> None:
        agent = self._agent()
        backend = agent._resolve_backend(
            None, self._snapshot({"cf-ray": "abc-SJC"}), "https://xyz.supabase.co"
        )
        assert backend == "Cloudflare + Supabase"

    def test_no_signals_empty(self) -> None:
        agent = self._agent()
        assert agent._resolve_backend(None, self._snapshot({}), None) == ""

    def test_sast_backend_takes_precedence(self) -> None:
        agent = self._agent()
        repo = MagicMock()
        repo.backend.value = "Django"
        backend = agent._resolve_backend(
            repo, self._snapshot({"cf-ray": "abc"}), "https://xyz.supabase.co"
        )
        assert backend == "Django"


# ---------------------------------------------------------------------------
# url-only anon RLS wiring
# ---------------------------------------------------------------------------

async def _collect(gen) -> list[DeepScanEvent]:
    return [event async for event in gen]


def _make_agent_with_supabase(rls_scanner) -> DeepSecurityScanAgent:
    ingestion = AsyncMock()
    snap = MagicMock()
    snap.url = "https://example.com"
    snap.all_js_content = "const x = 1"
    snap.html_content = "<html></html>"
    snap.assets = []
    snap.headers.raw_headers = {"cf-ray": "abc-SJC"}
    ingestion.ingest.return_value = snap

    endpoint_scanner = AsyncMock()
    # Non-empty endpoints so Phase 4 DAST block (and the anon RLS block) runs.
    ep = DiscoveredEndpoint(url="https://example.com/api/data")
    endpoint_scanner.discover.return_value = [ep]

    return DeepSecurityScanAgent(
        ingestion_service=ingestion,
        endpoint_scanner=endpoint_scanner,
        rls_deep_scanner=rls_scanner,
    )


@pytest.mark.asyncio
async def test_url_only_invokes_anon_rls_when_supabase_present() -> None:
    """A url-only scan with a discovered Supabase project should call the RLS
    deep scanner with the anon key and NO sessions."""
    rls_scanner = MagicMock()
    rls_scanner.scan = AsyncMock(return_value=[])

    agent = _make_agent_with_supabase(rls_scanner)

    supabase_url = "https://xyz.supabase.co"
    anon_key = "anon-key-123"
    tables = ["profiles", "orders"]

    with patch.object(
        agent, "_extract_supabase_info",
        return_value=(supabase_url, anon_key, tables),
    ), patch.object(
        agent, "_run_dast_scanners", AsyncMock(return_value=([], []))
    ), patch.object(
        agent, "_extract_page_urls", return_value=[]
    ), patch(
        "isitsecure.engine.shared.oob_callback.OOBCallbackService"
    ) as mock_oob:
        mock_oob.return_value.register = AsyncMock()
        mock_oob.return_value.is_registered = False
        events = await _collect(agent.scan(target_url="https://example.com"))

    rls_scanner.scan.assert_awaited_once()
    kwargs = rls_scanner.scan.await_args.kwargs
    assert kwargs["supabase_url"] == supabase_url
    assert kwargs["anon_key"] == anon_key
    assert kwargs["tables"] == tables
    # url-only path must NOT pass sessions.
    assert "user_a_session" not in kwargs
    assert "user_b_session" not in kwargs

    # backend should reflect Cloudflare header + Supabase discovery.
    report = events[-1].data["report"]
    assert report["backend"] == "Cloudflare + Supabase"


@pytest.mark.asyncio
async def test_url_only_skips_anon_rls_when_no_supabase() -> None:
    """No Supabase project discovered -> RLS deep scanner is not invoked."""
    rls_scanner = MagicMock()
    rls_scanner.scan = AsyncMock(return_value=[])

    agent = _make_agent_with_supabase(rls_scanner)

    with patch.object(
        agent, "_extract_supabase_info", return_value=(None, None, []),
    ), patch.object(
        agent, "_run_dast_scanners", AsyncMock(return_value=([], []))
    ), patch.object(
        agent, "_extract_page_urls", return_value=[]
    ), patch(
        "isitsecure.engine.shared.oob_callback.OOBCallbackService"
    ) as mock_oob:
        mock_oob.return_value.register = AsyncMock()
        mock_oob.return_value.is_registered = False
        await _collect(agent.scan(target_url="https://example.com"))

    rls_scanner.scan.assert_not_called()
