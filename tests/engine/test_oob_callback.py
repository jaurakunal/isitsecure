"""Tests for OOB (Out-of-Band) callback service — interactsh v1 protocol."""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, patch, MagicMock

import httpx
import pytest

from isitsecure.engine.constants import OOBConfig
from isitsecure.engine.models import FindingSource
from isitsecure.engine.shared.oob_callback import (
    OOBCallbackService,
    OOBInteraction,
    OOBSession,
    _TagMetadata,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def service() -> OOBCallbackService:
    return OOBCallbackService()


@pytest.fixture
def registered_service() -> OOBCallbackService:
    """Service with a pre-registered session (skips HTTP call)."""
    svc = OOBCallbackService()
    svc._session = OOBSession(
        correlation_id="a1b2c3d4e5f6g7h8i9j0",
        domain="oob.isitsecure.ai",
        server_url="http://oob.isitsecure.ai",
        secret_key="dGVzdHNlY3JldA==",
        registered=True,
        private_key=None,  # Not needed for URL generation / finding tests
    )
    return svc


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:

    def test_not_registered_initially(self, service: OOBCallbackService) -> None:
        assert not service.is_registered

    def test_interaction_count_starts_zero(self, service: OOBCallbackService) -> None:
        assert service.interaction_count == 0

    @pytest.mark.asyncio
    async def test_register_success(self, service: OOBCallbackService) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"message": "registration successful"}

        with patch("httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            client.post = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await service.register()

        assert result is True
        assert service.is_registered
        assert len(service._session.correlation_id) == OOBConfig.CORRELATION_ID_LENGTH
        assert service._session.domain  # domain resolved
        assert service._session.private_key is not None  # RSA key generated

    @pytest.mark.asyncio
    async def test_register_sends_rsa_public_key(self, service: OOBCallbackService) -> None:
        """Registration payload must include base64-encoded PEM public key."""
        captured_json = {}

        async def capture_post(url, **kwargs):
            captured_json.update(kwargs.get("json", {}))
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"message": "registration successful"}
            return resp

        with patch("httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            client.post = capture_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await service.register()

        assert "public-key" in captured_json
        assert "secret-key" in captured_json
        assert "correlation-id" in captured_json
        # Public key should be base64-encoded PEM
        decoded = base64.b64decode(captured_json["public-key"]).decode()
        assert "BEGIN PUBLIC KEY" in decoded

    @pytest.mark.asyncio
    async def test_register_failure_all_servers(self, service: OOBCallbackService) -> None:
        with patch("httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await service.register()

        assert result is False
        assert not service.is_registered

    @pytest.mark.asyncio
    async def test_register_tries_fallback_servers(self, service: OOBCallbackService) -> None:
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise httpx.ConnectError("refused")
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"message": "registration successful"}
            return resp

        with patch("httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            client.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await service.register()

        assert result is True
        assert call_count >= 3

    @pytest.mark.asyncio
    async def test_register_skips_non_200(self, service: OOBCallbackService) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            client.post = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await service.register()

        assert result is False

    def test_resolve_domain_self_hosted(self) -> None:
        domain = OOBCallbackService._resolve_domain("http://oob.isitsecure.ai")
        assert domain == OOBConfig.SELF_HOSTED_DOMAIN

    def test_resolve_domain_public_server(self) -> None:
        domain = OOBCallbackService._resolve_domain("https://oast.pro")
        assert domain == "oast.pro"


# ---------------------------------------------------------------------------
# URL Generation
# ---------------------------------------------------------------------------


class TestURLGeneration:

    def test_generates_url_with_corr_id(self, registered_service: OOBCallbackService) -> None:
        url = registered_service.generate_url(
            scanner_name="ssrf",
            payload_id="test-param",
            endpoint_url="https://target.com/api",
            param_name="url",
        )
        # URL format: http://<corr_id><nonce>.<domain>
        assert url.startswith(f"http://{registered_service._session.correlation_id}")
        assert url.endswith(f".{registered_service._session.domain}")

    def test_generates_correct_subdomain_length(self, registered_service: OOBCallbackService) -> None:
        url = registered_service.generate_url("ssrf", "p1")
        # Extract subdomain (between http:// and .domain)
        subdomain = url.split("//")[1].split(".")[0]
        expected_len = OOBConfig.CORRELATION_ID_LENGTH + OOBConfig.NONCE_LENGTH
        assert len(subdomain) == expected_len

    def test_generates_unique_urls(self, registered_service: OOBCallbackService) -> None:
        url1 = registered_service.generate_url("ssrf", "p1")
        url2 = registered_service.generate_url("ssrf", "p2")
        assert url1 != url2

    def test_tracks_pending_tags_with_nonce(self, registered_service: OOBCallbackService) -> None:
        registered_service.generate_url(
            scanner_name="ssrf",
            payload_id="test",
            endpoint_url="https://target.com",
            param_name="url",
            description="blind SSRF test",
        )
        assert len(registered_service._pending_tags) == 1
        tag = list(registered_service._pending_tags.keys())[0]
        meta = registered_service._pending_tags[tag]
        assert meta.scanner_name == "ssrf"
        assert meta.description == "blind SSRF test"
        assert len(meta.nonce) == OOBConfig.NONCE_LENGTH

    def test_returns_empty_when_not_registered(self, service: OOBCallbackService) -> None:
        url = service.generate_url("ssrf", "test")
        assert url == ""


# ---------------------------------------------------------------------------
# Polling (with encrypted protocol)
# ---------------------------------------------------------------------------


class TestPolling:

    @pytest.mark.asyncio
    async def test_poll_decrypts_interactions(self, registered_service: OOBCallbackService) -> None:
        """Test that poll calls _decrypt_interactions and processes results."""
        registered_service.generate_url("ssrf", "test-param")
        tag = list(registered_service._pending_tags.keys())[0]
        nonce = registered_service._pending_tags[tag].nonce

        # Mock the HTTP response with encrypted data
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "aes_key": "fake_encrypted_key",
            "data": ["encrypted_interaction_1"],
        }

        # Mock decrypt to return a plain interaction
        corr_id = registered_service._session.correlation_id
        decrypted_interaction = {
            "protocol": "dns",
            "unique-id": f"{corr_id}{nonce}",
            "full-id": f"{corr_id}{nonce}",
            "remote-address": "1.2.3.4",
            "timestamp": "2024-01-01T00:00:00Z",
        }

        with patch("httpx.AsyncClient") as MockClient, \
             patch("asyncio.sleep", new_callable=AsyncMock), \
             patch.object(
                 registered_service, "_decrypt_interactions",
                 return_value=[decrypted_interaction],
             ):
            client = AsyncMock()
            client.get = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            interactions = await registered_service.poll()

        assert len(interactions) == 1
        assert interactions[0].tag == tag
        assert interactions[0].interaction_type == "dns"
        assert interactions[0].remote_address == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_poll_returns_empty_when_no_hits(self, registered_service: OOBCallbackService) -> None:
        registered_service.generate_url("ssrf", "test")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"aes_key": "", "data": None}

        with patch("httpx.AsyncClient") as MockClient, \
             patch("asyncio.sleep", new_callable=AsyncMock):
            client = AsyncMock()
            client.get = AsyncMock(return_value=mock_resp)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            interactions = await registered_service.poll()

        assert len(interactions) == 0

    @pytest.mark.asyncio
    async def test_poll_not_registered(self, service: OOBCallbackService) -> None:
        result = await service.poll()
        assert result == []

    @pytest.mark.asyncio
    async def test_poll_handles_exception_gracefully(self, registered_service: OOBCallbackService) -> None:
        registered_service.generate_url("ssrf", "test")

        with patch("httpx.AsyncClient") as MockClient, \
             patch("asyncio.sleep", new_callable=AsyncMock):
            client = AsyncMock()
            client.get = AsyncMock(side_effect=httpx.ConnectError("timeout"))
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            interactions = await registered_service.poll()

        assert interactions == []


# ---------------------------------------------------------------------------
# Tag Extraction (nonce-based)
# ---------------------------------------------------------------------------


class TestTagExtraction:

    def test_extracts_tag_by_nonce_from_unique_id(self, registered_service: OOBCallbackService) -> None:
        registered_service.generate_url("ssrf", "test")
        tag = list(registered_service._pending_tags.keys())[0]
        nonce = registered_service._pending_tags[tag].nonce
        corr_id = registered_service._session.correlation_id

        result = registered_service._extract_tag({
            "unique-id": f"{corr_id}{nonce}",
        })
        assert result == tag

    def test_extracts_tag_with_domain_suffix(self, registered_service: OOBCallbackService) -> None:
        registered_service.generate_url("ssrf", "test")
        tag = list(registered_service._pending_tags.keys())[0]
        nonce = registered_service._pending_tags[tag].nonce
        corr_id = registered_service._session.correlation_id
        domain = registered_service._session.domain

        result = registered_service._extract_tag({
            "full-id": f"{corr_id}{nonce}.{domain}",
        })
        assert result == tag

    def test_extracts_tag_from_raw_request_fallback(self, registered_service: OOBCallbackService) -> None:
        registered_service.generate_url("ssrf", "test")
        tag = list(registered_service._pending_tags.keys())[0]
        nonce = registered_service._pending_tags[tag].nonce

        result = registered_service._extract_tag({
            "raw-request": f"GET / HTTP/1.1\r\nHost: xxx{nonce}.oob.isitsecure.ai",
        })
        assert result == tag

    def test_returns_none_for_unknown(self, registered_service: OOBCallbackService) -> None:
        result = registered_service._extract_tag({
            "unique-id": "completelyrandomstringwithnomatch",
        })
        assert result is None

    def test_returns_none_for_empty_interaction(self, registered_service: OOBCallbackService) -> None:
        result = registered_service._extract_tag({})
        assert result is None

    def test_handles_camelcase_fields(self, registered_service: OOBCallbackService) -> None:
        registered_service.generate_url("ssrf", "test")
        tag = list(registered_service._pending_tags.keys())[0]
        nonce = registered_service._pending_tags[tag].nonce
        corr_id = registered_service._session.correlation_id

        result = registered_service._extract_tag({
            "fullId": f"{corr_id}{nonce}",
        })
        assert result == tag


# ---------------------------------------------------------------------------
# Finding Generation
# ---------------------------------------------------------------------------


class TestFindingGeneration:

    def test_converts_interaction_to_finding(self, registered_service: OOBCallbackService) -> None:
        registered_service.generate_url(
            scanner_name="ssrf",
            payload_id="url-param-api",
            endpoint_url="https://target.com/api/fetch",
            param_name="url",
            description="blind SSRF via url param",
        )
        tag = list(registered_service._pending_tags.keys())[0]

        registered_service._interactions = [
            OOBInteraction(
                tag=tag,
                interaction_type="dns",
                remote_address="target-ip",
            )
        ]

        findings = registered_service.get_findings()

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == SeverityLevel.CRITICAL
        assert f.category == FindingCategory.INJECTION_RISK
        assert f.source == FindingSource.DAST_URL
        assert f.confidence == OOBConfig.CONFIDENCE_OOB_CONFIRMED
        assert "ssrf" in f.scanner_name
        assert "blind" in f.title.lower() or "SSRF" in f.title
        assert f.endpoint_url == "https://target.com/api/fetch"

    def test_deduplicates_interactions(self, registered_service: OOBCallbackService) -> None:
        registered_service.generate_url("ssrf", "test")
        tag = list(registered_service._pending_tags.keys())[0]

        registered_service._interactions = [
            OOBInteraction(tag=tag, interaction_type="dns"),
            OOBInteraction(tag=tag, interaction_type="http"),
        ]

        findings = registered_service.get_findings()
        assert len(findings) == 1

    def test_multiple_scanners_produce_separate_findings(self, registered_service: OOBCallbackService) -> None:
        registered_service.generate_url("ssrf", "p1", endpoint_url="https://a.com")
        registered_service.generate_url("injection", "p2", endpoint_url="https://b.com")
        tags = list(registered_service._pending_tags.keys())

        registered_service._interactions = [
            OOBInteraction(tag=tags[0], interaction_type="http"),
            OOBInteraction(tag=tags[1], interaction_type="dns"),
        ]

        findings = registered_service.get_findings()
        assert len(findings) == 2
        scanners = {f.scanner_name for f in findings}
        assert "oob_ssrf" in scanners
        assert "oob_injection" in scanners

    def test_no_findings_without_interactions(self, registered_service: OOBCallbackService) -> None:
        registered_service.generate_url("ssrf", "test")
        findings = registered_service.get_findings()
        assert findings == []

    def test_unknown_scanner_gets_default_severity(self, registered_service: OOBCallbackService) -> None:
        registered_service.generate_url(
            scanner_name="unknown_scanner",
            payload_id="test",
            endpoint_url="https://target.com",
        )
        tag = list(registered_service._pending_tags.keys())[0]
        registered_service._interactions = [
            OOBInteraction(tag=tag, interaction_type="http"),
        ]

        findings = registered_service.get_findings()
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.HIGH

    def test_finding_has_technical_detail(self, registered_service: OOBCallbackService) -> None:
        registered_service.generate_url(
            scanner_name="ssrf",
            payload_id="test",
            endpoint_url="https://target.com/api",
            param_name="url",
        )
        tag = list(registered_service._pending_tags.keys())[0]
        registered_service._interactions = [
            OOBInteraction(
                tag=tag,
                interaction_type="dns",
                remote_address="1.2.3.4",
            ),
        ]

        findings = registered_service.get_findings()
        assert "Blind vulnerability confirmed" in findings[0].technical_detail
        assert "1.2.3.4" in findings[0].technical_detail
        assert "dns" in findings[0].technical_detail


# ---------------------------------------------------------------------------
# Agent-level: _inject_oob_payloads
# ---------------------------------------------------------------------------


class TestInjectOOBPayloads:

    @pytest.mark.asyncio
    async def test_injects_ssrf_callback_for_url_params(self, registered_service: OOBCallbackService) -> None:
        from isitsecure.engine.agent import DeepSecurityScanAgent
        from isitsecure.engine.enums import EndpointMethod
        from isitsecure.engine.models import DiscoveredEndpoint

        endpoints = [
            DiscoveredEndpoint(
                url="https://target.com/api/proxy?url=https://example.com",
                method=EndpointMethod.GET,
            ),
        ]
        original_count = len(endpoints)

        with patch(
            "isitsecure.engine.shared.rate_limited_client.RateLimitedClient",
        ) as MockClient:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(return_value=MagicMock(status_code=200))
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
            await DeepSecurityScanAgent._inject_oob_payloads(registered_service, endpoints)

        assert len(endpoints) > original_count
        oob_eps = [ep for ep in endpoints if ep.source_pattern == "oob_ssrf"]
        assert len(oob_eps) >= 1
        assert "oob.isitsecure.ai" in oob_eps[0].url

    @pytest.mark.asyncio
    async def test_skips_non_url_params(self, registered_service: OOBCallbackService) -> None:
        from isitsecure.engine.agent import DeepSecurityScanAgent
        from isitsecure.engine.enums import EndpointMethod
        from isitsecure.engine.models import DiscoveredEndpoint

        endpoints = [
            DiscoveredEndpoint(
                url="https://target.com/api/search?q=hello&page=1",
                method=EndpointMethod.GET,
            ),
        ]

        await DeepSecurityScanAgent._inject_oob_payloads(registered_service, endpoints)

        ssrf_oob = [ep for ep in endpoints if ep.source_pattern == "oob_ssrf"]
        assert len(ssrf_oob) == 0

    @pytest.mark.asyncio
    async def test_sends_injection_oob_to_post_endpoints(self, registered_service: OOBCallbackService) -> None:
        from isitsecure.engine.agent import DeepSecurityScanAgent
        from isitsecure.engine.enums import EndpointMethod
        from isitsecure.engine.models import DiscoveredEndpoint

        endpoints = [
            DiscoveredEndpoint(
                url="https://target.com/api/deals",
                method=EndpointMethod.POST,
            ),
        ]

        request_calls = []

        async def track_request(method, url, **kwargs):
            request_calls.append({"method": method, "url": url, "kwargs": kwargs})
            resp = MagicMock()
            resp.status_code = 200
            return resp

        with patch(
            "isitsecure.engine.shared.rate_limited_client.RateLimitedClient",
        ) as MockClient:
            mock_client = AsyncMock()
            mock_client.request = track_request
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await DeepSecurityScanAgent._inject_oob_payloads(registered_service, endpoints)

        assert len(request_calls) > 0
        assert len(registered_service._pending_tags) > 0
        scanners_used = {
            m.scanner_name for m in registered_service._pending_tags.values()
        }
        assert "injection" in scanners_used
        assert "xxe" in scanners_used
        assert "xss" in scanners_used

    @pytest.mark.asyncio
    async def test_no_post_endpoints_returns_zero(self, registered_service: OOBCallbackService) -> None:
        from isitsecure.engine.agent import DeepSecurityScanAgent
        from isitsecure.engine.enums import EndpointMethod
        from isitsecure.engine.models import DiscoveredEndpoint

        endpoints = [
            DiscoveredEndpoint(url="https://target.com/api?q=1", method=EndpointMethod.GET),
        ]

        await DeepSecurityScanAgent._inject_oob_payloads(registered_service, endpoints)
        assert len(registered_service._pending_tags) == 0

    @pytest.mark.asyncio
    async def test_handles_request_failures_gracefully(self, registered_service: OOBCallbackService) -> None:
        from isitsecure.engine.agent import DeepSecurityScanAgent
        from isitsecure.engine.enums import EndpointMethod
        from isitsecure.engine.models import DiscoveredEndpoint

        endpoints = [
            DiscoveredEndpoint(
                url="https://target.com/api/deals",
                method=EndpointMethod.POST,
            ),
        ]

        with patch(
            "isitsecure.engine.shared.rate_limited_client.RateLimitedClient",
        ) as MockClient:
            mock_client = AsyncMock()
            mock_client.request = AsyncMock(side_effect=Exception("connection refused"))
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await DeepSecurityScanAgent._inject_oob_payloads(registered_service, endpoints)

        assert len(registered_service._pending_tags) > 0


# ---------------------------------------------------------------------------
# Config Constants
# ---------------------------------------------------------------------------


class TestOOBConfig:

    def test_self_hosted_server_is_first(self) -> None:
        assert OOBConfig.SELF_HOSTED_DOMAIN in OOBConfig.SERVERS[0]

    def test_servers_non_empty(self) -> None:
        assert len(OOBConfig.SERVERS) >= 2

    def test_confidence_is_high(self) -> None:
        assert OOBConfig.CONFIDENCE_OOB_CONFIRMED >= 0.9

    def test_correlation_id_and_nonce_lengths(self) -> None:
        assert OOBConfig.CORRELATION_ID_LENGTH == 20
        assert OOBConfig.NONCE_LENGTH == 13

    def test_injection_payloads_have_callback_placeholder(self) -> None:
        for payload, _ in OOBConfig.INJECTION_OOB_PAYLOADS:
            assert "{callback}" in payload

    def test_xss_payloads_have_callback_placeholder(self) -> None:
        for payload in OOBConfig.XSS_OOB_PAYLOADS:
            assert "{callback}" in payload

    def test_xxe_payload_has_callback_placeholder(self) -> None:
        assert "{callback}" in OOBConfig.XXE_OOB_PAYLOAD

    def test_scanner_severity_mapping(self) -> None:
        assert OOBConfig.SCANNER_SEVERITY["ssrf"] == SeverityLevel.CRITICAL
        assert OOBConfig.SCANNER_SEVERITY["cmd"] == SeverityLevel.CRITICAL
        assert OOBConfig.SCANNER_SEVERITY["xss"] == SeverityLevel.HIGH
