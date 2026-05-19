"""Tests for cross-user IDOR scanning in IDORScanner."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import CrossUserIDORConfig, IDORConfig
from isitsecure.engine.enums import AuthProvider, IDORRiskLevel, IDORTestType
from isitsecure.engine.models import CrossUserIDORResult, IDORProbeResult
from isitsecure.engine.scanners.idor_scanner import IDORScanner


# ---------------------------------------------------------------------------
# Fixtures / Helpers
# ---------------------------------------------------------------------------

def _make_session(
    user_id: str = "user-a-uuid",
    access_token: str = "token-a",
) -> AuthSession:
    return AuthSession(
        user_id=user_id,
        access_token=access_token,
        refresh_token="refresh-token",
        headers={"Authorization": f"Bearer {access_token}"},
        provider=AuthProvider.SUPABASE,
    )


USER_A = _make_session(user_id="user-a-uuid", access_token="token-a")
USER_B = _make_session(user_id="user-b-uuid", access_token="token-b")

SUPABASE_URL = "https://test-project.supabase.co"
ANON_KEY = "test-anon-key"


def _mock_response(
    status_code: int = 200,
    body: str = "{}",
    content_type: str = "application/json",
) -> httpx.Response:
    """Create a mock httpx.Response."""
    return httpx.Response(
        status_code=status_code,
        text=body,
        headers={"content-type": content_type},
        request=httpx.Request("GET", "https://example.com"),
    )


# ---------------------------------------------------------------------------
# Cross-User Read IDOR Tests
# ---------------------------------------------------------------------------

class TestIDORScannerProtocolCompliance:
    """Protocol compliance tests for IDORScanner.

    Note: IDORScanner has a non-standard scan() signature
    (returns list[IDORTestResult] instead of list[DeepFinding])
    and has no scanner_name property, so it does not implement
    DASTScannerProtocol. We verify it has scan and scan_cross_user methods.
    """

    def test_has_scan_method(self) -> None:
        scanner = IDORScanner()
        assert hasattr(scanner, "scan")
        assert callable(scanner.scan)

    def test_has_scan_cross_user_method(self) -> None:
        scanner = IDORScanner()
        assert hasattr(scanner, "scan_cross_user")
        assert callable(scanner.scan_cross_user)


class TestCrossUserReadIDOR:
    """Test detection of cross-user read IDOR vulnerabilities."""

    @pytest.mark.asyncio
    async def test_read_idor_detected(self):
        """User B can read User A's resource -> IDOR confirmed."""
        scanner = IDORScanner()
        resources = {"profiles": ["resource-uuid-1"]}

        # Both users get 200 with data -> read IDOR
        with patch(
            "isitsecure.engine.scanners.idor_scanner.RateLimitedClient"
        ) as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.request = AsyncMock(
                return_value=_mock_response(
                    status_code=200,
                    body=json.dumps({"id": "resource-uuid-1", "data": "secret"}),
                )
            )
            mock_client_cls.return_value = mock_client

            results = await scanner.scan_cross_user(
                user_a_session=USER_A,
                user_b_session=USER_B,
                user_a_resources=resources,
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
            )

        assert len(results) == 1
        result = results[0]
        assert result.read_accessible is True
        assert result.risk_level == IDORRiskLevel.CONFIRMED
        assert result.confidence >= CrossUserIDORConfig.CONFIDENCE_CONFIRMED_READ

    @pytest.mark.asyncio
    async def test_read_blocked(self):
        """User B gets 403 on User A's resource -> safe."""
        scanner = IDORScanner()
        resources = {"profiles": ["resource-uuid-1"]}

        call_count = 0

        async def mock_request(method, url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Owner baseline succeeds
                return _mock_response(
                    status_code=200,
                    body=json.dumps({"id": "resource-uuid-1"}),
                )
            elif call_count == 2:
                # Attacker READ -> 403
                return _mock_response(status_code=403, body="Forbidden")
            else:
                # Attacker WRITE -> 403
                return _mock_response(status_code=403, body="Forbidden")

        with patch(
            "isitsecure.engine.scanners.idor_scanner.RateLimitedClient"
        ) as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.request = AsyncMock(side_effect=mock_request)
            mock_client_cls.return_value = mock_client

            results = await scanner.scan_cross_user(
                user_a_session=USER_A,
                user_b_session=USER_B,
                user_a_resources=resources,
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
            )

        assert len(results) == 1
        result = results[0]
        assert result.read_accessible is False
        assert result.risk_level == IDORRiskLevel.SAFE


# ---------------------------------------------------------------------------
# Cross-User Write IDOR Tests
# ---------------------------------------------------------------------------

class TestCrossUserWriteIDOR:
    """Test detection of cross-user write IDOR vulnerabilities."""

    @pytest.mark.asyncio
    async def test_write_idor_detected(self):
        """User B can PATCH User A's resource -> critical IDOR."""
        scanner = IDORScanner()
        resources = {"profiles": ["resource-uuid-1"]}

        call_count = 0

        async def mock_request(method, url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Owner baseline
                return _mock_response(
                    status_code=200,
                    body=json.dumps({"id": "resource-uuid-1"}),
                )
            elif call_count == 2:
                # Attacker READ -> 403 (read blocked)
                return _mock_response(status_code=403, body="")
            else:
                # Attacker PATCH -> 204 (write accepted!)
                return _mock_response(status_code=204, body="")

        with patch(
            "isitsecure.engine.scanners.idor_scanner.RateLimitedClient"
        ) as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.request = AsyncMock(side_effect=mock_request)
            mock_client_cls.return_value = mock_client

            results = await scanner.scan_cross_user(
                user_a_session=USER_A,
                user_b_session=USER_B,
                user_a_resources=resources,
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
            )

        assert len(results) == 1
        result = results[0]
        assert result.write_accessible is True
        assert result.risk_level == IDORRiskLevel.CONFIRMED
        assert result.confidence >= CrossUserIDORConfig.CONFIDENCE_CONFIRMED_WRITE

    @pytest.mark.asyncio
    async def test_write_blocked(self):
        """User B gets 403 on PATCH -> safe."""
        scanner = IDORScanner()
        resources = {"profiles": ["resource-uuid-1"]}

        call_count = 0

        async def mock_request(method, url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _mock_response(
                    status_code=200,
                    body=json.dumps({"id": "resource-uuid-1"}),
                )
            else:
                return _mock_response(status_code=403, body="Forbidden")

        with patch(
            "isitsecure.engine.scanners.idor_scanner.RateLimitedClient"
        ) as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.request = AsyncMock(side_effect=mock_request)
            mock_client_cls.return_value = mock_client

            results = await scanner.scan_cross_user(
                user_a_session=USER_A,
                user_b_session=USER_B,
                user_a_resources=resources,
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
            )

        result = results[0]
        assert result.write_accessible is False
        assert result.risk_level == IDORRiskLevel.SAFE


# ---------------------------------------------------------------------------
# Full Table SELECT Tests (RLS)
# ---------------------------------------------------------------------------

class TestFullTableSelectLeak:
    """Test detection of missing RLS policies via full table SELECT."""

    @pytest.mark.asyncio
    async def test_full_table_leak_detected(self):
        """User B can SELECT * and sees User A's IDs -> RLS missing."""
        scanner = IDORScanner()
        resources = {"profiles": ["owner-uuid-123"]}

        async def mock_request(method, url, **kwargs):
            # Return data containing the owner's UUID
            return _mock_response(
                status_code=200,
                body=json.dumps([
                    {"id": "owner-uuid-123"},
                    {"id": "user-b-uuid"},
                    {"id": "other-uuid"},
                ]),
            )

        with patch(
            "isitsecure.engine.scanners.idor_scanner.RateLimitedClient"
        ) as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.request = AsyncMock(side_effect=mock_request)
            mock_client_cls.return_value = mock_client

            results = await scanner.scan_cross_user(
                user_a_session=USER_A,
                user_b_session=USER_B,
                user_a_resources=resources,
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
                tables=["profiles"],
            )

        # Should have resource test + table test
        table_results = [r for r in results if r.resource_id == "*"]
        assert len(table_results) == 1
        assert table_results[0].full_table_readable is True
        assert table_results[0].risk_level == IDORRiskLevel.CONFIRMED
        assert table_results[0].confidence >= CrossUserIDORConfig.CONFIDENCE_FULL_TABLE_LEAK

    @pytest.mark.asyncio
    async def test_full_table_select_filtered(self):
        """User B's SELECT * only returns their own data -> RLS working."""
        scanner = IDORScanner()
        resources = {"profiles": ["owner-uuid-123"]}

        call_count = 0

        async def mock_request(method, url, **kwargs):
            nonlocal call_count
            call_count += 1
            # Resource tests return 200 for all
            if call_count <= 3:
                return _mock_response(
                    status_code=200,
                    body=json.dumps({"id": "owner-uuid-123"}),
                )
            # Table SELECT returns only User B's data (no owner IDs)
            return _mock_response(
                status_code=200,
                body=json.dumps([{"id": "user-b-uuid"}]),
            )

        with patch(
            "isitsecure.engine.scanners.idor_scanner.RateLimitedClient"
        ) as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.request = AsyncMock(side_effect=mock_request)
            mock_client_cls.return_value = mock_client

            results = await scanner.scan_cross_user(
                user_a_session=USER_A,
                user_b_session=USER_B,
                user_a_resources=resources,
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
                tables=["profiles"],
            )

        table_results = [r for r in results if r.resource_id == "*"]
        assert len(table_results) == 1
        assert table_results[0].full_table_readable is False


# ---------------------------------------------------------------------------
# Safe PATCH Verification
# ---------------------------------------------------------------------------

class TestSafePatchBehavior:
    """Verify that PATCH probes use empty body for safety."""

    @pytest.mark.asyncio
    async def test_safe_patch_uses_empty_body(self):
        """PATCH probe should use empty body, not real mutations."""
        scanner = IDORScanner()
        resources = {"profiles": ["resource-uuid-1"]}

        captured_kwargs: list[dict] = []

        async def capture_request(method, url, **kwargs):
            captured_kwargs.append({"method": method, "url": url, **kwargs})
            return _mock_response(
                status_code=200,
                body=json.dumps({"id": "resource-uuid-1"}),
            )

        with patch(
            "isitsecure.engine.scanners.idor_scanner.RateLimitedClient"
        ) as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.request = AsyncMock(side_effect=capture_request)
            mock_client_cls.return_value = mock_client

            await scanner.scan_cross_user(
                user_a_session=USER_A,
                user_b_session=USER_B,
                user_a_resources=resources,
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
            )

        # Find the PATCH request
        patch_calls = [c for c in captured_kwargs if c["method"] == "PATCH"]
        assert len(patch_calls) >= 1
        patch_call = patch_calls[0]
        assert patch_call["content"] == CrossUserIDORConfig.SAFE_PATCH_BODY
        assert patch_call["headers"]["Prefer"] == CrossUserIDORConfig.SAFE_PATCH_PREFER_HEADER


# ---------------------------------------------------------------------------
# Supabase-Specific Testing
# ---------------------------------------------------------------------------

class TestSupabaseSpecificTesting:
    """Verify Supabase REST endpoint testing with proper query params."""

    @pytest.mark.asyncio
    async def test_supabase_url_format(self):
        """Should test Supabase REST endpoints with proper query params."""
        scanner = IDORScanner()
        resources = {"profiles": ["uuid-123"]}

        captured_urls: list[str] = []

        async def capture_request(method, url, **kwargs):
            captured_urls.append(url)
            return _mock_response(
                status_code=200,
                body=json.dumps({"id": "uuid-123"}),
            )

        with patch(
            "isitsecure.engine.scanners.idor_scanner.RateLimitedClient"
        ) as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.request = AsyncMock(side_effect=capture_request)
            mock_client_cls.return_value = mock_client

            await scanner.scan_cross_user(
                user_a_session=USER_A,
                user_b_session=USER_B,
                user_a_resources=resources,
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
            )

        # Verify Supabase REST URL format
        supabase_urls = [u for u in captured_urls if "supabase.co" in u]
        assert len(supabase_urls) > 0
        first_url = supabase_urls[0]
        assert "/rest/v1/profiles" in first_url
        assert "select=id" in first_url
        assert "id=eq.uuid-123" in first_url

    @pytest.mark.asyncio
    async def test_auth_headers_include_apikey(self):
        """Requests should include apikey header when anon_key provided."""
        scanner = IDORScanner()
        resources = {"profiles": ["uuid-123"]}

        captured_headers: list[dict] = []

        async def capture_request(method, url, **kwargs):
            headers = kwargs.get("headers", {})
            captured_headers.append(dict(headers))
            return _mock_response(
                status_code=200,
                body=json.dumps({"id": "uuid-123"}),
            )

        with patch(
            "isitsecure.engine.scanners.idor_scanner.RateLimitedClient"
        ) as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.request = AsyncMock(side_effect=capture_request)
            mock_client_cls.return_value = mock_client

            await scanner.scan_cross_user(
                user_a_session=USER_A,
                user_b_session=USER_B,
                user_a_resources=resources,
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
            )

        assert len(captured_headers) > 0
        for headers in captured_headers:
            assert "apikey" in headers
            assert headers["apikey"] == ANON_KEY
            assert "Authorization" in headers


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------

class TestCrossUserIDORResultModel:
    """CrossUserIDORResult should have all required fields."""

    def test_default_values(self):
        """Should have sensible defaults."""
        result = CrossUserIDORResult(
            table_or_endpoint="profiles",
            resource_id="uuid-123",
            owner_user_id="user-a",
            attacker_user_id="user-b",
        )
        assert result.read_accessible is False
        assert result.write_accessible is False
        assert result.delete_accessible is False
        assert result.full_table_readable is False
        assert result.risk_level == IDORRiskLevel.SAFE
        assert result.confidence == 0.0
        assert result.evidence == []

    def test_confirmed_read(self):
        """Should represent confirmed read IDOR."""
        result = CrossUserIDORResult(
            table_or_endpoint="profiles",
            resource_id="uuid-123",
            owner_user_id="user-a",
            attacker_user_id="user-b",
            read_accessible=True,
            risk_level=IDORRiskLevel.CONFIRMED,
            confidence=CrossUserIDORConfig.CONFIDENCE_CONFIRMED_READ,
        )
        assert result.read_accessible is True
        assert result.risk_level == IDORRiskLevel.CONFIRMED

    def test_confirmed_write(self):
        """Should represent confirmed write IDOR."""
        result = CrossUserIDORResult(
            table_or_endpoint="profiles",
            resource_id="uuid-123",
            owner_user_id="user-a",
            attacker_user_id="user-b",
            write_accessible=True,
            risk_level=IDORRiskLevel.CONFIRMED,
            confidence=CrossUserIDORConfig.CONFIDENCE_CONFIRMED_WRITE,
        )
        assert result.write_accessible is True
        assert result.confidence >= CrossUserIDORConfig.CONFIDENCE_CONFIRMED_READ

    def test_evidence_list(self):
        """Should accept IDORProbeResult evidence."""
        probe = IDORProbeResult(
            original_url="https://example.com/api/profiles/1",
            probed_url="https://example.com/api/profiles/1",
            test_type=IDORTestType.CROSS_USER_READ,
            probed_status=200,
            data_returned=True,
        )
        result = CrossUserIDORResult(
            table_or_endpoint="profiles",
            resource_id="1",
            owner_user_id="user-a",
            attacker_user_id="user-b",
            evidence=[probe],
        )
        assert len(result.evidence) == 1
        assert result.evidence[0].test_type == IDORTestType.CROSS_USER_READ

    def test_confidence_bounds(self):
        """Confidence must be between 0 and 1."""
        with pytest.raises(ValueError):
            CrossUserIDORResult(
                table_or_endpoint="x",
                resource_id="y",
                owner_user_id="a",
                attacker_user_id="b",
                confidence=1.5,
            )

    def test_mutable_defaults_independent(self):
        """Two results should not share mutable default lists."""
        r1 = CrossUserIDORResult(
            table_or_endpoint="t1",
            resource_id="r1",
            owner_user_id="a",
            attacker_user_id="b",
        )
        r2 = CrossUserIDORResult(
            table_or_endpoint="t2",
            resource_id="r2",
            owner_user_id="a",
            attacker_user_id="b",
        )
        r1.evidence.append(
            IDORProbeResult(
                original_url="x",
                probed_url="x",
                test_type=IDORTestType.CROSS_USER_READ,
            )
        )
        assert len(r2.evidence) == 0


# ---------------------------------------------------------------------------
# Existing scan() method still works
# ---------------------------------------------------------------------------

class TestExistingScanUnchanged:
    """Verify that the original scan() method still functions."""

    @pytest.mark.asyncio
    async def test_scan_returns_results(self):
        """Original scan() should still work with no endpoints."""
        scanner = IDORScanner()
        results, mutation_findings = await scanner.scan(endpoints=[])
        assert results == []
        assert mutation_findings == []

    def test_filter_testable_endpoints(self):
        """_filter_testable_endpoints should still work."""
        from isitsecure.engine.models import DiscoveredEndpoint
        from isitsecure.engine.enums import EndpointCategory, EndpointMethod

        scanner = IDORScanner()
        endpoints = [
            DiscoveredEndpoint(
                url="https://example.com/api/users/123",
                method=EndpointMethod.GET,
                has_path_params=True,
                category=EndpointCategory.USER_DATA,
            ),
            DiscoveredEndpoint(
                url="https://example.com/api/public",
                method=EndpointMethod.GET,
                category=EndpointCategory.PUBLIC,
            ),
        ]
        testable = scanner._filter_testable_endpoints(endpoints)
        assert len(testable) == 1
        assert testable[0].url == "https://example.com/api/users/123"
