"""Tests for the mass assignment vulnerability scanner."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.constants import MassAssignmentConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.scanners.mass_assignment_scanner import (
    MassAssignmentScanner,
    _dict_has_field,
)
from isitsecure.engine.scanners.protocols import DASTScannerProtocol
from isitsecure.engine.enums import FindingCategory, SeverityLevel


def _make_endpoint(
    url: str = "https://example.com/api/users",
    method: EndpointMethod = EndpointMethod.POST,
) -> DiscoveredEndpoint:
    """Create a test endpoint."""
    return DiscoveredEndpoint(url=url, method=method)


def _make_response(
    body: str = '{"id":1}', status_code: int = 200
) -> httpx.Response:
    """Create a mock httpx.Response."""
    return httpx.Response(
        status_code=status_code,
        headers={"content-type": "application/json"},
        text=body,
    )


class TestMassAssignmentScannerProtocol:
    """Protocol compliance tests."""

    def test_implements_dast_protocol(self) -> None:
        """MassAssignmentScanner should satisfy DASTScannerProtocol."""
        scanner = MassAssignmentScanner()
        assert isinstance(scanner, DASTScannerProtocol)

    def test_scanner_name(self) -> None:
        """scanner_name should match MassAssignmentConfig."""
        scanner = MassAssignmentScanner()
        assert scanner.scanner_name == MassAssignmentConfig.SCANNER_NAME

    def test_scan_categories(self) -> None:
        """scan_categories should contain PRIVILEGE_ESCALATION."""
        scanner = MassAssignmentScanner()
        assert scanner.scan_categories == [FindingCategory.PRIVILEGE_ESCALATION]


class TestMassAssignmentDetection:
    """Tests for mass assignment detection."""

    @pytest.mark.asyncio
    async def test_detects_mass_assignment_field_reflected(self) -> None:
        """If extra field is reflected in response, should produce a finding."""
        scanner = MassAssignmentScanner()
        endpoint = _make_endpoint()

        async def mock_request(
            method: str, url: str, **kwargs: object
        ) -> httpx.Response:
            return _make_response(
                '{"id":1,"name":"test","role":"admin"}', status_code=200
            )

        with patch(
            "isitsecure.engine.scanners.mass_assignment_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = mock_request
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.title == MassAssignmentConfig.TITLE_MASS_ASSIGNMENT
        assert finding.severity == SeverityLevel.HIGH
        assert finding.confidence == MassAssignmentConfig.CONFIDENCE_MASS_ASSIGNMENT
        assert finding.source == FindingSource.DAST_URL
        assert finding.category == FindingCategory.PRIVILEGE_ESCALATION

    @pytest.mark.asyncio
    async def test_no_finding_when_field_not_reflected(self) -> None:
        """If extra field is NOT in response, should produce no finding."""
        scanner = MassAssignmentScanner()
        endpoint = _make_endpoint()

        async def mock_request(
            method: str, url: str, **kwargs: object
        ) -> httpx.Response:
            return _make_response('{"id":1,"name":"test"}', status_code=200)

        with patch(
            "isitsecure.engine.scanners.mass_assignment_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = mock_request
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_no_finding_for_error_response(self) -> None:
        """4xx response should not produce a finding."""
        scanner = MassAssignmentScanner()
        endpoint = _make_endpoint()

        async def mock_request(
            method: str, url: str, **kwargs: object
        ) -> httpx.Response:
            return _make_response('{"error":"unauthorized"}', status_code=401)

        with patch(
            "isitsecure.engine.scanners.mass_assignment_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = mock_request
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_supabase_endpoint_uses_supabase_fields(self) -> None:
        """Supabase endpoints should use Supabase-specific escalation fields."""
        scanner = MassAssignmentScanner()
        endpoint = _make_endpoint(
            url="https://abc.supabase.co/rest/v1/profiles",
            method=EndpointMethod.PATCH,
        )

        tested_bodies: list[str] = []

        async def mock_request(
            method: str, url: str, **kwargs: object
        ) -> httpx.Response:
            content = kwargs.get("content", "")
            tested_bodies.append(str(content))
            return _make_response('{"id":1}', status_code=200)

        with patch(
            "isitsecure.engine.scanners.mass_assignment_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = mock_request
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await scanner.scan([endpoint])

        # Should test supabase fields (stripe_customer_id is unique to supabase set)
        all_bodies = " ".join(tested_bodies)
        assert "stripe_customer_id" in all_bodies

    @pytest.mark.asyncio
    async def test_detects_array_response_with_field(self) -> None:
        """Supabase-style array response with extra field should trigger finding."""
        scanner = MassAssignmentScanner()
        endpoint = _make_endpoint(
            url="https://abc.supabase.co/rest/v1/profiles",
            method=EndpointMethod.PATCH,
        )

        async def mock_request(
            method: str, url: str, **kwargs: object
        ) -> httpx.Response:
            return _make_response(
                '[{"id":1,"role":"admin"}]', status_code=200
            )

        with patch(
            "isitsecure.engine.scanners.mass_assignment_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = mock_request
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) >= 1


class TestEdgeCases:
    """Edge case and error handling tests."""

    @pytest.mark.asyncio
    async def test_get_endpoints_skipped(self) -> None:
        """GET endpoints should not be tested for mass assignment."""
        scanner = MassAssignmentScanner()
        endpoint = _make_endpoint(method=EndpointMethod.GET)

        findings = await scanner.scan([endpoint])
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_empty_endpoints(self) -> None:
        """Empty endpoint list should produce no findings."""
        scanner = MassAssignmentScanner()
        findings = await scanner.scan([])
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_handles_connection_error(self) -> None:
        """Connection error should not crash the scanner."""
        scanner = MassAssignmentScanner()
        endpoint = _make_endpoint()

        async def mock_request(
            method: str, url: str, **kwargs: object
        ) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        with patch(
            "isitsecure.engine.scanners.mass_assignment_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.request = mock_request
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) == 0

    def test_dict_has_field_with_bool(self) -> None:
        """_dict_has_field should handle boolean values."""
        assert _dict_has_field({"is_admin": True}, "is_admin", True)
        assert not _dict_has_field({"is_admin": False}, "is_admin", True)

    def test_dict_has_field_with_string(self) -> None:
        """_dict_has_field should handle string values."""
        assert _dict_has_field({"role": "admin"}, "role", "admin")
        assert not _dict_has_field({"role": "user"}, "role", "admin")

    def test_dict_has_field_missing_key(self) -> None:
        """_dict_has_field should return False for missing key."""
        assert not _dict_has_field({"name": "test"}, "role", "admin")

    def test_field_in_response_non_json(self) -> None:
        """Non-JSON response should use string matching fallback."""
        assert MassAssignmentScanner._field_in_response(
            "role", "admin", "role=admin in response"
        )
        assert not MassAssignmentScanner._field_in_response(
            "role", "admin", "nothing relevant"
        )
