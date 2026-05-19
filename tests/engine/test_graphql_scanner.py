"""Tests for the GraphQL vulnerability scanner."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.constants import GraphQLConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.scanners.graphql_scanner import GraphQLScanner
from isitsecure.engine.scanners.protocols import DASTScannerProtocol
from isitsecure.engine.enums import FindingCategory, SeverityLevel


def _make_endpoint(
    url: str = "https://example.com/graphql",
    method: EndpointMethod = EndpointMethod.POST,
) -> DiscoveredEndpoint:
    """Create a test endpoint."""
    return DiscoveredEndpoint(url=url, method=method)


def _make_response(
    body: str, status_code: int = 200, content_type: str = "application/json"
) -> httpx.Response:
    """Create a mock httpx.Response."""
    return httpx.Response(
        status_code=status_code,
        headers={"content-type": content_type},
        text=body,
    )


class TestGraphQLScannerProtocol:
    """Protocol compliance tests."""

    def test_implements_dast_protocol(self) -> None:
        """GraphQLScanner should satisfy DASTScannerProtocol."""
        scanner = GraphQLScanner()
        assert isinstance(scanner, DASTScannerProtocol)

    def test_scanner_name(self) -> None:
        """scanner_name should match GraphQLConfig."""
        scanner = GraphQLScanner()
        assert scanner.scanner_name == GraphQLConfig.SCANNER_NAME

    def test_scan_categories(self) -> None:
        """scan_categories should contain expected categories."""
        scanner = GraphQLScanner()
        assert FindingCategory.INFO_DISCLOSURE in scanner.scan_categories
        assert FindingCategory.EXPOSED_API_ENDPOINT in scanner.scan_categories


class TestIntrospection:
    """Tests for introspection detection."""

    @pytest.mark.asyncio
    async def test_detects_introspection_enabled(self) -> None:
        """Response with __schema should produce a finding."""
        scanner = GraphQLScanner()
        endpoint = _make_endpoint()

        async def mock_post(url: str, **kwargs: object) -> httpx.Response:
            return _make_response('{"data":{"__schema":{"types":[{"name":"Query"}]}}}')

        with patch(
            "isitsecure.engine.scanners.graphql_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        introspection = [
            f for f in findings if f.title == GraphQLConfig.TITLE_INTROSPECTION
        ]
        assert len(introspection) >= 1
        assert introspection[0].severity == SeverityLevel.MEDIUM
        assert introspection[0].confidence == GraphQLConfig.CONFIDENCE_INTROSPECTION
        assert introspection[0].source == FindingSource.DAST_URL

    @pytest.mark.asyncio
    async def test_no_introspection_finding_when_schema_absent(self) -> None:
        """Response without __schema should not produce introspection finding."""
        scanner = GraphQLScanner()
        endpoint = _make_endpoint()

        async def mock_post(url: str, **kwargs: object) -> httpx.Response:
            return _make_response('{"errors":[{"message":"forbidden"}]}')

        with patch(
            "isitsecure.engine.scanners.graphql_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        introspection = [
            f for f in findings if f.title == GraphQLConfig.TITLE_INTROSPECTION
        ]
        assert len(introspection) == 0


class TestDepthLimit:
    """Tests for depth limit detection."""

    @pytest.mark.asyncio
    async def test_detects_no_depth_limit(self) -> None:
        """Response with data to deep query should produce a finding."""
        scanner = GraphQLScanner()
        endpoint = _make_endpoint()

        call_count = 0

        async def mock_post(url: str, **kwargs: object) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            content = kwargs.get("content", "")
            if "__schema" in str(content):
                return _make_response('{"errors":[{"message":"forbidden"}]}')
            if "__typename" in str(content) and "[" not in str(content):
                return _make_response('{"data":{"a":{"__typename":"Query"}}}')
            return _make_response('{"errors":[{"message":"not supported"}]}')

        with patch(
            "isitsecure.engine.scanners.graphql_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        depth_findings = [
            f for f in findings if f.title == GraphQLConfig.TITLE_NO_DEPTH_LIMIT
        ]
        assert len(depth_findings) >= 1
        assert depth_findings[0].confidence == GraphQLConfig.CONFIDENCE_NO_DEPTH_LIMIT


class TestBatchQueries:
    """Tests for batch query detection."""

    @pytest.mark.asyncio
    async def test_detects_batch_queries_allowed(self) -> None:
        """Array response to batch query should produce a finding."""
        scanner = GraphQLScanner()
        endpoint = _make_endpoint()

        async def mock_post(url: str, **kwargs: object) -> httpx.Response:
            content = kwargs.get("content", "")
            if isinstance(content, str) and content.strip().startswith("["):
                return _make_response(
                    '[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]'
                )
            return _make_response('{"errors":[{"message":"forbidden"}]}')

        with patch(
            "isitsecure.engine.scanners.graphql_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        batch_findings = [
            f for f in findings if f.title == GraphQLConfig.TITLE_BATCH_ALLOWED
        ]
        assert len(batch_findings) >= 1
        assert batch_findings[0].severity == SeverityLevel.LOW


class TestEdgeCases:
    """Edge case and error handling tests."""

    @pytest.mark.asyncio
    async def test_no_graphql_endpoints(self) -> None:
        """Non-GraphQL endpoints should produce no findings."""
        scanner = GraphQLScanner()
        endpoint = _make_endpoint(url="https://example.com/api/users")

        findings = await scanner.scan([endpoint])
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_empty_endpoints(self) -> None:
        """Empty endpoint list should produce no findings."""
        scanner = GraphQLScanner()
        findings = await scanner.scan([])
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_handles_connection_error(self) -> None:
        """Connection error should not crash the scanner."""
        scanner = GraphQLScanner()
        endpoint = _make_endpoint()

        async def mock_post(url: str, **kwargs: object) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        with patch(
            "isitsecure.engine.scanners.graphql_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_handles_error_response(self) -> None:
        """4xx/5xx responses should not produce findings."""
        scanner = GraphQLScanner()
        endpoint = _make_endpoint()

        async def mock_post(url: str, **kwargs: object) -> httpx.Response:
            return _make_response("Not found", status_code=404)

        with patch(
            "isitsecure.engine.scanners.graphql_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            findings = await scanner.scan([endpoint])

        assert len(findings) == 0

    def test_build_nested_query_depth(self) -> None:
        """Nested query should have the correct nesting depth."""
        scanner = GraphQLScanner()
        query = scanner._build_nested_query(3)
        assert query.count("{") == 3
        assert "__typename" in query

    @pytest.mark.asyncio
    async def test_multiple_graphql_endpoints(self) -> None:
        """Should test all GraphQL endpoints."""
        scanner = GraphQLScanner()
        endpoints = [
            _make_endpoint(url="https://example.com/graphql"),
            _make_endpoint(url="https://example.com/api/graphql"),
        ]

        tested_urls: list[str] = []

        async def mock_post(url: str, **kwargs: object) -> httpx.Response:
            tested_urls.append(url)
            return _make_response('{"errors":[{"message":"forbidden"}]}')

        with patch(
            "isitsecure.engine.scanners.graphql_scanner.RateLimitedClient"
        ) as MockClient:
            client_instance = AsyncMock()
            client_instance.post = mock_post
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await scanner.scan(endpoints)

        # Each endpoint should get 3 tests (introspection, depth, batch)
        assert any("example.com/graphql" in u for u in tested_urls)
        assert any("example.com/api/graphql" in u for u in tested_urls)
