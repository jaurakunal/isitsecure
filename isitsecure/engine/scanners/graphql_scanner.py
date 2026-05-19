"""GraphQL vulnerability scanner.

Tests GraphQL endpoints for common misconfigurations:
1. Introspection enabled -- exposes full API schema
2. No query depth limit -- allows DoS via deeply nested queries
3. Batch query support -- can bypass rate limiting
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from isitsecure.engine.constants import DeepScanConfig, GraphQLConfig
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


class GraphQLScanner:
    """Tests GraphQL endpoints for common vulnerabilities.

    Detects GraphQL endpoints from path indicators, then probes for
    introspection, missing depth limits, and batch query support.
    """

    CONTENT_TYPE_JSON = "application/json"
    HTTP_STATUS_OK_LOWER = 200
    HTTP_STATUS_OK_UPPER = 300

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return GraphQLConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.INFO_DISCLOSURE, FindingCategory.EXPOSED_API_ENDPOINT]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run GraphQL vulnerability tests on discovered endpoints.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot (unused by this scanner).

        Returns:
            List of unified findings from this scanner.
        """
        findings: list[DeepFinding] = []

        graphql_endpoints = self._detect_graphql_endpoints(endpoints)
        if not graphql_endpoints:
            logger.info("GraphQLScanner: no GraphQL endpoints detected")
            return findings

        async with RateLimitedClient(
            max_concurrent=GraphQLConfig.MAX_CONCURRENT,
            delay_seconds=GraphQLConfig.PROBE_DELAY,
            timeout_seconds=GraphQLConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            for endpoint in graphql_endpoints:
                ep_findings = await self._test_endpoint(client, endpoint)
                findings.extend(ep_findings)

        logger.info("GraphQLScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Endpoint detection
    # ------------------------------------------------------------------

    def _detect_graphql_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """Filter endpoints that look like GraphQL endpoints."""
        graphql_eps: list[DiscoveredEndpoint] = []
        for ep in endpoints:
            parsed = urlparse(ep.url)
            path_lower = parsed.path.lower()
            if any(
                indicator in path_lower
                for indicator in GraphQLConfig.GRAPHQL_PATH_INDICATORS
            ):
                graphql_eps.append(ep)
        return graphql_eps

    # ------------------------------------------------------------------
    # Per-endpoint testing
    # ------------------------------------------------------------------

    async def _test_endpoint(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
    ) -> list[DeepFinding]:
        """Run all GraphQL tests on a single endpoint."""
        findings: list[DeepFinding] = []

        introspection = await self._test_introspection(client, endpoint.url)
        if introspection:
            findings.append(introspection)

        depth = await self._test_depth_limit(client, endpoint.url)
        if depth:
            findings.append(depth)

        batch = await self._test_batch_queries(client, endpoint.url)
        if batch:
            findings.append(batch)

        return findings

    # ------------------------------------------------------------------
    # Introspection test
    # ------------------------------------------------------------------

    async def _test_introspection(
        self, client: RateLimitedClient, url: str
    ) -> DeepFinding | None:
        """Test if introspection is enabled by sending __schema query."""
        try:
            response = await client.post(
                url,
                content=GraphQLConfig.INTROSPECTION_QUERY,
                headers={"Content-Type": self.CONTENT_TYPE_JSON},
            )

            if not (
                self.HTTP_STATUS_OK_LOWER
                <= response.status_code
                < self.HTTP_STATUS_OK_UPPER
            ):
                return None

            body = response.text
            if "__schema" in body or "__type" in body or '"types"' in body:
                return DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.INFO_DISCLOSURE,
                    severity=SeverityLevel.MEDIUM,
                    title=GraphQLConfig.TITLE_INTROSPECTION,
                    description=GraphQLConfig.DESC_INTROSPECTION.format(url=url),
                    technical_detail=(
                        f"Sent introspection query to {url}\n"
                        f"Response contained schema data"
                    ),
                    evidence=f"POST {url} -> introspection response with schema",
                    confidence=GraphQLConfig.CONFIDENCE_INTROSPECTION,
                    scanner_name=self.scanner_name,
                    endpoint_url=url,
                    http_method="POST",
                    request_payload=GraphQLConfig.INTROSPECTION_QUERY,
                    response_preview=body[:300],
                )

        except Exception as exc:
            logger.debug(
                GraphQLConfig.ERROR_GRAPHQL_SCAN_FAILED.format(
                    endpoint=url, error=str(exc)
                )
            )

        return None

    # ------------------------------------------------------------------
    # Depth limit test
    # ------------------------------------------------------------------

    def _build_nested_query(self, depth: int) -> str:
        """Build a deeply nested GraphQL query string."""
        query = "__typename"
        for _ in range(depth):
            query = f"a {{ {query} }}"
        return query

    async def _test_depth_limit(
        self, client: RateLimitedClient, url: str
    ) -> DeepFinding | None:
        """Test if the server accepts deeply nested queries."""
        nested_query = self._build_nested_query(GraphQLConfig.MAX_DEPTH_TEST)
        payload = GraphQLConfig.DEPTH_BOMB_QUERY_TEMPLATE.format(
            nested_query=nested_query
        )

        try:
            response = await client.post(
                url,
                content=payload,
                headers={"Content-Type": self.CONTENT_TYPE_JSON},
            )

            if not (
                self.HTTP_STATUS_OK_LOWER
                <= response.status_code
                < self.HTTP_STATUS_OK_UPPER
            ):
                return None

            body = response.text
            # If the server returns data (not an error about depth),
            # it accepted the deep query
            if "error" not in body.lower() or "data" in body.lower():
                return DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.EXPOSED_API_ENDPOINT,
                    severity=SeverityLevel.MEDIUM,
                    title=GraphQLConfig.TITLE_NO_DEPTH_LIMIT,
                    description=GraphQLConfig.DESC_NO_DEPTH_LIMIT.format(
                        url=url, depth=GraphQLConfig.MAX_DEPTH_TEST
                    ),
                    technical_detail=(
                        f"Sent {GraphQLConfig.MAX_DEPTH_TEST}-level nested "
                        f"query to {url}\n"
                        f"Response status: {response.status_code}"
                    ),
                    evidence=(
                        f"POST {url} with {GraphQLConfig.MAX_DEPTH_TEST}-deep "
                        f"query -> {response.status_code}"
                    ),
                    confidence=GraphQLConfig.CONFIDENCE_NO_DEPTH_LIMIT,
                    scanner_name=self.scanner_name,
                    endpoint_url=url,
                    http_method="POST",
                    request_payload=payload[:300],
                )

        except Exception as exc:
            logger.debug(
                GraphQLConfig.ERROR_GRAPHQL_SCAN_FAILED.format(
                    endpoint=url, error=str(exc)
                )
            )

        return None

    # ------------------------------------------------------------------
    # Batch query test
    # ------------------------------------------------------------------

    async def _test_batch_queries(
        self, client: RateLimitedClient, url: str
    ) -> DeepFinding | None:
        """Test if the server accepts batched GraphQL queries."""
        try:
            response = await client.post(
                url,
                content=GraphQLConfig.BATCH_QUERY,
                headers={"Content-Type": self.CONTENT_TYPE_JSON},
            )

            if not (
                self.HTTP_STATUS_OK_LOWER
                <= response.status_code
                < self.HTTP_STATUS_OK_UPPER
            ):
                return None

            body = response.text
            # Batch responses are arrays — check if we got an array back
            if body.strip().startswith("[") and "__typename" in body:
                return DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.EXPOSED_API_ENDPOINT,
                    severity=SeverityLevel.LOW,
                    title=GraphQLConfig.TITLE_BATCH_ALLOWED,
                    description=GraphQLConfig.DESC_BATCH_ALLOWED.format(url=url),
                    technical_detail=(
                        f"Sent batch query (2 queries) to {url}\n"
                        f"Response was an array, indicating batch support"
                    ),
                    evidence=f"POST {url} with batch -> array response",
                    confidence=GraphQLConfig.CONFIDENCE_BATCH_ALLOWED,
                    scanner_name=self.scanner_name,
                    endpoint_url=url,
                    http_method="POST",
                    request_payload=GraphQLConfig.BATCH_QUERY,
                    response_preview=body[:300],
                )

        except Exception as exc:
            logger.debug(
                GraphQLConfig.ERROR_GRAPHQL_SCAN_FAILED.format(
                    endpoint=url, error=str(exc)
                )
            )

        return None
