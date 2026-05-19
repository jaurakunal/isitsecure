"""Mass assignment vulnerability scanner.

Tests API endpoints for mass assignment by sending requests with extra
privilege-escalation fields (role, is_admin, etc.) alongside normal
payloads. If the server accepts and reflects back these extra fields,
the endpoint may be vulnerable to privilege escalation.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from isitsecure.engine.constants import DeepScanConfig, MassAssignmentConfig
from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


class MassAssignmentScanner:
    """Tests API endpoints for mass assignment vulnerabilities.

    Finds POST/PUT/PATCH endpoints and sends requests with extra
    escalation fields to test if they are accepted.
    """

    CONTENT_TYPE_JSON = "application/json"
    HTTP_STATUS_OK_LOWER = 200
    HTTP_STATUS_OK_UPPER = 300

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return MassAssignmentConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.PRIVILEGE_ESCALATION]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run mass assignment tests on discovered endpoints.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot (unused by this scanner).

        Returns:
            List of unified findings from this scanner.
        """
        findings: list[DeepFinding] = []

        state_changing_endpoints = self._filter_state_changing(endpoints)
        if not state_changing_endpoints:
            logger.info(
                "MassAssignmentScanner: no state-changing endpoints to test"
            )
            return findings

        async with RateLimitedClient(
            max_concurrent=MassAssignmentConfig.MAX_CONCURRENT,
            delay_seconds=MassAssignmentConfig.PROBE_DELAY,
            timeout_seconds=MassAssignmentConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            for endpoint in state_changing_endpoints:
                ep_findings = await self._test_endpoint(client, endpoint)
                findings.extend(ep_findings)

        logger.info("MassAssignmentScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Endpoint filtering
    # ------------------------------------------------------------------

    def _filter_state_changing(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """Filter to POST, PUT, PATCH endpoints."""
        return [
            ep
            for ep in endpoints
            if ep.method.value in MassAssignmentConfig.STATE_CHANGING_METHODS
        ]

    # ------------------------------------------------------------------
    # Per-endpoint testing
    # ------------------------------------------------------------------

    async def _test_endpoint(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
    ) -> list[DeepFinding]:
        """Test a single endpoint for mass assignment."""
        findings: list[DeepFinding] = []

        # Determine which escalation fields to use
        url_lower = endpoint.url.lower()
        is_supabase = "supabase" in url_lower or "rest/v1" in url_lower

        escalation_fields = (
            MassAssignmentConfig.SUPABASE_ESCALATION_FIELDS
            if is_supabase
            else MassAssignmentConfig.ESCALATION_FIELDS
        )

        for field_name, field_value in escalation_fields:
            finding = await self._test_field(
                client, endpoint, field_name, field_value
            )
            if finding:
                findings.append(finding)

        return findings

    async def _test_field(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        field_name: str,
        field_value: Any,
    ) -> DeepFinding | None:
        """Test if a single extra field is accepted by the endpoint."""
        body = json.dumps({field_name: field_value})

        try:
            headers: dict[str, str] = {
                "Content-Type": self.CONTENT_TYPE_JSON,
                "Prefer": MassAssignmentConfig.PREFER_RETURN_REPRESENTATION,
            }

            response = await client.request(
                method=endpoint.method.value,
                url=endpoint.url,
                content=body,
                headers=headers,
            )

            if not (
                self.HTTP_STATUS_OK_LOWER
                <= response.status_code
                < self.HTTP_STATUS_OK_UPPER
            ):
                return None

            response_body = response.text

            # Check if the field appears in the response body
            if self._field_in_response(field_name, field_value, response_body):
                return DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.PRIVILEGE_ESCALATION,
                    severity=SeverityLevel.HIGH,
                    title=MassAssignmentConfig.TITLE_MASS_ASSIGNMENT,
                    description=MassAssignmentConfig.DESC_MASS_ASSIGNMENT.format(
                        url=endpoint.url,
                        field=field_name,
                        value=field_value,
                        method=endpoint.method.value,
                    ),
                    technical_detail=(
                        f"Sent {endpoint.method.value} {endpoint.url} with "
                        f"extra field '{field_name}': {field_value}\n"
                        f"Response status: {response.status_code}\n"
                        f"Field was reflected in response body"
                    ),
                    evidence=(
                        f"{endpoint.method.value} {endpoint.url} with "
                        f"'{field_name}': {field_value} -> {response.status_code}, "
                        f"field reflected"
                    ),
                    confidence=MassAssignmentConfig.CONFIDENCE_MASS_ASSIGNMENT,
                    scanner_name=self.scanner_name,
                    endpoint_url=endpoint.url,
                    http_method=endpoint.method.value,
                    request_payload=body,
                    response_preview=response_body[:300],
                )

        except Exception as exc:
            logger.debug(
                MassAssignmentConfig.ERROR_MASS_ASSIGNMENT_FAILED.format(
                    endpoint=endpoint.url, error=str(exc)
                )
            )

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _field_in_response(
        field_name: str, field_value: Any, response_body: str
    ) -> bool:
        """Check if the injected field appears in the response."""
        try:
            data = json.loads(response_body)
        except (json.JSONDecodeError, TypeError):
            # Fallback: string matching
            return str(field_name) in response_body and str(field_value) in response_body

        # Check top-level dict
        if isinstance(data, dict):
            return _dict_has_field(data, field_name, field_value)

        # Check array of dicts (common for Supabase)
        if isinstance(data, list):
            return any(
                _dict_has_field(item, field_name, field_value)
                for item in data
                if isinstance(item, dict)
            )

        return False


def _dict_has_field(data: dict[str, Any], field_name: str, field_value: Any) -> bool:
    """Check if a dict contains a specific field with the expected value."""
    if field_name not in data:
        return False
    actual = data[field_name]
    # Coerce types for comparison (True vs "true", 99999 vs "99999")
    if isinstance(field_value, bool):
        return actual is True or actual == field_value
    return str(actual) == str(field_value)
