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
from urllib.parse import quote, urljoin

import httpx

from isitsecure.engine.constants import DeepScanConfig, MassAssignmentConfig
from isitsecure.engine.enums import EndpointMethod, FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.auth_aware import AuthAwareScanner
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.shared.time_budget import TimeBudget

logger = logging.getLogger(__name__)


class MassAssignmentScanner(AuthAwareScanner):
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
            extra_headers=self.auth_headers,
        ) as client:
            # Stop cooperatively before the runner's hard timeout cancels us
            # (which discards every finding so far).
            budget = TimeBudget()
            for endpoint in state_changing_endpoints:
                if budget.expired():
                    logger.info(
                        "MassAssignmentScanner: time budget reached, stopping early"
                    )
                    break
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

        echoes = await self._endpoint_echoes_input(client, endpoint)

        reflected: list[DeepFinding] = []
        for field_name, field_value in escalation_fields:
            finding = await self._test_field(
                client, endpoint, field_name, field_value
            )
            if finding:
                reflected.append(finding)

        if echoes is None:
            # The control request failed (transient): do not drop every
            # finding, but we cannot tell reflection from persistence.
            for finding in reflected:
                finding.confidence = MassAssignmentConfig.CONFIDENCE_NO_CONTROL
            return reflected
        if not echoes:
            return reflected
        if not reflected:
            return findings

        # Echoing endpoint: reflection proves nothing, so read the object
        # back. A schemaless endpoint that persists any field and returns the
        # stored object echoes the control field too, and is still vulnerable.
        values = dict(escalation_fields)
        persisted = [
            f for f in reflected
            if await self._persisted_on_read_back(
                client, endpoint, _field_of(f), values[_field_of(f)],
            )
        ]
        if persisted:
            for finding in persisted:
                finding.technical_detail = (
                    (finding.technical_detail or "")
                    + "\nPrivileged field persisted on read-back (GET)"
                )
            return persisted

        # Pure echo (or read-back unavailable): one low note.
        first = reflected[0]
        first.severity = SeverityLevel.LOW
        first.title = MassAssignmentConfig.TITLE_ECHO_ONLY
        first.description = MassAssignmentConfig.DESC_ECHO_ONLY.format(
            url=endpoint.url,
            method=endpoint.method.value,
            fields=", ".join(
                (f.request_payload or "")[:60] for f in reflected[:5]
            ),
        )
        first.confidence = MassAssignmentConfig.CONFIDENCE_ECHO_ONLY
        findings.append(first)
        return findings

    async def _persisted_on_read_back(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        field_name: str,
        field_value: Any,
    ) -> bool:
        """Write the field with a unique marker, GET it back, look for both.

        The marker ties the privileged field to the object just written, so a
        pre-existing admin row in a collection is not mistaken for proof.
        """
        marker = f"{MassAssignmentConfig.ECHO_CONTROL_VALUE}-{field_name}"
        body = json.dumps(
            {field_name: field_value, MassAssignmentConfig.ECHO_CONTROL_FIELD: marker}
        )
        headers = {
            "Content-Type": self.CONTENT_TYPE_JSON,
            "Prefer": MassAssignmentConfig.PREFER_RETURN_REPRESENTATION,
        }
        try:
            response = await client.request(
                method=endpoint.method.value, url=endpoint.url,
                content=body, headers=headers,
            )
            if not (
                self.HTTP_STATUS_OK_LOWER
                <= response.status_code
                < self.HTTP_STATUS_OK_UPPER
            ):
                return False
            for url in self._read_back_urls(endpoint, response):
                got = await client.request(method="GET", url=url, headers={})
                if not (
                    self.HTTP_STATUS_OK_LOWER
                    <= got.status_code
                    < self.HTTP_STATUS_OK_UPPER
                ):
                    continue
                try:
                    data = json.loads(got.text)
                except (json.JSONDecodeError, TypeError):
                    continue
                if _contains_object(
                    data,
                    {
                        field_name: field_value,
                        MassAssignmentConfig.ECHO_CONTROL_FIELD: marker,
                    },
                ):
                    return True
        except Exception as exc:
            logger.debug(
                MassAssignmentConfig.ERROR_MASS_ASSIGNMENT_FAILED.format(
                    endpoint=endpoint.url, error=str(exc)
                )
            )
        return False

    @staticmethod
    def _read_back_urls(
        endpoint: DiscoveredEndpoint, response: httpx.Response
    ) -> list[str]:
        """Where the written object can be fetched: Location, id URL, collection."""
        base = endpoint.url.split("?", 1)[0]
        urls: list[str] = []
        location = response.headers.get("location")
        if location:
            urls.append(urljoin(base, location))
        try:
            data = json.loads(response.text)
        except (json.JSONDecodeError, TypeError):
            data = None
        object_id = _find_id(data)
        if object_id is not None and endpoint.method.value == "POST":
            urls.append(base.rstrip("/") + "/" + quote(str(object_id), safe=""))
        urls.append(endpoint.url)  # the resource itself (PUT/PATCH) or collection
        return list(dict.fromkeys(urls))

    async def _endpoint_echoes_input(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
    ) -> bool | None:
        """Control request: does the endpoint reflect an unknown field?

        Returns True when it does (a pure echo), False when it does not, and
        None when the control could not be sent.
        """
        body = json.dumps(
            {
                MassAssignmentConfig.ECHO_CONTROL_FIELD:
                    MassAssignmentConfig.ECHO_CONTROL_VALUE
            }
        )
        try:
            response = await client.request(
                method=endpoint.method.value,
                url=endpoint.url,
                content=body,
                headers={
                    "Content-Type": self.CONTENT_TYPE_JSON,
                    "Prefer": MassAssignmentConfig.PREFER_RETURN_REPRESENTATION,
                },
            )
        except Exception as exc:
            logger.debug(
                MassAssignmentConfig.ERROR_MASS_ASSIGNMENT_FAILED.format(
                    endpoint=endpoint.url, error=str(exc)
                )
            )
            return None
        if not (
            self.HTTP_STATUS_OK_LOWER
            <= response.status_code
            < self.HTTP_STATUS_OK_UPPER
        ):
            return False
        return self._field_in_response(
            MassAssignmentConfig.ECHO_CONTROL_FIELD,
            MassAssignmentConfig.ECHO_CONTROL_VALUE,
            response.text,
        )

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
            # Not JSON (SPA shell, plain text): a bare substring match would
            # fire on any HTML page that contains the words "role"/"admin".
            return False

        return _contains_field(data, field_name, field_value)


# Most APIs wrap the created object in an envelope -- {"status": .., "data": ..},
# {"result": ..}, JSON:API's {"data": {"attributes": ..}}. A top-level-only
# check calls every one of those "not reflected" and reports nothing, which is
# how a live, confirmed mass assignment reads as clean. Search the whole tree
# instead of guessing at envelope key names.
MAX_RESPONSE_DEPTH = 8


def _contains_field(
    data: Any, field_name: str, field_value: Any, depth: int = 0
) -> bool:
    """Whether the field appears anywhere in a decoded JSON response."""
    if depth > MAX_RESPONSE_DEPTH:
        return False

    if isinstance(data, dict):
        if _dict_has_field(data, field_name, field_value):
            return True
        return any(
            _contains_field(value, field_name, field_value, depth + 1)
            for value in data.values()
        )

    if isinstance(data, list):
        return any(
            _contains_field(item, field_name, field_value, depth + 1)
            for item in data
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


def _field_of(finding: DeepFinding) -> str:
    """The escalation field a reflected finding was raised for."""
    try:
        return next(iter(json.loads(finding.request_payload or "{}")))
    except (json.JSONDecodeError, StopIteration, TypeError):
        return ""


def _find_id(data: Any, depth: int = 0) -> Any:
    """First id-like value in a decoded response (envelope-tolerant)."""
    if depth > MAX_RESPONSE_DEPTH:
        return None
    if isinstance(data, dict):
        for key in ("id", "_id", "uuid"):
            if isinstance(data.get(key), (str, int)) and data[key] != "":
                return data[key]
        for value in data.values():
            found = _find_id(value, depth + 1)
            if found is not None:
                return found
    elif isinstance(data, list):
        for item in data:
            found = _find_id(item, depth + 1)
            if found is not None:
                return found
    return None


def _contains_object(data: Any, expected: dict[str, Any], depth: int = 0) -> bool:
    """Whether ONE object in the tree carries every expected field/value."""
    if depth > MAX_RESPONSE_DEPTH:
        return False
    if isinstance(data, dict):
        if all(_dict_has_field(data, k, v) for k, v in expected.items()):
            return True
        return any(_contains_object(v, expected, depth + 1) for v in data.values())
    if isinstance(data, list):
        return any(_contains_object(i, expected, depth + 1) for i in data)
    return False
