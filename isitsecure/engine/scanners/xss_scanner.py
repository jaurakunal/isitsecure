"""Active Cross-Site Scripting (XSS) scanner.

Tests for four types of XSS:
1. Reflected XSS -- injects canary strings in query params, checks if reflected unescaped
2. POST body XSS -- injects canary strings in JSON POST bodies for state-changing endpoints
3. DOM-based XSS -- analyzes JavaScript for dangerous sinks (innerHTML, eval, etc.)
4. Stored XSS detection hints -- flags writable endpoints that could lead to stored XSS

Uses a canary-based approach: first inject a unique identifier with HTML-significant
characters. If the canary appears unescaped in the response, the endpoint is vulnerable.
"""

import json
import logging
import re
import uuid
from urllib.parse import parse_qs, urlparse

from isitsecure.engine.constants import DeepScanConfig, XSSConfig
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.probe_capture import build_probe_capture
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.shared.url_utils import inject_query_param
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


class XSSScanner:
    """Active XSS scanner implementing DASTScannerProtocol.

    Performs canary-based reflected XSS testing (GET query params and POST
    bodies) and static DOM sink analysis.
    """

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return XSSConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.INJECTION_RISK]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run XSS tests on discovered endpoints and JS content.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot for code-aware scanning.

        Returns:
            List of unified findings from this scanner.
        """
        findings: list[DeepFinding] = []

        # Phase 1: Reflected XSS testing on GET endpoints
        reflected_findings = await self._test_reflected_xss(endpoints)
        findings.extend(reflected_findings)

        # Phase 2: POST body XSS testing on state-changing endpoints
        post_findings = await self._test_post_body_xss(endpoints)
        findings.extend(post_findings)

        # Phase 3: DOM-based XSS analysis on JS content
        if snapshot:
            dom_findings = self._test_dom_xss(snapshot)
            findings.extend(dom_findings)

        logger.info("XSSScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Reflected XSS (GET query parameters)
    # ------------------------------------------------------------------

    async def _test_reflected_xss(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DeepFinding]:
        """Test endpoints for reflected XSS via query parameters."""
        findings: list[DeepFinding] = []
        testable = self._get_testable_endpoints(endpoints)

        async with RateLimitedClient(
            max_concurrent=XSSConfig.MAX_CONCURRENT,
            delay_seconds=XSSConfig.PROBE_DELAY,
            timeout_seconds=XSSConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            for endpoint in testable[: XSSConfig.MAX_ENDPOINTS_TO_TEST]:
                params = self._get_testable_params(endpoint)
                for param in params[: XSSConfig.MAX_PARAMS_PER_ENDPOINT]:
                    finding = await self._test_param_reflection(
                        client, endpoint, param
                    )
                    if finding:
                        findings.append(finding)

        return findings

    async def _test_param_reflection(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        param_name: str,
    ) -> DeepFinding | None:
        """Test a single parameter for reflection.

        Strategy:
        1. Inject canary with HTML chars: <canary_xss_abc123>
        2. Check if the canary appears in the response WITH the < > intact
        3. If yes: the parameter is reflected without encoding -- XSS confirmed
        """
        canary_id = uuid.uuid4().hex[:8]

        for probe_template in XSSConfig.REFLECTION_PROBES:
            probe_value = probe_template.format(id=canary_id)

            try:
                url = inject_query_param(endpoint.url, param_name, probe_value)
                response = await client.get(url)

                if response.status_code >= 400:
                    continue

                body = response.text
                content_type = response.headers.get("content-type", "")

                # Check if canary is reflected with HTML chars unescaped
                if probe_value in body and "text/html" in content_type.lower():
                    capture = build_probe_capture(
                        method="GET",
                        url=url,
                        headers=dict(response.request.headers),
                        body="",
                        response_status=response.status_code,
                        response_headers=dict(response.headers),
                        response_body=body,
                        elapsed_ms=response.elapsed.total_seconds() * 1000,
                        scanner_name=self.scanner_name,
                    )
                    return DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.INJECTION_RISK,
                        severity=SeverityLevel.HIGH,
                        title=XSSConfig.TITLE_REFLECTED_XSS,
                        description=XSSConfig.DESC_REFLECTED_XSS.format(
                            url=endpoint.url, param=param_name,
                        ),
                        technical_detail=(
                            f"**Request:** GET {url}\n"
                            f"**Injected value:** `{probe_value}`\n"
                            f"**Parameter:** `{param_name}`\n"
                            f"**Response status:** {response.status_code}\n"
                            f"**Content-Type:** {content_type}\n"
                            f"**Observation:** The full probe value including "
                            f"HTML characters (<, >, quotes) appears UNESCAPED "
                            f"in the response body. This confirms the server "
                            f"does not encode user input before rendering."
                        ),
                        evidence=(
                            f"GET {url}\n"
                            f"Response body contains `{probe_value}` — "
                            f"HTML chars NOT encoded (confirmed XSS)"
                        ),
                        confidence=XSSConfig.CONFIDENCE_REFLECTED_CONFIRMED,
                        scanner_name=self.scanner_name,
                        endpoint_url=endpoint.url,
                        http_method="GET",
                        request_payload=probe_value,
                        response_preview=body[:300],
                        probe_captures=[capture],
                    )

                # Check for partial reflection (some chars encoded, some not)
                # This is where context-aware XSS kicks in: the text is
                # reflected but HTML chars are encoded. Detect which context
                # the canary landed in and send a context-specific payload.
                canary_text = f"canary_xss_{canary_id}"
                if canary_text in body and "text/html" in content_type.lower():
                    # Attempt context-aware confirmation before reporting LOW
                    ctx_finding = await self._test_context_xss(
                        client, endpoint, param_name, canary_text, body,
                    )
                    if ctx_finding:
                        return ctx_finding

                    return DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.INJECTION_RISK,
                        severity=SeverityLevel.LOW,
                        title=XSSConfig.TITLE_REFLECTED_XSS_POSSIBLE,
                        description=XSSConfig.DESC_REFLECTED_XSS_POSSIBLE.format(
                            url=endpoint.url, param=param_name,
                        ),
                        technical_detail=(
                            f"**Request:** GET {url}\n"
                            f"**Injected value:** `{probe_value}`\n"
                            f"**Parameter:** `{param_name}`\n"
                            f"**Response status:** {response.status_code}\n"
                            f"**Observation:** The canary text `{canary_text}` "
                            f"appears in the response body, but the HTML-significant "
                            f"characters (<, >) from the probe were encoded. "
                            f"This suggests framework-level output encoding is active."
                        ),
                        evidence=(
                            f"GET {url}\n"
                            f"Response contains `{canary_text}` as text — "
                            f"HTML chars encoded (< → &lt;, > → &gt;)"
                        ),
                        confidence=XSSConfig.CONFIDENCE_REFLECTED_POSSIBLE,
                        scanner_name=self.scanner_name,
                        endpoint_url=endpoint.url,
                        http_method="GET",
                        request_payload=probe_value,
                    )

            except Exception as exc:
                logger.debug(
                    XSSConfig.ERROR_XSS_SCAN_FAILED.format(
                        endpoint=endpoint.url, error=str(exc)
                    )
                )

        return None

    # ------------------------------------------------------------------
    # POST body XSS
    # ------------------------------------------------------------------

    async def _test_post_body_xss(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DeepFinding]:
        """Test state-changing endpoints for XSS via JSON POST bodies.

        Identifies POST/PUT/PATCH endpoints and sends JSON bodies with
        canary values in common field names. If canaries are reflected
        unescaped in the response, the endpoint is vulnerable.
        """
        findings: list[DeepFinding] = []
        post_endpoints = self._get_post_testable_endpoints(endpoints)

        if not post_endpoints:
            return findings

        async with RateLimitedClient(
            max_concurrent=XSSConfig.MAX_CONCURRENT,
            delay_seconds=XSSConfig.PROBE_DELAY,
            timeout_seconds=XSSConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            for endpoint in post_endpoints[: XSSConfig.MAX_POST_ENDPOINTS_TO_TEST]:
                finding = await self._test_single_post_body(client, endpoint)
                if finding:
                    findings.append(finding)

        return findings

    async def _test_single_post_body(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
    ) -> DeepFinding | None:
        """Test a single POST endpoint for body reflection XSS.

        Builds a JSON body with canary values for each common field name
        and checks whether any canary is reflected unescaped in the response.
        """
        canary_id = uuid.uuid4().hex[:8]

        # Build JSON body with a unique canary per field
        body_payload: dict[str, str] = {}
        field_canary_map: dict[str, str] = {}
        for field_name in XSSConfig.POST_BODY_FIELD_NAMES:
            canary_value = f"<canary_xss_{canary_id}_{field_name}>"
            body_payload[field_name] = canary_value
            field_canary_map[field_name] = canary_value

        http_method = endpoint.method.value

        try:
            response = await client.request(
                http_method,
                endpoint.url,
                content=json.dumps(body_payload),
                headers={"Content-Type": "application/json"},
            )

            if response.status_code >= 400:
                return None

            response_body = response.text
            content_type = response.headers.get("content-type", "")

            # Check each field's canary for unescaped reflection
            for field_name, canary_value in field_canary_map.items():
                if canary_value in response_body:
                    capture = build_probe_capture(
                        method=http_method,
                        url=endpoint.url,
                        headers=dict(response.request.headers),
                        body=json.dumps(body_payload),
                        response_status=response.status_code,
                        response_headers=dict(response.headers),
                        response_body=response_body,
                        elapsed_ms=response.elapsed.total_seconds() * 1000,
                        scanner_name=self.scanner_name,
                    )
                    return DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.INJECTION_RISK,
                        severity=SeverityLevel.HIGH,
                        title=XSSConfig.TITLE_POST_BODY_XSS,
                        description=XSSConfig.DESC_POST_BODY_XSS.format(
                            url=endpoint.url, field=field_name
                        ),
                        technical_detail=(
                            f"Sent {http_method} with JSON body containing "
                            f"canary in field '{field_name}'.\n"
                            f"Canary: {canary_value}\n"
                            f"Reflected unescaped in response body.\n"
                            f"Content-Type: {content_type}"
                        ),
                        evidence=(
                            f"{http_method} {endpoint.url} with JSON body -> "
                            f"canary in '{field_name}' reflected unescaped"
                        ),
                        confidence=XSSConfig.CONFIDENCE_POST_BODY_REFLECTED,
                        scanner_name=self.scanner_name,
                        endpoint_url=endpoint.url,
                        http_method=http_method,
                        request_payload=json.dumps(body_payload),
                        response_preview=response_body[:300],
                        probe_captures=[capture],
                    )

                # Check for partial reflection (canary text without HTML chars)
                canary_text = f"canary_xss_{canary_id}_{field_name}"
                if canary_text in response_body:
                    return DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.INJECTION_RISK,
                        severity=SeverityLevel.LOW,
                        title=XSSConfig.TITLE_POST_BODY_XSS_POSSIBLE,
                        description=(
                            XSSConfig.DESC_POST_BODY_XSS.format(
                                url=endpoint.url, field=field_name
                            )
                            + " HTML characters appear to be encoded by the "
                            "framework, but the input text is reflected. "
                            "Verify that encoding is applied in all contexts."
                        ),
                        technical_detail=(
                            f"Sent {http_method} with JSON body containing "
                            f"canary in field '{field_name}'.\n"
                            f"Canary text reflected (HTML chars may be encoded)."
                        ),
                        evidence=(
                            f"{http_method} {endpoint.url} with JSON body -> "
                            f"canary in '{field_name}' partially reflected"
                        ),
                        confidence=XSSConfig.CONFIDENCE_REFLECTED_POSSIBLE,
                        scanner_name=self.scanner_name,
                        endpoint_url=endpoint.url,
                        http_method=http_method,
                        request_payload=json.dumps(body_payload),
                    )

        except Exception as exc:
            logger.debug(
                XSSConfig.ERROR_XSS_SCAN_FAILED.format(
                    endpoint=endpoint.url, error=str(exc)
                )
            )

        return None

    # ------------------------------------------------------------------
    # DOM-based XSS
    # ------------------------------------------------------------------

    def _test_dom_xss(self, snapshot: CodebaseSnapshot) -> list[DeepFinding]:
        """Scan JavaScript for dangerous DOM sinks."""
        findings: list[DeepFinding] = []
        js_content = snapshot.all_js_content

        if not js_content:
            return findings

        for sink_pattern in XSSConfig.DANGEROUS_SINKS:
            matches = list(re.finditer(sink_pattern, js_content))
            if not matches:
                continue

            # Check if ALL matches are in safe contexts
            if self._all_matches_safe(sink_pattern, js_content, matches):
                continue

            # Deduplicate: report once per unique sink type
            sink_name = self._readable_sink_name(sink_pattern)

            findings.append(
                DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.INJECTION_RISK,
                    severity=SeverityLevel.LOW,
                    title=XSSConfig.TITLE_DOM_XSS,
                    description=XSSConfig.DESC_DOM_XSS.format(sink=sink_name),
                    technical_detail=(
                        f"Pattern: {sink_pattern}\n"
                        f"Matches: {len(matches)} occurrences in JS bundles"
                    ),
                    evidence=(
                        f"Found {len(matches)} instances of "
                        f"{sink_name} in JavaScript"
                    ),
                    confidence=XSSConfig.CONFIDENCE_DOM_BASED,
                    scanner_name=self.scanner_name,
                    endpoint_url=snapshot.url,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Context-aware XSS confirmation
    # ------------------------------------------------------------------

    async def _test_context_xss(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        param_name: str,
        canary_text: str,
        response_body: str,
    ) -> DeepFinding | None:
        """Detect the injection context and send a targeted breakout payload.

        Called when the canary text is reflected but HTML chars are encoded.
        Analyzes the surrounding HTML/JS to determine which context the
        canary landed in, then sends a context-appropriate payload.

        Returns a HIGH-severity finding if the breakout payload is
        reflected unescaped, or None if no context yields a confirmed XSS.
        """
        for ctx_name, (detect_re, payload, desc) in XSSConfig.CONTEXT_PAYLOADS.items():
            # Check if the canary appears in this context
            pattern = detect_re.replace("{canary}", re.escape(canary_text))
            if not re.search(pattern, response_body):
                continue

            # Canary is in this context — send the breakout payload
            try:
                url = inject_query_param(endpoint.url, param_name, payload)
                resp = await client.get(url)

                if resp.status_code >= 400:
                    continue

                # Check if the breakout payload is reflected unescaped
                if payload in resp.text:
                    capture = build_probe_capture(
                        method="GET",
                        url=url,
                        headers=dict(resp.request.headers),
                        body="",
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body=resp.text,
                        elapsed_ms=resp.elapsed.total_seconds() * 1000,
                        scanner_name=self.scanner_name,
                    )
                    return DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.INJECTION_RISK,
                        severity=SeverityLevel.HIGH,
                        title=XSSConfig.TITLE_CONTEXT_XSS.format(
                            context_desc=desc, param=param_name,
                        ),
                        description=XSSConfig.DESC_CONTEXT_XSS.format(
                            url=endpoint.url,
                            param=param_name,
                            context_desc=desc,
                            payload=payload,
                        ),
                        technical_detail=(
                            f"**Context:** {desc}\n"
                            f"**Parameter:** `{param_name}`\n"
                            f"**Detection:** Canary `{canary_text}` found "
                            f"inside {ctx_name} context\n"
                            f"**Confirmation payload:** `{payload}`\n"
                            f"**Result:** Payload reflected unescaped in "
                            f"response (status {resp.status_code})"
                        ),
                        evidence=(
                            f"GET {url}\n"
                            f"Context: {desc}\n"
                            f"Payload `{payload}` reflected unescaped"
                        ),
                        confidence=XSSConfig.CONFIDENCE_CONTEXT_CONFIRMED,
                        scanner_name=self.scanner_name,
                        endpoint_url=endpoint.url,
                        http_method="GET",
                        request_payload=payload,
                        response_preview=resp.text[:300],
                        probe_captures=[capture],
                    )

            except Exception as exc:
                logger.debug(
                    "Context XSS test failed for %s/%s: %s",
                    endpoint.url, ctx_name, exc,
                )

        return None

    def _all_matches_safe(
        self,
        sink_pattern: str,
        js_content: str,
        matches: list[re.Match[str]],
    ) -> bool:
        """Check whether all matches of a sink are in safe contexts."""
        sink_prefix = sink_pattern.split(r"\s")[0]
        relevant_safe_patterns = [
            sp
            for sp in XSSConfig.SAFE_SINK_CONTEXTS
            if sink_prefix in sp
        ]
        if not relevant_safe_patterns:
            return False

        for match in matches:
            # Extract surrounding context (up to 80 chars after match start)
            start = match.start()
            context = js_content[start : start + 80]
            is_safe = any(
                re.search(safe_p, context)
                for safe_p in relevant_safe_patterns
            )
            if not is_safe:
                return False
        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_testable_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """Filter endpoints that are worth testing for reflected XSS."""
        testable: list[DiscoveredEndpoint] = []
        for ep in endpoints:
            parsed = urlparse(ep.url)
            # Has query params already, or is a GET endpoint we can add params to
            if parsed.query or ep.method.value == "GET":
                testable.append(ep)
        return testable

    def _get_post_testable_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """Filter endpoints with state-changing HTTP methods (POST/PUT/PATCH)."""
        return [
            ep
            for ep in endpoints
            if ep.method.value in XSSConfig.STATE_CHANGING_METHODS
        ]

    def _get_testable_params(self, endpoint: DiscoveredEndpoint) -> list[str]:
        """Get parameter names to test for an endpoint.

        Priority order:
        1. Params already in the URL query string (known to exist)
        2. Params from endpoint discovery (query_param_names)
        3. Small fallback set of common reflectable params (capped)
        """
        seen: set[str] = set()
        params: list[str] = []

        # 1. Params in the URL
        parsed = urlparse(endpoint.url)
        for p in parse_qs(parsed.query).keys():
            if p not in seen:
                params.append(p)
                seen.add(p)

        # 2. Discovered query params
        for p in endpoint.query_param_names:
            if p not in seen:
                params.append(p)
                seen.add(p)

        # 3. If still empty, use a small fallback (not the full list)
        if not params:
            for p in XSSConfig.COMMON_REFLECTABLE_PARAMS:
                if len(params) >= XSSConfig.MAX_PARAMS_PER_ENDPOINT:
                    break
                if p not in seen:
                    params.append(p)
                    seen.add(p)

        return params[: XSSConfig.MAX_PARAMS_PER_ENDPOINT]

    @staticmethod
    def _readable_sink_name(pattern: str) -> str:
        """Convert a regex sink pattern to a human-readable name."""
        return (
            pattern.replace(r"\s*", "")
            .replace(r"\s*\(", "(")
            .replace(r"\(", "(")
            .replace(r"\.", ".")
            .replace("\\", "")
        )
