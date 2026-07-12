"""Active SQL/NoSQL/Command/Template injection scanner.

Tests API endpoints for injection vulnerabilities using safe detection payloads:
1. Error-based SQLi — inject SQL syntax errors, check for SQL error in response
2. Time-based blind SQLi — inject sleep/delay, measure response time delta
3. NoSQL injection — inject MongoDB operators, check for unexpected data
4. Command injection — inject shell metacharacters, check for canary in output
5. Template injection (SSTI) — inject template expressions, check for evaluation

Uses read-only detection: payloads are designed to reveal the vulnerability
without modifying data.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from urllib.parse import parse_qs, quote, unquote_plus, urlparse

import httpx

from isitsecure.engine.constants import (
    DeepScanConfig,
    InjectionConfig,
    TemplateInjectionConfig,
)
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.endpoint_prioritizer import PriorityDimension, rank
from isitsecure.engine.shared.probe_capture import build_probe_capture
from isitsecure.engine.shared.progress import emit
from isitsecure.engine.shared.scanner_runner import ScannerTimeouts
from isitsecure.engine.shared.time_budget import TimeBudget
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.shared.url_utils import inject_query_param
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class ActiveInjectionScanner:
    """Active injection scanner implementing DASTScannerProtocol.

    Scans discovered endpoints for SQL injection, NoSQL injection,
    and command injection vulnerabilities using safe detection payloads.
    """

    # --- Testable HTTP methods ---
    _TESTABLE_METHODS = frozenset({"GET", "POST"})

    def __init__(self, time_based: bool = True) -> None:
        """Args:
        time_based: Run time-based (blind) SQLi probes. These inject
            server-side sleep payloads and are the dominant cost of a scan, so
            they are disabled in QUICK depth and enabled only for DEEP.
        """
        self._time_based = time_based

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return InjectionConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.INJECTION_RISK]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: object | None = None,
    ) -> list[DeepFinding]:
        """Run injection tests against discovered endpoints.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot (unused by this scanner).

        Returns:
            List of injection findings.
        """
        findings: list[DeepFinding] = []
        testable = self._get_testable_endpoints(endpoints)
        budget = TimeBudget(ScannerTimeouts.INJECTION_ACTIVE_SECONDS)
        candidates = testable[: InjectionConfig.MAX_ENDPOINTS_TO_TEST]

        async with RateLimitedClient(
            max_concurrent=InjectionConfig.MAX_CONCURRENT,
            delay_seconds=InjectionConfig.PROBE_DELAY,
            timeout_seconds=InjectionConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            # Target-level probe: auth-bypass SQLi on conventional login paths.
            # A login POST is rarely recoverable from a minified SPA bundle, so
            # discovery usually misses it — probe the standard paths directly.
            base_url = self._derive_base_url(endpoints)
            if base_url and not budget.expired():
                try:
                    ab = await self._test_auth_bypass(client, base_url)
                    if ab:
                        findings.append(ab)
                except Exception:
                    logger.warning("auth-bypass probe failed", exc_info=True)

            for tested, ep in enumerate(candidates):
                # Stop cooperatively before the external hard timeout cancels
                # us (which would discard every finding so far). Endpoints are
                # ranked, so anything skipped is the lowest-priority tail.
                if budget.expired():
                    logger.info(
                        "ActiveInjectionScanner: time budget reached, tested "
                        "%d/%d endpoints", tested, len(candidates),
                    )
                    break
                emit(f"injection: testing {urlparse(ep.url).path or ep.url}")
                params = self._get_testable_params(ep)
                for param in params[: InjectionConfig.MAX_PARAMS_PER_ENDPOINT]:
                    try:
                        ep_findings = await self._test_param(client, ep, param)
                        findings.extend(ep_findings)
                    except Exception:
                        logger.warning(
                            InjectionConfig.ERROR_INJECTION_SCAN_FAILED.format(
                                endpoint=ep.url, error="unexpected error during param test"
                            ),
                            exc_info=True,
                        )

                # XXE test is per-endpoint, not per-param (content-type based)
                try:
                    xxe_finding = await self._test_xxe_injection(client, ep)
                    if xxe_finding:
                        findings.append(xxe_finding)
                except Exception:
                    logger.warning(
                        InjectionConfig.ERROR_INJECTION_SCAN_FAILED.format(
                            endpoint=ep.url, error="unexpected error during XXE test"
                        ),
                        exc_info=True,
                    )

        logger.info("ActiveInjectionScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Orchestration per parameter
    # ------------------------------------------------------------------

    async def _test_param(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        param_name: str,
    ) -> list[DeepFinding]:
        """Run all injection tests for a single parameter.

        Error-based SQLi is checked first; if found we skip time-based
        for the same parameter to avoid redundant probing.
        """
        findings: list[DeepFinding] = []

        sqli_error = await self._test_error_based_sqli(client, endpoint, param_name)
        if sqli_error:
            findings.append(sqli_error)
        elif self._time_based:
            sqli_time = await self._test_time_based_sqli(client, endpoint, param_name)
            if sqli_time:
                findings.append(sqli_time)

        cmd_finding = await self._test_command_injection(client, endpoint, param_name)
        if cmd_finding:
            findings.append(cmd_finding)

        nosql_finding = await self._test_nosql_injection(client, endpoint, param_name)
        if nosql_finding:
            findings.append(nosql_finding)

        ssti_finding = await self._test_template_injection(client, endpoint, param_name)
        if ssti_finding:
            findings.append(ssti_finding)

        return findings

    # ------------------------------------------------------------------
    # Authentication-bypass (boolean) SQL injection
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_base_url(endpoints: list[DiscoveredEndpoint]) -> str | None:
        """Return the target's scheme://host from any discovered endpoint."""
        for ep in endpoints:
            parsed = urlparse(ep.url)
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
        return None

    async def _test_auth_bypass(
        self,
        client: RateLimitedClient,
        base_url: str,
    ) -> DeepFinding | None:
        """Probe conventional login paths for authentication-bypass SQLi.

        Differential oracle: a benign invalid credential must be REJECTED, and a
        SQL tautology in the identity field must AUTHENTICATE (return a session
        token). That state change is near-unambiguous, so it is false-positive
        safe — a hardened login rejects the tautology exactly like the benign
        credential. The hit is reproduced once before it is reported.
        """
        for path in InjectionConfig.AUTH_LOGIN_PATHS:
            url = base_url.rstrip("/") + path
            for field in InjectionConfig.AUTH_IDENTITY_FIELDS:
                control = await self._auth_post(
                    client, url, field, "isitsecure_no_such_user", "wrong_pw_x1y2",
                )
                if control is None:
                    break                       # unreachable — skip this path
                if control.status_code == 404:
                    break                       # path doesn't exist — next path
                if self._looks_authenticated(control):
                    continue                    # auths anything — can't tell; next field
                for payload in InjectionConfig.AUTH_BYPASS_PAYLOADS:
                    resp = await self._auth_post(client, url, field, payload, "x")
                    if resp is None or not self._looks_authenticated(resp):
                        continue
                    repro = await self._auth_post(client, url, field, payload, "x")
                    if repro is not None and self._looks_authenticated(repro):
                        return self._build_auth_bypass_finding(
                            url, field, payload, resp.text,
                        )
        return None

    async def _auth_post(
        self,
        client: RateLimitedClient,
        url: str,
        field: str,
        identity: str,
        password: str,
    ):
        """POST a JSON credential body ``{field: identity, password: ...}``."""
        body = json.dumps({field: identity, InjectionConfig.AUTH_PASSWORD_FIELD: password})
        try:
            return await client.request(
                "POST", url, content=body,
                headers={"Content-Type": "application/json"},
            )
        except Exception:
            return None

    @staticmethod
    def _looks_authenticated(response) -> bool:
        """True only if the response is 2xx AND carries a session token/cookie."""
        if not (200 <= response.status_code < 300):
            return False
        body = response.text
        for pat in InjectionConfig.AUTH_TOKEN_PATTERNS:
            if re.search(pat, body):
                return True
        cookie = response.headers.get("set-cookie", "")
        return bool(cookie and re.search(
            InjectionConfig.AUTH_SESSION_COOKIE_PATTERN, cookie
        ))

    def _build_auth_bypass_finding(
        self,
        url: str,
        field: str,
        payload: str,
        body: str,
    ) -> DeepFinding:
        """Build a DeepFinding for a confirmed auth-bypass SQLi."""
        return DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.INJECTION_RISK,
            severity=SeverityLevel.CRITICAL,
            title=InjectionConfig.TITLE_AUTH_BYPASS,
            description=InjectionConfig.DESC_AUTH_BYPASS.format(
                url=url, field=field, payload=payload,
            ),
            technical_detail=(
                f"Authentication-bypass SQLi at {url}: a benign invalid "
                f"credential was rejected, but the body "
                f'`{{"{field}": "{payload}", "password": "x"}}` returned an '
                f"authenticated session (reproduced)."
            ),
            evidence=body[:500],
            confidence=InjectionConfig.CONFIDENCE_AUTH_BYPASS,
            scanner_name=self.scanner_name,
            endpoint_url=url,
            http_method="POST",
            request_payload=f'{{"{field}": "{payload}", "password": "x"}}',
            response_preview=body[:300],
        )

    # ------------------------------------------------------------------
    # Error-based SQL injection
    # ------------------------------------------------------------------

    async def _probe(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        param_name: str,
        payload: str,
    ):
        """Send `payload` in `param_name` the right way for the endpoint method.

        Templated path param → substituted into the URL; else GET → query
        string; POST/PUT/PATCH → JSON body. Returns the httpx response (or
        None on error), so path-, query-, and body-based injection are all
        reachable (e.g. a SQLi in `/users/{name}`, `?q=`, or a JSON field).
        """
        method = endpoint.method.value
        placeholder = "{" + param_name + "}"
        try:
            if placeholder in endpoint.url:
                url = endpoint.url.replace(placeholder, quote(str(payload), safe=""))
                if method == "GET":
                    return await client.get(url)
                return await client.request(method, url)
            if method == "GET":
                return await client.get(
                    inject_query_param(endpoint.url, param_name, payload)
                )
            return await client.request(
                method,
                endpoint.url,
                content=json.dumps({param_name: payload}),
                headers={"Content-Type": "application/json"},
            )
        except Exception:
            return None

    async def _test_error_based_sqli(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        param_name: str,
    ) -> DeepFinding | None:
        """Inject SQL error payloads and check for SQL error messages in response."""
        for payload in InjectionConfig.SQLI_ERROR_PAYLOADS:
            response = await self._probe(client, endpoint, param_name, payload)
            if response is None:
                continue
            body = response.text

            matched_pattern = self._response_has_sql_error(body)
            if matched_pattern:
                capture = build_probe_capture(
                    method=endpoint.method.value,
                    url=endpoint.url,
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
                    severity=SeverityLevel.CRITICAL,
                    title=InjectionConfig.TITLE_SQLI_ERROR,
                    description=InjectionConfig.DESC_SQLI_ERROR.format(
                        url=endpoint.url, payload=payload, param=param_name,
                    ),
                    technical_detail=f"Matched SQL error pattern: {matched_pattern}",
                    evidence=body[:500],
                    confidence=InjectionConfig.CONFIDENCE_ERROR_BASED,
                    scanner_name=self.scanner_name,
                    endpoint_url=endpoint.url,
                    http_method=endpoint.method.value,
                    request_payload=f"{param_name}={payload}",
                    response_preview=body[:300],
                    probe_captures=[capture],
                )
        return None

    # ------------------------------------------------------------------
    # Time-based blind SQL injection
    # ------------------------------------------------------------------

    async def _test_time_based_sqli(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        param_name: str,
    ) -> DeepFinding | None:
        """Inject time-delay payloads and measure response time difference."""
        # 1. Measure baseline response time with a benign value
        baseline_time = await self._measure_response_time(
            client, endpoint.url, param_name, "1"
        )
        if baseline_time is None:
            return None

        # 2. Test each time-delay payload
        for payload, db_type in InjectionConfig.SQLI_TIME_PAYLOADS:
            injected_time = await self._measure_response_time(
                client, endpoint.url, param_name, payload
            )
            if injected_time is None:
                continue

            delta = injected_time - baseline_time
            if delta >= InjectionConfig.TIME_BASED_DELAY_THRESHOLD:
                # Confirm with an independent re-measurement. A real time-based
                # SQLi reproduces the delay; a one-off slow response (load, GC,
                # network jitter — common on DBs that don't even honor the sleep
                # payload) does not. This kills time-based false positives.
                baseline_confirm = await self._measure_response_time(
                    client, endpoint.url, param_name, "1"
                )
                injected_confirm = await self._measure_response_time(
                    client, endpoint.url, param_name, payload
                )
                if baseline_confirm is None or injected_confirm is None:
                    continue
                confirm_delta = injected_confirm - baseline_confirm
                if confirm_delta < InjectionConfig.TIME_BASED_DELAY_THRESHOLD:
                    continue  # did not reproduce → timing noise, not injection
                delta = min(delta, confirm_delta)
                capture = build_probe_capture(
                    method="GET",
                    url=inject_query_param(endpoint.url, param_name, payload),
                    headers={},
                    body="",
                    response_status=0,
                    response_headers={},
                    response_body="",
                    elapsed_ms=injected_time * 1000,
                    scanner_name=self.scanner_name,
                )
                return DeepFinding(
                    source=FindingSource.DAST_URL,
                    category=FindingCategory.INJECTION_RISK,
                    severity=SeverityLevel.CRITICAL,
                    title=InjectionConfig.TITLE_SQLI_TIME,
                    description=InjectionConfig.DESC_SQLI_TIME.format(
                        url=endpoint.url, delta=delta, param=param_name,
                    ),
                    technical_detail=(
                        f"Baseline: {baseline_time:.2f}s, "
                        f"Injected: {injected_time:.2f}s, "
                        f"Delta: {delta:.2f}s, DB hint: {db_type}"
                    ),
                    evidence=f"Time delta {delta:.2f}s with payload: {payload}",
                    confidence=InjectionConfig.CONFIDENCE_TIME_BASED,
                    scanner_name=self.scanner_name,
                    endpoint_url=endpoint.url,
                    http_method=endpoint.method.value,
                    request_payload=f"{param_name}={payload}",
                    probe_captures=[capture],
                )
        return None

    # ------------------------------------------------------------------
    # Command injection
    # ------------------------------------------------------------------

    async def _test_command_injection(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        param_name: str,
    ) -> DeepFinding | None:
        """Inject shell metacharacters and check for canary in response."""
        for payload in InjectionConfig.COMMAND_INJECTION_PAYLOADS:
            injected_url = inject_query_param(endpoint.url, param_name, payload)
            try:
                response = await client.get(injected_url)
                body = response.text
            except (httpx.HTTPError, Exception):
                continue

            # Require the canary to appear WITHOUT the un-executed "echo <canary>"
            # form — otherwise an app that merely reflects the payload (very
            # common in error pages, often URL-encoded) is a false positive,
            # not real command execution. Decode first so echo%20canary counts.
            canary = InjectionConfig.COMMAND_INJECTION_CANARY
            decoded = unquote_plus(body)
            if canary in decoded and f"echo {canary}" not in decoded:
                capture = build_probe_capture(
                    method="GET",
                    url=injected_url,
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
                    severity=SeverityLevel.CRITICAL,
                    title=InjectionConfig.TITLE_COMMAND_INJECTION,
                    description=InjectionConfig.DESC_COMMAND_INJECTION.format(
                        url=endpoint.url, payload=payload, param=param_name,
                    ),
                    technical_detail=(
                        f"Canary '{InjectionConfig.COMMAND_INJECTION_CANARY}' "
                        f"found in response body"
                    ),
                    evidence=body[:500],
                    confidence=InjectionConfig.CONFIDENCE_COMMAND_INJECTION,
                    scanner_name=self.scanner_name,
                    endpoint_url=endpoint.url,
                    http_method=endpoint.method.value,
                    request_payload=f"{param_name}={payload}",
                    response_preview=body[:300],
                    probe_captures=[capture],
                )
        return None

    # ------------------------------------------------------------------
    # NoSQL injection
    # ------------------------------------------------------------------

    async def _test_nosql_injection(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        param_name: str,
    ) -> DeepFinding | None:
        """Inject NoSQL operator payloads and compare response to baseline.

        Tests both query-string format ([$ne]=null appended to param name)
        and JSON body payloads via POST. Detection relies on response size
        inflation or NoSQL error/document indicators in the response.
        """
        # 1. Get baseline response for comparison
        baseline_url = inject_query_param(endpoint.url, param_name, "baseline_safe_value")
        try:
            baseline_response = await client.get(baseline_url)
            baseline_body = baseline_response.text
            baseline_size = len(baseline_body)
        except (httpx.HTTPError, Exception):
            return None

        # 2. Test query-string NoSQL payloads ([$ne]=null style)
        for qs_payload in InjectionConfig.NOSQL_QUERY_PAYLOADS:
            injected_url = inject_query_param(
                endpoint.url, f"{param_name}{qs_payload}", ""
            )
            try:
                response = await client.get(injected_url)
                body = response.text
            except (httpx.HTTPError, Exception):
                continue

            finding = self._check_nosql_response(
                body, baseline_size, endpoint, param_name, qs_payload
            )
            if finding:
                return finding

        # 3. Test JSON body NoSQL payloads (POST endpoints)
        if endpoint.method.value == "POST":
            for payload in InjectionConfig.NOSQL_PAYLOADS:
                # Build a body with the param name wrapping the NoSQL operator
                nosql_body = '{{"{}": {}}}'.format(param_name, payload)
                try:
                    response = await client.request(
                        "POST",
                        endpoint.url,
                        content=nosql_body,
                        headers={"Content-Type": "application/json"},
                    )
                    body = response.text
                except (httpx.HTTPError, Exception):
                    continue

                finding = self._check_nosql_response(
                    body, baseline_size, endpoint, param_name, payload
                )
                if finding:
                    return finding

        return None

    def _check_nosql_response(
        self,
        body: str,
        baseline_size: int,
        endpoint: DiscoveredEndpoint,
        param_name: str,
        payload: str,
    ) -> DeepFinding | None:
        """Analyze a response for NoSQL injection indicators.

        Returns a DeepFinding if the response contains MongoDB indicators
        or is significantly larger than the baseline (data leak).
        """
        # Check for NoSQL error/document indicators
        for pattern in InjectionConfig.NOSQL_INDICATORS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return self._build_nosql_finding(
                    endpoint, param_name, payload, body,
                    f"Matched NoSQL indicator: {match.group(0)}",
                )

        # Check for response size inflation (data leak)
        if (
            baseline_size >= InjectionConfig.NOSQL_MIN_BASELINE_SIZE
            and len(body) > baseline_size * InjectionConfig.NOSQL_RESPONSE_SIZE_RATIO
        ):
            return self._build_nosql_finding(
                endpoint, param_name, payload, body,
                f"Response size inflated: baseline={baseline_size}, "
                f"injected={len(body)} "
                f"(ratio={len(body) / baseline_size:.1f}x)",
            )

        return None

    def _build_nosql_finding(
        self,
        endpoint: DiscoveredEndpoint,
        param_name: str,
        payload: str,
        body: str,
        technical_detail: str,
    ) -> DeepFinding:
        """Build a DeepFinding for a confirmed NoSQL injection."""
        return DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.INJECTION_RISK,
            severity=SeverityLevel.CRITICAL,
            title=InjectionConfig.TITLE_NOSQL,
            description=InjectionConfig.DESC_NOSQL.format(
                url=endpoint.url, payload=payload, param=param_name,
            ),
            technical_detail=technical_detail,
            evidence=body[:500],
            confidence=InjectionConfig.CONFIDENCE_NOSQL,
            scanner_name=self.scanner_name,
            endpoint_url=endpoint.url,
            http_method=endpoint.method.value,
            request_payload=f"{param_name}={payload}",
            response_preview=body[:300],
        )

    # ------------------------------------------------------------------
    # XXE / XML injection
    # ------------------------------------------------------------------

    async def _test_xxe_injection(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
    ) -> DeepFinding | None:
        """Test if an endpoint accepting XML is vulnerable to XXE injection.

        Only tests endpoints that accept XML content types. Sends a payload
        with an external entity referencing /etc/passwd and checks the
        response for file-system content indicators.
        """
        # Pre-check: probe with OPTIONS or HEAD to see if XML is accepted
        accepts_xml = await self._endpoint_accepts_xml(client, endpoint)
        if not accepts_xml:
            return None

        for content_type in InjectionConfig.XXE_CONTENT_TYPES:
            try:
                response = await client.request(
                    "POST",
                    endpoint.url,
                    content=InjectionConfig.XXE_PAYLOAD,
                    headers={"Content-Type": content_type},
                )
                body = response.text
            except (httpx.HTTPError, Exception):
                continue

            # Check for file content indicators in the response
            for pattern in InjectionConfig.XXE_INDICATORS:
                match = re.search(pattern, body)
                if match:
                    capture = build_probe_capture(
                        method="POST",
                        url=endpoint.url,
                        headers=dict(response.request.headers),
                        body=InjectionConfig.XXE_PAYLOAD,
                        response_status=response.status_code,
                        response_headers=dict(response.headers),
                        response_body=body,
                        elapsed_ms=response.elapsed.total_seconds() * 1000,
                        scanner_name=self.scanner_name,
                    )
                    return DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.INJECTION_RISK,
                        severity=SeverityLevel.CRITICAL,
                        title=InjectionConfig.TITLE_XXE,
                        description=InjectionConfig.DESC_XXE.format(
                            url=endpoint.url,
                        ),
                        technical_detail=(
                            f"Matched file-system indicator: {match.group(0)} | "
                            f"Content-Type used: {content_type}"
                        ),
                        evidence=body[:500],
                        confidence=InjectionConfig.CONFIDENCE_XXE,
                        scanner_name=self.scanner_name,
                        endpoint_url=endpoint.url,
                        http_method="POST",
                        request_payload=InjectionConfig.XXE_PAYLOAD,
                        response_preview=body[:300],
                        probe_captures=[capture],
                    )

        return None

    async def _endpoint_accepts_xml(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
    ) -> bool:
        """Check whether an endpoint likely accepts XML input.

        Sends an OPTIONS request and inspects the Accept or
        Content-Type headers. Falls back to True for POST endpoints
        so we always attempt the probe if OPTIONS is inconclusive.
        """
        try:
            response = await client.request("OPTIONS", endpoint.url)
            accept_header = response.headers.get("accept", "").lower()
            content_type_header = response.headers.get("content-type", "").lower()
            combined = accept_header + content_type_header

            for xml_ct in InjectionConfig.XXE_CONTENT_TYPES:
                if xml_ct in combined:
                    return True

            # If OPTIONS doesn't reveal XML support but endpoint is POST,
            # still try — many APIs don't advertise XML support via OPTIONS
            return endpoint.method.value == "POST"
        except (httpx.HTTPError, Exception):
            # If OPTIONS fails, attempt XXE probe on POST endpoints anyway
            return endpoint.method.value == "POST"

    # ------------------------------------------------------------------
    # Response analysis helpers
    # ------------------------------------------------------------------

    def _response_has_sql_error(self, body: str) -> str | None:
        """Check if response body contains SQL error indicators.

        Returns:
            The matched text if found, otherwise None.
        """
        for pattern in InjectionConfig.SQL_ERROR_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    # ------------------------------------------------------------------
    # Timing helpers
    # ------------------------------------------------------------------

    async def _measure_response_time(
        self,
        client: RateLimitedClient,
        base_url: str,
        param_name: str,
        value: str,
    ) -> float | None:
        """Measure the wall-clock time of a single GET request.

        Returns:
            Elapsed seconds, or None if the request failed.
        """
        injected_url = inject_query_param(base_url, param_name, value)
        try:
            start = time.monotonic()
            await client.get(injected_url)
            return time.monotonic() - start
        except (httpx.HTTPError, Exception):
            return None

    # ------------------------------------------------------------------
    # Endpoint / parameter helpers
    # ------------------------------------------------------------------

    def _get_testable_endpoints(
        self, endpoints: list[DiscoveredEndpoint],
    ) -> list[DiscoveredEndpoint]:
        """Filter to injection-testable endpoints, most-promising first.

        Injection testing is capped by time budget, so ordering matters on
        large apps — the likely injection points must be tested before boring
        collections. Ranking is delegated to the shared endpoint_prioritizer.
        """
        testable = [
            ep for ep in endpoints if ep.method.value in self._TESTABLE_METHODS
        ]
        return rank(testable, PriorityDimension.INJECTION)

    def _get_testable_params(self, endpoint: DiscoveredEndpoint) -> list[str]:
        """Extract parameters to test from an endpoint.

        Uses query param names already known from discovery. Falls back
        to common injectable parameter names when none are available.
        """
        parsed = urlparse(endpoint.url)
        params = list(parse_qs(parsed.query).keys())
        # Known path + query params from discovery (e.g. an OpenAPI spec).
        for name in list(endpoint.path_param_names) + list(endpoint.query_param_names):
            if name and name not in params:
                params.append(name)
        if not params:
            params = list(InjectionConfig.DEFAULT_FUZZ_PARAMS)
        return params[: InjectionConfig.MAX_PARAMS_PER_ENDPOINT]

    # ------------------------------------------------------------------
    # Template injection (SSTI)
    # ------------------------------------------------------------------

    async def _test_template_injection(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
        param_name: str,
    ) -> DeepFinding | None:
        """Test for server-side template injection (SSTI).

        Injects template expressions and checks if the computed result
        appears in the response (e.g., ``{{7*7}}`` → ``49``).
        """
        for payload, expected, engine in TemplateInjectionConfig.SSTI_PAYLOADS:
            try:
                resp = await self._probe(client, endpoint, param_name, payload)
                if resp is None or resp.status_code >= 500:
                    continue

                body = resp.text
                if expected in body:
                    # Verify: the expected output should NOT appear when we
                    # send a non-template value (avoid false positives from
                    # pages that naturally contain "49")
                    safe_resp = await self._probe(
                        client, endpoint, param_name, "harmless_test_value",
                    )
                    if safe_resp is None or expected in safe_resp.text:
                        continue  # "49" appears naturally — not SSTI

                    capture = build_probe_capture(
                        method="GET",
                        url=endpoint.url,
                        headers=dict(resp.request.headers),
                        body="",
                        response_status=resp.status_code,
                        response_headers=dict(resp.headers),
                        response_body=body,
                        elapsed_ms=resp.elapsed.total_seconds() * 1000,
                        scanner_name=self.scanner_name,
                    )
                    return DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.INJECTION_RISK,
                        severity=SeverityLevel.CRITICAL,
                        title=TemplateInjectionConfig.TITLE_SSTI.format(
                            engine=engine,
                            param=param_name,
                            url=endpoint.url,
                        ),
                        description=TemplateInjectionConfig.DESC_SSTI.format(
                            param=param_name,
                            url=endpoint.url,
                            payload=payload,
                            expected=expected,
                        ),
                        confidence=TemplateInjectionConfig.CONFIDENCE_SSTI,
                        scanner_name=self.scanner_name,
                        endpoint_url=endpoint.url,
                        probe_captures=[capture],
                    )
            except Exception as e:
                logger.debug(
                    "SSTI test failed for %s param %s: %s",
                    endpoint.url, param_name, e,
                )

        return None

