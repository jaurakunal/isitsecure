"""JSON body parameter fuzzer.

For every POST/PATCH intercepted during the authenticated crawl,
extracts JSON keys and fuzzes each one with:
- SQL injection payloads (checks for error-based detection)
- XSS payloads (checks for reflection)
- Type confusion (sends wrong types: int→string, null, array)

This is how most real API vulnerabilities are found — not by fuzzing
query params on GET requests, but by manipulating the actual fields
in API request bodies.
"""

from __future__ import annotations

import json
import logging
import re
from urllib.parse import urlparse

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import (
    BodyParamFuzzerConfig,
    DeepScanConfig,
    SharedPatterns,
)
from isitsecure.engine.models import (
    DeepFinding,
    FindingSource,
    InterceptedRequest,
)
from isitsecure.engine.shared.rate_limited_client import (
    RateLimitedClient,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class BodyParamFuzzer:
    """Fuzzes JSON body parameters from intercepted authenticated requests."""

    @property
    def scanner_name(self) -> str:
        return BodyParamFuzzerConfig.SCANNER_NAME

    _ERROR_RE = [
        re.compile(p, re.IGNORECASE)
        for p in BodyParamFuzzerConfig.ERROR_INDICATORS
    ]

    async def scan(
        self,
        intercepted_requests: list[InterceptedRequest],
        session: AuthSession,
    ) -> list[DeepFinding]:
        """Fuzz JSON body parameters from intercepted requests.

        Args:
            intercepted_requests: Requests captured during authenticated crawl.
            session: Auth session for replaying requests.
        """
        findings: list[DeepFinding] = []

        mutations = [
            r for r in intercepted_requests
            if r.method.upper() in BodyParamFuzzerConfig.WRITE_METHODS
            and r.request_body
            and r.response_status in BodyParamFuzzerConfig.SUCCESS_CODES
        ]

        async with RateLimitedClient(
            max_concurrent=BodyParamFuzzerConfig.MAX_CONCURRENT,
            delay_seconds=BodyParamFuzzerConfig.PROBE_DELAY_SECONDS,
            timeout_seconds=BodyParamFuzzerConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            for req in mutations[: BodyParamFuzzerConfig.MAX_REQUESTS_TO_FUZZ]:
                try:
                    body = json.loads(req.request_body)
                    if not isinstance(body, dict):
                        continue
                except (json.JSONDecodeError, TypeError):
                    continue

                params = list(body.keys())[
                    : BodyParamFuzzerConfig.MAX_PARAMS_PER_REQUEST
                ]
                from isitsecure.engine.shared.auth_headers import (
                    build_replay_headers,
                )
                headers = build_replay_headers(session, req)

                for param in params:
                    original_value = body[param]

                    # SQLi fuzzing
                    for payload in BodyParamFuzzerConfig.SQLI_PAYLOADS:
                        f = await self._fuzz_param(
                            client, req, body, param, payload,
                            headers, "sqli",
                        )
                        if f:
                            findings.append(f)

                    # XSS fuzzing
                    for payload in BodyParamFuzzerConfig.XSS_PAYLOADS:
                        f = await self._fuzz_param(
                            client, req, body, param, payload,
                            headers, "xss",
                        )
                        if f:
                            findings.append(f)

                    # Type confusion
                    if isinstance(original_value, str):
                        for label, value in BodyParamFuzzerConfig.TYPE_CONFUSION_PAYLOADS:
                            f = await self._fuzz_param(
                                client, req, body, param, value,
                                headers, "type", label,
                            )
                            if f:
                                findings.append(f)

                # Prototype pollution (tested per-request, not per-param)
                for proto_key, proto_value in BodyParamFuzzerConfig.PROTOTYPE_POLLUTION_PAYLOADS:
                    f = await self._fuzz_param(
                        client, req, body, proto_key, proto_value,
                        headers, "prototype_pollution",
                    )
                    if f:
                        findings.append(f)

        logger.info(
            "BodyParamFuzzer: %d findings from %d mutations",
            len(findings), len(mutations),
        )
        return findings

    async def _fuzz_param(
        self,
        client: RateLimitedClient,
        original_req: InterceptedRequest,
        body: dict,
        param: str,
        payload: object,
        headers: dict[str, str],
        fuzz_type: str,
        payload_label: str = "",
    ) -> DeepFinding | None:
        """Send a fuzzed request and analyze the response."""
        fuzzed_body = {**body, param: payload}
        method = original_req.method.upper()

        try:
            resp = await client.request(
                method, original_req.url,
                headers=headers,
                content=json.dumps(fuzzed_body, default=str),
            )
            path = urlparse(original_req.url).path

            if fuzz_type == "sqli":
                if self._has_sql_error(resp.text):
                    return self._make_finding(
                        SeverityLevel.CRITICAL,
                        BodyParamFuzzerConfig.TITLE_SQL_ERROR.format(param=param),
                        BodyParamFuzzerConfig.DESC_SQL_ERROR.format(
                            param=param, method=method, path=path,
                        ),
                        BodyParamFuzzerConfig.CONFIDENCE_SQL_ERROR,
                        original_req.url, method, resp.text,
                        json.dumps(fuzzed_body, default=str),
                    )

            elif fuzz_type == "xss":
                if isinstance(payload, str) and payload in resp.text:
                    return self._make_finding(
                        SeverityLevel.HIGH,
                        BodyParamFuzzerConfig.TITLE_XSS_BODY.format(param=param),
                        BodyParamFuzzerConfig.DESC_XSS_BODY.format(
                            param=param, path=path,
                        ),
                        BodyParamFuzzerConfig.CONFIDENCE_XSS_REFLECTED,
                        original_req.url, method, resp.text,
                        json.dumps(fuzzed_body, default=str),
                    )

            elif fuzz_type == "prototype_pollution":
                # Server accepted __proto__ / constructor key without 400
                if resp.status_code < 400:
                    return self._make_finding(
                        SeverityLevel.HIGH,
                        BodyParamFuzzerConfig.TITLE_PROTOTYPE_POLLUTION.format(
                            param=param,
                        ),
                        BodyParamFuzzerConfig.DESC_PROTOTYPE_POLLUTION.format(
                            param=param, method=method, path=path,
                        ),
                        BodyParamFuzzerConfig.CONFIDENCE_PROTOTYPE_POLLUTION,
                        original_req.url, method, resp.text,
                        json.dumps(fuzzed_body, default=str),
                    )

            elif fuzz_type == "type":
                if resp.status_code >= 500:
                    return self._make_finding(
                        SeverityLevel.MEDIUM,
                        BodyParamFuzzerConfig.TITLE_TYPE_CONFUSION.format(param=param),
                        BodyParamFuzzerConfig.DESC_TYPE_CONFUSION.format(
                            param=param, method=method, path=path,
                            payload_type=payload_label,
                            original_type=type(body.get(param, "")).__name__,
                            status=resp.status_code,
                        ),
                        BodyParamFuzzerConfig.CONFIDENCE_TYPE_ERROR,
                        original_req.url, method, resp.text,
                        json.dumps(fuzzed_body, default=str),
                    )

        except Exception as exc:
            logger.debug(
                BodyParamFuzzerConfig.ERROR_FUZZ_FAILED.format(
                    url=original_req.url, error=str(exc),
                )
            )
        return None

    def _has_sql_error(self, response_text: str) -> bool:
        """Check if response contains SQL error indicators."""
        return any(p.search(response_text) for p in self._ERROR_RE)

    def _make_finding(
        self, severity: SeverityLevel, title: str, description: str,
        confidence: float, endpoint_url: str, http_method: str,
        response_preview: str, request_payload: str,
    ) -> DeepFinding:
        return DeepFinding(
            source=FindingSource.DAST_AUTHENTICATED,
            category=FindingCategory.INJECTION_RISK,
            severity=severity,
            title=title,
            description=description,
            confidence=confidence,
            scanner_name=self.scanner_name,
            endpoint_url=endpoint_url,
            http_method=http_method,
            response_preview=response_preview[
                : BodyParamFuzzerConfig.RESPONSE_PREVIEW_LENGTH
            ],
            request_payload=request_payload,
        )
