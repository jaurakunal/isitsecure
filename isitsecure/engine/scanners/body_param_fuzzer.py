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
from isitsecure.engine.shared.progress import emit
from isitsecure.engine.shared.request_contract import (
    MAX_RETRIES_PER_PROBE,
    ContractLedger,
    contract_blocked_finding,
    probe_with_repair,
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

    def __init__(self) -> None:
        # What each endpoint's validation layer has disclosed this scan; shared by every probe
        # so a contract learned once repairs (or skips) the rest.
        self._ledger = ContractLedger()

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
        self._ledger = ContractLedger()

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

                emit(f"fuzzing body params: {req.method.upper()} {req.url}")

                params = list(body.keys())[
                    : BodyParamFuzzerConfig.MAX_PARAMS_PER_REQUEST
                ]
                from isitsecure.engine.shared.auth_headers import (
                    build_replay_headers,
                )
                headers = build_replay_headers(session, req)

                for param in params:
                    original_value = body[param]

                    # The server pins this field to a closed set: any payload dies in request
                    # validation, so skip the probes and report the field as not tested.
                    if param in self._ledger.pinned(req.method, req.url):
                        self._ledger.record_probe(
                            req.method, req.url, param, blocked=True,
                        )
                        continue

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

                # Prototype pollution (tested per-request, not per-param).
                # Unconfirmed "accepted" notes are reported once per request.
                accepted_noted = False
                for proto_key, proto_value in BodyParamFuzzerConfig.PROTOTYPE_POLLUTION_PAYLOADS:
                    f = await self._fuzz_param(
                        client, req, body, proto_key, proto_value,
                        headers, "prototype_pollution",
                    )
                    if not f:
                        continue
                    if f.severity == SeverityLevel.LOW:
                        if accepted_noted:
                            continue
                        accepted_noted = True
                    findings.append(f)

        # A rejected request is not a safe one: say which fields were never tested.
        findings.extend(
            contract_blocked_finding(
                entry,
                scanner_name=self.scanner_name,
                category=FindingCategory.INJECTION_RISK,
                source=FindingSource.DAST_AUTHENTICATED,
            )
            for entry in self._ledger.blocked()
        )

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
            probe = await probe_with_repair(
                self._sender(client, method, original_req.url, headers),
                self._ledger, method, original_req.url, fuzzed_body,
                param=param,
                # A type-confusion rejection is the behaviour under test, not a coverage gap.
                max_retries=0 if fuzz_type == "type" else MAX_RETRIES_PER_PROBE,
                track=fuzz_type != "type",
                # This scanner already replays the captured write (WRITE_METHODS); repairing
                # its siblings sends no request a plain probe would not.
                repair_writes=True,
            )
            resp, fuzzed_body = probe.response, probe.fields
            # Rejected by request validation: the payload never reached the application, so
            # the response (which may merely echo the payload) says nothing about the sink.
            if probe.blocked:
                return None
            path = urlparse(original_req.url).path

            if fuzz_type == "sqli":
                # A DB error already in the recorded (unfuzzed) response is
                # not caused by the payload.
                baseline = original_req.response_body_preview
                if self._has_sql_error(resp.text) and not self._has_sql_error(
                    baseline
                ):
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
                if resp.status_code >= 500 and original_req.response_status < 500:
                    return self._make_finding(
                        SeverityLevel.MEDIUM,
                        BodyParamFuzzerConfig.TITLE_SQL_GENERIC_CRASH.format(
                            param=param,
                        ),
                        BodyParamFuzzerConfig.DESC_SQL_GENERIC_CRASH.format(
                            param=param, method=method, path=path,
                            status=resp.status_code,
                        ),
                        BodyParamFuzzerConfig.CONFIDENCE_SQL_GENERIC_CRASH,
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
                if resp.status_code < 400:
                    # Read-back: a CLEAN follow-up request must now carry the
                    # marker, otherwise this is just an ignored unknown key.
                    follow = (await probe_with_repair(
                        self._sender(client, method, original_req.url, headers),
                        self._ledger, method, original_req.url, body,
                        max_retries=0, track=False, repair_writes=True,
                    )).response
                    marker = BodyParamFuzzerConfig.PROTOTYPE_POLLUTION_MARKER
                    if marker in follow.text:
                        return self._make_finding(
                            SeverityLevel.HIGH,
                            BodyParamFuzzerConfig.TITLE_PROTOTYPE_POLLUTION.format(
                                param=param,
                            ),
                            BodyParamFuzzerConfig.DESC_PROTOTYPE_POLLUTION.format(
                                param=param, method=method, path=path,
                            ),
                            BodyParamFuzzerConfig.CONFIDENCE_PROTOTYPE_POLLUTION,
                            original_req.url, method, follow.text,
                            json.dumps(fuzzed_body, default=str),
                        )
                    return self._make_finding(
                        SeverityLevel.LOW,
                        BodyParamFuzzerConfig.TITLE_PROTOTYPE_ACCEPTED.format(
                            param=param,
                        ),
                        BodyParamFuzzerConfig.DESC_PROTOTYPE_ACCEPTED.format(
                            param=param, method=method, path=path,
                        ),
                        BodyParamFuzzerConfig.CONFIDENCE_PROTOTYPE_ACCEPTED,
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

    @staticmethod
    def _sender(
        client: RateLimitedClient, method: str, url: str, headers: dict[str, str],
    ):
        """The ``send`` callback ``probe_with_repair`` drives: the content type follows the
        encoding the endpoint turned out to demand."""
        async def send(content: str, content_type: str):
            return await client.request(
                method, url,
                headers={**headers, "Content-Type": content_type},
                content=content,
            )
        return send

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
