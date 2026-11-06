"""Scanner hooks for request contracts: a rejected probe is repaired and retried so it reaches
the sink; one that stays rejected is reported as not tested, never as safe."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.enums import AuthProvider, EndpointMethod, SeverityLevel
from isitsecure.engine.models import DiscoveredEndpoint, InterceptedRequest
from isitsecure.engine.scanners.body_param_fuzzer import BodyParamFuzzer
from isitsecure.engine.scanners.mass_assignment_scanner import MassAssignmentScanner
from isitsecure.engine.shared.request_contract import (
    MAX_RETRIES_PER_ENDPOINT,
    PROBE_MARKER,
    TITLE_CONTRACT_BLOCKED,
)

URL = "https://example.com/api/notes"


def _resp(status: int, body) -> httpx.Response:
    text = body if isinstance(body, str) else json.dumps(body)
    return httpx.Response(status, text=text, headers={"content-type": "application/json"},
                          request=httpx.Request("POST", URL))


def _missing(name: str) -> httpx.Response:
    return _resp(422, {"detail": [{"loc": ["body", name], "msg": "field required",
                                   "type": "value_error.missing"}]})


def _blocked(findings):
    return [f for f in findings if f.title == TITLE_CONTRACT_BLOCKED]


async def _fuzz(handler, body='{"text": "hello"}'):
    client = AsyncMock()
    client.request = handler
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    req = InterceptedRequest(url=URL, method="POST", response_status=201, request_body=body)
    session = AuthSession(user_id="u", access_token="t", provider=AuthProvider.SUPABASE)
    with patch("isitsecure.engine.scanners.body_param_fuzzer.RateLimitedClient",
               return_value=client):
        return await BodyParamFuzzer().scan([req], session)


class TestBodyParamFuzzerContracts:
    @pytest.mark.asyncio
    async def test_probe_repaired_then_reaches_sink(self):
        """The server demands an extra field the recorded body lacked; without the repair every
        payload dies at validation and the SQL error behind it is never seen."""
        sunk: list[str] = []

        async def handler(method, url, **kw):
            data = json.loads(kw["content"])
            if "csrf_token" not in data:
                return _missing("csrf_token")
            if "'" in str(data.get("text")):
                sunk.append(data["text"])
                return _resp(500, "psycopg2.errors.SyntaxError: syntax error at or near \"'\"")
            return _resp(200, {"ok": True})

        findings = await _fuzz(handler)
        assert sunk, "payloads never reached the sink"
        assert [f for f in findings if f.severity == SeverityLevel.CRITICAL
                and "SQL" in f.title]
        assert not _blocked(findings)

    @pytest.mark.asyncio
    async def test_still_rejected_is_contract_blocked_not_safe(self):
        async def handler(method, url, **kw):
            return _resp(422, {"detail": [{"loc": ["body", "text"],
                                           "msg": "String should match pattern '^[a-z ]+$'",
                                           "type": "string_pattern_mismatch"}]})

        findings = await _fuzz(handler)
        notes = _blocked(findings)
        assert len(notes) == 1
        assert notes[0].severity == SeverityLevel.INFO
        assert "'text'" in notes[0].description and "NOT tested" in notes[0].description
        assert not [f for f in findings if f.severity != SeverityLevel.INFO]

    @pytest.mark.asyncio
    async def test_rejection_that_echoes_payload_is_not_reflected_xss(self):
        """A 422 that quotes the rejected input is not a reflection at the sink."""
        async def handler(method, url, **kw):
            sent = json.loads(kw["content"])["text"]
            return _resp(422, {"detail": [{"loc": ["body", "text"],
                                           "msg": "String should match pattern '^[a-z ]+$'",
                                           "type": "string_pattern_mismatch",
                                           "input": sent}]})

        findings = await _fuzz(handler)
        assert not [f for f in findings if "xss" in f.title.lower()
                    or "cross-site" in f.title.lower()]

    @pytest.mark.asyncio
    async def test_pinned_field_skipped_after_contract_learned(self):
        async def handler(method, url, **kw):
            data = json.loads(kw["content"])
            if data.get("kind") != "user":
                return _resp(422, {"detail": [{"loc": ["body", "kind"],
                                               "msg": "Input should be 'user'",
                                               "type": "literal_error"}]})
            return _resp(200, {"ok": True})

        findings = await _fuzz(handler, '{"kind": "user", "text": "hello"}')
        notes = _blocked(findings)
        assert notes and "'kind'" in notes[0].description

    @pytest.mark.asyncio
    async def test_request_volume_is_bounded(self):
        calls = 0

        async def handler(method, url, **kw):
            nonlocal calls
            calls += 1
            return _resp(422, {"errors": {f"f{calls}": ["is required"]}})

        await _fuzz(handler)
        # 1 field x (3 sqli + 2 xss + 7 type + 3 proto) = 15 first attempts, plus exactly the
        # per-endpoint retry budget (6), however many new fields the server keeps demanding.
        assert calls == 15 + MAX_RETRIES_PER_ENDPOINT

    @pytest.mark.asyncio
    async def test_misparsed_pin_does_not_skip_a_real_field(self):
        """DRF's "is not a valid choice" quotes the value we sent; it must not pin the field and
        silently drop every probe for it."""
        calls = 0

        async def handler(method, url, **kw):
            nonlocal calls
            calls += 1
            return _resp(400, {"role": [f'"{json.loads(kw["content"])["role"]}" is not a '
                                        "valid choice."]})

        findings = await _fuzz(handler, '{"role": "user"}')
        assert calls == 15          # every probe sent once, none skipped, none retried
        assert not _blocked(findings)

    @pytest.mark.asyncio
    async def test_415_switches_to_form_encoding(self):
        seen: list[str] = []

        async def handler(method, url, **kw):
            ctype = kw["headers"]["Content-Type"]
            seen.append(ctype)
            if ctype == "application/json":
                return _resp(415, "Unsupported Media Type")
            if "%27" in kw["content"] or "'" in kw["content"]:
                return _resp(500, "SQLSTATE[42000]: Syntax error or access violation")
            return _resp(200, "ok")

        findings = await _fuzz(handler)
        assert "application/x-www-form-urlencoded" in seen
        assert [f for f in findings if "SQL" in f.title]


EP = DiscoveredEndpoint(url="https://example.com/api/users", method=EndpointMethod.POST)


async def _mass(handler):
    with patch(
        "isitsecure.engine.scanners.mass_assignment_scanner.RateLimitedClient"
    ) as MockClient:
        client = AsyncMock()
        client.request = handler
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        return await MassAssignmentScanner().scan([EP])


class TestMassAssignmentContracts:
    @pytest.mark.asyncio
    async def test_repaired_probe_reaches_handler(self):
        """Strict API: needs 'email'. The bare {"role": "admin"} probe is rejected; the
        repaired one reaches the handler, which persists the privileged field."""
        async def handler(method, url, **kw):
            data = json.loads(kw["content"])
            if "email" not in data:
                return _resp(422, {"errors": {"email": ["can't be blank"]}})
            return _resp(201, {"id": 1, **data})

        findings = await _mass(handler)
        hits = [f for f in findings if f.title != TITLE_CONTRACT_BLOCKED]
        assert hits, "repaired probes never reached the handler"
        assert any('"role"' in (f.request_payload or "") and '"email"' in f.request_payload
                   for f in hits)
        assert not _blocked(findings)
        # The invented value is recognisable, so junk rows a repaired write leaves are findable.
        assert all(f'"email": "{PROBE_MARKER}"' in (f.request_payload or "") for f in hits)

    @pytest.mark.asyncio
    async def test_unsatisfiable_contract_is_blocked_not_clean(self):
        """The server pins `role` to a closed set that excludes the probe value: the 'role'
        probe can never reach the handler, which must be said, not read as 'not vulnerable'."""
        async def handler(method, url, **kw):
            if json.loads(kw["content"]).get("role") not in ("user", "guest"):
                return _resp(422, {"errors": {"role": ["must be one of: 'user', 'guest'"]}})
            return _resp(200, {"ok": True})

        findings = await _mass(handler)
        notes = _blocked(findings)
        assert len(notes) == 1 and "'role'" in notes[0].description
        assert "'is_admin'" not in notes[0].description   # repaired probes did reach the handler
        assert all(f.severity == SeverityLevel.INFO for f in findings)

    @pytest.mark.asyncio
    async def test_plain_rejection_without_contract_unchanged(self):
        """A 400 that names no field is the application's answer: no retries, no note."""
        calls = 0

        async def handler(method, url, **kw):
            nonlocal calls
            calls += 1
            return _resp(400, {"message": "bad request"})

        findings = await _mass(handler)
        assert findings == []
        assert calls == 1 + len(MassAssignmentScanner_fields())


def MassAssignmentScanner_fields():
    from isitsecure.engine.constants import MassAssignmentConfig
    return MassAssignmentConfig.ESCALATION_FIELDS


def test_blocked_note_appears_in_html_report():
    """The INFO coverage note is only useful if a reader can see it."""
    from isitsecure.engine.enums import FindingCategory
    from isitsecure.engine.models import DeepScanReport, FindingSource
    from isitsecure.engine.reporting.html_renderer import HTMLReportRenderer
    from isitsecure.engine.reporting.report_generator import ReportGenerator
    from isitsecure.engine.shared.request_contract import (
        ContractLedger,
        contract_blocked_finding,
    )

    ledger = ContractLedger()
    ledger.record_probe("POST", URL, "text", blocked=True)
    finding = contract_blocked_finding(
        ledger.blocked()[0], scanner_name="body_param_fuzzer",
        category=FindingCategory.INJECTION_RISK, source=FindingSource.DAST_AUTHENTICATED)
    report = DeepScanReport(target_url="https://example.com", findings=[finding])
    html = HTMLReportRenderer().render(ReportGenerator().generate(report))
    assert "blocked by request validation" in html
