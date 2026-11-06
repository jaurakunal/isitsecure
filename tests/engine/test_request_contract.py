"""Request contracts: parsing per framework, repair, the ledger, and the bounded probe loop."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import FindingSource
from isitsecure.engine.shared.request_contract import (
    CONTENT_TYPE_FORM,
    CONTENT_TYPE_JSON,
    MAX_RETRIES_PER_ENDPOINT,
    TITLE_CONTRACT_BLOCKED,
    ContractLedger,
    FieldRule,
    RequestContract,
    contract_blocked_finding,
    encode_body,
    parse_validation,
    probe_with_repair,
)

URL = "https://api.example.com/v1/users/42/profile"


def _rules(body) -> dict[str, FieldRule]:
    text = body if isinstance(body, str) else json.dumps(body)
    return {r.name: r for r in parse_validation(text)}


class TestParsersPerFramework:
    def test_fastapi_pydantic_missing(self):
        rules = _rules({"detail": [
            {"loc": ["body", "email"], "msg": "field required", "type": "value_error.missing"},
            {"loc": ["body", "age"], "msg": "Field required", "type": "missing"},
        ]})
        assert rules["email"].kind == "required"
        assert rules["age"].kind == "required"

    def test_fastapi_pydantic_literal_and_pattern(self):
        rules = _rules({"detail": [
            {"loc": ["body", "grant_type"], "msg": "String should match pattern 'password'",
             "type": "string_pattern_mismatch"},
            {"loc": ["body", "kind"], "msg": "Input should be 'user' or 'admin'",
             "type": "literal_error"},
        ]})
        assert rules["grant_type"].kind == "pattern"
        assert rules["grant_type"].preferred() == "password"
        assert rules["grant_type"].pinned
        assert rules["kind"].kind == "enum"
        assert rules["kind"].values == ("user", "admin")

    def test_drf_flat_field_map(self):
        rules = _rules({"username": ["This field is required."],
                        "role": ["\"x\" is not a valid choice."]})
        assert rules["username"].kind == "required"
        assert rules["role"].kind in ("enum", "invalid")

    def test_rails_errors_dict(self):
        rules = _rules({"errors": {"email": ["can't be blank"], "name": ["is too short"]}})
        assert rules["email"].kind == "required"
        assert rules["name"].kind == "invalid"

    def test_laravel_errors_dict(self):
        rules = _rules({"message": "The given data was invalid.",
                        "errors": {"email": ["The email field is required."]}})
        assert rules["email"].kind == "required"

    def test_express_validator_list(self):
        rules = _rules({"errors": [{"param": "email", "msg": "Email is required",
                                    "location": "body"}]})
        assert rules["email"].kind == "required"

    def test_zod_issues(self):
        rules = _rules({"issues": [
            {"code": "invalid_type", "path": ["name"], "message": "Required",
             "expected": "string", "received": "undefined"},
            {"code": "invalid_literal", "path": ["type"], "message": "Invalid literal value, "
             "expected \"card\"", "expected": "card"},
            {"code": "invalid_enum_value", "path": ["plan"], "options": ["free", "pro"],
             "message": "Invalid enum value"},
        ]})
        assert rules["name"].kind == "required"
        assert rules["type"].kind == "literal" and rules["type"].values == ("card",)
        assert rules["plan"].kind == "enum" and rules["plan"].values == ("free", "pro")

    def test_spring_errors_list(self):
        rules = _rules({"status": 400, "errors": [
            {"field": "email", "defaultMessage": "must not be blank", "code": "NotBlank"}]})
        assert rules["email"].kind == "required"

    def test_aspnet_problem_details(self):
        rules = _rules({"type": "https://tools.ietf.org/html/rfc7231#section-6.5.1",
                        "title": "One or more validation errors occurred.", "status": 400,
                        "errors": {"Email": ["The Email field is required."]}})
        assert rules["Email"].kind == "required"

    def test_joi_celebrate(self):
        rules = _rules({"statusCode": 400, "validation": {"body": {
            "source": "body", "keys": ["email"], "message": "\"email\" is required"}}})
        assert rules["email"].kind == "required"

    def test_wordpress_missing_params(self):
        rules = _rules({"code": "rest_missing_callback_param",
                        "message": "Missing parameter(s): title",
                        "data": {"status": 400, "params": ["title"]}})
        assert rules["title"].kind == "required"

    def test_oauth_unsupported_grant(self):
        rules = _rules({"error": "unsupported_grant_type"})
        assert rules["grant_type"].kind == "enum"
        assert "password" in rules["grant_type"].values

    def test_plain_text_phrases(self):
        assert _rules("'username' is required")["username"].kind == "required"
        assert _rules("the email field is required.")["email"].kind == "required"
        assert _rules("mode must be one of: 'a', 'b'")["mode"].values == ("a", "b")

    def test_garbage_yields_nothing(self):
        assert parse_validation("<html>Bad Request</html>") == []
        assert parse_validation("") == []
        assert parse_validation('{"detail": "nope"}') == []


class TestRepair:
    def test_fills_required_and_pins_without_touching_keep(self):
        contract = RequestContract("POST", "/x")
        contract.note([FieldRule("name", "required"),
                       FieldRule("kind", "enum", ("user", "admin")),
                       FieldRule("target", "required")])
        out = contract.repair({"target": "' OR 1=1--", "kind": "bogus"}, keep="target")
        assert out["target"] == "' OR 1=1--"          # the payload field is never repaired
        assert out["kind"] == "user"
        assert out["name"] == "probe"

    def test_filler_and_never_removes(self):
        contract = RequestContract("POST", "/x")
        contract.note([FieldRule("email", "required")])
        out = contract.repair({"keep_me": 1}, filler=lambda n: f"{n}@x.io")
        assert out == {"keep_me": 1, "email": "email@x.io"}

    def test_pattern_without_literal_finds_a_candidate(self):
        rule = FieldRule("code", "pattern", (r"^\d+$",))
        assert rule.accepts("1") and not rule.accepts("abc")
        assert rule.preferred() == "1"
        assert not rule.pinned

    def test_rule_merge_prefers_specific(self):
        merged = FieldRule("a", "required").merge(FieldRule("a", "literal", ("x",)))
        assert merged.kind == "literal"
        both = FieldRule("a", "enum", ("x",)).merge(FieldRule("a", "enum", ("y",)))
        assert both.values == ("x", "y")


class TestLedger:
    def test_actionable_rejection_is_learned(self):
        ledger = ContractLedger()
        body = json.dumps({"detail": [{"loc": ["body", "email"], "msg": "field required",
                                       "type": "missing"}]})
        got = ledger.observe("POST", URL, 422, body, sent_body='{"x": 1}',
                             content_type="application/json")
        assert got is not None and "email" in got.rules
        assert ledger.rejections("POST", URL) == 1

    def test_complaint_about_an_acceptable_value_is_an_answer(self):
        ledger = ContractLedger()
        body = json.dumps({"errors": {"email": ["can't be blank"]}})
        assert ledger.observe("POST", URL, 422, body, sent_body='{"email": "a@b.c"}',
                             content_type="application/json") is None

    def test_non_validation_status_and_unparseable_ignored(self):
        ledger = ContractLedger()
        assert ledger.observe("POST", URL, 200, "{}") is None
        assert ledger.observe("POST", URL, 500, "boom") is None
        assert ledger.observe("POST", URL, 400, "invalid username or password") is None

    def test_path_template_collapses_ids(self):
        ledger = ContractLedger()
        ledger.observe("POST", URL, 422, json.dumps({"errors": {"a": ["is required"]}}),
                       sent_body="{}", content_type="application/json")
        assert ledger.get("POST", "https://api.example.com/v1/users/99/profile") is not None
        assert ledger.get("GET", URL) is None

    def test_415_records_other_encoding(self):
        ledger = ContractLedger()
        ledger.observe("POST", URL, 415, "", sent_body="{}", content_type="application/json")
        assert ledger.encoding("POST", URL) == "form"
        ledger.observe("POST", URL, 400, "Unsupported Content-Type: form",
                       sent_body="a=1", content_type=CONTENT_TYPE_FORM)
        assert ledger.encoding("POST", URL) == "json"

    def test_encode_body_switches(self):
        content, ctype = encode_body({"a": "x", "b": [1]}, "form")
        assert ctype == CONTENT_TYPE_FORM and "a=x" in content and "b=%5B1%5D" in content
        assert encode_body({"a": 1}) == ('{"a": 1}', CONTENT_TYPE_JSON)

    def test_pinned_and_lines(self):
        ledger = ContractLedger()
        body = json.dumps({"detail": [{"loc": ["body", "grant_type"],
                                       "msg": "String should match pattern 'password'",
                                       "type": "string_pattern_mismatch"}]})
        ledger.observe("POST", URL, 422, body, sent_body='{"grant_type": "x"}',
                       content_type="application/json")
        assert ledger.pinned("POST", URL) == {"grant_type"}
        assert any("grant_type must be 'password'" in line for line in ledger.lines())

    def test_blocked_requires_every_probe_rejected(self):
        ledger = ContractLedger()
        ledger.record_probe("POST", URL, "a", blocked=True)
        ledger.record_probe("POST", URL, "a", blocked=True)
        ledger.record_probe("POST", URL, "b", blocked=True)
        ledger.record_probe("POST", URL, "b", blocked=False)
        blocked = ledger.blocked()
        assert len(blocked) == 1 and blocked[0].params == ["a"]
        assert blocked[0].url == URL

    def test_retry_budget_per_endpoint(self):
        ledger = ContractLedger()
        assert all(ledger.take_retry("POST", URL) for _ in range(MAX_RETRIES_PER_ENDPOINT))
        assert not ledger.take_retry("POST", URL)
        assert ledger.take_retry("POST", URL + "/other")


def _resp(status: int, body) -> SimpleNamespace:
    return SimpleNamespace(status_code=status,
                           text=body if isinstance(body, str) else json.dumps(body))


class TestProbeWithRepair:
    @pytest.mark.asyncio
    async def test_rejected_then_repaired_reaches_sink(self):
        sent: list[dict] = []

        async def send(content, ctype):
            data = json.loads(content)
            sent.append(data)
            if "name" not in data:
                return _resp(422, {"detail": [{"loc": ["body", "name"], "msg": "field required",
                                               "type": "missing"}]})
            return _resp(200, {"ok": True})

        ledger = ContractLedger()
        result = await probe_with_repair(send, ledger, "POST", URL, {"q": "' OR 1=1--"},
                                         param="q")
        assert not result.blocked and result.requests == 2
        assert sent[-1] == {"q": "' OR 1=1--", "name": "probe"}
        assert result.fields == sent[-1]
        # The next probe is repaired up front: one request, no second rejection.
        again = await probe_with_repair(send, ledger, "POST", URL, {"q": "<script>"}, param="q")
        assert again.requests == 1 and not again.blocked
        assert ledger.blocked() == []

    @pytest.mark.asyncio
    async def test_still_rejected_is_blocked_and_bounded(self):
        calls = 0

        async def send(content, ctype):
            nonlocal calls
            calls += 1
            return _resp(422, {"detail": [{"loc": ["body", "q"],
                                           "msg": "String should match pattern '^[a-z]+$'",
                                           "type": "string_pattern_mismatch"}]})

        ledger = ContractLedger()
        result = await probe_with_repair(send, ledger, "POST", URL, {"q": "' OR 1=1--"},
                                         param="q")
        assert result.blocked
        assert calls <= 2   # nothing to repair outside the payload field: no pointless retries
        assert [b.params for b in ledger.blocked()] == [["q"]]

    @pytest.mark.asyncio
    async def test_retry_loop_cannot_run_away(self):
        calls = 0

        async def send(content, ctype):
            nonlocal calls
            calls += 1
            # Names a brand-new required field on every response: an endless contract.
            return _resp(422, {"errors": {f"f{calls}": ["is required"]}})

        result = await probe_with_repair(send, ContractLedger(), "POST", URL, {"q": 1},
                                         param="q", max_retries=2)
        assert result.blocked and calls == 3

    @pytest.mark.asyncio
    async def test_415_switches_encoding_once(self):
        types: list[str] = []

        async def send(content, ctype):
            types.append(ctype)
            return _resp(415, "") if ctype == CONTENT_TYPE_JSON else _resp(200, "ok")

        result = await probe_with_repair(send, ContractLedger(), "POST", URL, {"q": "x"},
                                         param="q")
        assert types == [CONTENT_TYPE_JSON, CONTENT_TYPE_FORM] and not result.blocked

    @pytest.mark.asyncio
    async def test_application_verdict_is_not_blocked(self):
        async def send(content, ctype):
            return _resp(400, {"message": "invalid username or password"})

        ledger = ContractLedger()
        result = await probe_with_repair(send, ledger, "POST", URL, {"u": "a"}, param="u")
        assert not result.blocked and result.requests == 1 and ledger.blocked() == []

    @pytest.mark.asyncio
    async def test_untracked_probe_does_not_enter_blocked_report(self):
        async def send(content, ctype):
            return _resp(422, {"errors": {"z": ["is required"]}})

        ledger = ContractLedger()
        await probe_with_repair(send, ledger, "POST", URL, {"q": 1}, param="q", max_retries=0,
                                track=False)
        assert ledger.blocked() == []


def test_blocked_finding_is_info_not_a_safe_claim():
    ledger = ContractLedger()
    ledger.observe("POST", URL, 422, json.dumps({"errors": {"name": ["is required"]}}),
                   sent_body="{}", content_type="application/json")
    ledger.record_probe("POST", URL, "q", blocked=True)
    [entry] = ledger.blocked()
    finding = contract_blocked_finding(
        entry, scanner_name="s", category=FindingCategory.INJECTION_RISK,
        source=FindingSource.DAST_URL)
    assert finding.severity == SeverityLevel.INFO
    assert finding.title == TITLE_CONTRACT_BLOCKED
    assert "NOT tested" in finding.description and "name required" in finding.description
