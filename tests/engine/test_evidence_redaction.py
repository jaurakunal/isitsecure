"""Shared evidence redaction and the baseline-vs-proof pair (#282)."""

import json
import time

import pytest

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import (
    DeepFinding,
    DeepScanReport,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.reporting.sarif_renderer import SARIFRenderer
from isitsecure.engine.scanners.active_injection_scanner import ActiveInjectionScanner
from isitsecure.engine.shared.evidence_pair import build_evidence_pair
from isitsecure.engine.shared.probe_capture import build_probe_capture
from isitsecure.engine.shared.redaction import (
    redact_finding,
    redact_headers,
    redact_report,
    redact_sample,
    redact_text,
)

# Assembled at runtime so no source line is a full JWT-shaped literal.
JWT = ".".join(["ey" + "JhbGciOiJIUzI1NiJ9", "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0",
                "c2lnbmF0dXJlLXZhbHVlLWhlcmU"])
HEX_KEY = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
B64_KEY = "dGhpcy1pcy1hLXNlY3JldC1rZXktMTIzNDU2Nzg5MA0aZ"
SECRETS = [JWT, HEX_KEY, B64_KEY, "123-45-6789", "4111 1111 1111 1111",
           "alice.smith@corp.example", "(415) 555-0134", "supersecretpw"]


class TestMaskClasses:
    def test_email_keeps_first_char_and_domain(self):
        assert redact_text("mail alice.smith@corp.example now") == "mail a***@corp.example now"

    def test_ssn_shape_preserved(self):
        assert redact_text("ssn: 123-45-6789!") == "ssn: ***-**-****!"

    def test_phone_formats(self):
        assert redact_text("call (415) 555-0134") == "call (***) ***-****"
        assert redact_text("call +1 415-555-0134") == "call +* ***-***-****"
        assert "415" not in redact_text("tel +44 20 7946 0958")

    def test_card_number(self):
        assert redact_text("pan 4111 1111 1111 1111") == "pan **** **** **** ****"

    def test_long_digit_run(self):
        assert redact_text("acct 12345678901234") == "acct **************"

    def test_jwt_shape_preserved(self):
        assert redact_text(f"token {JWT} end") == "token eyJ…[redacted JWT, 3 segments] end"

    def test_two_segment_jwt(self):
        assert "2 segments" in redact_text(
            "ey" + "JhbGciOiJub25lIn0." + "ey" + "JzdWIiOiJ4eHh4In0")

    def test_long_hex_and_base64_secret(self):
        out = redact_text(f"key={HEX_KEY} other {B64_KEY}")
        assert HEX_KEY not in out and B64_KEY not in out
        assert "[redacted token]" in out

    def test_token_inside_path_masks_only_the_secret_segment(self):
        out = redact_text(f"/api/v2/users/{B64_KEY}/profile")
        assert out == "/api/v2/users/[redacted token]/profile"

    def test_credential_key_values_in_nested_json(self):
        body = json.dumps({"user": {"name": "bob", "profile": [{"password": "supersecretpw"}]}})
        out = redact_text(body)
        assert "supersecretpw" not in out and "bob" in out

    def test_nested_json_string_values_get_pii_masks(self):
        rows = {"rows": [{"email": "bob@example.com", "ssn": "123-45-6789"}]}
        out = redact_text(json.dumps(rows))
        assert "b***@example.com" in out and "***-**-****" in out
        assert "bob@" not in out and "6789" not in out

    def test_unicode_preserved(self):
        out = redact_text("名前: 山田 mail yamada@example.jp ✓ ñandú")
        assert "名前: 山田" in out and "ñandú" in out and "yamada@" not in out

    def test_none_and_empty(self):
        assert redact_text(None) == "" and redact_text("") == ""


class TestFalsePositiveGuard:
    @pytest.mark.parametrize("text", [
        "id=550e8400-e29b-41d4-a716-446655440000",
        "2024-01-15T10:30:00.123Z",
        "created 2024-01-15 and 2024-01-16",
        "ts=1700000000 ms=1700000000123",
        "version 1.2.3 build 20240115",
        "port 8080 count 1234567 year 2025",
        "getUserProfileByAccountIdentifierFromDatabase",
        "some_really_long_snake_case_identifier_name",
        "/api/v1/users/12345/orders/67890",
        "price 1,234.56 sku AB-1234",
    ])
    def test_not_masked(self, text):
        assert redact_text(text) == text


class TestIdempotenceAndBounds:
    @pytest.mark.parametrize("text", [
        f"{JWT} alice@example.com 123-45-6789 {HEX_KEY} (415) 555-0134 12345678901234",
        json.dumps({"a": {"token": "x" * 30, "email": "z@y.com"}}),
        "plain prose with nothing to hide",
    ])
    def test_redacting_twice_is_stable(self, text):
        once = redact_text(text)
        assert redact_text(once) == once

    def test_sample_cut_happens_after_masking(self):
        out = redact_sample("x" * 290 + " " + HEX_KEY, limit=300)
        assert HEX_KEY[:6] not in out and len(out) <= 300

    @pytest.mark.parametrize("payload", [
        "a" * 1_000_000,
        "a." * 500_000,
        "a@" * 300_000,
        "1" * 1_000_000,
        "(" * 500_000,
        "-".join(["12"] * 300_000),
        "/".join(["ab"] * 400_000),
    ], ids=["word", "dots", "ats", "digits", "parens", "dashes", "slashes"])
    def test_pathological_input_is_bounded(self, payload):
        start = time.monotonic()
        redact_text(payload)
        assert time.monotonic() - start < 5


class TestHeaders:
    def test_credential_header_values_masked_names_kept(self):
        out = redact_headers({
            "Authorization": f"Bearer {JWT}", "Cookie": "sid=abc123", "Set-Cookie": "s=1; HttpOnly",
            "X-API-Key": "k-123", "apikey": "k", "Content-Type": "application/json",
            "X-Owner": "alice@example.com",
        })
        for name in ("Authorization", "Cookie", "Set-Cookie", "X-API-Key", "apikey"):
            assert out[name] == "...REDACTED"
        assert out["Content-Type"] == "application/json"
        assert out["X-Owner"] == "a***@example.com"

    def test_none(self):
        assert redact_headers(None) == {}

    def test_raw_header_lines_in_text(self):
        out = redact_text("Authorization: Bearer abcdef0123456789xyz\nHost: x.com")
        assert "abcdef0123456789xyz" not in out and "Host: x.com" in out


class TestEvidencePair:
    def test_pair_is_redacted_and_summarised(self):
        pair = build_evidence_pair(
            method="GET", url="https://t.example/api?token=abc&id=1",
            baseline_payload="id=1", baseline_status=200, baseline_body='{"email":"a@b.com"}',
            proof_payload="id=1'", proof_status=500, proof_body="SQL error near " + HEX_KEY,
        )
        assert pair.baseline.status == 200 and pair.proof.status == 500
        assert "a@b.com" not in pair.baseline.body_excerpt
        assert HEX_KEY not in pair.proof.body_excerpt
        assert "token=abc" not in pair.proof.url
        assert "HTTP 200" in pair.note and "HTTP 500" in pair.note
        assert pair.proof.body_length == len("SQL error near " + HEX_KEY)

    def test_no_control_means_no_pair(self):
        assert build_evidence_pair(
            method="GET", url="u", baseline_payload="", baseline_body="",
            proof_payload="p", proof_body="b",
        ) is None

    def test_old_report_json_without_pair_still_loads(self):
        finding = DeepFinding(
            source=FindingSource.DAST_URL, category=FindingCategory.INJECTION_RISK,
            severity=SeverityLevel.HIGH, title="t", description="d", confidence=0.5,
            scanner_name="s",
        )
        data = finding.model_dump(mode="json")
        data.pop("evidence_pair")
        assert DeepFinding.model_validate(data).evidence_pair is None


def _planted_finding() -> DeepFinding:
    leaked = (
        '{"email": "alice.smith@corp.example", "ssn": "123-45-6789", '
        '"card": "4111 1111 1111 1111", '
        f'"phone": "(415) 555-0134", "note": "{JWT}", "k": "{HEX_KEY}", "blob": "{B64_KEY}"}}'
    )
    capture = build_probe_capture(
        "GET", "https://t.example/x", {"Authorization": f"Bearer {JWT}"}, "",
        200, {"Set-Cookie": "sid=supersecretpw"}, leaked, 5.0, "test",
    )
    # Simulate a capture built by a code path that skipped the capture redactor.
    capture = capture.model_copy(update={
        "response_body": leaked, "request_headers": {"Authorization": f"Bearer {JWT}"},
        "curl_command": f"curl -H 'X-Leak: {HEX_KEY}' u",
    })
    pair = build_evidence_pair(
        method="GET", url="https://t.example/x", baseline_payload="id=1", baseline_status=200,
        baseline_body="ok", proof_payload="id=2", proof_status=200, proof_body=leaked,
    )
    return DeepFinding(
        source=FindingSource.DAST_URL, category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.HIGH, title="Exposed PII on /x",
        description=f"Leaked {leaked}", technical_detail=leaked, evidence=leaked,
        confidence=0.9, scanner_name="test", endpoint_url="https://t.example/x",
        request_payload=f"token={JWT}", response_preview=leaked, baseline_response_preview=leaked,
        probe_captures=[capture], evidence_pair=pair,
    )


class TestExports:
    def _report(self) -> DeepScanReport:
        return DeepScanReport(target_url="https://t.example", findings=[_planted_finding()])

    def _assert_clean(self, blob: str):
        for secret in SECRETS:
            assert secret not in blob, secret

    def test_json_export(self):
        from isitsecure.cli.render import _report_json
        out = _report_json(self._report())
        self._assert_clean(out)
        assert "Exposed PII on /x" in out and "***-**-****" in out

    def test_sarif_export(self):
        self._assert_clean(SARIFRenderer().render(redact_report(self._report())))

    def test_html_export(self):
        from isitsecure.cli.render import _generate_html_report
        self._assert_clean(_generate_html_report(self._report()))

    def test_every_mcp_export_format(self):
        from isitsecure.mcp_server import _render_report
        for fmt in ("json", "markdown", "sarif", "html"):
            self._assert_clean(_render_report(self._report(), fmt))

    def test_redact_finding_does_not_mutate_original_and_keeps_identity(self):
        f = _planted_finding()
        red = redact_finding(f)
        assert HEX_KEY in f.evidence
        assert HEX_KEY not in red.evidence
        assert red.fingerprint == f.fingerprint
        assert red.title == f.title

    def test_redacted_evidence_still_proves_what_was_exposed(self):
        red = redact_finding(_planted_finding())
        for marker in ("a***@corp.example", "***-**-****", "redacted JWT, 3 segments"):
            assert marker in red.evidence


class TestScannerWiring:
    def test_nosql_finding_carries_redacted_pair(self):
        scanner = ActiveInjectionScanner()
        ep = DiscoveredEndpoint(url="https://t.example/login")
        f = scanner._build_nosql_finding(
            ep, "user", '{"$ne": null}', '[{"email":"a@b.com"},{"email":"c@d.com"}]',
            "detail", baseline_body="[]", proof_status=200,
        )
        assert f.evidence_pair.baseline.body_excerpt == "[]"
        assert f.evidence_pair.proof.status == 200
        assert "a@b.com" not in f.evidence_pair.proof.body_excerpt
