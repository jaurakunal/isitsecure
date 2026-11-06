"""Review-round hardening of the shared redactor (#282): fail-closed server paths,
explain/fix, SAST snippets and pinned fingerprints, over/under-redaction rules,
and a planted-secret test per renderer and field."""

import json
import time

import pytest
from fastapi.testclient import TestClient

from isitsecure.engine.enums import FindingCategory, IDORRiskLevel, IDORTestType, SeverityLevel
from isitsecure.engine.identity import known_fingerprints, matches_any
from isitsecure.engine.models import (
    CodeLocation,
    DeepFinding,
    DeepScanReport,
    DiscoveredEndpoint,
    FindingSource,
    IDORProbeResult,
    IDORTestResult,
)
from isitsecure.engine.shared.probe_capture import redact_body
from isitsecure.engine.shared.redaction import (
    redact_code,
    redact_finding,
    redact_report,
    redact_text,
    scrub_value,
)

# Fake secrets are assembled at runtime so no source line holds a full provider pattern
# (GitHub push protection scans for them).
STRIPE = "sk_" + "live_" + "51H8abcDEFghi123456789xyz"
AWS_ID = "AK" + "IA" + "IOSFODNN7EXAMPLE"
AWS_SECRET = "wJal" + "rXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"  # noqa: S105
BEARER = "Bearer abcdef0123456789secretvalue"


def _pem(kind: str, body: str, *, closed: bool = True) -> str:
    begin = "-----" + "BEGIN " + kind + "PRIVATE KEY" + "-----"
    end = "-----" + "END " + kind + "PRIVATE KEY" + "-----"
    return f"{begin}\n{body}\n{end}" if closed else f"{begin}\n{body}"


# --------------------------------------------------------------------------- server

@pytest.fixture
def client():
    from isitsecure.server import app as srv

    srv.app.state.allowed_hosts = None
    yield TestClient(srv.app, base_url="http://localhost:3000", raise_server_exceptions=False)
    srv.app.state.allowed_hosts = None
    srv._scans.clear()


def _malformed_report() -> dict:
    # confidence=5 violates the model (le=1.0): model_validate fails for the whole report.
    return {"findings": [{
        "id": "f1", "title": "t", "description": "d", "severity": "high", "confidence": 5,
        "evidence": f"Authorization: {BEARER} key {STRIPE}",
        "request_headers": {"Authorization": BEARER, "X-Ok": "fine"},
        "probe_captures": [{"request_headers": {"Authorization": BEARER}}],
    }], "scanner_errors": [f"boom {STRIPE}"]}


class TestServerFailsClosed:
    def _arm(self, client):
        from isitsecure.server import app as srv

        srv._scans["m1"] = {"status": "complete", "report": _malformed_report(),
                            "events": [], "error": None}

    @pytest.mark.parametrize("path", [
        "/api/scan/m1/report", "/api/scan/m1/report.html", "/api/scan/m1/stream",
    ])
    def test_malformed_report_never_leaves_raw(self, client, path):
        self._arm(client)
        body = client.get(path).text
        assert "abcdef0123456789secretvalue" not in body
        assert STRIPE not in body

    def test_report_endpoint_still_returns_scrubbed_data(self, client):
        self._arm(client)
        data = client.get("/api/scan/m1/report").json()
        assert data["findings"][0]["id"] == "f1"
        assert data["findings"][0]["request_headers"]["X-Ok"] == "fine"

    def test_scrub_value_never_returns_raw(self):
        out = json.dumps(scrub_value(_malformed_report()))
        assert "abcdef0123456789secretvalue" not in out and STRIPE not in out

    def test_scrub_value_keeps_token_usage_dict_and_booleans(self):
        out = scrub_value({"token_usage": {"input_tokens": 5}, "password": None, "token": True})
        assert out == {"token_usage": {"input_tokens": 5}, "password": None, "token": True}


# --------------------------------------------------------------------- explain / fix

def _sast_finding(snippet: str | None = None) -> DeepFinding:
    snippet = snippet or f'12 |  const a = 1;\n13 >>>  const k = "{STRIPE}";\n14 |  run(k);'
    return DeepFinding(
        source=FindingSource.SAST_CODE, category=FindingCategory.EXPOSED_SECRETS,
        severity=SeverityLevel.HIGH, title="Hardcoded Stripe key",
        description=f"key {STRIPE} in source", evidence=f"{STRIPE} / mail bob@example.com",
        remediation_guidance=f"rotate {STRIPE}", confidence=0.9, scanner_name="secret_scanner",
        code_location=CodeLocation(file_path="src/pay.js", line_number=13, code_snippet=snippet),
    )


class TestExplainAndFix:
    def test_explain_is_redacted(self):
        from isitsecure.mcp_server import _finding_detail

        detail = _finding_detail(_sast_finding(), DeepScanReport())
        blob = json.dumps(detail)
        assert STRIPE not in blob and "bob@" not in blob
        assert "sk_live_[redacted token]" in blob and "b***@example.com" in blob

    def test_fix_brief_redacts_text_but_keeps_file_content_raw(self):
        from isitsecure.mcp_server import _fix_brief

        source = f'const k = "{STRIPE}";\n'
        brief = _fix_brief(_sast_finding(), source)
        assert brief["file_content"] == source
        for field in ("description", "guidance", "title"):
            assert STRIPE not in brief[field]

    def test_scan_summary_is_redacted_and_keeps_raw_fingerprint(self):
        from isitsecure.mcp_server import _trim_report

        raw = _sast_finding()
        out = _trim_report(DeepScanReport(findings=[raw]), "low", "s1")
        assert STRIPE not in json.dumps(out)
        assert out["findings"][0]["fingerprint"] == raw.fingerprint


# ----------------------------------------------------------- SAST snippet + fingerprint

class TestSnippetAndFingerprints:
    def test_snippet_secret_masked_marker_and_lines_kept(self):
        out = redact_code(_sast_finding().code_location.code_snippet)
        assert STRIPE not in out
        lines = out.splitlines()
        assert len(lines) == 3 and lines[1].startswith("13 >>>")
        assert lines[0] == "12 |  const a = 1;"

    def test_snippet_key_value_and_pem(self):
        pem = _pem("RSA ", "MIIEabc\nxyz")
        out = redact_code(f'password = "hunter2hunter2"\n{pem}\nafter')
        assert "hunter2hunter2" not in out and "MIIEabc" not in out
        assert out.endswith(_pem("RSA ", "").split("\n")[-1] + "\nafter")

    def test_exported_finding_masked_but_fingerprints_equal_raw(self):
        raw = _sast_finding()
        red = redact_finding(raw)
        assert STRIPE not in red.code_location.code_snippet
        assert red.fingerprint == raw.fingerprint
        dumped = json.loads(red.model_dump_json())
        assert dumped["fingerprint"] == raw.fingerprint

    def test_json_export_carries_raw_fingerprint_and_masks_snippet(self):
        from isitsecure.cli.render import _report_json

        raw = _sast_finding()
        data = json.loads(_report_json(DeepScanReport(findings=[raw])))
        f = data["findings"][0]
        assert STRIPE not in json.dumps(data)
        assert f["fingerprint"] == raw.fingerprint

    def test_ignore_and_baseline_matching_survive_redaction(self):
        raw = _sast_finding()
        red = redact_finding(raw)
        assert matches_any(red, known_fingerprints([raw]))
        assert matches_any(raw, known_fingerprints([red]))

    def test_sarif_legacy_fingerprint_unchanged(self):
        from isitsecure.engine.reporting.sarif_renderer import SARIFRenderer

        raw = _sast_finding()
        raw = raw.model_copy(update={"title": f"Leaked {STRIPE}"})
        def sarif_fps(report):
            result = json.loads(SARIFRenderer().render(report))["runs"][0]["results"][0]
            return result["fingerprints"]
        assert sarif_fps(redact_report(DeepScanReport(findings=[raw]))) == \
            sarif_fps(DeepScanReport(findings=[raw]))


# ------------------------------------------------------------ over-redaction (proof kept)

class TestOverRedactionRules:
    @pytest.mark.parametrize("secret,expected", [
        (STRIPE, "sk_live_[redacted token]"),
        ("sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc", "sk_test_[redacted token]"),
        ("gh" + "p_" + "16C7e42F292c6912E7710c838347Ae178B4a", "ghp_[redacted token]"),
        ("xo" + "xb-" + "123456789012-abcdefABCDEF1234", "xoxb-[redacted token]"),
        ("AI" + "za" + "SyA-1234567890abcdefghijklmnopqrstu", "AIza[redacted token]"),
        (AWS_ID, "AKIA[redacted token]"),
    ])
    def test_provider_prefix_kept(self, secret, expected):
        assert redact_text(f"found {secret} here") == f"found {expected} here"

    def test_provider_masking_is_idempotent(self):
        once = redact_text(f"{STRIPE} {AWS_ID}")
        assert redact_text(once) == once

    def test_ids_of_9_to_12_digits_survive(self):
        text = '{"orderId": 123456789, "userId": 12345678901, "amount": 987654321098}'
        out = redact_text(text)
        assert "123456789" in out and "12345678901" in out
        assert "987654321098" not in out  # 12 digits under a non-id key

    def test_id_key_exempts_any_length(self):
        assert "1234567890123456" in redact_text('{"user_id": 1234567890123456}')

    def test_grouped_ssn_card_phone_still_masked(self):
        out = redact_text("123-45-6789 4111 1111 1111 1111 (415) 555-0134")
        assert "6789" not in out and "4111" not in out and "0134" not in out

    def test_ungrouped_long_card_number_still_masked(self):
        assert "4111111111111111" not in redact_text("pan 4111111111111111")

    @pytest.mark.parametrize("label", ["commit", "sha", "revision", "build", "hash"])
    def test_labelled_git_sha_kept(self, label):
        sha = "a" * 20 + "1234567890abcdef1234"
        assert redact_text(f'{label}: {sha}') == f"{label}: {sha}"
        assert redact_text(f'"{label}":"{sha}"') == f'"{label}": "{sha}"' or sha in redact_text(
            f'"{label}":"{sha}"')

    def test_unlabelled_hex_secret_masked(self):
        key = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"
        assert key not in redact_text(f"value {key}")

    def test_token_metadata_keys_keep_their_values_and_types(self):
        body = json.dumps({"tokenCount": 5, "token_type": "bearer", "max_tokens": 100,
                           "expires_in": 3600, "token_expiry": 1700000000})
        assert json.loads(redact_body(body)) == json.loads(body)

    def test_real_credential_keys_still_masked(self):
        out = json.loads(redact_body(json.dumps(
            {"access_token": "abc123", "password": "pw", "api_key": "k", "token": "t"})))
        assert set(out.values()) == {"[REDACTED]"}

    def test_booleans_and_null_under_secret_keys_are_not_coerced(self):
        out = json.loads(redact_body('{"password": null, "token": true}'))
        assert out == {"password": None, "token": True}


# ----------------------------------------------------------- under-redaction rules

class TestUnderRedactionRules:
    def test_aws_secret_access_key_free_text(self):
        out = redact_text(f"secret is {AWS_SECRET} ok")
        assert "K7MDENG" not in out and "[redacted token]" in out

    def test_aws_secret_under_key(self):
        assert AWS_SECRET[:5] not in redact_text(f"aws_secret_access_key={AWS_SECRET}")

    def test_aws_access_key_id_standalone(self):
        assert AWS_ID not in redact_text(f"id {AWS_ID}")

    def test_forty_char_path_not_mistaken_for_aws_secret(self):
        path = "/api/v1/users/profile/settings/notifications"
        assert redact_text(path) == path

    def test_pem_block_is_one_rule(self):
        pem = _pem("", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nZm9vYmFyYmF6")
        out = redact_text(f"key:\n{pem}\nend")
        lines = _pem("", "").split("\n")
        assert out == f"key:\n{lines[0]}[redacted]{lines[-1]}\nend"
        assert redact_text(out) == out

    def test_unterminated_pem_masked_to_end(self):
        out = redact_text("x " + _pem("RSA ", "MIIEsecretsecret", closed=False))
        assert "MIIE" not in out

    def test_many_pem_headers_stay_linear(self):
        start = time.monotonic()
        redact_text(_pem("", "", closed=False).split("\n")[0] * 7000)
        assert time.monotonic() - start < 5

    def test_cookie_value_keeps_closing_quote(self):
        out = redact_text("curl -b 'sessionid=s3cr3tvalue12' https://x.example/")
        assert "s3cr3tvalue12" not in out
        assert out.endswith("' https://x.example/")
        assert out.count("'") == 2


# ---------------------------------------------- planted secrets: every renderer + field

def _full_finding() -> DeepFinding:
    leak = f"{STRIPE} {AWS_ID} {AWS_SECRET} bob@example.com"
    return DeepFinding(
        source=FindingSource.DAST_URL, category=FindingCategory.EXPOSED_SECRETS,
        severity=SeverityLevel.HIGH, title=f"Leaks {STRIPE}",
        description=leak, technical_detail=leak, evidence=leak,
        remediation_guidance=f"rotate {STRIPE}", confidence=0.9, scanner_name="t",
        endpoint_url=f"https://t.example/api?api_key={STRIPE}&page=1",
        code_location=CodeLocation(file_path="a.js", line_number=1,
                                   code_snippet=f'1 >>> k = "{STRIPE}"'),
    )


def _full_report() -> DeepScanReport:
    ep = DiscoveredEndpoint(url=f"https://t.example/x?token={STRIPE}")
    probe = IDORProbeResult(
        original_url=f"https://t.example/o?api_key={STRIPE}", probed_url="https://t.example/p",
        test_type=next(iter(IDORTestType)), original_body_preview=f"mail bob@example.com {STRIPE}",
        probed_body_preview=STRIPE,
    )
    return DeepScanReport(
        findings=[_full_finding()], scanner_errors=[f"fail {STRIPE}"],
        idor_results=[IDORTestResult(endpoint=ep, risk_level=next(iter(IDORRiskLevel)),
                                     probes=[probe], summary="ok")],
    )


@pytest.mark.parametrize("fmt", ["json", "markdown", "sarif", "html"])
def test_every_renderer_masks_every_field(fmt):
    from isitsecure.mcp_server import _render_report

    out = _render_report(_full_report(), fmt)
    for secret in (STRIPE, AWS_ID, AWS_SECRET, "bob@example.com"):
        assert secret not in out, (fmt, secret)


def test_cli_html_and_sarif_masks_every_field():
    from isitsecure.cli.render import _generate_html_report, _generate_sarif_report

    for out in (_generate_html_report(_full_report()), _generate_sarif_report(_full_report())):
        assert STRIPE not in out and AWS_ID not in out
