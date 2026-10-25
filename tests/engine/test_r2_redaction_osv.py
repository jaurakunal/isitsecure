"""R3: redaction completeness and OSV record handling."""

import json
import logging
import time

import httpx
import pytest
import respx

from isitsecure.engine.code_analysis import osv_enrichment
from isitsecure.engine.code_analysis.dependency_scanner import DependencyScanner
from isitsecure.engine.code_analysis.osv_dependency_scanner import OSVDependencyScanner
from isitsecure.engine.code_analysis.osv_enrichment import (
    fetch_vuln_details,
    fixed_version_from_osv,
    severity_from_osv,
)
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.enums import BackendType, FrameworkType, SeverityLevel
from isitsecure.engine.scanners.endpoint_discovery import EndpointDiscoveryScanner
from isitsecure.engine.shared.probe_capture import (
    build_probe_capture,
    redact_body,
    redact_url,
    sanitize_headers,
)

BATCH_URL = "https://api.osv.dev/v1/querybatch"


# ----------------------------------------------------------------------
# Redaction
# ----------------------------------------------------------------------

class TestRedactBody:
    @pytest.mark.parametrize("key", [
        "newPassword", "userToken", "api-key", "apiKey", "pwd", "user_password",
        "private_key", "PrivateKey", "client_secret", "Authorization", "sessionId",
        "passphrase", "x-jwt", "signature", "credentials",
    ])
    def test_json_key_variants_redacted(self, key):
        out = redact_body(json.dumps({key: "S3CRET", "name": "bob"}))
        assert "S3CRET" not in out
        assert '"name": "bob"' in out

    def test_nested_object_value_redacted_and_json_valid(self):
        out = redact_body('{"token": {"value": "SECRETVAL", "ttl": 5}, "ok": 1}')
        assert "SECRETVAL" not in out
        assert json.loads(out) == {"token": "[REDACTED]", "ok": 1}

    def test_arrays_and_non_string_values(self):
        out = redact_body('{"items": [{"password": 12345, "n": "x"}], "secret": [1, 2, "tail"]}')
        assert "12345" not in out and "tail" not in out
        assert json.loads(out)["items"][0]["n"] == "x"

    def test_top_level_array(self):
        out = redact_body('[{"token": "T0K"}, {"id": 3}]')
        assert "T0K" not in out and '"id": 3' in out

    def test_json_embedded_in_string(self):
        out = redact_body(json.dumps({"payload": json.dumps({"password": "inner-pw", "a": 1})}))
        assert "inner-pw" not in out

    def test_truncated_json_with_nested_object(self):
        out = redact_body('{"token": {"value": "SECRETVAL"}, "name": "x", "refresh_token": "abc')
        assert "SECRETVAL" not in out
        assert '"name": "x"' in out
        assert "abc" not in out

    @pytest.mark.parametrize("text,secret", [
        ("api-key=ABCDEF123&x=1", "ABCDEF123"),
        ("x-api-key: ABCDEF123", "ABCDEF123"),
        ("pwd=ABCDEF123", "ABCDEF123"),
        ("user_password=ABCDEF123", "ABCDEF123"),
        ("private_key: ABCDEF123", "ABCDEF123"),
        ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA"),
        ("password=hello world", "world"),
        ("password=hello world&user=bob", "world"),
        ("newPassword=ABCDEF123", "ABCDEF123"),
        ("password='two words'", "words"),
        ('password="two words" tail', "words"),
    ])
    def test_text_forms(self, text, secret):
        assert secret not in redact_body(text)

    def test_text_keeps_boundaries(self):
        out = redact_body("password=hello world&user=bob&n=2")
        assert "user=bob" in out and "n=2" in out
        out = redact_body("password=hunter2\nnext line stays")
        assert "next line stays" in out

    def test_non_secret_fields_intact(self):
        body = '{"email": "a@b.c", "id": 7, "tags": ["x"], "msg": "hello"}'
        assert json.loads(redact_body(body)) == json.loads(body)
        assert redact_body("user=bob&page=2") == "user=bob&page=2"

    def test_userinfo_in_text(self):
        assert "hunter2" not in redact_body("connect to postgres://admin:hunter2@db/x now")

    @pytest.mark.parametrize("body", [
        '"' * 10**6, "token=" * 170000, '"token":[' * 100000, "[" * 10**6,
        "password " * 130000, "a:" * 500000, "a" + " " * 10**6 + "b",
        '{"a":' * 100000, 'password="' + "\\" * 10**6,
    ])
    def test_one_megabyte_adversarial_bodies_are_fast(self, body):
        start = time.perf_counter()
        redact_body(body)
        assert time.perf_counter() - start < 1.0


class TestRedactUrlsAndHeaders:
    def test_url_query_and_userinfo(self):
        out = redact_url("https://bob:pw123@h.test/x?access_token=TOK&api_key=K&page=2#id_token=ID")
        for secret in ("pw123", "TOK", "=K&", "=ID"):
            assert secret not in out
        assert "page=2" in out and "h.test/x" in out

    def test_probe_capture_url_and_curl_redacted(self):
        cap = build_probe_capture(
            "GET", "http://h.test/a?access_token=TOK123&q=1", {}, "",
            302, {"Location": "http://h.test/cb?token=LOC456&x=1"}, "", 1.0, "t",
        )
        dumped = cap.model_dump_json()
        assert "TOK123" not in dumped and "LOC456" not in dumped
        assert "q=1" in cap.request_url and "x=1" in cap.response_headers["Location"]
        assert "TOK123" not in cap.curl_command

    def test_non_secret_headers_untouched(self):
        out = sanitize_headers({"Content-Type": "text/html", "Location": "/home?x=1"})
        assert out == {"Content-Type": "text/html", "Location": "/home?x=1"}


def test_endpoint_discovery_log_does_not_print_key(caplog):
    key = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.c2lnbmF0dXJl"
    with caplog.at_level(logging.INFO):
        found = EndpointDiscoveryScanner()._discover_supabase_anon_key(f'k="{key}"')
    assert found == key
    assert "eyJ" not in caplog.text and key[:10] not in caplog.text


# ----------------------------------------------------------------------
# fixed_version_from_osv
# ----------------------------------------------------------------------

def _affected(name, ranges, eco="npm"):
    return {"package": {"name": name, "ecosystem": eco}, "ranges": ranges}


class TestFixedVersion:
    def test_git_range_commit_sha_never_returned(self):
        vuln = {"affected": [_affected("foo", [{
            "type": "GIT", "events": [{"introduced": "0"}, {"fixed": "3f9a" * 10}],
        }])]}
        assert fixed_version_from_osv(vuln, "foo", "npm", "1.0.0") is None
        assert fixed_version_from_osv(vuln) is None

    def test_sha_in_ecosystem_range_ignored(self):
        vuln = {"affected": [_affected("foo", [{
            "type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "a" * 40}],
        }])]}
        assert fixed_version_from_osv(vuln, "foo", "npm", "1.0.0") is None

    def test_other_package_ignored(self):
        vuln = {"affected": [
            _affected("bar", [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]),
            _affected("foo", [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]),
        ]}
        assert fixed_version_from_osv(vuln, "foo", "npm", "1.0.0") == "1.2.3"
        assert fixed_version_from_osv(vuln, "baz", "npm", "1.0.0") is None

    def test_other_ecosystem_ignored(self):
        vuln = {"affected": [_affected("foo", [
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.0"}]}
        ], eco="PyPI")]}
        assert fixed_version_from_osv(vuln, "foo", "npm", "1.0") is None

    MULTI = {"affected": [_affected("foo", [{"type": "SEMVER", "events": [
        {"introduced": "0"}, {"fixed": "1.5.0"}, {"introduced": "2.0.0"}, {"fixed": "2.3.1"},
    ]}])]}

    def test_multi_branch_picks_range_containing_installed(self):
        assert fixed_version_from_osv(self.MULTI, "foo", "npm", "1.2.0") == "1.5.0"
        assert fixed_version_from_osv(self.MULTI, "foo", "npm", "2.1.0") == "2.3.1"

    def test_installed_outside_ranges_takes_smallest_greater_fix(self):
        assert fixed_version_from_osv(self.MULTI, "foo", "npm", "1.7.0") == "2.3.1"

    def test_installed_already_fixed_omits_version(self):
        assert fixed_version_from_osv(self.MULTI, "foo", "npm", "3.0.0") is None

    def test_unknown_installed_with_ambiguous_fixes_omits(self):
        assert fixed_version_from_osv(self.MULTI, "foo", "npm") is None

    def test_numeric_not_lexical_ordering(self):
        vuln = {"affected": [_affected("foo", [{"type": "SEMVER", "events": [
            {"introduced": "0"}, {"fixed": "1.10.0"}]}])]}
        assert fixed_version_from_osv(vuln, "foo", "npm", "1.9.0") == "1.10.0"
        assert fixed_version_from_osv(vuln, "foo", "npm", "1.11.0") is None


# ----------------------------------------------------------------------
# Severity notes, cap, unchecked packages
# ----------------------------------------------------------------------

class TestSeverityAndCap:
    def test_cvss4_logged_once_and_defaults_medium(self, caplog, monkeypatch):
        monkeypatch.setattr(osv_enrichment, "_v4_noted", False)
        vuln = {"severity": [{
            "type": "CVSS_V4",
            "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        }]}
        with caplog.at_level(logging.INFO):
            assert severity_from_osv(vuln) == SeverityLevel.MEDIUM
            assert severity_from_osv(vuln) == SeverityLevel.MEDIUM
        assert sum("CVSS 4.0" in r.getMessage() for r in caplog.records) == 1

    @respx.mock
    async def test_detail_cap_reports_unenriched_count(self, caplog):
        ids = [f"GHSA-{i}" for i in range(osv_enrichment.MAX_DETAIL_IDS + 5)]
        respx.get(url__regex=r"https://api\.osv\.dev/v1/vulns/.*").mock(
            return_value=httpx.Response(200, json={"id": "x"})
        )
        async with httpx.AsyncClient() as client:
            with caplog.at_level(logging.WARNING):
                records, failed = await fetch_vuln_details(client, ids)
        assert failed == 5 and len(records) == osv_enrichment.MAX_DETAIL_IDS
        assert "5 not enriched" in caplog.text
        assert "5 vulnerability record(s) were not enriched" in osv_enrichment.unenriched_message(5)


def _snapshot(files, package_json=None):
    return RepoSnapshot(
        repo_url="t", branch="main", commit_hash="a", clone_path="/tmp/t",
        framework=FrameworkType.UNKNOWN, backend=BackendType.UNKNOWN,
        file_index=files, total_files=len(files), package_json=package_json or {},
    )


class TestUncheckedPackages:
    @respx.mock
    async def test_osv_scanner_counts_and_resets(self):
        route = respx.post(BATCH_URL).mock(return_value=httpx.Response(503))
        scanner = OSVDependencyScanner()
        assert scanner.unchecked_packages == 0
        await scanner.scan(_snapshot({"requirements.txt": "django==3.2.0\nflask==1.0.0\n"}))
        assert scanner.unchecked_packages == 2
        route.mock(return_value=httpx.Response(200, json={"results": [{}]}))
        await scanner.scan(_snapshot({"requirements.txt": "django==3.2.0\n"}))
        assert scanner.unchecked_packages == 0
        route.mock(return_value=httpx.Response(503))
        await scanner.scan(_snapshot({"requirements.txt": "django==3.2.0\n"}))
        assert scanner.unchecked_packages == 1
        await scanner.scan(_snapshot({}))  # no deps: still reset
        assert scanner.unchecked_packages == 0

    @respx.mock
    async def test_npm_scanner_counts_and_resets(self):
        route = respx.post(BATCH_URL).mock(return_value=httpx.Response(503))
        scanner = DependencyScanner()
        pj = {"dependencies": {"lodash": "4.17.0", "left-pad": "1.0.0"}}
        await scanner.scan(_snapshot({}, package_json=pj))
        assert scanner.unchecked_packages == 2
        route.mock(return_value=httpx.Response(200, json={"results": [{}, {}]}))
        await scanner.scan(_snapshot({}, package_json=pj))
        assert scanner.unchecked_packages == 0

    @respx.mock
    async def test_fix_suggestion_uses_matching_package_and_installed(self):
        respx.post(BATCH_URL).mock(return_value=httpx.Response(
            200, json={"results": [{"vulns": [{"id": "GHSA-9", "modified": "x"}]}]}))
        record = {"id": "GHSA-9", "summary": "s", "affected": [
            _affected("lodash", [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "ab" * 20}]}]),
            _affected("lodash", [{"type": "SEMVER", "events": [
                {"introduced": "0"}, {"fixed": "4.17.21"}]}]),
        ]}
        respx.get("https://api.osv.dev/v1/vulns/GHSA-9").mock(
            return_value=httpx.Response(200, json=record))
        findings = await DependencyScanner().scan(
            _snapshot({}, package_json={"dependencies": {"lodash": "4.17.0"}}))
        assert findings[0].fix_suggestion == "Upgrade lodash to 4.17.21 or later"
