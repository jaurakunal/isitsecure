"""Secret redaction in probe captures / auth-bypass evidence, and OSV detail enrichment."""

import logging

import httpx
import pytest
import respx

from isitsecure.engine.code_analysis.dependency_scanner import (
    DependencyScanner,
    _cvss_to_severity,
)
from isitsecure.engine.code_analysis.osv_dependency_scanner import OSVDependencyScanner
from isitsecure.engine.code_analysis.osv_enrichment import (
    cvss3_base_score,
    severity_from_osv,
)
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.enums import BackendType, FrameworkType, SeverityLevel
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.auth_bypass_scanner import AuthBypassScanner
from isitsecure.engine.shared.probe_capture import (
    build_probe_capture,
    mask_jwts,
    mask_token,
    sanitize_headers,
)

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVlLWhlcmU"
VECTOR_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
BATCH_URL = "https://api.osv.dev/v1/querybatch"


# ----------------------------------------------------------------------
# Probe capture redaction
# ----------------------------------------------------------------------

class TestProbeCaptureRedaction:
    def test_sensitive_headers_redacted_names_kept(self):
        out = sanitize_headers({
            "Set-Cookie": "sid=abc123secretvalue; HttpOnly",
            "Cookie": "sid=abc",
            "Authorization": "Bearer xyz",
            "Proxy-Authorization": "Basic abc",
            "X-Auth-Token": "tok",
            "X-API-Key": "k",
            "X-CSRF-Token": "c",
            "X-Session-Id": "s",
            "X-My-Secret": "z",
            "Content-Type": "application/json",
        })
        assert out["Content-Type"] == "application/json"
        for name, value in out.items():
            if name != "Content-Type":
                assert value == "...REDACTED", name
        assert set(out) >= {"Set-Cookie", "X-Auth-Token", "X-Session-Id"}

    def test_login_response_body_token_not_captured(self):
        body = (
            '{"access_token": "%s", "refresh_token": "r-secret-1", '
            '"user": {"email": "a@b.c", "id": 7}}' % JWT
        )
        cap = build_probe_capture(
            "POST", "http://x/login", {"Authorization": "Bearer " + JWT},
            '{"email":"a@b.c","password":"hunter2"}',
            200, {"Set-Cookie": "session=topsecret"}, body, 5.0, "t",
        )
        dumped = cap.model_dump_json()
        for secret in (JWT, "r-secret-1", "hunter2", "topsecret"):
            assert secret not in dumped
        assert "a@b.c" in cap.response_body  # rest of the body is kept
        assert '"id": 7' in cap.response_body

    def test_plain_text_bearer_and_kv_redacted(self):
        cap = build_probe_capture(
            "GET", "http://x", {}, "password=hunter2&user=bob",
            200, {}, "your Bearer abcdefghijklmnop1234 ok token: zzz999", 1.0, "t",
        )
        assert "hunter2" not in cap.request_body and "user=bob" in cap.request_body
        assert "abcdefghijklmnop1234" not in cap.response_body
        assert "zzz999" not in cap.response_body

    def test_mask_helpers(self):
        assert mask_token(JWT) == f"{JWT[:8]}...[len={len(JWT)}]"
        assert JWT not in mask_jwts(f"resp {JWT} end")


class TestAuthBypassEvidenceMasking:
    @respx.mock
    async def test_reset_token_leak_preview_has_no_full_jwt(self):
        respx.post("http://t.test/api/forgot-password").mock(
            return_value=httpx.Response(200, text='{"reset_token": "%s"}' % JWT)
        )
        endpoint = DiscoveredEndpoint(url="http://t.test/api/forgot-password", method="POST")
        async with httpx.AsyncClient() as client:
            finding = await AuthBypassScanner()._test_reset_token_leak(client, endpoint)
        assert finding is not None
        blob = finding.technical_detail + finding.evidence + str(finding.probe_captures)
        assert JWT not in blob
        assert JWT[:8] in finding.technical_detail


# ----------------------------------------------------------------------
# CVSS / severity
# ----------------------------------------------------------------------

class TestSeverity:
    def test_cvss_scores(self):
        assert cvss3_base_score(VECTOR_CRITICAL) == 9.8
        assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
        assert cvss3_base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 5.5
        assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
        assert cvss3_base_score("garbage") is None

    def test_vector_maps_to_severity(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": VECTOR_CRITICAL}]}
        assert severity_from_osv(vuln) == SeverityLevel.CRITICAL
        assert severity_from_osv({}) == SeverityLevel.MEDIUM

    def test_db_specific_wins(self):
        v = {"database_specific": {"severity": "LOW"},
             "severity": [{"type": "CVSS_V3", "score": VECTOR_CRITICAL}]}
        assert severity_from_osv(v) == SeverityLevel.LOW

    def test_dependency_scanner_vector_not_always_high(self):
        # was: any vector string -> HIGH immediately
        low = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
        assert _cvss_to_severity(low) == SeverityLevel.LOW.value
        assert _cvss_to_severity(VECTOR_CRITICAL) == SeverityLevel.CRITICAL.value
        assert DependencyScanner._extract_severity(
            {"severity": [{"type": "CVSS_V3", "score": low}]}
        ) == SeverityLevel.LOW.value


# ----------------------------------------------------------------------
# OSV enrichment and failure handling
# ----------------------------------------------------------------------

def _snapshot(files, package_json=None):
    return RepoSnapshot(
        repo_url="t", branch="main", commit_hash="a", clone_path="/tmp/t",
        framework=FrameworkType.UNKNOWN, backend=BackendType.UNKNOWN,
        file_index=files, total_files=len(files), package_json=package_json or {},
    )


FULL = {
    "id": "GHSA-1",
    "summary": "Bad thing",
    "aliases": ["CVE-2024-0001"],
    "severity": [{"type": "CVSS_V3", "score": VECTOR_CRITICAL}],
    "affected": [{"ranges": [{"type": "ECOSYSTEM",
                              "events": [{"introduced": "0"}, {"fixed": "2.0.1"}]}]}],
}


def _batch(*pkgs_vulns):
    return httpx.Response(200, json={"results": [
        {"vulns": [{"id": i, "modified": "x"} for i in ids]} for ids in pkgs_vulns
    ]})


class TestOSVScanner:
    @respx.mock
    async def test_success_fetches_details(self):
        respx.post(BATCH_URL).mock(return_value=_batch(["GHSA-1"]))
        route = respx.get("https://api.osv.dev/v1/vulns/GHSA-1").mock(
            return_value=httpx.Response(200, json=FULL)
        )
        findings = await OSVDependencyScanner().scan(
            _snapshot({"requirements.txt": "django==3.2.0\n"})
        )
        assert route.called
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == SeverityLevel.CRITICAL
        assert "Bad thing" in f.description
        assert f.fix_suggestion == "Upgrade django to 2.0.1 or later"

    @respx.mock
    async def test_unique_ids_fetched_once(self):
        respx.post(BATCH_URL).mock(return_value=_batch(["GHSA-1"], ["GHSA-1"]))
        route = respx.get("https://api.osv.dev/v1/vulns/GHSA-1").mock(
            return_value=httpx.Response(200, json=FULL)
        )
        await OSVDependencyScanner().scan(
            _snapshot({"requirements.txt": "django==3.2.0\nflask==1.0.0\n"})
        )
        assert route.call_count == 1

    @respx.mock
    async def test_partial_failure_keeps_finding_defaults_medium(self, caplog):
        respx.post(BATCH_URL).mock(return_value=_batch(["GHSA-1"]))
        respx.get("https://api.osv.dev/v1/vulns/GHSA-1").mock(return_value=httpx.Response(500))
        with caplog.at_level(logging.WARNING):
            findings = await OSVDependencyScanner().scan(
                _snapshot({"requirements.txt": "django==3.2.0\n"})
            )
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.MEDIUM
        assert "could not be fetched" in caplog.text

    @respx.mock
    @pytest.mark.parametrize("status", [429, 503])
    async def test_batch_http_failure_not_clean(self, status, caplog, monkeypatch):
        messages = []
        monkeypatch.setattr(
            "isitsecure.engine.code_analysis.osv_dependency_scanner.emit", messages.append
        )
        respx.post(BATCH_URL).mock(return_value=httpx.Response(status))
        with caplog.at_level(logging.WARNING):
            findings = await OSVDependencyScanner().scan(
                _snapshot({"requirements.txt": "django==3.2.0\nflask==1.0.0\n"})
            )
        assert findings == []  # nothing fabricated
        assert any("2 of 2 package(s) could not be checked" in m for m in messages)
        assert "could not be checked" in caplog.text

    @respx.mock
    async def test_total_failure_offline(self, monkeypatch):
        messages = []
        monkeypatch.setattr(
            "isitsecure.engine.code_analysis.osv_dependency_scanner.emit", messages.append
        )
        respx.post(BATCH_URL).mock(side_effect=httpx.ConnectError("offline"))
        findings = await OSVDependencyScanner().scan(
            _snapshot({"requirements.txt": "django==3.2.0\n"})
        )
        assert findings == []
        assert any("1 of 1 package(s) could not be checked" in m for m in messages)


class TestNpmDependencyScanner:
    @respx.mock
    async def test_success_enriches_and_maps_severity(self):
        respx.post(BATCH_URL).mock(return_value=_batch(["GHSA-1"]))
        respx.get("https://api.osv.dev/v1/vulns/GHSA-1").mock(
            return_value=httpx.Response(200, json=FULL)
        )
        snap = _snapshot({}, {"dependencies": {"lodash": "4.17.0"}})
        async with httpx.AsyncClient() as client:
            findings = await DependencyScanner(http_client=client).scan(snap)
        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.CRITICAL
        assert "Bad thing" in findings[0].description
        assert "2.0.1" in findings[0].fix_suggestion

    @respx.mock
    async def test_429_reports_unchecked(self, monkeypatch):
        messages = []
        monkeypatch.setattr(
            "isitsecure.engine.code_analysis.dependency_scanner.emit", messages.append
        )
        respx.post(BATCH_URL).mock(return_value=httpx.Response(429))
        snap = _snapshot({}, {"dependencies": {"lodash": "4.17.0"}})
        async with httpx.AsyncClient() as client:
            findings = await DependencyScanner(http_client=client).scan(snap)
        assert findings == []
        assert any("1 of 1 npm package(s) could not be checked" in m for m in messages)
