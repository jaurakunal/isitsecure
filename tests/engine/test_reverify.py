"""Tests for per-finding re-verification (#53)."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from isitsecure.engine import reverify as R
from isitsecure.engine.enums import EndpointMethod, FindingCategory, SeverityLevel
from isitsecure.engine.models import CodeLocation, DeepFinding, FindingSource


def _dast(url="http://x/login", method="GET", payload="q='",
          scanner="active_injection_scanner", title="SQL injection vulnerability (error-based)"):
    return DeepFinding(
        source=FindingSource.DAST_URL, category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.CRITICAL, title=title, description="d", confidence=0.9,
        scanner_name=scanner, endpoint_url=url, http_method=method, request_payload=payload,
    )


def _sast(file_path="app/db.py", scanner="semgrep_taint", title="SQLi"):
    return DeepFinding(
        source=FindingSource.SAST_CODE, category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.HIGH, title=title, description="d", confidence=0.9,
        scanner_name=scanner, code_location=CodeLocation(file_path=file_path, line_number=10),
    )


def _llm():
    return DeepFinding(
        source=FindingSource.SAST_CODE, category=FindingCategory.BUSINESS_LOGIC,
        severity=SeverityLevel.HIGH, title="Logic flaw", description="d", confidence=0.7,
        scanner_name="llm_code_reviewer", code_location=CodeLocation(file_path="a.py"),
    )


class TestHelpers:
    def test_param_names_from_form_payload(self):
        assert R._param_names_from_payload("username=' OR 1=1") == ["username"]

    def test_param_names_from_json_payload(self):
        assert R._param_names_from_payload('{"user": "x", "pw": "y"}') == ["user", "pw"]

    def test_param_names_from_empty_or_bad(self):
        assert R._param_names_from_payload(None) == []
        assert R._param_names_from_payload("{not json") == []

    def test_endpoint_rebased_onto_target(self):
        ep = R._endpoint_for(_dast(url="http://old:9999/login?x=1"),
                             "https://prod.example.com", ["q"])
        assert ep.url == "https://prod.example.com/login?x=1"
        assert ep.method == EndpointMethod.GET
        assert ep.query_param_names == ["q"]

    def test_param_recovery_rejects_raw_injection_payload(self):
        # A raw injection value is NOT a parameter name.
        assert R._param_names_from_payload("' OR 1=1") == []
        assert R._param_names_from_payload("<canary_xss_abc>") == []
        assert R._param_names_from_payload("<?xml version='1.0'?>") == []


class TestDASTReverify:
    @pytest.mark.asyncio
    async def test_still_present_when_scanner_reraises(self):
        f = _dast()
        scanner = type("S", (), {
            "scanner_name": "active_injection_scanner",
            "scan": AsyncMock(return_value=[_dast(url="http://prod/login")]),  # same fp
        })()
        v = await R._reverify_dast(f, "http://prod", {"active_injection_scanner": scanner})
        assert v.status == R.VerifyStatus.STILL_PRESENT

    @pytest.mark.asyncio
    async def test_fixed_when_scanner_finds_nothing(self):
        f = _dast()
        scanner = type("S", (), {"scanner_name": "active_injection_scanner",
                                 "scan": AsyncMock(return_value=[])})()
        v = await R._reverify_dast(f, "http://prod", {"active_injection_scanner": scanner})
        assert v.status == R.VerifyStatus.FIXED

    @pytest.mark.asyncio
    async def test_scanner_error_is_a_verdict_not_a_crash(self):
        f = _dast()
        scanner = type("S", (), {"scanner_name": "active_injection_scanner",
                                 "scan": AsyncMock(side_effect=RuntimeError("boom"))})()
        v = await R._reverify_dast(f, "http://prod", {"active_injection_scanner": scanner})
        assert v.status == R.VerifyStatus.ERROR

    @pytest.mark.asyncio
    async def test_unknown_scanner_is_unverifiable(self):
        f = _dast(scanner="idor_scanner")
        v = await R._reverify_dast(f, "http://prod", {})
        assert v.status == R.VerifyStatus.UNVERIFIABLE

    @pytest.mark.asyncio
    async def test_lossy_param_recovery_is_unverifiable_not_false_fixed(self):
        """SSTI-style: a param-level scanner whose payload doesn't encode the
        param must NOT be reported FIXED just because a lossy re-probe found
        nothing — it's UNVERIFIABLE. (The core safety property.)"""
        f = _dast(scanner="active_injection_scanner", payload=None)  # no param
        scanner = type("S", (), {"scanner_name": "active_injection_scanner",
                                 "scan": AsyncMock(return_value=[])})()
        v = await R._reverify_dast(f, "http://prod", {"active_injection_scanner": scanner})
        assert v.status == R.VerifyStatus.UNVERIFIABLE
        scanner.scan.assert_not_called()  # never even ran a lossy probe

    @pytest.mark.asyncio
    async def test_xss_finding_is_unverifiable_not_false_fixed(self):
        """XSS (raw canary / multi-request stored flow) is not single-endpoint
        reproducible → UNVERIFIABLE, never a false FIXED."""
        f = _dast(scanner="xss_scanner", payload="<canary>", title="Reflected XSS")
        scanner = type("S", (), {"scanner_name": "xss_scanner",
                                 "scan": AsyncMock(return_value=[])})()
        v = await R._reverify_dast(f, "http://prod", {"xss_scanner": scanner})
        assert v.status == R.VerifyStatus.UNVERIFIABLE
        scanner.scan.assert_not_called()

    @pytest.mark.asyncio
    async def test_endpoint_level_scanner_needs_no_param(self):
        """An endpoint-level finding (e.g. missing security headers) is
        reproducible from URL+method alone — no param required."""
        f = _dast(scanner="security_headers_scanner", payload=None,
                  title="Missing security headers")
        scanner = type("S", (), {"scanner_name": "security_headers_scanner",
                                 "scan": AsyncMock(return_value=[f])})()
        v = await R._reverify_dast(f, "http://prod", {"security_headers_scanner": scanner})
        assert v.status == R.VerifyStatus.STILL_PRESENT


class TestReverifyFindings:
    @pytest.mark.asyncio
    async def test_llm_finding_is_unverifiable(self):
        (v,) = await R.reverify_findings([_llm()], target_url="http://x", repo_path="repo")
        assert v.status == R.VerifyStatus.UNVERIFIABLE

    @pytest.mark.asyncio
    async def test_dast_without_target_is_unverifiable(self):
        (v,) = await R.reverify_findings([_dast()], target_url=None)
        assert v.status == R.VerifyStatus.UNVERIFIABLE

    @pytest.mark.asyncio
    async def test_sast_without_repo_is_unverifiable(self):
        (v,) = await R.reverify_findings([_sast()], repo_path=None)
        assert v.status == R.VerifyStatus.UNVERIFIABLE

    @pytest.mark.asyncio
    async def test_sast_fixed_and_still_present(self, monkeypatch):
        present, gone = _sast(file_path="present.py"), _sast(file_path="gone.py")

        async def fake_present(_repo):
            return {present.fingerprint}  # only 'present' still detected
        monkeypatch.setattr(R, "_sast_present_fingerprints", fake_present)

        verdicts = await R.reverify_findings([present, gone], repo_path="repo")
        by_fp = {v.finding.fingerprint: v.status for v in verdicts}
        assert by_fp[present.fingerprint] == R.VerifyStatus.STILL_PRESENT
        assert by_fp[gone.fingerprint] == R.VerifyStatus.FIXED

    @pytest.mark.asyncio
    async def test_preserves_input_order(self):
        a, b, c = _dast(url="http://x/a"), _llm(), _dast(url="http://x/c")
        verdicts = await R.reverify_findings([a, b, c])  # no target → all unverifiable
        assert [v.finding.id for v in verdicts] == [a.id, b.id, c.id]
