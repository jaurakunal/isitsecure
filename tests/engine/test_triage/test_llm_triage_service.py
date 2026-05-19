"""Tests for the LLM triage service.

Validates:
- Rule-based deduplication (pre-filter)
- SAST auto-triage (no LLM needed)
- LLM enrichment via batched calls
- Owner summary generation
- Fallback behavior when LLM fails
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from isitsecure.engine.constants import TriageConfig
from isitsecure.engine.enums import (
    ImpactCategory,
    LikelihoodLevel,
    ScanMode,
)
from isitsecure.engine.models import (
    DeepFinding,
    FindingSource,
    OwnerSummary,
)
from isitsecure.engine.triage.llm_triage_service import (
    LLMTriageService,
    TriageResult,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    finding_id: str = "finding-1",
    severity: SeverityLevel = SeverityLevel.HIGH,
    category: FindingCategory = FindingCategory.IDOR,
    title: str = "Test finding",
    description: str = "A test finding description",
    scanner_name: str = "llm_code_reviewer",
    **kwargs: object,
) -> DeepFinding:
    defaults = {
        "id": finding_id,
        "source": FindingSource.SAST_CODE,
        "category": category,
        "severity": severity,
        "title": title,
        "description": description,
        "confidence": 0.9,
        "scanner_name": scanner_name,
    }
    defaults.update(kwargs)
    return DeepFinding(**defaults)


def _build_dev_triage_response(
    triaged_findings: list[dict] | None = None,
    duplicate_ids: list[str] | None = None,
) -> str:
    return json.dumps({
        "triaged_findings": triaged_findings or [],
        "duplicate_ids": duplicate_ids or [],
    })


def _build_theme_detection_response() -> str:
    """Build a minimal theme detection LLM response."""
    return json.dumps({"themes": []})


def _build_owner_summary_response(
    grade: str = "C",
    risk_summary: str = "Moderate risk detected.",
    key_risks: list[str] | None = None,
    remediation_phases: list[dict] | None = None,
) -> str:
    return json.dumps({
        "grade": grade,
        "risk_summary": risk_summary,
        "key_risks": key_risks or ["SQL injection in login"],
        "remediation_phases": remediation_phases or [
            {"phase_number": 1, "title": "Immediate", "description": "Fix it."}
        ],
    })


def _make_service(
    responses: list[str | Exception] | str | Exception = "",
) -> tuple[LLMTriageService, AsyncMock]:
    """Create a service with a mocked LLM client.

    responses can be:
    - A single string/Exception (used for all calls)
    - A list of strings/Exceptions (used in order via side_effect)
    """
    mock_llm = AsyncMock()
    if isinstance(responses, Exception):
        mock_llm.generate_with_system.side_effect = responses
    elif isinstance(responses, list):
        mock_llm.generate_with_system.side_effect = responses
    else:
        mock_llm.generate_with_system.return_value = responses
    return LLMTriageService(mock_llm), mock_llm


# ---------------------------------------------------------------------------
# TestRuleBasedDedup
# ---------------------------------------------------------------------------

class TestRuleBasedDedup:
    """Test rule-based deduplication (pre-filter, no LLM)."""

    def test_identical_titles_keep_highest_severity(self) -> None:
        service, _ = _make_service()
        findings = [
            _make_finding(finding_id="f1", title="Missing auth", severity=SeverityLevel.MEDIUM),
            _make_finding(finding_id="f2", title="Missing auth", severity=SeverityLevel.HIGH),
        ]
        deduped, removed = service._rule_based_dedup(findings)
        assert len(deduped) == 1
        assert deduped[0].severity == SeverityLevel.HIGH
        assert removed == 1

    def test_different_titles_kept(self) -> None:
        service, _ = _make_service()
        findings = [
            _make_finding(finding_id="f1", title="Missing auth"),
            _make_finding(finding_id="f2", title="SQL injection"),
        ]
        deduped, removed = service._rule_based_dedup(findings)
        assert len(deduped) == 2
        assert removed == 0

    def test_prefers_llm_over_sast_on_tie(self) -> None:
        service, _ = _make_service()
        findings = [
            _make_finding(finding_id="sast", title="Rate limit issue",
                          scanner_name="express_middleware_analyzer"),
            _make_finding(finding_id="llm", title="Rate limit issue",
                          scanner_name="llm_code_reviewer"),
        ]
        deduped, _ = service._rule_based_dedup(findings)
        assert len(deduped) == 1
        assert deduped[0].scanner_name == "llm_code_reviewer"


# ---------------------------------------------------------------------------
# TestSASTAutoTriage
# ---------------------------------------------------------------------------

class TestSASTAutoTriage:
    """Test auto-triage for SAST findings (no LLM call needed)."""

    def test_sast_findings_get_impact_assigned(self) -> None:
        service, _ = _make_service()
        f = _make_finding(scanner_name="drizzle_schema_analyzer",
                          category=FindingCategory.EXPOSED_SECRETS)
        service._auto_triage_sast([f])
        assert f.impact == ImpactCategory.DATA_BREACH
        assert f.likelihood is not None
        assert f.priority is not None

    def test_dependency_vuln_gets_operational_impact(self) -> None:
        service, _ = _make_service()
        f = _make_finding(scanner_name="dependency_scanner",
                          category=FindingCategory.DEPENDENCY_VULNERABILITY)
        service._auto_triage_sast([f])
        assert f.impact == ImpactCategory.OPERATIONAL

    def test_sast_not_sent_to_llm(self) -> None:
        service, _ = _make_service()
        findings = [
            _make_finding(scanner_name="iac_scanner"),
            _make_finding(scanner_name="docker_scanner"),
        ]
        sast, llm = service._split_by_scanner(findings)
        assert len(sast) == 2
        assert len(llm) == 0


# ---------------------------------------------------------------------------
# TestTriageServiceBasic
# ---------------------------------------------------------------------------

class TestTriageServiceBasic:

    @pytest.mark.asyncio
    async def test_empty_findings_returns_empty(self) -> None:
        service, _ = _make_service()
        result = await service.triage([], ScanMode.CODE_ONLY)
        assert result.triaged_findings == []

    @pytest.mark.asyncio
    async def test_empty_findings_still_has_owner_summary(self) -> None:
        service, _ = _make_service()
        result = await service.triage([], ScanMode.CODE_ONLY)
        assert isinstance(result.owner_summary, OwnerSummary)
        assert result.owner_summary.grade != ""

    @pytest.mark.asyncio
    async def test_empty_findings_has_scope_disclaimer(self) -> None:
        service, _ = _make_service()
        result = await service.triage([], ScanMode.CODE_ONLY)
        expected = TriageConfig.SCOPE_DISCLAIMERS["code_only"]
        assert result.owner_summary.scope_disclaimer == expected


# ---------------------------------------------------------------------------
# TestTriageEnrichment
# ---------------------------------------------------------------------------

class TestTriageEnrichment:

    @pytest.mark.asyncio
    async def test_applies_impact_from_llm(self) -> None:
        dev_resp = _build_dev_triage_response(
            triaged_findings=[{
                "id": "f1", "impact": "financial",
                "likelihood": "actively_exploitable",
            }]
        )
        owner_resp = _build_owner_summary_response()
        service, _ = _make_service([dev_resp, _build_theme_detection_response(), owner_resp])
        finding = _make_finding(finding_id="f1")

        result = await service.triage([finding], ScanMode.CODE_ONLY)
        assert result.triaged_findings[0].impact == ImpactCategory.FINANCIAL

    @pytest.mark.asyncio
    async def test_applies_likelihood_from_llm(self) -> None:
        dev_resp = _build_dev_triage_response(
            triaged_findings=[{
                "id": "f1", "impact": "data_breach",
                "likelihood": "requires_auth",
            }]
        )
        owner_resp = _build_owner_summary_response()
        service, _ = _make_service([dev_resp, _build_theme_detection_response(), owner_resp])
        finding = _make_finding(finding_id="f1")

        result = await service.triage([finding], ScanMode.CODE_ONLY)
        assert result.triaged_findings[0].likelihood == LikelihoodLevel.REQUIRES_AUTH

    @pytest.mark.asyncio
    async def test_calculates_priority(self) -> None:
        dev_resp = _build_dev_triage_response(
            triaged_findings=[{
                "id": "f1", "impact": "financial",
                "likelihood": "actively_exploitable",
            }]
        )
        owner_resp = _build_owner_summary_response()
        service, _ = _make_service([dev_resp, _build_theme_detection_response(), owner_resp])
        finding = _make_finding(finding_id="f1")

        result = await service.triage([finding], ScanMode.CODE_ONLY)
        assert result.triaged_findings[0].priority == 1

    @pytest.mark.asyncio
    async def test_fills_remediation_guidance(self) -> None:
        dev_resp = _build_dev_triage_response(
            triaged_findings=[{
                "id": "f1", "impact": "financial",
                "likelihood": "requires_admin",
                "remediation_guidance": "Use parameterized queries.",
            }]
        )
        owner_resp = _build_owner_summary_response()
        service, _ = _make_service([dev_resp, _build_theme_detection_response(), owner_resp])
        finding = _make_finding(finding_id="f1")

        result = await service.triage([finding], ScanMode.CODE_ONLY)
        assert result.triaged_findings[0].remediation_guidance == "Use parameterized queries."

    @pytest.mark.asyncio
    async def test_severity_adjustment(self) -> None:
        dev_resp = _build_dev_triage_response(
            triaged_findings=[{
                "id": "f1", "impact": "financial",
                "likelihood": "actively_exploitable",
                "severity_adjustment": "CRITICAL",
            }]
        )
        owner_resp = _build_owner_summary_response()
        service, _ = _make_service([dev_resp, _build_theme_detection_response(), owner_resp])
        finding = _make_finding(finding_id="f1", severity=SeverityLevel.HIGH)

        result = await service.triage([finding], ScanMode.CODE_ONLY)
        assert result.triaged_findings[0].severity == SeverityLevel.CRITICAL


# ---------------------------------------------------------------------------
# TestTriageOwnerSummary
# ---------------------------------------------------------------------------

class TestTriageOwnerSummary:

    @pytest.mark.asyncio
    async def test_parses_grade(self) -> None:
        dev_resp = _build_dev_triage_response(triaged_findings=[{"id": "f1"}])
        owner_resp = _build_owner_summary_response(grade="B")
        service, _ = _make_service([dev_resp, _build_theme_detection_response(), owner_resp])
        finding = _make_finding(finding_id="f1")

        result = await service.triage([finding], ScanMode.CODE_ONLY)
        assert result.owner_summary.grade == "B"

    @pytest.mark.asyncio
    async def test_parses_key_risks(self) -> None:
        risks = ["SQL injection", "Missing CSRF"]
        dev_resp = _build_dev_triage_response(triaged_findings=[{"id": "f1"}])
        owner_resp = _build_owner_summary_response(key_risks=risks)
        service, _ = _make_service([dev_resp, _build_theme_detection_response(), owner_resp])
        finding = _make_finding(finding_id="f1")

        result = await service.triage([finding], ScanMode.CODE_ONLY)
        assert result.owner_summary.key_risks == risks

    @pytest.mark.asyncio
    async def test_includes_scope_disclaimer(self) -> None:
        dev_resp = _build_dev_triage_response(triaged_findings=[{"id": "f1"}])
        owner_resp = _build_owner_summary_response()
        service, _ = _make_service([dev_resp, _build_theme_detection_response(), owner_resp])
        finding = _make_finding(finding_id="f1")

        result = await service.triage([finding], ScanMode.CODE_ONLY)
        expected = TriageConfig.SCOPE_DISCLAIMERS["code_only"]
        assert result.owner_summary.scope_disclaimer == expected

    @pytest.mark.asyncio
    async def test_owner_summary_fallback_when_step2_fails(self) -> None:
        dev_resp = _build_dev_triage_response(
            triaged_findings=[{"id": "f1", "impact": "financial",
                               "likelihood": "actively_exploitable"}]
        )
        service, _ = _make_service([dev_resp, _build_theme_detection_response(), RuntimeError("timeout")])
        finding = _make_finding(finding_id="f1")

        result = await service.triage([finding], ScanMode.CODE_ONLY)
        assert result.triaged_findings[0].impact == ImpactCategory.FINANCIAL
        assert isinstance(result.owner_summary, OwnerSummary)
        assert result.owner_summary.grade != ""


# ---------------------------------------------------------------------------
# TestTriageFallback
# ---------------------------------------------------------------------------

class TestTriageFallback:

    @pytest.mark.asyncio
    async def test_llm_failure_returns_findings(self) -> None:
        service, _ = _make_service(RuntimeError("LLM unavailable"))
        f1 = _make_finding(finding_id="f1")
        f2 = _make_finding(finding_id="f2", title="Different issue")

        result = await service.triage([f1, f2], ScanMode.CODE_ONLY)
        assert len(result.triaged_findings) == 2

    @pytest.mark.asyncio
    async def test_llm_failure_generates_rule_based_summary(self) -> None:
        service, _ = _make_service(RuntimeError("timeout"))
        finding = _make_finding(severity=SeverityLevel.HIGH)

        result = await service.triage([finding], ScanMode.CODE_ONLY)
        assert isinstance(result.owner_summary, OwnerSummary)
        assert result.owner_summary.grade != ""

    @pytest.mark.asyncio
    async def test_fallback_grade_a_no_critical_no_high(self) -> None:
        service, _ = _make_service(RuntimeError("fail"))
        findings = [
            _make_finding(finding_id="low1", severity=SeverityLevel.LOW),
            _make_finding(finding_id="med1", severity=SeverityLevel.MEDIUM),
        ]
        result = await service.triage(findings, ScanMode.CODE_ONLY)
        assert result.owner_summary.grade == "A"

    @pytest.mark.asyncio
    async def test_fallback_grade_f_many_critical(self) -> None:
        service, _ = _make_service(RuntimeError("fail"))
        # Use truly distinct titles so dedup doesn't merge them
        crit_titles = [
            "SQL injection in login", "RCE via template engine",
            "Auth bypass in admin panel", "SSRF in image proxy",
            "Hardcoded master API key",
        ]
        high_titles = [
            "Missing CSRF token", "Open redirect in OAuth callback",
            "Insecure deserialization", "Broken access control on profile",
            "Sensitive data in error response", "XSS in comment field",
            "IDOR in purchase endpoint", "Privilege escalation via role",
            "Weak password policy", "Missing rate limiting on login",
            "Unencrypted PII in database", "Session fixation vulnerability",
            "Insecure direct object reference", "Missing input validation",
            "Unrestricted file upload",
        ]
        findings = [
            _make_finding(finding_id=f"crit{i}", severity=SeverityLevel.CRITICAL,
                          title=crit_titles[i])
            for i in range(5)
        ] + [
            _make_finding(finding_id=f"high{i}", severity=SeverityLevel.HIGH,
                          title=high_titles[i])
            for i in range(15)
        ]
        result = await service.triage(findings, ScanMode.CODE_ONLY)
        assert result.owner_summary.grade == "F"

    @pytest.mark.asyncio
    async def test_sast_findings_triaged_even_when_llm_fails(self) -> None:
        """SAST findings should have impact/likelihood even if LLM fails."""
        service, _ = _make_service(RuntimeError("fail"))
        sast_f = _make_finding(
            finding_id="sast1",
            scanner_name="dependency_scanner",
            category=FindingCategory.DEPENDENCY_VULNERABILITY,
        )
        llm_f = _make_finding(finding_id="llm1", title="LLM finding")

        result = await service.triage([sast_f, llm_f], ScanMode.CODE_ONLY)

        # SAST finding should be auto-triaged
        sast_result = next(
            f for f in result.triaged_findings if f.id == "sast1"
        )
        assert sast_result.impact == ImpactCategory.OPERATIONAL
        assert sast_result.priority is not None
