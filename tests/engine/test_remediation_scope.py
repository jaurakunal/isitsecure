"""Tests for remediation scope — how many places a finding must be fixed in.

Findings arrive one per affected location. That is right for detection and
wrong for reporting, and the two failure modes point opposite ways: a missing
header restated on 76 endpoints buries the report, while four IDORs collapsed
into one hides three vulnerabilities behind something that looks handled.
"""

from __future__ import annotations

from isitsecure.engine.enums import (
    REMEDIATION_SCOPE,
    FindingCategory,
    RemediationScope,
    SeverityLevel,
)
from isitsecure.engine.models import DeepFinding
from isitsecure.engine.triage.llm_triage_service import LLMTriageService


def _finding(category: FindingCategory, title: str, endpoint: str) -> DeepFinding:
    return DeepFinding(
        source="dast_url",
        category=category,
        severity=SeverityLevel.MEDIUM,
        title=title,
        description="d",
        confidence=0.9,
        scanner_name="test_scanner",
        endpoint_url=endpoint,
    )


class TestEveryCategoryIsClassified:
    def test_no_category_is_left_out(self) -> None:
        """An unclassified category falls back to INSTANCE — never
        collapsed — so the failure is noisy rather than silent. Still, a new
        category should be a deliberate decision."""
        missing = [c for c in FindingCategory if c not in REMEDIATION_SCOPE]
        assert missing == []

    def test_the_scopes_are_all_used(self) -> None:
        used = set(REMEDIATION_SCOPE.values())
        assert used == set(RemediationScope)


class TestServerScopeCollapses:
    """One configuration change covers every endpoint."""

    def test_a_missing_header_is_reported_once(self) -> None:
        findings = [
            _finding(
                FindingCategory.MISSING_HEADERS,
                "Missing Content-Security-Policy header",
                f"https://x/api/r{i}",
            )
            for i in range(76)
        ]
        deduped, removed = LLMTriageService._rule_based_dedup(findings)

        assert len(deduped) == 1
        assert removed == 75

    def test_the_affected_endpoints_survive_the_collapse(self) -> None:
        """The list is the point: one URL reads like one misconfigured page,
        while 76 says the server has no CSP at all."""
        findings = [
            _finding(
                FindingCategory.MISSING_HEADERS,
                "Missing Content-Security-Policy header",
                f"https://x/api/r{i}",
            )
            for i in range(76)
        ]
        deduped, _ = LLMTriageService._rule_based_dedup(findings)

        assert "Affects 76 endpoints" in deduped[0].description

    def test_a_cors_wildcard_is_reported_once(self) -> None:
        findings = [
            _finding(
                FindingCategory.CORS_MISCONFIGURATION,
                "CORS allows wildcard origin (data leakage risk)",
                f"https://x/api/r{i}",
            )
            for i in range(43)
        ]
        deduped, _ = LLMTriageService._rule_based_dedup(findings)
        assert len(deduped) == 1


class TestInstanceScopeIsNeverCollapsed:
    """Each occurrence is its own fix, in its own handler."""

    def test_four_idors_stay_four_findings(self) -> None:
        """The regression this guards. Collapsing on title kept one of these
        and discarded three real vulnerabilities — each needing its own
        ownership check — behind a report that looked handled."""
        endpoints = [
            "https://x/api/Products/1",
            "https://x/rest/track-order/1",
            "https://x/api/Deliverys/1",
            "https://x/rest/memories",
        ]
        findings = [
            _finding(
                FindingCategory.IDOR,
                "IDOR — resource accessible via direct ID reference",
                e,
            )
            for e in endpoints
        ]
        deduped, removed = LLMTriageService._rule_based_dedup(findings)

        assert len(deduped) == 4
        assert removed == 0
        assert {f.endpoint_url for f in deduped} == set(endpoints)

    def test_injection_on_two_routes_stays_two(self) -> None:
        findings = [
            _finding(FindingCategory.INJECTION_RISK, "SQL injection", "https://x/a"),
            _finding(FindingCategory.INJECTION_RISK, "SQL injection", "https://x/b"),
        ]
        deduped, _ = LLMTriageService._rule_based_dedup(findings)
        assert len(deduped) == 2

    def test_the_same_endpoint_twice_is_still_one(self) -> None:
        """Not collapsing across endpoints is not the same as never
        collapsing: one endpoint reported twice is one fix."""
        findings = [
            _finding(FindingCategory.IDOR, "IDOR", "https://x/a"),
            _finding(FindingCategory.IDOR, "IDOR", "https://x/a"),
        ]
        deduped, _ = LLMTriageService._rule_based_dedup(findings)
        assert len(deduped) == 1


class TestSharedRootGroups:
    """One cause, many call sites."""

    def test_a_leaked_secret_is_grouped(self) -> None:
        findings = [
            _finding(FindingCategory.EXPOSED_SECRETS, "Stripe key in bundle", f"https://x/{i}")
            for i in range(5)
        ]
        deduped, _ = LLMTriageService._rule_based_dedup(findings)

        assert len(deduped) == 1
        assert "Affects 5 endpoints" in deduped[0].description
