"""Guided DAST dedup keys on the test type, not just url + coarse category."""

from __future__ import annotations

from isitsecure.engine.constants import GuidedDASTConfig as C
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.guided_dast.protocols import GuidedTestCase
from isitsecure.engine.guided_dast.runner import SASTGuidedDASTRunner
from isitsecure.engine.models import DeepFinding, FindingSource

BASE = "http://app.test"


def _existing(category, title, url) -> DeepFinding:
    return DeepFinding(
        source=FindingSource.DAST_URL, category=category, severity=SeverityLevel.HIGH,
        title=title, description="d", evidence="e", confidence=0.9,
        scanner_name="x", endpoint_url=url,
    )


def _tc(test_type, path, method="GET") -> GuidedTestCase:
    return GuidedTestCase(
        source_finding_id="f", source_scanner="s", test_type=test_type,
        target_url=BASE + path, http_method=method, payload={"q": "1"},
    )


def test_auth_weakness_finding_does_not_remove_guided_race_test() -> None:
    existing = _existing(FindingCategory.AUTH_WEAKNESS, "Missing authentication",
                         BASE + "/api/admin/users")
    cases = [_tc(C.TEST_TYPE_AUTH_BYPASS, "/api/admin/users"),
             _tc(C.TEST_TYPE_RACE_CONDITION, "/api/admin/users", "POST")]
    kept = SASTGuidedDASTRunner._deduplicate(cases, [existing])
    assert [c.test_type for c in kept] == [C.TEST_TYPE_RACE_CONDITION]


def test_xss_finding_does_not_remove_guided_sqli_test() -> None:
    existing = _existing(FindingCategory.INJECTION_RISK, "Reflected XSS in q",
                         BASE + "/search?q=1")
    cases = [_tc(C.TEST_TYPE_SQLI, "/search"), _tc(C.TEST_TYPE_XSS, "/search")]
    kept = SASTGuidedDASTRunner._deduplicate(cases, [existing])
    assert [c.test_type for c in kept] == [C.TEST_TYPE_SQLI]


def test_positive_control_same_kind_still_deduped() -> None:
    sqli = _existing(FindingCategory.INJECTION_RISK, "SQL injection in q", BASE + "/search")
    race = _existing(FindingCategory.AUTH_WEAKNESS, "Race condition on redeem", BASE + "/redeem")
    cases = [_tc(C.TEST_TYPE_SQLI, "/search"), _tc(C.TEST_TYPE_RACE_CONDITION, "/redeem", "POST")]
    assert SASTGuidedDASTRunner._deduplicate(cases, [sqli, race]) == []
