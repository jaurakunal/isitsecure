"""SARIF rule severity must not depend on which finding came first (#14)."""

from __future__ import annotations

import json

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import CodeLocation, DeepFinding, DeepScanReport, FindingSource
from isitsecure.engine.reporting.sarif_renderer import SARIFRenderer


def _f(sev: SeverityLevel, line: int) -> DeepFinding:
    return DeepFinding(
        source=FindingSource.SAST_CODE, category=FindingCategory.INJECTION_RISK,
        severity=sev, title=f"SQL injection {line}", description="d", confidence=0.9,
        scanner_name="static_injection_analyzer",
        code_location=CodeLocation(file_path="a.py", line_number=line, code_snippet=f"{line} >>>   q{line}"),
    )


def _doc(findings: list[DeepFinding]) -> dict:
    report = DeepScanReport(
        target_url="https://example.com", scan_mode="code-only", findings=findings,
        scanners_run=["static_injection_analyzer"], scan_duration_seconds=1.0,
        total_endpoints_discovered=0,
    )
    return json.loads(SARIFRenderer().render(report))["runs"][0]


def test_rule_severity_is_the_highest_of_its_findings_whatever_the_order() -> None:
    for order in ([SeverityLevel.LOW, SeverityLevel.CRITICAL], [SeverityLevel.CRITICAL, SeverityLevel.LOW]):
        run = _doc([_f(s, i) for i, s in enumerate(order, 1)])
        (rule,) = run["tool"]["driver"]["rules"]
        assert rule["properties"]["security-severity"] == "9.5"
        assert rule["defaultConfiguration"]["level"] == "error"


def test_each_result_keeps_its_own_level_and_security_severity() -> None:
    run = _doc([_f(SeverityLevel.LOW, 1), _f(SeverityLevel.CRITICAL, 2)])
    by_level = {r["level"]: r for r in run["results"]}
    assert set(by_level) == {"note", "error"}
    assert by_level["note"]["properties"]["security-severity"] == "3.0"
    assert by_level["error"]["properties"]["security-severity"] == "9.5"


def test_rule_ids_are_unchanged_so_existing_alerts_keep_their_identity() -> None:
    run = _doc([_f(SeverityLevel.LOW, 1), _f(SeverityLevel.CRITICAL, 2)])
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == [
        "static_injection_analyzer/injection_risk",
    ]


def test_both_fingerprint_generations_are_emitted() -> None:
    from isitsecure.engine.identity import legacy_fingerprint
    f = _f(SeverityLevel.HIGH, 5)
    (result,) = _doc([f])["results"]
    assert result["fingerprints"]["isitsecure/v1"] == legacy_fingerprint(f)
    assert result["fingerprints"]["isitsecure/v2"] == f.fingerprint
