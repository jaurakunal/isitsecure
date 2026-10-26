"""Rule-based dedup must not merge distinct vulnerabilities or lose locations (#5)."""

from __future__ import annotations

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import CodeLocation, DeepFinding, FindingSource
from isitsecure.engine.triage.llm_triage_service import LLMTriageService

dedup = LLMTriageService._rule_based_dedup


def _f(title: str, cat: FindingCategory, *, scanner: str = "secret_scanner",
       file: str | None = None, line: int | None = None, url: str | None = None,
       sev: SeverityLevel = SeverityLevel.HIGH, fid: str | None = None) -> DeepFinding:
    kw = {"id": fid} if fid else {}
    return DeepFinding(
        source=FindingSource.SAST_CODE, category=cat, severity=sev, title=title,
        description="d", confidence=0.9, scanner_name=scanner, endpoint_url=url,
        code_location=CodeLocation(file_path=file, line_number=line) if file else None,
        **kw,
    )


SECRETS = FindingCategory.EXPOSED_SECRETS
DEPS = FindingCategory.DEPENDENCY_VULNERABILITY
INJ = FindingCategory.INJECTION_RISK


def test_different_vulnerable_packages_stay_separate() -> None:
    out, removed = dedup([
        _f("Vulnerable dependency: lodash@4.17.15", DEPS, scanner="dependency_scanner", file="package-lock.json"),
        _f("Vulnerable dependency: express@4.16.0", DEPS, scanner="dependency_scanner", file="package-lock.json"),
    ])
    assert len(out) == 2 and removed == 0


def test_different_secret_types_in_different_files_stay_separate() -> None:
    out, _ = dedup([
        _f("AWS access key hardcoded in config", SECRETS, file="a.py", line=3),
        _f("Stripe secret key hardcoded in config", SECRETS, file="b.py", line=9),
    ])
    assert sorted(o.code_location.file_path for o in out) == ["a.py", "b.py"]


def test_same_secret_title_in_two_files_merges_but_names_both_files() -> None:
    out, removed = dedup([
        _f("Hardcoded API key", SECRETS, file="a.py", line=3),
        _f("Hardcoded API key", SECRETS, file="b.py", line=9),
    ])
    assert len(out) == 1 and removed == 1
    both = out[0].code_location.file_path + " " + out[0].description
    assert "a.py" in both and "b.py" in both


def test_different_vulnerabilities_on_one_line_stay_separate() -> None:
    out, _ = dedup([
        _f("SQL injection via concatenation", INJ, scanner="s1", file="a.py", line=3),
        _f("Hardcoded password", SECRETS, file="a.py", line=3),
    ])
    assert {o.title for o in out} == {"SQL injection via concatenation", "Hardcoded password"}


def test_same_issue_reported_twice_on_one_line_merges_and_notes_other_title() -> None:
    out, removed = dedup([
        _f("SQL injection via concatenation", INJ, scanner="static_injection_analyzer", file="a.py", line=3),
        _f("SQL injection in query builder", INJ, scanner="llm_code_reviewer", file="a.py", line=3),
    ])
    assert len(out) == 1 and removed == 1
    assert "Also affects" in out[0].description


def test_distinct_injection_classes_in_one_file_are_not_collapsed() -> None:
    out, _ = dedup([
        _f("SQL injection via string concatenation", INJ, scanner="static_injection_analyzer", file="a.py", line=10),
        _f("Command injection via os.system", INJ, scanner="static_injection_analyzer", file="a.py", line=20),
        _f("Reflected XSS via unescaped output", INJ, scanner="static_injection_analyzer", file="a.py", line=30),
    ])
    assert len(out) == 3


def test_repeated_same_pattern_in_one_file_still_collapses_and_lists_lines() -> None:
    out, removed = dedup([
        _f("Stripe test key in plaintext", SECRETS, scanner="secret_scanner", file="c.py", line=i)
        for i in (5, 6, 7, 8)
    ])
    assert len(out) == 1 and removed == 3
    for line in (5, 6, 7, 8):
        assert f"c.py:{line}" in out[0].description or line == 5


def test_fuzzy_never_merges_across_categories() -> None:
    out, _ = dedup([
        _f("Missing rate limiting on login endpoint handler", FindingCategory.AUTH_WEAKNESS,
           scanner="llm_code_reviewer", file="a.py", line=1),
        _f("Missing rate limiting on login endpoint handler code", FindingCategory.BUSINESS_LOGIC,
           scanner="llm_code_reviewer", file="a.py", line=1),
    ])
    # same line, different category: two findings
    assert len(out) == 2


def test_fuzzy_guard_applies_to_both_findings() -> None:
    # f1 is SERVER-scope (no guard); f2 same category is irrelevant here, so use
    # an INSTANCE finding second with a different location: still not merged.
    out, _ = dedup([
        _f("Missing authentication on orders handler route", FindingCategory.AUTH_WEAKNESS,
           scanner="llm_code_reviewer", file="orders.py", line=1),
        _f("Missing authentication on users handler route", FindingCategory.AUTH_WEAKNESS,
           scanner="llm_code_reviewer", file="users.py", line=1),
    ])
    assert len(out) == 2


def test_server_scope_near_duplicate_titles_still_merge() -> None:
    out, removed = dedup([
        _f("Missing Content-Security-Policy header", FindingCategory.MISSING_HEADERS,
           scanner="header_scanner", url="https://x/a"),
        _f("Missing Content-Security-Policy header on page", FindingCategory.MISSING_HEADERS,
           scanner="header_scanner", url="https://x/a"),
    ])
    assert len(out) == 1 and removed == 1
