"""Fingerprints separate same-titled instances without breaking old entries (#9)."""

from __future__ import annotations

from pathlib import Path

from isitsecure.engine import baseline as B
from isitsecure.engine import suppression as S
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import CodeLocation, DeepFinding, FindingSource

SQLI_TITLE = "SQL injection via string concatenation"


def _sast(line: int, snippet: str = "", file: str = "app.py", title: str = SQLI_TITLE) -> DeepFinding:
    return DeepFinding(
        source=FindingSource.SAST_CODE, category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.HIGH, title=title, description="d", confidence=0.9,
        scanner_name="static_injection_analyzer",
        code_location=CodeLocation(file_path=file, line_number=line, code_snippet=snippet),
    )


def _ctx(line: int, flagged: str) -> str:
    """A snippet in the code-context-extractor format, flagged line marked >>>."""
    return "\n".join([
        f"{line - 1} |   x = 1",
        f"{line} >>>   {flagged}",
        f"{line + 1} |   y = 2",
    ])


def _dast(payload: str | None, url: str = "http://t/search") -> DeepFinding:
    return DeepFinding(
        source=FindingSource.DAST_URL, category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.HIGH, title="Reflected XSS", description="d", confidence=0.8,
        scanner_name="xss_scanner", endpoint_url=url, http_method="GET", request_payload=payload,
    )


def test_two_instances_in_one_file_have_different_fingerprints() -> None:
    a = _sast(10, _ctx(10, "cur.execute('SELECT ' + a)"))
    b = _sast(200, _ctx(200, "cur.execute('DELETE ' + b)"))
    assert a.fingerprint != b.fingerprint


def test_fingerprint_survives_edits_above_and_changed_context() -> None:
    a = _sast(10, _ctx(10, "cur.execute('SELECT ' + a)"))
    moved = _sast(150, _ctx(150, "cur.execute('SELECT ' + a)").replace("x = 1", "z = 99"))
    assert a.fingerprint == moved.fingerprint


def test_no_snippet_keeps_the_original_fingerprint_value() -> None:
    f = _sast(10)
    assert f.fingerprint == _sast(900).fingerprint
    from isitsecure.engine.identity import legacy_fingerprint
    assert f.fingerprint == legacy_fingerprint(f)


def test_dast_same_path_different_injected_parameter_differs() -> None:
    assert _dast("q=<x>").fingerprint != _dast("name=<x>").fingerprint


def test_dast_same_parameter_different_payload_is_stable() -> None:
    assert _dast("q=<a>").fingerprint == _dast("q=<b>").fingerprint


def test_dast_host_and_query_remain_agnostic() -> None:
    assert _dast("q=<a>", "http://localhost:3000/search").fingerprint == \
        _dast("q=<a>", "https://prod.example.com/search?q=1").fingerprint


# --- backward compatibility with ignore files and baselines written before ---


def test_old_ignore_entry_still_suppresses_both_instances(tmp_path: Path) -> None:
    from isitsecure.engine.identity import legacy_fingerprint
    a = _sast(10, _ctx(10, "cur.execute('SELECT ' + a)"))
    b = _sast(200, _ctx(200, "cur.execute('DELETE ' + b)"))
    old_fp = legacy_fingerprint(a)
    assert old_fp == legacy_fingerprint(b)  # what the old ignore file held
    ignore = tmp_path / ".isitsecureignore"
    ignore.write_text(f"{old_fp}   # [injection_risk] app.py\n")
    active, hidden = S.partition([a, b], S.load_suppressed_fingerprints(ignore))
    assert active == [] and len(hidden) == 2


def test_new_ignore_entry_hides_only_its_own_instance(tmp_path: Path) -> None:
    a = _sast(10, _ctx(10, "cur.execute('SELECT ' + a)"))
    b = _sast(200, _ctx(200, "cur.execute('DELETE ' + b)"))
    active, hidden = S.partition([a, b], {a.fingerprint})
    assert [f.id for f in hidden] == [a.id] and [f.id for f in active] == [b.id]


def test_old_baseline_still_marks_existing_findings_known() -> None:
    from isitsecure.engine.identity import legacy_fingerprint
    a = _sast(10, _ctx(10, "cur.execute('SELECT ' + a)"))
    new, known = B.partition_new([a], {legacy_fingerprint(a)})
    assert new == [] and known == [a]


def test_new_baseline_surfaces_a_newly_added_second_instance() -> None:
    a = _sast(10, _ctx(10, "cur.execute('SELECT ' + a)"))
    b = _sast(200, _ctx(200, "cur.execute('DELETE ' + b)"))
    new, known = B.partition_new([a, b], {a.fingerprint})
    assert new == [b] and known == [a]


def test_suppress_by_old_fingerprint_resolves_the_finding(tmp_path: Path) -> None:
    from isitsecure.engine.identity import legacy_fingerprint
    a = _sast(10, _ctx(10, "cur.execute('SELECT ' + a)"))
    ignore = tmp_path / ".isitsecureignore"
    newly = S.add_suppressions(ignore, [a], [legacy_fingerprint(a)])
    assert [f.id for f in newly] == [a.id]
