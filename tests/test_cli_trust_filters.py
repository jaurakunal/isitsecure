"""CLI-level tests for the suppression + baseline composition hook (#51/#52).

Exercises `cli._apply_trust_filters` directly — the seam that wires the
suppression and baseline modules together and mutates the report — without
running a full scan.
"""

from __future__ import annotations

# `cli` here is the module that owns these helpers; the `isitsecure.cli`
# package façade deliberately re-exports only `app` and the consoles.
from isitsecure.cli import main as cli
from isitsecure.engine import baseline as B
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import DeepFinding, DeepScanReport, FindingSource


def _f(title, url):
    return DeepFinding(
        source=FindingSource.DAST_URL, category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.CRITICAL, title=title, description="d", confidence=0.8,
        scanner_name="active_injection_scanner", endpoint_url=url, http_method="GET",
    )


def _report(findings):
    return DeepScanReport(target_url="http://app", findings=list(findings))


def _apply(report, tmp_path, **kw):
    opts = dict(
        output="table", target_url="http://app", repo=None,
        suppress=None, suppress_reason="", suppress_file=str(tmp_path / ".isitsecureignore"),
        show_suppressed=False, baseline=False, baseline_accept=False,
        baseline_file=str(tmp_path / "bl.json"),
    )
    opts.update(kw)
    cli._apply_trust_filters(report, **opts)


def test_suppress_adds_and_hides(tmp_path):
    fp = _f("SQLi", "http://app/createdb").fingerprint
    r = _report([_f("SQLi", "http://app/createdb"), _f("SQLi", "http://app/login")])
    _apply(r, tmp_path, suppress=[fp], suppress_reason="benign")
    assert [f.endpoint_url for f in r.findings] == ["http://app/login"]
    assert (tmp_path / ".isitsecureignore").exists()


def test_baseline_accept_records_post_suppression_set(tmp_path):
    """The baseline must exclude a finding suppressed in the same run."""
    supp = _f("SQLi", "http://app/createdb").fingerprint
    r = _report([_f("SQLi", "http://app/createdb"), _f("SQLi", "http://app/login")])
    _apply(r, tmp_path, suppress=[supp], baseline_accept=True)
    saved = B.load_baseline(tmp_path / "bl.json")
    assert supp not in saved  # suppressed finding not baselined
    assert _f("SQLi", "http://app/login").fingerprint in saved


def test_accept_then_baseline_shows_only_new(tmp_path):
    # Run 1: accept a,b.
    r1 = _report([_f("SQLi", "http://app/a"), _f("SQLi", "http://app/b")])
    _apply(r1, tmp_path, baseline_accept=True)
    # Run 2: a,c — only c is new.
    r2 = _report([_f("SQLi", "http://app/a"), _f("SQLi", "http://app/c")])
    _apply(r2, tmp_path, baseline=True)
    assert [f.endpoint_url for f in r2.findings] == ["http://app/c"]
    assert r2.critical_count == 1  # counts follow the filtered set


def test_suppression_and_baseline_compose(tmp_path):
    # Accept baseline of the active (post-suppression) set: suppress b.
    supp = _f("SQLi", "http://app/b").fingerprint
    r1 = _report([_f("SQLi", "http://app/a"), _f("SQLi", "http://app/b"), _f("SQLi", "http://app/c")])
    _apply(r1, tmp_path, suppress=[supp], baseline_accept=True)
    # Run 2: a,c,d with b still suppressed → only d is new.
    r2 = _report([_f("SQLi", "http://app/a"), _f("SQLi", "http://app/c"), _f("SQLi", "http://app/d")])
    _apply(r2, tmp_path, baseline=True)
    assert [f.endpoint_url for f in r2.findings] == ["http://app/d"]


def test_show_suppressed_disables_baseline(tmp_path):
    # With --show-suppressed, baseline_accept must NOT write a baseline.
    r = _report([_f("SQLi", "http://app/a")])
    _apply(r, tmp_path, show_suppressed=True, baseline_accept=True)
    assert not (tmp_path / "bl.json").exists()


def test_baseline_missing_shows_all(tmp_path):
    r = _report([_f("SQLi", "http://app/a"), _f("SQLi", "http://app/b")])
    _apply(r, tmp_path, baseline=True)  # no baseline accepted yet
    assert len(r.findings) == 2  # falls open, not closed


def test_corrupt_baseline_shows_all_without_crashing(tmp_path):
    (tmp_path / "bl.json").write_text("}{ not json")
    r = _report([_f("SQLi", "http://app/a")])
    _apply(r, tmp_path, baseline=True)
    assert len(r.findings) == 1  # corrupt → show all, no crash
