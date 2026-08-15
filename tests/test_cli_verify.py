"""CLI-level tests for the `verify` command (#53)."""

from __future__ import annotations

import json

import pytest
import typer

from isitsecure import cli
from isitsecure.engine import reverify as R
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import DeepFinding, DeepScanReport, FindingSource


def _dast(url, title="SQL injection vulnerability (error-based)"):
    return DeepFinding(
        source=FindingSource.DAST_URL, category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.CRITICAL, title=title, description="d", confidence=0.9,
        scanner_name="active_injection_scanner", endpoint_url=url, http_method="GET",
        request_payload="q='",
    )


def _write_report(tmp_path, findings):
    report = DeepScanReport(target_url="http://app", findings=findings)
    p = tmp_path / "before.json"
    p.write_text(report.model_dump_json())
    return p


def _run_verify(monkeypatch, report_path, verdicts, **kw):
    async def fake(findings, *, target_url=None, repo_path=None):
        return verdicts(findings)
    monkeypatch.setattr(R, "reverify_findings", fake)
    opts = dict(target_url="http://app", report=str(report_path),
                fingerprint=None, repo=None, output="json")
    opts.update(kw)
    with pytest.raises(typer.Exit) as exc:
        cli.verify(**opts)
    return exc.value.exit_code


def test_exit_zero_when_all_fixed(tmp_path, monkeypatch, capsys):
    f = _dast("http://app/login")
    p = _write_report(tmp_path, [f])
    code = _run_verify(monkeypatch, p,
                       lambda fs: [R.Verdict(fs[0], R.VerifyStatus.FIXED)])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["fixed"] == 1 and out["still_present"] == 0


def test_exit_one_when_any_still_present(tmp_path, monkeypatch):
    f = _dast("http://app/login")
    p = _write_report(tmp_path, [f])
    code = _run_verify(monkeypatch, p,
                       lambda fs: [R.Verdict(fs[0], R.VerifyStatus.STILL_PRESENT)])
    assert code == 1


def test_fingerprint_filter_selects_subset(tmp_path, monkeypatch):
    a, b = _dast("http://app/a"), _dast("http://app/b")
    p = _write_report(tmp_path, [a, b])
    captured = {}

    async def fake(findings, *, target_url=None, repo_path=None):
        captured["ids"] = [f.endpoint_url for f in findings]
        return [R.Verdict(f, R.VerifyStatus.FIXED) for f in findings]
    monkeypatch.setattr(R, "reverify_findings", fake)
    with pytest.raises(typer.Exit):
        cli.verify(target_url="http://app", report=str(p),
                   fingerprint=[a.fingerprint], repo=None, output="json")
    assert captured["ids"] == ["http://app/a"]  # only the requested finding verified


def test_missing_report_exits_two(tmp_path):
    with pytest.raises(typer.Exit) as exc:
        cli.verify(target_url="http://app", report=str(tmp_path / "nope.json"),
                   fingerprint=None, repo=None, output="json")
    assert exc.value.exit_code == 2


def test_unknown_fingerprint_exits_two(tmp_path, monkeypatch):
    # A typo'd fingerprint must NOT read as a green gate (inconclusive → exit 2).
    p = _write_report(tmp_path, [_dast("http://app/a")])
    monkeypatch.setattr(R, "reverify_findings", None)  # must not be called
    with pytest.raises(typer.Exit) as exc:
        cli.verify(target_url="http://app", report=str(p),
                   fingerprint=["deadbeefdeadbeef"], repo=None, output="json")
    assert exc.value.exit_code == 2


def test_unverifiable_exits_two_not_green(tmp_path, monkeypatch):
    # If nothing could be definitively verified, the gate must not pass.
    f = _dast("http://app/login")
    p = _write_report(tmp_path, [f])
    code = _run_verify(monkeypatch, p,
                       lambda fs: [R.Verdict(fs[0], R.VerifyStatus.UNVERIFIABLE)])
    assert code == 2
