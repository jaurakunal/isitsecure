"""Tests for repeat-run stability, per-class deltas and the auth smoke guard.

All synthetic: saved-report-shaped dicts and fake runners/providers. No Docker,
no scan, no network.
"""

import asyncio
import json
import pathlib
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parents[2] / "benchmarks"))

import auth_smoke  # noqa: E402
import run_benchmarks as rb  # noqa: E402
import score  # noqa: E402
import stability as st  # noqa: E402


def _f(title="SQL injection", url="http://h:3000/rest/products/search?q=1",
       scanner="active_injection_scanner", category="injection_risk"):
    return {"scanner_name": scanner, "category": category, "title": title,
            "endpoint_url": url}


def _run(findings, found=1, total=2, dur=10.0):
    return st.RunRecord(st.fingerprint_set(findings), found, total, dur)


class TestFingerprint:
    def test_ignores_host_query_and_ids(self):
        a = st.finding_fingerprint(_f(url="http://a:1/api/Users/7?x=1"))
        b = st.finding_fingerprint(_f(url="https://b/api/Users/9"))
        assert a == b and "{id}" in a

    def test_distinguishes_endpoint_and_title(self):
        base = st.finding_fingerprint(_f())
        assert base != st.finding_fingerprint(_f(url="http://h/rest/other"))
        assert base != st.finding_fingerprint(_f(title="NoSQL injection"))

    def test_title_whitespace_and_case_normalised(self):
        assert st.finding_fingerprint(_f(title="SQL  Injection")) == \
            st.finding_fingerprint(_f(title="sql injection"))

    def test_sast_ignores_line_number(self):
        def f(line, snippet="cur.execute(q)"):
            return {"scanner_name": "semgrep_taint", "title": "t",
                    "code_location": {"file_path": "a.py", "line_number": line,
                                      "code_snippet": snippet}}
        assert st.finding_fingerprint(f(3)) == st.finding_fingerprint(f(40))
        assert "a.py#" in st.finding_fingerprint(f(3))
        # Different code in the same file stays distinct; whitespace doesn't matter.
        assert st.finding_fingerprint(f(3)) != st.finding_fingerprint(f(3, "other()"))
        assert st.finding_fingerprint(f(3, "a  =  b")) == st.finding_fingerprint(f(9, "a = b"))

    def test_sast_without_snippet_is_file_only(self):
        f = {"scanner_name": "s", "title": "t",
             "code_location": {"file_path": "a.py", "line_number": 9}}
        assert st.finding_fingerprint(f).endswith("|a.py")

    def test_volatile_title_text_normalised(self):
        a = st.finding_fingerprint(_f(title="SQL injection in 'q' param, 3 payloads, id 4f1c2a9b"))
        b = st.finding_fingerprint(_f(title="SQL injection in 'search' param, 12 payloads, id 99"))
        assert a != "" and a.split("|")[2].startswith("sql injection in '?' param")
        assert st.finding_fingerprint(_f(title="SQL injection in 'q' param, 3 payloads")) == \
            st.finding_fingerprint(_f(title="SQL injection in 'search' param, 12 payloads"))
        del b


class TestStability:
    def test_stable_is_intersection_flaky_is_rest(self):
        a, b, c = _f(url="http://h/a"), _f(url="http://h/b"), _f(url="http://h/c")
        rep = st.compute_stability([_run([a, b]), _run([a, c]), _run([a, b])])
        assert rep.stable == st.fingerprint_set([a])
        assert rep.flaky == st.fingerprint_set([b, c])

    def test_spread_and_duration(self):
        rep = st.compute_stability([_run([], 1, 4, 10), _run([], 3, 4, 30)])
        assert rep.recall_spread == pytest.approx(0.5)
        assert (rep.duration_min, rep.duration_max) == (10, 30)

    def test_empty_runs(self):
        assert st.compute_stability([]).stable == frozenset()


class TestBaseline:
    def test_regression_lost_vs_demoted(self):
        a, b, c = _f(url="http://h/a"), _f(url="http://h/b"), _f(url="http://h/c")
        rep = st.compute_stability([_run([a, b]), _run([a])])  # b flaky, c absent
        cmp = st.compare_to_baseline(rep, st.fingerprint_set([a, b, c]))
        assert cmp.regressed
        assert cmp.lost == [st.finding_fingerprint(c)]
        assert cmp.demoted == [st.finding_fingerprint(b)]

    def test_new_stable_is_not_a_regression(self):
        a, b = _f(url="http://h/a"), _f(url="http://h/b")
        rep = st.compute_stability([_run([a, b]), _run([a, b])])
        cmp = st.compare_to_baseline(rep, st.fingerprint_set([a]))
        assert not cmp.regressed and cmp.new_stable == [st.finding_fingerprint(b)]

    def test_roundtrip_and_missing_file(self, tmp_path):
        p = tmp_path / "base.json"
        assert st.load_baseline(p) == {"version": 1, "targets": {}}
        rep = st.compute_stability([_run([_f()], 1, 2), _run([_f()], 2, 2)])
        st.save_baseline(p, st.load_baseline(p), "t",
                         st.baseline_entry(rep, {"sqli": {"found": 1, "total": 1}}))
        data = st.load_baseline(p)
        assert data["targets"]["t"]["stable"] == sorted(rep.stable)
        assert data["targets"]["t"]["recall"] == {"found": 2, "total": 2}

    def test_unknown_version_rejected(self, tmp_path):
        p = tmp_path / "b.json"
        p.write_text(json.dumps({"version": 99}))
        with pytest.raises(ValueError):
            st.load_baseline(p)


def _result(findings, found=1, total=2, **extra):
    return {"name": "t", "recall": [("a", True)] * found + [("b", False)] * (total - found),
            "fingerprints": sorted(st.fingerprint_set(findings)),
            "duration_s": 5.0, **extra}


class TestEvaluateRepeat:
    def test_no_baseline_never_fails(self):
        code, text, rep = rb.evaluate_repeat("t", [_result([_f()])] * 3, None)
        assert code == 0 and rep.stable and "STABILITY" in text

    def test_regression_exits_1(self):
        base = {"targets": {"t": {"stable": sorted(st.fingerprint_set([_f()]))}}}
        code, text, _ = rb.evaluate_repeat("t", [_result([]), _result([])], base)
        assert code == 1 and "LOST" in text

    def test_flaky_baseline_finding_exits_1(self):
        base = {"targets": {"t": {"stable": sorted(st.fingerprint_set([_f()]))}}}
        code, _, _ = rb.evaluate_repeat("t", [_result([_f()]), _result([])], base)
        assert code == 1

    def test_holding_baseline_exits_0(self):
        base = {"targets": {"t": {"stable": sorted(st.fingerprint_set([_f()]))}}}
        assert rb.evaluate_repeat("t", [_result([_f()])] * 2, base)[0] == 0

    def test_errored_runs_excluded_and_all_errored_is_2(self):
        err = {"name": "t", "error": "boom"}
        code, text, rep = rb.evaluate_repeat("t", [_result([_f()])] * 2 + [err], None)
        assert code == 2 and "1 of 3 run(s) errored" in text and rep.stable
        assert rb.evaluate_repeat("t", [err, err], None)[0] == 2

    def test_single_good_run_is_not_stability(self):
        err = {"name": "t", "error": "boom"}
        code, _, rep = rb.evaluate_repeat("t", [_result([_f()]), err, err], None)
        assert code == 2 and rep is None

    def test_ground_truth_recall_counts(self):
        r = {"scorecard": {"recall": {"found": 7, "in_scope": 45}}}
        assert rb.recall_counts(r) == (7, 45)


class TestRunRepeated:
    def test_repeat_one_is_single_untagged_run(self):
        seen = []
        out = rb.run_repeated(SimpleNamespace(name="T"), 1, False,
                              runner=lambda t, k: seen.append(rb.REPORT_TAG) or {"n": 1})
        assert seen == [""] and len(out) == 1

    def test_repeat_n_tags_reports_and_resets(self):
        seen = []
        rb.run_repeated(SimpleNamespace(name="T"), 3, False,
                        runner=lambda t, k: seen.append(rb.REPORT_TAG) or {})
        assert seen == [".run1", ".run2", ".run3"] and rb.REPORT_TAG == ""

    def test_tag_reset_when_runner_raises(self):
        def boom(t, k):
            raise RuntimeError
        with pytest.raises(RuntimeError):
            rb.run_repeated(SimpleNamespace(name="T"), 2, False, runner=boom)
        assert rb.REPORT_TAG == ""


class TestReportStability:
    def test_write_then_gate_round_trip(self, tmp_path):
        p = str(tmp_path / "b.json")
        runs = {"t": [_result([_f()]), _result([_f()])]}
        assert rb.report_stability(runs, p, write=True) == 0
        assert rb.report_stability(runs, p, write=False) == 0
        regressed = {"t": [_result([]), _result([])]}
        assert rb.report_stability(regressed, p, write=False) == 1


class TestBaselineWriteGuard:
    def test_errored_run_blocks_baseline_write(self, tmp_path):
        p = tmp_path / "b.json"
        runs = {"t": [_result([_f()]), _result([_f()]), {"name": "t", "error": "x"}]}
        assert rb.report_stability(runs, str(p), write=True) == 2
        assert st.load_baseline(p)["targets"] == {}

    def test_single_ok_run_blocks_baseline_write(self, tmp_path):
        p = tmp_path / "b.json"
        runs = {"t": [_result([_f()]), {"name": "t", "error": "x"}]}
        assert rb.report_stability(runs, str(p), write=True) == 2
        assert not p.exists()


class TestMustDetectAcrossRuns:
    def _r(self, missed):
        return {"scorecard": {"regression_failures": [{}] * missed}}

    def test_counts_every_ok_run_not_just_first(self):
        runs = {"t": [self._r(0), self._r(1), self._r(2)]}
        assert rb.count_must_detect_regressions(runs) == 3

    def test_errored_runs_ignored(self):
        assert rb.count_must_detect_regressions({"t": [self._r(0), {"error": "x"}]}) == 0


class TestFinalExitCode:
    def test_all_clear(self):
        assert rb.final_exit_code(0, 0, 0, 0) == 0

    def test_prints_every_failure_not_just_first(self, capsys):
        # a stability failure must not hide the SAST / Go-SAST failures.
        assert rb.final_exit_code(1, 0, 1, 1) == 1
        out = capsys.readouterr().out
        assert "stability" in out and "SAST injection" in out and "Go SAST" in out

    def test_unverifiable_beats_regression(self):
        assert rb.final_exit_code(2, 3, 1, 0) == 2

    def test_sast_alone_still_fails(self):
        assert rb.final_exit_code(0, 0, 1, 0) == 1


class TestMainFlags:
    @pytest.mark.parametrize("argv", [
        ["--repeat", "0"], ["--baseline", "b.json"],
        ["--repeat", "2", "--write-baseline"]])
    def test_bad_flag_combinations_exit_2(self, argv, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["rb", *argv])
        assert rb.main() == 2


def _sc(**classes):
    return {"by_class": {k: {"found": f, "total": t} for k, (f, t) in classes.items()}}


class TestClassDeltas:
    def test_regressions_sorted_first(self):
        rows = score.class_deltas(_sc(sqli=(1, 3), xss=(4, 4), idor=(0, 2)),
                                  _sc(sqli=(3, 3), xss=(2, 4), idor=(0, 2)))
        assert [(r["vuln_class"], r["delta"]) for r in rows] == \
            [("sqli", -2), ("idor", 0), ("xss", 2)]

    def test_class_only_in_one_side(self):
        rows = {r["vuln_class"]: r for r in score.class_deltas(_sc(a=(1, 1)), _sc(b=(2, 2)))}
        assert rows["a"]["delta"] == 1 and rows["b"]["delta"] == -2

    def test_print_marks_regression(self, capsys):
        score.print_deltas(score.class_deltas(_sc(sqli=(0, 1)), _sc(sqli=(1, 1))))
        out = capsys.readouterr().out
        assert "REGRESSED" in out and "1/1 -> 0/1" in out

    def test_print_no_change(self, capsys):
        score.print_deltas(score.class_deltas(_sc(a=(1, 1)), _sc(a=(1, 1))))
        assert "no per-class change" in capsys.readouterr().out

    def test_cli_previous_flag(self, tmp_path, capsys):
        findings = tmp_path / "f.json"
        findings.write_text("[]")
        prev = tmp_path / "prev.json"
        prev.write_text(json.dumps(_sc(sqli=(5, 5))))
        assert score.main(["juiceshop", str(findings), "--previous", str(prev)]) == 0
        assert "REGRESSED" in capsys.readouterr().out

    def test_help_exits_zero(self):
        with pytest.raises(SystemExit) as e:
            score.main(["-h"])
        assert e.value.code == 0

    def test_cli_bad_app_exit_2(self, tmp_path):
        assert score.main(["nope", "x.json"]) == 2


class TestAuthSmokeExitCodes:
    def test_all_pass_is_0(self):
        assert auth_smoke.exit_code([auth_smoke.CheckResult("a", auth_smoke.PASS)]) == 0

    def test_fail_is_1(self):
        rs = [auth_smoke.CheckResult("a", auth_smoke.PASS),
              auth_smoke.CheckResult("b", auth_smoke.FAIL)]
        assert auth_smoke.exit_code(rs) == 1

    def test_infra_beats_fail_is_2(self):
        rs = [auth_smoke.CheckResult("a", auth_smoke.FAIL),
              auth_smoke.CheckResult("b", auth_smoke.INFRA)]
        assert auth_smoke.exit_code(rs) == 2


class _Provider:
    def __init__(self, token=None, exc=None):
        self.token, self.exc = token, exc

    async def authenticate(self, creds):
        if self.exc:
            raise self.exc
        return SimpleNamespace(access_token=self.token)


class TestAuthSmokeCheck:
    creds = SimpleNamespace(email="smoke@x.test")

    def _check(self, provider, who, monkeypatch):
        monkeypatch.setattr(auth_smoke, "whoami_email", lambda u, t: who)
        return asyncio.run(auth_smoke._check_provider("p", provider, self.creds, "http://h"))

    def test_live_token_passes(self, monkeypatch):
        r = self._check(_Provider("tok"), "SMOKE@x.test", monkeypatch)
        assert r.status == auth_smoke.PASS

    def test_dead_token_fails(self, monkeypatch):
        assert self._check(_Provider("tok"), None, monkeypatch).status == auth_smoke.FAIL

    def test_wrong_account_fails(self, monkeypatch):
        assert self._check(_Provider("tok"), "other@x", monkeypatch).status == auth_smoke.FAIL

    def test_login_error_fails(self, monkeypatch):
        r = self._check(_Provider(exc=ValueError("bad creds")), None, monkeypatch)
        assert r.status == auth_smoke.FAIL and "bad creds" in r.detail

    def test_missing_playwright_is_infra(self, monkeypatch):
        r = self._check(_Provider(exc=ImportError("playwright")), None, monkeypatch)
        assert r.status == auth_smoke.INFRA
