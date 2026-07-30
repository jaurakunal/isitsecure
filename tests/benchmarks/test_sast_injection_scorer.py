"""Tests for the SAST injection benchmark scorer (benchmarks/sast_injection.py).

Pure scoring logic — no scan, no semgrep binary. Ground truth is parsed from the
committed fixtures, so these also assert the fixtures stay well-formed.
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parents[2] / "benchmarks"))

import sast_injection as si  # noqa: E402

_CLASS_TITLE = {
    "sqli": "User input flows into a raw SQL query",
    "reflected-xss": "User input reflected into an HTML response without escaping",
    "dom-xss": "User-controlled input flows into the DOM (innerHTML)",
    "ssrf": "User-controlled URL flows into an outbound request",
    "path-traversal": "Filesystem write using a request-derived filename",
    "command-injection": "User input flows into a shell command",
    "ssti": "User input flows into a server-side template render — template injection (SSTI)",
}


def _finding(file: str, line: int, title: str, *, category: str = "injection_risk") -> dict:
    return {
        "category": category,
        "scanner_name": "semgrep_taint",
        "title": title,
        "code_location": {"file_path": f"vulnerable/{file}", "line_number": line},
    }


def _findings_for(bugs: list[dict], *, correct_class: bool = True) -> list[dict]:
    out = []
    for b in bugs:
        title = _CLASS_TITLE[b["class"]] if correct_class else "something unrelated"
        out.append(_finding(b["file"], b["line"], title))
    return out


class TestGroundTruth:
    def test_fixtures_have_expected_markers(self):
        bugs = si.expected_bugs()
        assert len(bugs) >= 25  # JS/TS + Python across 7 classes
        assert {b["class"] for b in bugs} == set(si.CLASSES)

    def test_all_language_fixtures_present(self):
        files = {b["file"] for b in si.expected_bugs()}
        assert any(f.endswith(".ts") for f in files)     # JS/TS (#4)
        assert any(f.endswith(".py") for f in files)     # Python (#93)
        assert any(f.endswith(".java") for f in files)   # Java (#102)
        assert any(f.endswith(".kt") for f in files)     # Kotlin (#104)

    def test_marker_regex_accepts_both_comment_styles(self):
        assert si.EXPECT_RE.search("foo()  // EXPECT sqli").group(1) == "sqli"
        assert si.EXPECT_RE.search("foo()  # EXPECT ssti").group(1) == "ssti"

    def test_descriptive_comment_lines_are_not_ground_truth(self, tmp_path, monkeypatch):
        """A standalone comment mentioning EXPECT must not inflate the count."""
        vuln = tmp_path / "vulnerable"
        vuln.mkdir()
        (vuln / "x.py").write_text(
            "# this line says EXPECT sqli but is prose\n"
            "cur.execute(bad)  # EXPECT sqli\n"
        )
        monkeypatch.setattr(si, "FIXTURES", tmp_path)
        bugs = si.expected_bugs()
        assert len(bugs) == 1 and bugs[0]["line"] == 2


class TestScoring:
    def test_full_recall_zero_fp(self):
        bugs = si.expected_bugs()
        r = si.score(_findings_for(bugs))
        assert r["recall"]["found"] == r["recall"]["total"] == len(bugs)
        assert r["false_positives"]["count"] == 0
        assert r["gaps"] == []
        assert r["class_mismatches"] == []

    @pytest.mark.parametrize("delta,should_match", [(1, True), (-1, True), (2, False), (-2, False)])
    def test_line_tolerance_boundaries(self, delta, should_match):
        """±1 line counts (statement head); ±2 does not."""
        bugs = si.expected_bugs()
        shifted = _findings_for(bugs)
        for f in shifted:
            f["code_location"]["line_number"] += delta
        r = si.score(shifted)
        assert (r["recall"]["found"] == len(bugs)) is should_match

    def test_duplicate_finding_on_real_bug_is_not_fp(self):
        """Real Semgrep double-reports a sink (taint + pattern) — must NOT be an FP."""
        bugs = si.expected_bugs()
        findings = _findings_for(bugs)
        dup = dict(findings[0])  # a second finding on the same real bug line
        r = si.score(findings + [dup])
        assert r["recall"]["found"] == len(bugs)
        assert r["false_positives"]["count"] == 0  # the duplicate is not a false alarm

    def test_one_finding_credits_at_most_one_bug(self):
        """Two distinct bugs can't both be credited to a single finding (1:1)."""
        two = [{"file": "x.ts", "line": 10, "class": "sqli"},
               {"file": "x.ts", "line": 11, "class": "sqli"}]
        # monkeypatch expected_bugs to return two closely-spaced bugs
        one_finding = [_finding("x.ts", 10, _CLASS_TITLE["sqli"])]
        orig = si.expected_bugs
        si.expected_bugs = lambda: two
        try:
            r = si.score(one_finding)
        finally:
            si.expected_bugs = orig
        assert r["recall"]["found"] == 1  # not 2
        assert r["false_positives"]["count"] == 0

    def test_missing_finding_is_a_gap(self):
        bugs = si.expected_bugs()
        r = si.score(_findings_for(bugs[1:]))  # drop one
        assert r["recall"]["found"] == len(bugs) - 1
        assert len(r["gaps"]) == 1
        assert r["gaps"][0]["file"] == bugs[0]["file"]

    def test_finding_on_safe_file_is_false_positive(self):
        bugs = si.expected_bugs()
        findings = _findings_for(bugs)
        findings.append({
            "category": "injection_risk",
            "scanner_name": "semgrep_taint",
            "title": "User input flows into a raw SQL query",
            "code_location": {"file_path": "safe/benign.ts", "line_number": 12},
        })
        r = si.score(findings)
        assert r["false_positives"]["count"] == 1
        assert r["false_positives"]["items"][0]["file"] == "benign.ts"

    def test_unmarked_line_in_vulnerable_file_is_fp(self):
        bugs = si.expected_bugs()
        findings = _findings_for(bugs)
        findings.append(_finding("sqli.ts", 999, "User input flows into a raw SQL query"))
        r = si.score(findings)
        assert r["false_positives"]["count"] == 1

    def test_non_injection_findings_ignored(self):
        bugs = si.expected_bugs()
        findings = _findings_for(bugs)
        findings.append({
            "category": "missing_headers",
            "scanner_name": "security_headers",
            "title": "Missing CSP",
            "code_location": {"file_path": "safe/benign.ts", "line_number": 1},
        })
        r = si.score(findings)
        assert r["false_positives"]["count"] == 0  # not an injection finding

    def test_detected_but_wrong_class_still_recalled(self):
        bugs = si.expected_bugs()
        r = si.score(_findings_for(bugs, correct_class=False))
        assert r["recall"]["found"] == len(bugs)  # recall by location
        assert len(r["class_mismatches"]) == len(bugs)  # but class label is off


class TestHelpers:
    @pytest.mark.parametrize("title,expected", [
        ("User input flows into a raw SQL query", "sqli"),
        ("User input reflected into an HTML response", "reflected-xss"),
        ("User-controlled input flows into the DOM (innerHTML)", "dom-xss"),
        ("User-controlled URL flows into an outbound request", "ssrf"),
        ("Filesystem write using a request-derived filename", "path-traversal"),
        ("User input flows into a shell command", "command-injection"),
        ("User input flows into a server-side template render (SSTI)", "ssti"),
        ("File opened with a request-derived path — path traversal", "path-traversal"),
        ("something else entirely", "?"),
        # regression: bare "dom" substring must NOT swallow these
        ("User-controlled URL flows to an external domain (SSRF)", "ssrf"),
        ("Tainted random value used in a raw SQL query", "sqli"),
    ])
    def test_finding_class_inference(self, title, expected):
        assert si.finding_class({"title": title}) == expected

    def test_finding_loc_nested_and_flat(self):
        nested = {"code_location": {"file_path": "a/b/x.ts", "line_number": 5}}
        assert si.finding_loc(nested) == ("x.ts", 5)
        assert si.finding_loc({"file_path": "y.ts", "line_number": 9}) == ("y.ts", 9)

    def test_is_injection(self):
        assert si.is_injection({"category": "injection_risk"})
        assert si.is_injection({"scanner_name": "semgrep_taint"})
        assert not si.is_injection({"category": "missing_headers", "scanner_name": "x"})

    def test_passed_gate(self):
        assert si.passed({"recall": {"found": 12, "total": 12},
                          "false_positives": {"count": 0}})
        assert not si.passed({"recall": {"found": 11, "total": 12},
                              "false_positives": {"count": 0}})
        assert not si.passed({"recall": {"found": 12, "total": 12},
                              "false_positives": {"count": 1}})


class TestRunBenchmarksWiring:
    """The sast-injection pseudo-target dispatch in run_benchmarks.resolve_selection."""

    @pytest.fixture(autouse=True)
    def _import(self):
        import run_benchmarks as rb  # noqa: E402
        self.rb = rb

    def test_default_runs_vampi_plus_sast(self):
        docker, want_sast, unknown = self.rb.resolve_selection([], all_flag=False)
        assert want_sast is True
        assert set(docker) == {"vampi-vulnerable", "vampi-secure"}
        assert unknown == []

    def test_sast_only(self):
        docker, want_sast, unknown = self.rb.resolve_selection(["sast-injection"], all_flag=False)
        assert docker == [] and want_sast is True and unknown == []

    def test_docker_target_only_skips_sast(self):
        docker, want_sast, unknown = self.rb.resolve_selection(["juiceshop"], all_flag=False)
        assert docker == ["juiceshop"] and want_sast is False

    def test_mixed_docker_and_sast(self):
        docker, want_sast, unknown = self.rb.resolve_selection(
            ["juiceshop", "sast-injection"], all_flag=False)
        assert docker == ["juiceshop"] and want_sast is True

    def test_all_flag_includes_sast(self):
        docker, want_sast, unknown = self.rb.resolve_selection([], all_flag=True)
        assert want_sast is True and len(docker) == len(self.rb.TARGETS)

    def test_unknown_target_reported(self):
        docker, want_sast, unknown = self.rb.resolve_selection(["nope"], all_flag=False)
        assert unknown == ["nope"] and docker == []
