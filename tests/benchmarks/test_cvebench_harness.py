"""Tests for the CVE-Bench pentest path in the benchmark harness.

Everything is mocked — NO real Docker, NO real pentest, NO API spend, NO network.
These assert the pure/testable seams: objective mapping, DoS -> skip-by-design,
selector routing via resolve_selection, `isitsecure pentest` command construction,
score aggregation, graceful skip when the repo/Docker is absent, and error-not-miss
on a failed run.
"""

import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parents[2] / "benchmarks"))

import run_benchmarks as rb  # noqa: E402


def _proc(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=["x"], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


class TestObjectiveMapping:
    def test_curated_categories_map_to_objective_strings(self):
        task = rb.build_cvebench_task("CVE-2024-34359")   # llama-cpp-python -> RCE
        assert task.objective_categories == ("rce",)
        assert task.objectives() == [rb.ATTACK_OBJECTIVES["rce"]]

    def test_multi_category_cve_yields_multiple_objectives(self):
        task = rb.build_cvebench_task("CVE-2024-3408")     # auth bypass -> RCE
        assert task.objective_categories == ("admin_login", "rce")
        assert task.objectives() == [
            rb.ATTACK_OBJECTIVES["admin_login"], rb.ATTACK_OBJECTIVES["rce"]]

    def test_uncurated_cve_falls_back_to_all_non_dos(self):
        task = rb.build_cvebench_task("CVE-2024-5084")     # not in curated map
        assert task.objective_categories == rb.ALL_NON_DOS
        # Every mapped objective is offered, and DoS is never among them.
        assert task.objectives() == list(rb.ATTACK_OBJECTIVES.values())
        assert rb.DOS not in task.objective_categories

    def test_dos_has_no_objective_string(self):
        assert rb.DOS not in rb.ATTACK_OBJECTIVES

    def test_starting_creds_come_from_metadata_defaults(self):
        task = rb.build_cvebench_task("CVE-2024-2624")
        assert task.default_username == rb.CVEBENCH_DEFAULT_USERNAME
        assert task.default_password == rb.CVEBENCH_DEFAULT_PASSWORD


class TestDoSSkippedBySafetyDesign:
    def test_dos_only_task_is_skipped_by_design(self):
        task = rb.CVEBenchTask(cve_id="CVE-FAKE-DOS", objective_categories=(rb.DOS,))
        assert task.skipped_by_safety_design is True
        assert task.objectives() == []       # DoS is never handed to the agent

    def test_task_with_a_non_dos_objective_is_not_skipped(self):
        task = rb.CVEBenchTask(cve_id="CVE-X", objective_categories=(rb.DOS, "rce"))
        assert task.skipped_by_safety_design is False
        assert task.objectives() == [rb.ATTACK_OBJECTIVES["rce"]]   # DoS stripped

    def test_run_task_records_skip_not_miss(self, monkeypatch):
        # A DoS-only task must never touch Docker and must not be a scored miss.
        called = []
        monkeypatch.setattr(rb, "_cvebench_run",
                            lambda *a, **k: called.append(a) or _proc())
        task = rb.CVEBenchTask(cve_id="CVE-FAKE-DOS", objective_categories=(rb.DOS,))
        result = rb.run_cvebench_task(task, keep=False)
        assert result == {"cve_id": "CVE-FAKE-DOS", "skipped_by_safety_design": True}
        assert "exploited" not in result
        assert called == []


class TestSelectorRouting:
    def test_bare_cvebench_selects_default_subset(self):
        docker, want_sast, cvebench, unknown = rb.resolve_selection(
            ["cve-bench"], all_flag=False)
        assert cvebench == list(rb.CVEBENCH_DEFAULT_SUBSET)
        assert docker == [] and want_sast is False and unknown == []

    def test_all_selector_selects_every_cve(self):
        _, _, cvebench, unknown = rb.resolve_selection(["cve-bench:all"], all_flag=False)
        assert set(cvebench) == set(rb.CVEBENCH_CVES)
        assert len(cvebench) == 40 and unknown == []

    def test_specific_cve_selector(self):
        _, _, cvebench, unknown = rb.resolve_selection(
            ["cve-bench:CVE-2024-34359"], all_flag=False)
        assert cvebench == ["CVE-2024-34359"] and unknown == []

    def test_unknown_cve_reported_not_run(self):
        _, _, cvebench, unknown = rb.resolve_selection(
            ["cve-bench:CVE-9999-0000"], all_flag=False)
        assert cvebench == [] and unknown == ["cve-bench:CVE-9999-0000"]

    def test_cvebench_never_in_default_set(self):
        _, _, cvebench, _ = rb.resolve_selection([], all_flag=False)
        assert cvebench == []

    def test_cvebench_never_in_all_flag(self):
        # --all pulls the heavy scan targets but must NOT pull the LLM-driven,
        # API-spending cve-bench path.
        docker, _, cvebench, _ = rb.resolve_selection([], all_flag=True)
        assert cvebench == [] and len(docker) == len(rb.TARGETS)

    def test_cvebench_coexists_with_docker_and_sast(self):
        docker, want_sast, cvebench, unknown = rb.resolve_selection(
            ["juiceshop", "sast-injection", "cve-bench:CVE-2024-2624"], all_flag=False)
        assert docker == ["juiceshop"] and want_sast is True
        assert cvebench == ["CVE-2024-2624"] and unknown == []

    def test_selectors_dedupe_and_preserve_order(self):
        ids, unknown = rb.resolve_cvebench_selectors(
            ["cve-bench:CVE-2024-2624", "cve-bench:CVE-2024-2624", "cve-bench:CVE-2024-34359"])
        assert ids == ["CVE-2024-2624", "CVE-2024-34359"] and unknown == []


class TestPentestCommandConstruction:
    def test_command_shape(self):
        task = rb.build_cvebench_task("CVE-2024-34359")
        cmd = rb.build_pentest_cmd(task, "report.json", cost_cap=4.0)
        assert cmd[:3] == ["isitsecure", "pentest", "http://localhost:9090"]
        # authorized host attestation names the in-scope host
        i = cmd.index("--i-am-authorized")
        assert cmd[i + 1] == "localhost"
        # bounded cost cap
        j = cmd.index("--cost-cap")
        assert cmd[j + 1] == "4.0"
        # JSON report to the given path
        assert "--output" in cmd and cmd[cmd.index("--output") + 1] == "json"
        assert "-f" in cmd and cmd[cmd.index("-f") + 1] == "report.json"
        # objective handed through
        assert "--objective" in cmd
        assert rb.ATTACK_OBJECTIVES["rce"] in cmd
        # synthetic disposable target -> destructive proofs allowed
        assert "--allow-destructive-any-account" in cmd
        # scope is PORT-PINNED to the target service, so the agent (running with
        # --allow-destructive-any-account) can't reach the grader :9091, db :3306,
        # or any other service on the operator's localhost.
        k = cmd.index("--scope")
        assert cmd[k + 1] == "localhost:9090"

    def test_auth_flags_from_creds(self):
        task = rb.build_cvebench_task("CVE-2024-2624")
        cmd = rb.build_pentest_cmd(task, "report.json")
        assert cmd[cmd.index("--auth-email") + 1] == rb.CVEBENCH_DEFAULT_USERNAME
        assert cmd[cmd.index("--auth-password") + 1] == rb.CVEBENCH_DEFAULT_PASSWORD

    def test_no_auth_flags_when_creds_absent(self):
        task = rb.CVEBenchTask(cve_id="CVE-X", objective_categories=("rce",))
        cmd = rb.build_pentest_cmd(task, "report.json")
        assert "--auth-email" not in cmd and "--auth-password" not in cmd

    def test_multiple_objectives_each_get_a_flag(self):
        task = rb.build_cvebench_task("CVE-2024-3408")   # two categories
        cmd = rb.build_pentest_cmd(task, "report.json")
        assert cmd.count("--objective") == 2


class TestRunTaskGraddingAndErrors:
    """The grader is the oracle; a crashed run is an error, never a clean miss."""

    def _patch_env(self, monkeypatch, up_rc=0, ready=True, pentest=None,
                   grader=None, self_report=None):
        monkeypatch.setattr(rb, "cvebench_available", lambda: True)
        monkeypatch.setattr(rb, "wait_ready", lambda *a, **k: ready)
        monkeypatch.setattr(rb, "read_self_report", lambda p: self_report)
        monkeypatch.setattr(rb, "query_grader", lambda *a, **k: grader)
        calls = {"up": 0, "down": 0}

        def fake_cvebench_run(sub, cve_id, timeout):
            calls[sub] = calls.get(sub, 0) + 1
            return _proc(returncode=up_rc if sub == "up" else 0)

        monkeypatch.setattr(rb, "_cvebench_run", fake_cvebench_run)
        monkeypatch.setattr(rb, "_run", lambda *a, **k: pentest or _proc())
        return calls

    def test_exploited_when_grader_status_true(self, monkeypatch):
        calls = self._patch_env(
            monkeypatch, grader={"status": True, "message": "Remote code execution successful"},
            self_report={"proven": True, "outcome": "objective_met", "cost_usd": 1.2})
        task = rb.build_cvebench_task("CVE-2024-34359")
        result = rb.run_cvebench_task(task, keep=False)
        assert result["exploited"] is True
        assert result["grader_message"] == "Remote code execution successful"
        assert result["self_report"]["proven"] is True   # secondary signal recorded
        # one pre-clean down (hygiene) + one teardown in finally
        assert calls["down"] == 2

    def test_not_exploited_when_grader_status_false(self, monkeypatch):
        self._patch_env(monkeypatch, grader={"status": False, "message": "Attack unsuccessful"})
        result = rb.run_cvebench_task(rb.build_cvebench_task("CVE-2024-34359"), keep=False)
        assert result["exploited"] is False and "error" not in result

    def test_bringup_failure_is_error_not_miss(self, monkeypatch):
        self._patch_env(monkeypatch, up_rc=1)
        result = rb.run_cvebench_task(rb.build_cvebench_task("CVE-2024-34359"), keep=False)
        assert result["error"] == "bring-up failed" and "exploited" not in result

    def test_not_ready_is_error(self, monkeypatch):
        self._patch_env(monkeypatch, ready=False)
        result = rb.run_cvebench_task(rb.build_cvebench_task("CVE-2024-34359"), keep=False)
        assert result["error"] == "not ready" and "exploited" not in result

    def test_grader_unreachable_is_error_not_miss(self, monkeypatch):
        self._patch_env(monkeypatch, grader=None)   # oracle down
        result = rb.run_cvebench_task(rb.build_cvebench_task("CVE-2024-34359"), keep=False)
        assert result["error"] == "grader unreachable" and "exploited" not in result

    def test_pentest_timeout_is_error(self, monkeypatch):
        self._patch_env(monkeypatch)

        def boom(*a, **k):
            raise subprocess.TimeoutExpired(cmd="isitsecure", timeout=1)

        monkeypatch.setattr(rb, "_run", boom)
        result = rb.run_cvebench_task(rb.build_cvebench_task("CVE-2024-34359"), keep=False)
        assert result["error"] == "pentest timed out"

    def test_keep_skips_teardown(self, monkeypatch):
        # With --keep, only the pre-clean down runs; the finally teardown is skipped
        # (keep=False would produce 2 downs — see test_exploited_when_grader_status_true).
        calls = self._patch_env(monkeypatch, grader={"status": True, "message": "ok"})
        rb.run_cvebench_task(rb.build_cvebench_task("CVE-2024-34359"), keep=True)
        assert calls["down"] == 1


class TestGracefulSkip:
    def test_skips_when_repo_or_docker_absent(self, monkeypatch):
        monkeypatch.setattr(rb, "cvebench_available", lambda: False)
        # Ensure no Docker/subprocess call happens on the skip path.
        monkeypatch.setattr(rb, "_cvebench_run",
                            lambda *a, **k: pytest.fail("must not run Docker when unavailable"))
        result = rb.run_cvebench_task(rb.build_cvebench_task("CVE-2024-34359"), keep=False)
        assert result["skipped"] is True and result["cve_id"] == "CVE-2024-34359"
        assert "exploited" not in result

    def test_available_requires_repo_docker_and_uv(self, monkeypatch):
        monkeypatch.setattr(rb.os.path, "isdir", lambda p: True)
        # uv present -> available; uv missing -> not available (the failure we hit live).
        monkeypatch.setattr(rb.shutil, "which",
                            lambda t: "/bin/" + t if t in {"docker", "uv"} else None)
        assert rb.cvebench_available() is True
        monkeypatch.setattr(rb.shutil, "which",
                            lambda t: "/bin/docker" if t == "docker" else None)
        assert rb.cvebench_available() is False


class TestScoreAggregation:
    def test_scorecard_counts(self, capsys):
        results = [
            {"cve_id": "CVE-A", "exploited": True, "grader_message": "RCE"},
            {"cve_id": "CVE-B", "exploited": False},
            {"cve_id": "CVE-C", "error": "grader unreachable"},
            {"cve_id": "CVE-D", "skipped_by_safety_design": True},
            {"cve_id": "CVE-E", "skipped": True, "error": "unavailable"},
        ]
        rb.print_cvebench_scorecard(results)
        out = capsys.readouterr().out
        # 1 exploited out of 3 attempted (A, B, C); D skipped-by-design; E unavailable.
        assert "Exploited: 1/3 attempted" in out
        assert "1 skipped-by-safety-design" in out
        assert "1 error" in out and "1 unavailable" in out
        assert "CVE-D" in out and "skipped-by-safety-design" in out

    def test_empty_results_prints_nothing(self, capsys):
        rb.print_cvebench_scorecard([])
        assert capsys.readouterr().out == ""
