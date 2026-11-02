"""F1 "honest verification": the fix flow must never claim fixed/verified/resolved
unless it proved it.

Covers: silent scanner skips (semgrep missing/timeout/crash/empty), per-finding
re-verify under v2+legacy fingerprints (findings WITH the ``>>>`` snippet marker,
which the older tests lacked), verifier moved/duplicate semantics, and the
fix generator's reply validation + applicable diffs (checked with a real
``git apply --check``).
"""

from __future__ import annotations

import asyncio
import subprocess
from unittest.mock import AsyncMock

import pytest

from isitsecure.engine import reverify as R
from isitsecure.engine.code_analysis import semgrep_analyzer as SA
from isitsecure.engine.code_analysis.semgrep_analyzer import SemgrepAnalyzer, require_semgrep
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.fixes import verifier as V
from isitsecure.engine.fixes.fix_generator import FixGenerator
from isitsecure.engine.identity import finding_fingerprint, legacy_fingerprint
from isitsecure.engine.models import CodeLocation, DeepFinding, FindingSource
from isitsecure.engine.shared.scanner_runner import reset_failure_log, use_failure_log

PY_VULN = (
    "import sqlite3\n"
    "\n"
    "def get(uid):\n"
    "    db = sqlite3.connect('x')\n"
    "    return db.execute('select * from t where id=' + uid)\n"
)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _snippet(line_no: int, text: str) -> str:
    """Code-context shape the extractor produces: '>>>' marks the flagged line."""
    return f"{line_no - 1} |   # above\n{line_no} >>> {text}\n{line_no + 1} |   # below"


def _finding(*, file_path="app.py", title="SQL injection", flagged="return db.execute(q + uid)",
             line=5, scanner="semgrep_taint") -> DeepFinding:
    return DeepFinding(
        source=FindingSource.SAST_CODE, category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.HIGH, title=title, description="d", confidence=0.9,
        scanner_name=scanner,
        code_location=CodeLocation(
            file_path=file_path, line_number=line, code_snippet=_snippet(line, flagged)
        ),
    )


def _as_dict(f: DeepFinding) -> dict:
    d = f.model_dump(mode="json")
    d["fingerprint"] = finding_fingerprint(f)
    return d


class _Repo:
    def __init__(self, path):
        self.clone_path = str(path)
        self.file_index = {}


# --------------------------------------------------------------------------
# F1: semgrep must not fail silently
# --------------------------------------------------------------------------

class TestSemgrepSilentFailure:
    @pytest.fixture
    def log(self):
        entries: list[str] = []
        token = use_failure_log(entries)
        yield entries
        reset_failure_log(token)

    @pytest.fixture
    def py_repo(self, tmp_path):
        (tmp_path / "app.py").write_text(PY_VULN)
        return _Repo(tmp_path)

    async def test_missing_semgrep_normal_scan_is_not_a_failure(self, monkeypatch, py_repo, log):
        """Optional extra: a default scan stays complete (grade not provisional)."""
        monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: None))
        assert await SemgrepAnalyzer().scan(py_repo) == []
        assert log == []

    async def test_missing_semgrep_in_verification_is_recorded(self, monkeypatch, py_repo, log):
        monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: None))
        with require_semgrep():
            assert await SemgrepAnalyzer().scan(py_repo) == []
        assert len(log) == 1 and log[0].startswith("semgrep_taint: ")
        # the context manager does not leak into later scans
        log.clear()
        assert await SemgrepAnalyzer().scan(py_repo) == []
        assert log == []

    async def test_no_covered_language_is_never_an_error(self, monkeypatch, tmp_path, log):
        (tmp_path / "README.md").write_text("# hi\n")
        monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: None))
        with require_semgrep():
            assert await SemgrepAnalyzer().scan(_Repo(tmp_path)) == []
        assert log == []

    async def test_empty_output_is_recorded(self, monkeypatch, py_repo, log):
        class Proc:
            returncode = 0

            async def communicate(self):
                return b"", b"boom"

        async def fake_exec(*a, **k):
            return Proc()

        monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: "/bin/semgrep"))
        monkeypatch.setattr(SA.asyncio, "create_subprocess_exec", fake_exec)
        assert await SemgrepAnalyzer().scan(py_repo) == []
        assert any("no output" in e for e in log)

    async def test_crash_invalid_json_is_recorded(self, monkeypatch, py_repo, log):
        class Proc:
            returncode = 1

            async def communicate(self):
                return b"not json", b""

        async def fake_exec(*a, **k):
            return Proc()

        monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: "/bin/semgrep"))
        monkeypatch.setattr(SA.asyncio, "create_subprocess_exec", fake_exec)
        assert await SemgrepAnalyzer().scan(py_repo) == []
        assert any(e.startswith("semgrep_taint: ") for e in log)

    async def test_timeout_is_recorded(self, monkeypatch, py_repo, log):
        class Proc:
            returncode = None

            async def communicate(self):
                await asyncio.sleep(30)

            def kill(self):
                self.returncode = -9

            async def wait(self):
                return -9

        async def fake_exec(*a, **k):
            return Proc()

        monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: "/bin/semgrep"))
        monkeypatch.setattr(SA.asyncio, "create_subprocess_exec", fake_exec)
        monkeypatch.setattr(SA, "_SCAN_TIMEOUT_S", 0.05)
        assert await SemgrepAnalyzer().scan(py_repo) == []
        assert any("timed out" in e for e in log)

    async def test_verification_rescan_with_missing_semgrep_cannot_verify(
        self, monkeypatch, tmp_path
    ):
        """End to end through the real re-scan: absent semgrep != resolved."""
        (tmp_path / "app.py").write_text(PY_VULN)
        monkeypatch.setattr(SemgrepAnalyzer, "_find_semgrep", staticmethod(lambda: None))
        rescan = await V._rescan_sast_findings(str(tmp_path))
        assert any(e.startswith("semgrep_taint: ") for e in rescan.scanner_errors)

        result = await V.verify_findings_resolved(str(tmp_path), [_finding()])
        assert result.resolved == 0
        assert result.could_not_verify is True
        assert result.unverifiable == 1


class TestOsvUnreachableIsReported:
    async def test_unreachable_osv_surfaces_as_scanner_error(self, monkeypatch):
        """OSV outages already reach scanner_errors via unchecked_packages."""
        from isitsecure.engine.code_analysis.osv_dependency_scanner import OSVDependencyScanner
        from isitsecure.engine.shared.scanner_runner import record_skipped_work

        scanner = OSVDependencyScanner()

        class Repo:
            file_index = {"requirements.txt": "flask==0.1\n"}

        async def boom(self, deps):
            self.unchecked_packages += len(deps)
            return []

        monkeypatch.setattr(OSVDependencyScanner, "_query_batch", boom)
        entries: list[str] = []
        token = use_failure_log(entries)
        try:
            assert await scanner.scan(Repo()) == []
            record_skipped_work(scanner.scanner_name, scanner)
        finally:
            reset_failure_log(token)
        assert entries and entries[0].startswith("osv_dependency_scanner: ")
        failed, unmapped = V.failed_scanner_names(entries)
        assert V.failure_blocks("osv_dependency_scanner", failed, unmapped)


# --------------------------------------------------------------------------
# F2: per-finding reverify survives a cosmetic edit of the flagged line
# --------------------------------------------------------------------------

class TestReverifyFingerprints:
    def test_precondition_edit_changes_v2_but_not_legacy(self):
        before = _finding(flagged="return db.execute(q + uid)")
        after = _finding(flagged="return db.execute(q + str(uid))")
        assert finding_fingerprint(before) != finding_fingerprint(after)
        assert legacy_fingerprint(before) == legacy_fingerprint(after)

    async def test_edited_but_still_vulnerable_line_is_still_present(self, monkeypatch):
        before = _finding(flagged="return db.execute(q + uid)")
        after = _finding(flagged="return db.execute(q + str(uid))")
        rescan = V.RescanFindings([_as_dict(after)], [])
        monkeypatch.setattr(V, "_rescan_sast_findings", AsyncMock(return_value=rescan))

        verdicts = await R.reverify_findings([before], repo_path="repo")
        assert verdicts[0].status == R.VerifyStatus.STILL_PRESENT

    async def test_genuinely_gone_is_fixed(self, monkeypatch):
        before = _finding()
        monkeypatch.setattr(
            V, "_rescan_sast_findings", AsyncMock(return_value=V.RescanFindings([], []))
        )
        verdicts = await R.reverify_findings([before], repo_path="repo")
        assert verdicts[0].status == R.VerifyStatus.FIXED

    async def test_semgrep_failure_in_rescan_is_could_not_verify(self, monkeypatch):
        rescan = V.RescanFindings([], ["semgrep_taint: semgrep timed out after 120s"])
        monkeypatch.setattr(V, "_rescan_sast_findings", AsyncMock(return_value=rescan))
        verdicts = await R.reverify_findings([_finding()], repo_path="repo")
        assert verdicts[0].status == R.VerifyStatus.COULD_NOT_VERIFY


# --------------------------------------------------------------------------
# F4: verifier resolution semantics
# --------------------------------------------------------------------------

class TestVerifierSemantics:
    def test_edited_line_same_file_is_still_present(self):
        before = _finding(flagged="return db.execute(q + uid)")
        after = _finding(flagged="return db.execute(q + str(uid))")
        still, moved, gone = V.classify_against_rescan([before], [_as_dict(after)])
        assert (len(still), len(moved), len(gone)) == (1, 0, 0)

    def test_nothing_remaining_is_resolved(self):
        still, moved, gone = V.classify_against_rescan([_finding()], [])
        assert (len(still), len(moved), len(gone)) == (0, 0, 1)

    def test_moved_to_other_file_is_not_resolved(self):
        before = _finding(file_path="a.py")
        relocated = _finding(file_path="b.py", flagged="return db.execute(q + uid)")
        still, moved, gone = V.classify_against_rescan([before], [_as_dict(relocated)])
        assert (len(still), len(moved), len(gone)) == (0, 1, 0)

    def test_same_title_elsewhere_with_different_code_is_not_a_move(self):
        before = _finding(file_path="a.py", flagged="return db.execute(q + uid)")
        other = _finding(file_path="b.py", flagged="return other.run(x)")
        _still, moved, gone = V.classify_against_rescan([before], [_as_dict(other)])
        assert (len(moved), len(gone)) == (0, 1)

    def test_two_instances_one_fixed_credits_exactly_one(self):
        a = _finding(flagged="return db.execute(q + a)", line=5)
        b = _finding(flagged="return db.execute(q + b)", line=9)
        # the second instance remains in the re-scan, the first is gone
        still, _moved, gone = V.classify_against_rescan([a, b], [_as_dict(b)])
        assert [f.code_location.line_number for f in still] == [9]
        assert [f.code_location.line_number for f in gone] == [5]

    def test_duplicates_without_marker_are_matched_as_multiset(self):
        def plain(line):
            f = _finding(line=line)
            f.code_location.code_snippet = "no marker here"
            return f

        a, b = plain(3), plain(8)
        still, _m, gone = V.classify_against_rescan([a, b], [_as_dict(b)])
        assert (len(still), len(gone)) == (1, 1)

    async def test_verify_findings_resolved_reports_moved_as_unverifiable(self, monkeypatch):
        before = _finding(file_path="a.py")
        relocated = _finding(file_path="b.py")
        monkeypatch.setattr(
            V, "_rescan_sast_findings",
            AsyncMock(return_value=V.RescanFindings([_as_dict(relocated)], [])),
        )
        res = await V.verify_findings_resolved("repo", [before])
        assert res.resolved == 0 and res.still_present == 0
        assert res.unverifiable == 1
        assert res.possibly_moved_titles == [before.title]

    async def test_verify_findings_resolved_edited_line_still_present(self, monkeypatch):
        before = _finding(flagged="return db.execute(q + uid)")
        after = _finding(flagged="return db.execute(q + str(uid))")
        monkeypatch.setattr(
            V, "_rescan_sast_findings",
            AsyncMock(return_value=V.RescanFindings([_as_dict(after)], [])),
        )
        res = await V.verify_findings_resolved("repo", [before])
        assert (res.resolved, res.still_present) == (0, 1)

    async def test_failed_scanner_blocks_gone(self, monkeypatch):
        monkeypatch.setattr(
            V, "_rescan_sast_findings",
            AsyncMock(return_value=V.RescanFindings([], ["semgrep_taint: semgrep timed out"])),
        )
        res = await V.verify_findings_resolved("repo", [_finding()])
        assert res.resolved == 0 and res.could_not_verify is True


# --------------------------------------------------------------------------
# F3 / F8 / F13: fix generator
# --------------------------------------------------------------------------

BIG_PY = "".join(f"def f{i}(x):\n    return x + {i}\n\n" for i in range(40))


def _reply(code: str, lang="python") -> str:
    return f"Parametrised the query.\n```{lang}\n{code}\n```"


def _gen(finding, content, reply):
    llm = AsyncMock()
    llm.generate_with_system = AsyncMock(return_value=reply)
    return FixGenerator(llm).generate_fix(finding, content)


class TestFixReplyValidation:
    @pytest.mark.parametrize("placeholder", [
        "# ... rest of file unchanged ...",
        "# ... existing code ...",
        "// ... rest of the file ...",
        "...",
        "    # rest of the code remains the same",
    ])
    async def test_elided_reply_rejected(self, placeholder):
        fixed = BIG_PY.replace("def f39", f"{placeholder}\ndef f39")
        res = await _gen(_finding(file_path="m.py"), BIG_PY, _reply(fixed))
        assert not res.success
        assert "placeholder" in res.error

    async def test_placeholder_already_in_original_is_not_flagged(self):
        original = "# ... rest of file unchanged ...\n" + BIG_PY
        fixed = original.replace("return x + 1\n", "return x + 1000\n")
        res = await _gen(_finding(file_path="m.py"), original, _reply(fixed))
        assert res.success, res.error

    async def test_ordinary_new_comment_is_fine(self):
        fixed = BIG_PY.replace(
            "def f1(x):\n", "def f1(x):\n    # the value stays unchanged for callers\n"
        )
        res = await _gen(_finding(file_path="m.py"), BIG_PY, _reply(fixed))
        assert res.success, res.error

    async def test_much_shorter_reply_rejected(self):
        res = await _gen(_finding(file_path="m.py"), BIG_PY, _reply(BIG_PY[: len(BIG_PY) // 2]))
        assert not res.success and "truncated" in res.error

    async def test_broken_python_rejected(self):
        fixed = BIG_PY.replace("return x + 1\n", "return (x + 1\n")
        res = await _gen(_finding(file_path="m.py"), BIG_PY, _reply(fixed))
        assert not res.success and "syntax" in res.error

    async def test_broken_json_rejected(self):
        original = '{\n  "a": 1,\n  "b": 2\n}\n' * 1
        res = await _gen(_finding(file_path="c.json"), original, _reply('{\n  "a": 1,\n', "json"))
        assert not res.success

    async def test_unparseable_original_is_not_blocked_by_checker(self):
        original = "def f(:\n    pass\n" * 30
        fixed = original.replace("pass", "return 1", 1)
        res = await _gen(_finding(file_path="m.py"), original, _reply(fixed))
        assert res.success, res.error

    async def test_unknown_language_skips_syntax_check(self):
        original = "class A {\n  void f() { run(a + b); }\n}\n" * 3
        fixed = original.replace("a + b", "a, b", 1)
        res = await _gen(_finding(file_path="A.java"), original, _reply(fixed, "java"))
        assert res.success, res.error

    async def test_cut_off_reply_gives_clear_message(self):
        reply = "Fixed it.\n```python\n" + BIG_PY[:300]  # fence never closes
        res = await _gen(_finding(file_path="m.py"), BIG_PY, reply)
        assert not res.success
        assert "cut off" in res.error and "output limit" in res.error


class TestChainedFixesDoNotReuseStaleLines:
    async def test_second_prompt_drops_line_numbers_after_a_change(self):
        prompts: list[str] = []
        content = BIG_PY

        async def fake(system_prompt, user_prompt, max_tokens):
            prompts.append(user_prompt)
            return _reply(content.replace("return x + 3\n", "return x + 3000\n", len(prompts)))

        llm = AsyncMock()
        llm.generate_with_system = fake
        f1 = _finding(file_path="m.py", title="First", line=2)
        f2 = _finding(file_path="m.py", title="Second", line=5)
        plan = await FixGenerator(llm).generate_file_fixes([f1, f2], {"m.py": content})
        assert len(prompts) == 2
        assert "m.py:2" in prompts[0]
        assert "m.py:5" not in prompts[1] and "**File:** m.py" in prompts[1]
        assert plan.files  # chain produced a result


# --------------------------------------------------------------------------
# F8: the diff must be a patch git accepts
# --------------------------------------------------------------------------

def _git(cwd, *args, **kw):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, **kw)


def _apply_check(tmp_path, rel, original: bytes, diff: str):
    _git(tmp_path, "init", "-q")
    target = tmp_path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(original)
    patch = tmp_path / "fix.patch"
    patch.write_bytes(diff.encode("utf-8"))
    return _git(tmp_path, "apply", "--check", "fix.patch")


class TestDiffApplies:
    async def test_lf_file(self, tmp_path):
        fixed = PY_VULN.replace("'select * from t where id=' + uid",
                                "'select * from t where id=?', (uid,)")
        res = await _gen(_finding(file_path="pkg/app.py"), PY_VULN, _reply(fixed.rstrip("\n")))
        assert res.success, res.error
        out = _apply_check(tmp_path, "pkg/app.py", PY_VULN.encode(), res.diff)
        assert out.returncode == 0, out.stderr

    async def test_diff_has_no_doubled_newlines(self):
        fixed = PY_VULN.replace("+ uid)", "+ str(uid))")
        res = await _gen(_finding(file_path="app.py"), PY_VULN, _reply(fixed.rstrip("\n")))
        assert res.success, res.error
        assert "\n\n" not in res.diff.rstrip("\n")
        assert res.diff.startswith("--- a/app.py\n+++ b/app.py\n@@ ")

    async def test_original_without_trailing_newline(self, tmp_path):
        original = PY_VULN.rstrip("\n")
        fixed = original.replace("+ uid)", "+ str(uid))")
        res = await _gen(_finding(file_path="app.py"), original, _reply(fixed))
        assert res.success, res.error
        assert "\\ No newline at end of file" in res.diff
        out = _apply_check(tmp_path, "app.py", original.encode(), res.diff)
        assert out.returncode == 0, out.stderr

    async def test_crlf_file(self, tmp_path):
        original = PY_VULN.replace("\n", "\r\n")
        fixed = PY_VULN.replace("+ uid)", "+ str(uid))")
        res = await _gen(_finding(file_path="app.py"), original, _reply(fixed.rstrip("\n")))
        assert res.success, res.error
        out = _apply_check(tmp_path, "app.py", original.encode(), res.diff)
        assert out.returncode == 0, out.stderr

    async def test_form_feed_in_source_does_not_shift_hunks(self, tmp_path):
        original = "a = 1\n\x0c\nb = db.execute('x' + uid)\n"
        fixed = "a = 1\n\x0c\nb = db.execute('x', (uid,))\n"
        res = await _gen(_finding(file_path="app.py"), original, _reply(fixed.rstrip("\n")))
        assert res.success, res.error
        out = _apply_check(tmp_path, "app.py", original.encode(), res.diff)
        assert out.returncode == 0, out.stderr
