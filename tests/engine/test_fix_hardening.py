"""Hardening of the fix/verify flow: honest "could not check", safe file IO."""

from __future__ import annotations

import inspect
import os
import stat
import subprocess
from unittest.mock import AsyncMock

import pytest

from isitsecure.engine import reverify as R
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.fixes import fix_generator as FG
from isitsecure.engine.fixes import plain_results, verifier
from isitsecure.engine.fixes.fix_generator import FixGenerator
from isitsecure.engine.fixes.safety_net import create_safety_net
from isitsecure.engine.models import CodeLocation, DeepFinding, FindingSource


def _sast(file_path="app/db.py", title="SQLi"):
    return DeepFinding(
        source=FindingSource.SAST_CODE, category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.HIGH, title=title, description="d", confidence=0.9,
        scanner_name="semgrep_taint", code_location=CodeLocation(file_path=file_path, line_number=3),
    )


def _dast():
    return DeepFinding(
        source=FindingSource.DAST_URL, category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.MEDIUM, title="Missing headers", description="d", confidence=0.9,
        scanner_name="security_headers_scanner", endpoint_url="http://127.0.0.1:9/", http_method="GET",
    )


# --- verifier: a failed re-scan must never read as "resolved" -----------------

class _Evt:
    def __init__(self, message="", data=None):
        self.message, self.data = message, data


class _AbortAgent:
    async def scan(self, **kw):
        yield _Evt("Repository ingestion failed: boom", {"error": True})


async def test_rescan_without_report_raises(monkeypatch):
    import isitsecure.engine.factory as F
    monkeypatch.setattr(F, "create_repo_ingestion_service", lambda: object())
    monkeypatch.setattr(F, "create_deep_security_scan_agent", lambda **k: _AbortAgent())
    with pytest.raises(verifier.RescanFailed, match="ingestion failed"):
        await verifier._rescan_sast_findings("/nonexistent")


async def test_verify_findings_aborted_rescan_counts_nothing_resolved(monkeypatch):
    monkeypatch.setattr(verifier, "_rescan_sast_findings",
                        AsyncMock(side_effect=verifier.RescanFailed("Repository ingestion failed: boom")))
    r = await verifier.verify_findings_resolved("/x", [_sast()])
    assert r.resolved == 0 and r.still_present == 0
    assert r.could_not_verify is True and "ingestion failed" in r.error
    assert r.to_dict()["could_not_verify"] is True


def test_plain_results_says_check_did_not_run():
    counts = plain_results.classify_verification(
        attempted=2, fix_failed=0,
        verification={"resolved": 0, "still_present": 0, "unverifiable": 2,
                      "error": "Repository ingestion failed", "could_not_verify": True},
    )
    assert counts.fixed == 0 and counts.needs_review == 2
    text = plain_results.summarize(counts)
    assert "did not run" in text and "none of them are confirmed fixed" in text
    assert "did not run" in plain_results.next_step_hint(counts)


# --- reverify: could-not-verify is distinct and never FIXED -------------------

async def test_reverify_sast_rescan_failure_is_could_not_verify(monkeypatch):
    monkeypatch.setattr(R, "_sast_present_fingerprints",
                        AsyncMock(side_effect=verifier.RescanFailed("ingestion failed")))
    (v,) = await R.reverify_findings([_sast()], repo_path="/x")
    assert v.status == R.VerifyStatus.COULD_NOT_VERIFY
    assert v.status != R.VerifyStatus.FIXED


async def test_reverify_dast_unreachable_target_is_could_not_verify(monkeypatch):
    monkeypatch.setattr(R, "_target_reachable", AsyncMock(return_value=False))
    monkeypatch.setattr(R, "_dast_scanners_by_name", lambda: pytest.fail("must not probe"))
    (v,) = await R.reverify_findings([_dast()], target_url="http://127.0.0.1:9")
    assert v.status == R.VerifyStatus.COULD_NOT_VERIFY


async def test_target_reachable_false_on_closed_port():
    assert await R._target_reachable("http://127.0.0.1:9") is False


# --- fix_generator ------------------------------------------------------------

def _llm(reply):
    m = AsyncMock()
    m.generate_with_system.return_value = reply
    return m


async def test_inner_fence_in_file_does_not_truncate():
    original = "doc = '''\n```python\nprint(1)\n```\n'''\nx = 1\n"
    fixed = original.replace("x = 1", "x = 2")
    reply = f"Changed x.\n\n```python\n{fixed}```"
    res = await FixGenerator(_llm(reply)).generate_fix(_sast(), original)
    assert res.success and res.fixed_code == fixed


async def test_inner_bare_fence_in_file_does_not_truncate():
    original = "doc = '''\n```\nprint(1)\n```\n'''\nx = 1\n"
    fixed = original.replace("x = 1", "x = 2")
    reply = f"Changed x.\n\n```python\n{fixed}```"
    res = await FixGenerator(_llm(reply)).generate_fix(_sast(), original)
    assert res.success and res.fixed_code == fixed


async def test_ambiguous_blocks_rejected_when_original_has_no_fence():
    reply = "ok\n```python\na = 1\n```\nand also\n```python\nb = 2\n```"
    res = await FixGenerator(_llm(reply)).generate_fix(_sast(), "a = 0\n")
    assert not res.success


async def test_identical_answer_is_no_change_even_without_trailing_newline():
    original = "    indented()\nx = 1\n"
    res = await FixGenerator(_llm(f"same\n```python\n{original}```")).generate_fix(_sast(), original)
    assert not res.success and "no changes" in res.error.lower()


async def test_trailing_newline_and_indent_preserved():
    original = "    a = 1\n    b = 2\n"
    reply = "```python\n    a = 1\n    b = 3\n```"
    res = await FixGenerator(_llm(reply)).generate_fix(_sast(), original)
    assert res.success and res.fixed_code == "    a = 1\n    b = 3\n"
    res2 = await FixGenerator(_llm(reply)).generate_fix(_sast(), "    a = 1\n    b = 2")
    assert res2.fixed_code == "    a = 1\n    b = 3"


async def test_crlf_preserved():
    original = "a = 1\r\nb = 2\r\n"
    reply = "```python\na = 1\nb = 3\n```"
    res = await FixGenerator(_llm(reply)).generate_fix(_sast(), original)
    assert res.success and res.fixed_code == "a = 1\r\nb = 3\r\n"


async def test_truncated_reply_is_rejected():
    original = "x = 1\n" * 200
    res = await FixGenerator(_llm("```python\nx = 1\n```")).generate_fix(_sast(), original)
    assert not res.success and "truncat" in res.error.lower()


def test_read_source_rejects_non_utf8_and_keeps_crlf(tmp_path):
    (tmp_path / "bin.py").write_bytes(b"x = '\xff\xfe'\n")
    (tmp_path / "crlf.py").write_bytes(b"a\r\nb\r\n")
    assert FG.read_source_file(str(tmp_path), "bin.py") is None
    assert FG.read_source_file(str(tmp_path), "crlf.py") == "a\r\nb\r\n"


def test_write_source_keeps_crlf(tmp_path):
    FG.write_source_file(str(tmp_path), "w.py", "a\r\nb\r\n")
    assert (tmp_path / "w.py").read_bytes() == b"a\r\nb\r\n"


@pytest.mark.parametrize("rel", [".git/config", "sub/.git/hooks/x", "../outside.py", "/etc/passwd"])
def test_fix_paths_refuse_git_and_outside(tmp_path, rel):
    with pytest.raises(ValueError):
        FG.resolve_fix_target(str(tmp_path), rel)
    assert FG.read_source_file(str(tmp_path), rel) is None


# --- safety net ---------------------------------------------------------------

def _git_repo(tmp_path):
    repo = str(tmp_path)
    for a in (("init",), ("config", "user.email", "t@t.co"), ("config", "user.name", "t")):
        subprocess.run(["git", "-C", repo, *a], check=True, capture_output=True)
    (tmp_path / "tracked.py").write_text("t\n")
    subprocess.run(["git", "-C", repo, "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", repo, "commit", "-m", "i"], check=True, capture_output=True)
    return repo


def test_untracked_file_is_backed_up(tmp_path):
    repo = _git_repo(tmp_path)
    (tmp_path / "new.py").write_text("untracked original\n")
    net = create_safety_net(repo, ["tracked.py", "new.py"])
    assert net.kind == "copy"
    assert open(os.path.join(net.location, "new.py")).read() == "untracked original\n"
    assert "nothing was lost" not in net.restore_hint


def test_git_hint_does_not_overclaim(tmp_path):
    repo = _git_repo(tmp_path)
    net = create_safety_net(repo, ["tracked.py"])
    assert net.kind == "git" and "nothing was lost" not in net.restore_hint


# --- config: 0600 from creation ----------------------------------------------

def test_write_secret_file_is_0600_from_creation(tmp_path, monkeypatch):
    from isitsecure.cli import config as C
    seen = {}
    real_open = os.open

    def spy(path, flags, mode=0o777, **kw):
        seen["mode"] = mode
        return real_open(path, flags, mode, **kw)

    monkeypatch.setattr(os, "open", spy)
    p = tmp_path / "config.toml"
    C.write_secret_file(p, "k = 1\n")
    assert seen["mode"] == 0o600
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_write_secret_file_tightens_existing_loose_file(tmp_path):
    from isitsecure.cli import config as C
    p = tmp_path / "config.toml"
    p.write_text("old")
    os.chmod(p, 0o644)
    C.write_secret_file(p, "new")
    assert stat.S_IMODE(p.stat().st_mode) == 0o600 and p.read_text() == "new"


# --- fix CLI: key per provider -----------------------------------------------

def test_api_key_option_has_no_provider_specific_envvar():
    from isitsecure.cli.fix_cmd import fix
    opt = inspect.signature(fix).parameters["api_key"].default
    assert not opt.envvar


def test_google_provider_never_gets_anthropic_key(monkeypatch):
    import typer
    from isitsecure.cli import fix_cmd

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.setattr(fix_cmd, "_load_api_key", lambda p: None if p == "google" else "x")
    with pytest.raises(typer.Exit):
        fix_cmd.fix(repo="/nonexistent", llm_provider="google", api_key=None, dry_run=True,
                    severity="high", technical=False, github_token=None,
                    pr_strategy="per-category", max_prs=8, verbose=False)
