"""Round 2: fix-flow file safety, verification honesty, GitHub URL parsing."""

from __future__ import annotations

import os
import subprocess
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from isitsecure.engine import reverify as R
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.fixes import fix_generator as FG
from isitsecure.engine.fixes import pr_flow, verifier
from isitsecure.engine.fixes.pr_flow import PRFlow, PRFlowResult, parse_github_url
from isitsecure.engine.models import CodeLocation, DeepFinding, FindingSource
from isitsecure.server import fix_service


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


def _repo(tmp_path, files: dict[str, bytes]):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "config", "core.autocrlf", "false")
    for rel, data in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    return repo


def _finding(path, scanner="semgrep_taint", title="SQLi"):
    return DeepFinding(
        source=FindingSource.SAST_CODE, category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.HIGH, title=title, description="d", confidence=0.9,
        scanner_name=scanner, code_location=CodeLocation(file_path=path, line_number=1),
    )


# --- #1 .git guard is case-insensitive ---------------------------------------

@pytest.mark.parametrize("rel", [
    ".GIT/hooks/pre-commit", ".Git/config", ".gIt/x", "sub/.GIT/config", ".GIT\\config",
])
def test_resolve_fix_target_refuses_case_variant_git(tmp_path, rel):
    repo = _repo(tmp_path, {"a.py": b"x\n"})
    with pytest.raises(ValueError, match=r"\.git"):
        FG.resolve_fix_target(str(repo), rel)


def test_resolve_fix_target_refuses_git_via_symlink_alias(tmp_path):
    repo = _repo(tmp_path, {"a.py": b"x\n"})
    (repo / "alias").symlink_to(repo / ".git")
    with pytest.raises(ValueError, match=r"\.git"):
        FG.resolve_fix_target(str(repo), "alias/config")


def test_resolve_fix_target_still_allows_normal_and_gitignore(tmp_path):
    repo = _repo(tmp_path, {"a.py": b"x\n"})
    assert FG.resolve_fix_target(str(repo), "a.py").endswith("a.py")
    assert FG.resolve_fix_target(str(repo), ".gitignore").endswith(".gitignore")


def test_write_source_file_preserves_bom(tmp_path):
    repo = _repo(tmp_path, {"a.py": b"\xef\xbb\xbfx = 1\r\n"})
    FG.write_source_file(str(repo), "a.py", "x = 2\r\n")  # generator dropped the BOM
    assert (repo / "a.py").read_bytes() == b"\xef\xbb\xbfx = 2\r\n"


def test_write_source_file_no_bom_added(tmp_path):
    repo = _repo(tmp_path, {"a.py": b"x = 1\n"})
    FG.write_source_file(str(repo), "a.py", "x = 2\n")
    assert (repo / "a.py").read_bytes() == b"x = 2\n"


# --- #2 fix_service apply path -------------------------------------------------

class _FakeGenerator:
    seen: dict = {}

    def __init__(self, *a, **k):
        pass

    async def generate_file_fixes(self, findings, contents, on_file_done=None):
        _FakeGenerator.seen = dict(contents)
        files = {p: c.replace("BAD", "GOOD").lstrip("﻿") for p, c in contents.items() if "BAD" in c}
        skipped = [f"{f.code_location.file_path} - source not available" for f in findings
                   if f.code_location.file_path not in contents]
        return SimpleNamespace(files=files, skipped=skipped, fixed_count=len(files))


async def _run_service(monkeypatch, repo, paths):
    monkeypatch.setattr(fix_service, "load_api_key", lambda p: "key")
    monkeypatch.setattr("isitsecure.llm.adapters.create_llm_client", lambda p, k: object())
    monkeypatch.setattr(fix_service, "FixGenerator", _FakeGenerator)
    monkeypatch.setattr(verifier, "verify_findings_resolved",
                        AsyncMock(return_value=verifier.VerifyResult(resolved=len(paths))))

    async def emit(e):
        pass

    report = {"repo_url": str(repo), "findings": [
        {"source": "sast_code", "category": "injection_risk", "severity": "high", "title": "SQLi",
         "description": "d", "scanner_name": "semgrep_taint", "confidence": 0.9,
         "code_location": {"file_path": p, "line_number": 1}} for p in paths]}
    return await fix_service.run_fix_all(report=report, llm_provider="anthropic", emit=emit)


async def test_service_preserves_crlf_and_bom_and_skips_non_utf8(tmp_path, monkeypatch):
    repo = _repo(tmp_path, {
        "crlf.py": b"a = BAD\r\nb = 1\r\n",
        "bom.py": b"\xef\xbb\xbfa = BAD\n",
        "latin.py": b"a = BAD  # caf\xe9\n",
    })
    res = await _run_service(monkeypatch, repo, ["crlf.py", "bom.py", "latin.py"])
    assert res["applied"] is True
    assert "latin.py" not in _FakeGenerator.seen  # non-UTF-8: never read lossily
    assert res["files_changed"] == ["bom.py", "crlf.py"]
    _git(repo, "checkout", "-q", res["branch"])
    assert (repo / "crlf.py").read_bytes() == b"a = GOOD\r\nb = 1\r\n"
    assert (repo / "bom.py").read_bytes() == b"\xef\xbb\xbfa = GOOD\n"
    assert (repo / "latin.py").read_bytes() == b"a = BAD  # caf\xe9\n"


async def test_service_refuses_dot_git_target(tmp_path, monkeypatch):
    repo = _repo(tmp_path, {"a.py": b"a = BAD\n"})
    (repo / ".git" / "hooks" / "pre-commit").write_text("BAD\n")
    res = await _run_service(monkeypatch, repo, [".GIT/hooks/pre-commit"])
    assert ".GIT/hooks/pre-commit" not in _FakeGenerator.seen
    assert res["applied"] is False
    assert (repo / ".git" / "hooks" / "pre-commit").read_text() == "BAD\n"


async def test_service_restores_detached_head(tmp_path, monkeypatch):
    repo = _repo(tmp_path, {"a.py": b"a = BAD\n"})
    sha = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "--detach", sha)
    res = await _run_service(monkeypatch, repo, ["a.py"])
    assert res["applied"] is True
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "HEAD"
    assert _git(repo, "rev-parse", "HEAD") == sha
    assert (repo / "a.py").read_bytes() == b"a = BAD\n"


async def test_service_restores_named_branch(tmp_path, monkeypatch):
    repo = _repo(tmp_path, {"a.py": b"a = BAD\n"})
    res = await _run_service(monkeypatch, repo, ["a.py"])
    assert _git(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert res["branch"].startswith("isitsecure/fixes")


async def test_service_aborts_without_backup(tmp_path, monkeypatch):
    repo = _repo(tmp_path, {"a.py": b"a = BAD\n"})
    from isitsecure.engine.fixes import safety_net
    monkeypatch.setattr(safety_net, "create_safety_net",
                        lambda *a, **k: safety_net.SafetyNet(kind="none", failed=["a.py"]))
    res = await _run_service(monkeypatch, repo, ["a.py"])
    assert res["applied"] is False and "backup" in res["message"].lower()
    assert _git(repo, "branch", "--list", "isitsecure/*") == ""
    assert (repo / "a.py").read_bytes() == b"a = BAD\n"


# --- #2 pr_flow apply path -----------------------------------------------------

class _PRGen:
    def __init__(self):
        self.seen = []

    async def generate_fix(self, finding, content):
        self.seen.append(content)
        return SimpleNamespace(success=True, fixed_code=content.replace("BAD", "GOOD").lstrip("﻿"), error="")


class _RecGit:
    def __init__(self):
        self.calls = []

    async def run(self, cwd, *args):
        self.calls.append(args)
        return ""


async def _pr_apply(tmp_path, rel, data):
    clone = tmp_path / "clone"
    clone.mkdir()
    (clone / ".git").mkdir()
    p = clone / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    gen, git, res = _PRGen(), _RecGit(), PRFlowResult()
    flow = PRFlow(gen, github_factory=lambda t: None, git_factory=lambda t: git, clone_fn=None)
    ok = await flow._apply_and_commit(finding=_finding(rel), clone_dir=str(clone), git=git, result=res)
    return ok, p, gen, git, res


async def test_pr_flow_preserves_crlf(tmp_path):
    ok, p, *_ = await _pr_apply(tmp_path, "a.py", b"a = BAD\r\nb = 1\r\n")
    assert ok and p.read_bytes() == b"a = GOOD\r\nb = 1\r\n"


async def test_pr_flow_preserves_bom(tmp_path):
    ok, p, *_ = await _pr_apply(tmp_path, "a.py", b"\xef\xbb\xbfa = BAD\n")
    assert ok and p.read_bytes() == b"\xef\xbb\xbfa = GOOD\n"


async def test_pr_flow_skips_non_utf8(tmp_path):
    ok, p, gen, git, res = await _pr_apply(tmp_path, "a.py", b"a = BAD # caf\xe9\n")
    assert not ok and gen.seen == [] and git.calls == []
    assert p.read_bytes() == b"a = BAD # caf\xe9\n"
    assert res.skipped


async def test_pr_flow_refuses_dot_git_case_variant(tmp_path):
    ok, p, gen, git, res = await _pr_apply(tmp_path, ".GIT/hooks/pre-commit", b"BAD\n")
    assert not ok and gen.seen == [] and git.calls == []
    assert p.read_bytes() == b"BAD\n"


# --- #5 scanner_errors make findings unverifiable ------------------------------

def _stub_rescan_report(monkeypatch, findings, scanner_errors):
    import isitsecure.engine.factory as F

    class _Agent:
        async def scan(self, **kw):
            yield SimpleNamespace(message="", data={"report": {"findings": findings,
                                                               "scanner_errors": scanner_errors}})

    monkeypatch.setattr(F, "create_repo_ingestion_service", lambda: object())
    monkeypatch.setattr(F, "create_deep_security_scan_agent", lambda **k: _Agent())


async def test_verifier_failed_scanner_is_unverifiable_not_resolved(monkeypatch):
    _stub_rescan_report(monkeypatch, [], ["semgrep_taint: timed out"])
    r = await verifier.verify_findings_resolved("/x", [_finding("a.py")])
    assert r.resolved == 0 and r.still_present == 0
    assert r.unverifiable == 1 and r.could_not_verify is True
    assert "semgrep_taint" in r.error


async def test_verifier_unrelated_scanner_failure_keeps_resolved(monkeypatch):
    _stub_rescan_report(monkeypatch, [], ["other_scanner: failed"])
    r = await verifier.verify_findings_resolved("/x", [_finding("a.py")])
    assert r.resolved == 1 and r.unverifiable == 0 and r.could_not_verify is False


async def test_verifier_unmappable_error_marks_everything_unverified(monkeypatch):
    _stub_rescan_report(monkeypatch, [], ["something odd without a colon"])
    r = await verifier.verify_findings_resolved("/x", [_finding("a.py")])
    assert r.resolved == 0 and r.unverifiable == 1


async def test_verifier_still_present_survives_scanner_errors(monkeypatch):
    f = _finding("a.py")
    d = {"scanner_name": f.scanner_name, "category": "injection_risk",
         "code_location": {"file_path": "a.py"}, "title": "SQLi"}
    _stub_rescan_report(monkeypatch, [d], ["semgrep_taint: failed"])
    r = await verifier.verify_findings_resolved("/x", [f])
    assert r.still_present == 1 and r.resolved == 0


async def test_reverify_failed_scanner_is_could_not_verify(monkeypatch):
    _stub_rescan_report(monkeypatch, [], ["semgrep_taint: timed out"])
    (v,) = await R.reverify_findings([_finding("a.py")], repo_path="/x")
    assert v.status == R.VerifyStatus.COULD_NOT_VERIFY
    assert "semgrep_taint" in v.detail


async def test_reverify_unrelated_failure_still_fixed(monkeypatch):
    _stub_rescan_report(monkeypatch, [], ["other: failed"])
    (v,) = await R.reverify_findings([_finding("a.py")], repo_path="/x")
    assert v.status == R.VerifyStatus.FIXED


# --- #10 parse_github_url ------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://github.com/o/../r",
    "https://github.com/./r",
    "https://github.com/o/..",
    "https://github.com/o/r\n",
    "https://github.com/o/r\t",
    "https://github.com/o/\tr",
    "https://github.com/o/r\x00",
    "https://github.com:abc/o/r",
    "https://github.com:99999/o/r",
    "https://github.com:8443/o/r",
    "https://github.com:/o/r/extra",
    "https://github.com/o/r.git.git",
    "git@github.com:o/r.git.git",
    "git@github.com:o/../r",
])
def test_parse_github_url_rejects(url):
    with pytest.raises(ValueError):
        parse_github_url(url)


def test_parse_github_url_accepts_default_port_and_normal():
    assert parse_github_url("https://github.com:443/o/r").slug == "o/r"
    assert parse_github_url("https://github.com/o/r.git").repo == "r"
    assert parse_github_url("HTTPS://GitHub.com/o/r").is_github
    assert parse_github_url("  https://github.com/o/r  ").slug == "o/r"


def test_normalize_repo_scheme_lowercases_only_scheme():
    assert pr_flow.normalize_repo_scheme("HTTPS://github.com/O/R") == "https://github.com/O/R"
    assert pr_flow.normalize_repo_scheme("https://github.com/o/r") == "https://github.com/o/r"
    assert pr_flow.normalize_repo_scheme("git@github.com:o/r") == "git@github.com:o/r"


async def test_flow_clones_with_lowercased_scheme(tmp_path):
    seen = {}

    async def clone(url, branch, d, tok):
        seen["url"] = url
        raise RuntimeError("stop")

    class _GH:
        async def get_default_branch(self, ref):
            return "main"

    flow = PRFlow(_PRGen(), github_factory=lambda t: _GH(), git_factory=lambda t: _RecGit(), clone_fn=clone)
    try:
        await flow.run(repo_url="HTTPS://github.com/o/r", findings=[_finding("a.py")], github_token="tok")
    except Exception:
        pass
    assert seen.get("url") == "https://github.com/o/r"
