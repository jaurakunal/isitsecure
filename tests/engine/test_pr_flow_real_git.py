"""PR flow against REAL git and a local bare "GitHub" remote.

Only the GitHub REST client is faked. Everything git does (clone, branch,
commit, ls-remote, push, hooks, rejections, timeouts) is the real thing, so the
failure modes the unit fakes cannot express (branch collisions, orphaned
branches after a failed PR, hook rejections, token leakage into ``.git/config``
or argv, hung commands) are exercised for real.
"""

from __future__ import annotations

import asyncio
import os
import stat
import subprocess
import time

import httpx
import pytest

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.fixes import git_ops, pr_flow
from isitsecure.engine.fixes.fix_generator import FixResult
from isitsecure.engine.fixes.git_ops import (
    GitError,
    GitRunner,
    GitTimeoutError,
    build_git_env,
    is_non_fast_forward,
)
from isitsecure.engine.fixes.pr_flow import (
    GitHubClient,
    PRFlow,
    RepoAccessError,
    RepoRef,
    group_findings,
    pr_body,
)
from isitsecure.engine.models import CodeLocation, DeepFinding, FindingSource

TOKEN = "ghp_TOKENabcdefghijklmnopqrstuvwxyz0123"
REPO_URL = "https://github.com/octo/app"


# ---------------------------------------------------------------------------
# Real-git fixtures / helpers
# ---------------------------------------------------------------------------

def _env(**extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    env.update(extra)
    return env


def sh(*args, cwd=None, check=True):
    """Run real git as the test harness (fixed identity, no user config)."""
    proc = subprocess.run(
        ["git", "-c", "user.name=Seed", "-c", "user.email=seed@example.com", *args],
        cwd=cwd, env=_env(), capture_output=True, text=True,
    )
    if check and proc.returncode != 0:
        raise AssertionError(f"git {args} failed: {proc.stderr}")
    return proc.stdout.strip()


@pytest.fixture(autouse=True)
def _clean_git_config(monkeypatch):
    # The flow must work with NO user identity/config on the machine (CI,
    # containers), and must not pick up a developer's hooks or gpg settings.
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


@pytest.fixture
def origin(tmp_path):
    """A bare remote with ``main`` (a.py, a_b.py, a-b.py ...) and ``develop``."""
    bare = tmp_path / "origin.git"
    seed = tmp_path / "seed"
    sh("init", "-q", "--bare", "-b", "main", str(bare))
    sh("init", "-q", "-b", "main", str(seed))
    for rel in ("a.py", "b.py", "src/a_b.py", "src/a-b.py", "we`ird.py", "real.py"):
        path = seed / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("print('original')\n")
    os.symlink("real.py", seed / "link.py")
    sh("add", "-A", cwd=seed)
    sh("commit", "-q", "-m", "seed", cwd=seed)
    sh("remote", "add", "origin", str(bare), cwd=seed)
    sh("push", "-q", "origin", "main", cwd=seed)
    sh("checkout", "-q", "-b", "develop", cwd=seed)
    (seed / "dev_only.py").write_text("print('dev')\n")
    sh("add", "-A", cwd=seed)
    sh("commit", "-q", "-m", "dev", cwd=seed)
    sh("push", "-q", "origin", "develop", cwd=seed)
    return str(bare)


def remote_heads(bare):
    out = sh("for-each-ref", "--format=%(refname:short)", "refs/heads", cwd=bare)
    return set(out.split())


def finding(path="a.py", title="SQL injection", severity=SeverityLevel.HIGH,
            category=FindingCategory.INJECTION_RISK):
    return DeepFinding(
        source=FindingSource.SAST_CODE, category=category, severity=severity,
        title=title, description="d", scanner_name="s", confidence=0.9,
        code_location=CodeLocation(file_path=path, line_number=1, code_snippet="x"),
    )


class AppendGenerator:
    def __init__(self, fixed=None):
        self.calls = 0
        self._fixed = fixed

    async def generate_fix(self, f, content):
        self.calls += 1
        new = content + "# fixed\n" if self._fixed is None else self._fixed(f, content)
        return FixResult(finding_id=f.id, file_path=f.code_location.file_path,
                         success=True, fixed_code=new)


class FakeGitHub:
    def __init__(self, default_branch="main"):
        self.default_branch = default_branch
        self.default_branch_calls = 0
        self.opened: list[dict] = []
        self.fail_open = False
        self.open_pr_url: str | None = None
        self.on_open = None

    async def get_default_branch(self, ref):
        self.default_branch_calls += 1
        return self.default_branch

    async def find_open_pr(self, ref, *, head, base):
        return self.open_pr_url

    async def open_pr(self, ref, *, title, body, head, base):
        if self.on_open:
            self.on_open()
        if self.fail_open:
            raise RuntimeError("GitHub PR creation failed (403): Resource not accessible")
        self.opened.append(dict(title=title, body=body, head=head, base=base))
        return f"https://github.com/octo/app/pull/{len(self.opened)}"


def make_flow(origin, github=None, generator=None, git=None, clone_dirs=None):
    github = github or FakeGitHub()
    generator = generator or AppendGenerator()

    def git_factory(tok):
        return git or GitRunner(tok, allow_protocol="file")

    async def clone(url, branch, dest, token):
        if clone_dirs is not None:
            clone_dirs.append(dest)
        await GitRunner(token, allow_protocol="file").run(
            os.path.dirname(dest), "clone", "-q", "--branch", branch, "--", origin, dest
        )

    flow = PRFlow(generator, github_factory=lambda t: github,
                  git_factory=git_factory, clone_fn=clone)
    return flow, github, generator


async def run(flow, findings, **kw):
    return await flow.run(repo_url=REPO_URL, findings=findings, github_token=TOKEN, **kw)


# ---------------------------------------------------------------------------
# 1. branch-name collisions
# ---------------------------------------------------------------------------

class TestBranchCollisions:
    async def test_colliding_slugs_get_distinct_branches_and_both_land(self, origin):
        assert pr_flow._slugify("src/a_b.py") == pr_flow._slugify("src/a-b.py")
        flow, github, _ = make_flow(origin)
        result = await run(flow, [finding("src/a_b.py", "t1"), finding("src/a-b.py", "t2")],
                           strategy="per-file")
        assert result.errors == []
        branches = {p.branch for p in result.opened_prs}
        assert len(branches) == 2
        assert branches <= remote_heads(origin)

    async def test_very_long_path_branch_is_bounded_and_pushes(self, origin, tmp_path):
        deep = "/".join(["d" * 60] * 6) + "/mod.py"
        seed = tmp_path / "seed2"
        sh("clone", "-q", origin, str(seed))
        (seed / deep).parent.mkdir(parents=True)
        (seed / deep).write_text("x = 1\n")
        sh("add", "-A", cwd=seed)
        sh("commit", "-q", "-m", "deep", cwd=seed)
        sh("push", "-q", "origin", "main", cwd=seed)
        flow, _, _ = make_flow(origin)
        result = await run(flow, [finding(deep)], strategy="per-file")
        assert result.errors == []
        assert len(result.opened_prs[0].branch.encode()) < 100

    def test_dedupe_is_a_safety_net_for_any_remaining_collision(self):
        groups = group_findings([finding("a.py"), finding("b.py")], strategy="per-file")
        groups[1].branch_suffix = groups[0].branch_suffix
        pr_flow._dedupe_branch_suffixes(groups)
        assert groups[0].branch_suffix != groups[1].branch_suffix


# ---------------------------------------------------------------------------
# 2. idempotent retry / orphaned branches
# ---------------------------------------------------------------------------

class TestRetry:
    async def test_open_pr_failure_reports_orphan_and_retry_is_safe(self, origin):
        github = FakeGitHub()
        github.fail_open = True
        flow, _, gen = make_flow(origin, github=github)
        r1 = await run(flow, [finding("a.py")])
        assert r1.opened_prs == []
        assert len(r1.orphaned_branches) == 1
        orphan = r1.orphaned_branches[0]
        assert orphan in remote_heads(origin)
        assert "orphaned" in r1.errors[0] and orphan in r1.errors[0]
        assert r1.to_dict()["orphaned_branches"] == [orphan]
        sha_before = sh("rev-parse", orphan, cwd=origin)

        # Retry, PR creation still failing or not: no LLM spend, no overwrite.
        gen.calls = 0
        github.fail_open = False
        r2 = await run(flow, [finding("a.py")])
        assert gen.calls == 0, "must pre-check the remote BEFORE spending LLM calls"
        assert r2.opened_prs == [] and github.opened == []
        assert "already exists" in r2.errors[0] and "no open pull request" in r2.errors[0]
        assert sh("rev-parse", orphan, cwd=origin) == sha_before

    async def test_existing_branch_with_open_pr_is_skipped_not_an_error(self, origin):
        github = FakeGitHub()
        github.fail_open = True
        flow, _, gen = make_flow(origin, github=github)
        await run(flow, [finding("a.py")])
        gen.calls = 0
        github.open_pr_url = "https://github.com/octo/app/pull/9"
        r = await run(flow, [finding("a.py")])
        assert gen.calls == 0 and r.errors == []
        assert any("pull/9" in s for s in r.skipped)

    async def test_genuine_non_fast_forward_race_is_reported_and_not_forced(
        self, origin, monkeypatch
    ):
        flow, github, _ = make_flow(origin)
        first = await run(flow, [finding("a.py")])
        branch = first.opened_prs[0].branch
        sha_before = sh("rev-parse", branch, cwd=origin)
        # Simulate the branch appearing between the pre-check and the push.
        async def blind(*a, **k):
            return set()
        monkeypatch.setattr(pr_flow, "remote_branches", blind)
        github.opened.clear()
        # Different content than run 1 (identical commits would push as a no-op).
        other = AppendGenerator(fixed=lambda f, c: c + "# other\n")
        flow2, _, _ = make_flow(origin, github=github, generator=other)
        second = await run(flow2, [finding("a.py")])
        assert github.opened == []
        assert "already exists on the remote with different commits" in second.errors[0]
        assert sh("rev-parse", branch, cwd=origin) == sha_before

    def test_non_ff_matcher_only_matches_real_non_fast_forward(self):
        assert is_non_fast_forward("! [rejected] HEAD -> x (non-fast-forward)")
        assert is_non_fast_forward("! [rejected] HEAD -> x (fetch first)")
        for msg in (
            "! [remote rejected] HEAD -> x (pre-receive hook declined)",
            "! [remote rejected] HEAD -> x (protected branch hook declined)",
            "error: failed to push some refs to 'https://github.com/o/r'",
            "remote: error: GH013: Repository rule violations (push protection)",
            "refusing to allow a Personal Access Token to create or update workflow",
        ):
            assert not is_non_fast_forward(msg), msg

    async def test_pre_receive_rejection_surfaces_real_message_scrubbed(self, origin):
        hook = os.path.join(origin, "hooks", "pre-receive")
        with open(hook, "w") as fh:
            fh.write(f"#!/bin/sh\necho 'policy: secret scanning blocked {TOKEN}' >&2\nexit 1\n")
        os.chmod(hook, 0o755)
        flow, github, _ = make_flow(origin)
        result = await run(flow, [finding("a.py")])
        assert github.opened == []
        msg = " ".join(result.errors)
        assert "policy: secret scanning blocked" in msg
        assert "already exists" not in msg
        assert TOKEN not in msg


# ---------------------------------------------------------------------------
# 4. token handling / clone dir permissions
# ---------------------------------------------------------------------------

class TestTokenAndPermissions:
    async def test_clone_dir_is_0700_and_no_token_in_config_or_argv(
        self, origin, monkeypatch
    ):
        argvs: list[tuple] = []
        real_exec = asyncio.create_subprocess_exec

        async def spy(*args, **kw):
            argvs.append(args)
            return await real_exec(*args, **kw)

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)
        dirs: list[str] = []
        github = FakeGitHub()
        seen = {}

        def inspect_clone():
            dest = dirs[0]
            seen["clone_mode"] = stat.S_IMODE(os.stat(dest).st_mode)
            seen["parent_mode"] = stat.S_IMODE(os.stat(os.path.dirname(dest)).st_mode)
            with open(os.path.join(dest, ".git", "config")) as fh:
                seen["config"] = fh.read()

        github.on_open = inspect_clone
        flow, _, _ = make_flow(origin, github=github, clone_dirs=dirs)
        result = await run(flow, [finding("a.py")])
        assert result.errors == [] and len(result.opened_prs) == 1
        assert seen["clone_mode"] == 0o700 and seen["parent_mode"] == 0o700
        assert TOKEN not in seen["config"] and "x-access-token" not in seen["config"]
        assert "extraheader" not in seen["config"].lower()
        assert argvs and all(TOKEN not in " ".join(map(str, a)) for a in argvs)
        assert not os.path.exists(os.path.dirname(dirs[0]))

    async def test_token_reaches_git_only_through_the_environment(self, origin, tmp_path):
        runner = GitRunner(TOKEN, allow_protocol="file")
        header = await runner.run(
            str(tmp_path), "config", "--get", "http.https://github.com/.extraheader"
        )
        assert header.startswith("AUTHORIZATION: basic ")
        assert TOKEN not in header  # base64, and scrubbed from output anyway

    def test_env_appends_to_existing_git_config_count(self):
        env = build_git_env(TOKEN, base={"GIT_CONFIG_COUNT": "1",
                                         "GIT_CONFIG_KEY_0": "a.b", "GIT_CONFIG_VALUE_0": "c"})
        assert env["GIT_CONFIG_KEY_0"] == "a.b"
        assert int(env["GIT_CONFIG_COUNT"]) > 2
        assert env["GIT_TERMINAL_PROMPT"] == "0"

    async def test_cleanup_runs_on_cancellation(self, origin, monkeypatch):
        created = []
        real = pr_flow.tempfile.mkdtemp
        monkeypatch.setattr(
            pr_flow.tempfile, "mkdtemp",
            lambda *a, **k: created.append(real(*a, **k)) or created[-1],
        )
        gate = asyncio.Event()

        class Hang(AppendGenerator):
            async def generate_fix(self, f, content):
                gate.set()
                await asyncio.sleep(60)

        flow, _, _ = make_flow(origin, generator=Hang())
        task = asyncio.create_task(run(flow, [finding("a.py")]))
        await asyncio.wait_for(gate.wait(), 20)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert created and not os.path.exists(created[0])


# ---------------------------------------------------------------------------
# 5. git timeouts / cancellation
# ---------------------------------------------------------------------------

HANG = ("-c", "alias.hang=!exec sleep 3", "hang")


class TestGitRunnerTimeouts:
    async def test_timeout_kills_and_reaps_the_child(self, tmp_path, monkeypatch):
        procs = []
        real_exec = asyncio.create_subprocess_exec

        async def spy(*args, **kw):
            p = await real_exec(*args, **kw)
            procs.append(p)
            return p

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)
        t0 = time.monotonic()
        with pytest.raises(GitTimeoutError, match="timed out"):
            await GitRunner(TOKEN, timeout=0.4).run(str(tmp_path), *HANG)
        assert time.monotonic() - t0 < 2.5
        assert procs[0].returncode is not None  # reaped, not orphaned

    async def test_cancellation_kills_the_child(self, tmp_path, monkeypatch):
        procs = []
        real_exec = asyncio.create_subprocess_exec

        async def spy(*args, **kw):
            p = await real_exec(*args, **kw)
            procs.append(p)
            return p

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)
        task = asyncio.create_task(GitRunner(TOKEN, timeout=30).run(str(tmp_path), *HANG))
        await asyncio.sleep(0.4)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert procs[0].returncode is not None

    def test_timeout_error_is_a_git_error(self):
        assert issubclass(GitTimeoutError, GitError)


# ---------------------------------------------------------------------------
# 6. default branch detection + branch from the report
# ---------------------------------------------------------------------------

def _client_with(monkeypatch, handler):
    real = httpx.AsyncClient

    def factory(*a, **k):
        k["transport"] = httpx.MockTransport(handler)
        return real(*a, **k)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return GitHubClient(TOKEN)


REF = RepoRef(host="github.com", owner="octo", repo="app")


class TestDefaultBranch:
    async def test_success_returns_the_default_branch(self, monkeypatch):
        c = _client_with(monkeypatch, lambda r: httpx.Response(200, json={"default_branch": "trunk"}))
        assert await c.get_default_branch(REF) == "trunk"

    @pytest.mark.parametrize("status,needle", [
        (401, "rejected the token"), (403, "denied access"),
        (404, "not found"), (500, "Unexpected GitHub response"),
    ])
    async def test_error_statuses_are_distinguished(self, monkeypatch, status, needle):
        c = _client_with(monkeypatch, lambda r: httpx.Response(status, json={"message": "x"}))
        with pytest.raises(RepoAccessError, match=needle):
            await c.get_default_branch(REF)

    async def test_redirect_reports_a_rename(self, monkeypatch):
        c = _client_with(monkeypatch, lambda r: httpx.Response(
            301, headers={"location": "https://api.github.com/repos/octo/renamed"}))
        with pytest.raises(RepoAccessError, match="moved or been renamed.*renamed"):
            await c.get_default_branch(REF)

    async def test_network_error_is_wrapped_without_leaking(self, monkeypatch):
        def boom(request):
            raise httpx.ConnectError("boom " + TOKEN)
        c = _client_with(monkeypatch, boom)
        with pytest.raises(RepoAccessError, match="Could not reach GitHub") as ei:
            await c.get_default_branch(REF)
        assert TOKEN not in str(ei.value)

    async def test_missing_default_branch_field_is_an_error(self, monkeypatch):
        c = _client_with(monkeypatch, lambda r: httpx.Response(200, json={}))
        with pytest.raises(RepoAccessError, match="no default branch"):
            await c.get_default_branch(REF)

    async def test_flow_reports_lookup_failure_and_never_falls_back_to_main(self, origin):
        class Failing(FakeGitHub):
            async def get_default_branch(self, ref):
                raise RepoAccessError("GitHub rejected the token (401)")

        cloned = []
        flow, _, gen = make_flow(origin, github=Failing(), clone_dirs=cloned)
        result = await run(flow, [finding("a.py")])
        assert result.opened_prs == [] and "401" in result.errors[0]
        assert cloned == [] and gen.calls == 0  # nothing cloned, no LLM spend


class TestBranchFromReport:
    async def test_pr_is_cloned_from_and_opened_against_the_scanned_branch(self, origin):
        flow, github, _ = make_flow(origin)
        result = await run(flow, [finding("dev_only.py")], branch="develop")
        assert github.default_branch_calls == 0
        assert result.base_branch == "develop"
        assert github.opened[0]["base"] == "develop"
        # The fix was made against develop's code (a file main does not have).
        shown = sh("show", f"{result.opened_prs[0].branch}:dev_only.py", cwd=origin)
        assert shown.endswith("# fixed")

    @pytest.mark.parametrize("empty", [None, "", "HEAD"])
    async def test_unknown_branch_uses_the_default(self, origin, empty):
        flow, github, _ = make_flow(origin)
        result = await run(flow, [finding("a.py")], branch=empty)
        assert result.base_branch == "main" and github.default_branch_calls == 1

    async def test_invalid_branch_is_refused(self, origin):
        flow, _, _ = make_flow(origin)
        with pytest.raises(ValueError, match="Invalid branch"):
            await run(flow, [finding("a.py")], branch="--upload-pack=evil")


# ---------------------------------------------------------------------------
# 7. hostile finding text
# ---------------------------------------------------------------------------

HOSTILE = (
    "SQLi @octocat ![x](http://evil.example/p.png) `rm -rf` fixes #123 "
    f"{TOKEN}\nsecond line"
)


class TestHostileText:
    async def test_commit_message_is_one_bounded_redacted_line(self, origin):
        flow, _, _ = make_flow(origin)
        result = await run(flow, [finding("a.py", title=HOSTILE * 5)])
        assert result.errors == []
        subject = sh("log", "-1", "--format=%s", result.opened_prs[0].branch, cwd=origin)
        full = sh("log", "-1", "--format=%B", result.opened_prs[0].branch, cwd=origin)
        assert "\n" not in subject and len(subject) <= 120
        assert TOKEN not in full
        assert len(full.strip().splitlines()) == 1

    def test_pr_body_neutralises_mentions_images_backticks_refs(self):
        g = group_findings([finding("we`ird`\n/x.py", title=HOSTILE)])[0]
        body = pr_body(g)
        assert "@octocat" not in body and "@​octocat" in body
        assert "![" not in body and "\\!\\[x\\]" in body
        assert "#123" not in body and TOKEN not in body
        line = next(ln for ln in body.splitlines() if ln.startswith("- [ ]"))
        # Only the intended code span carries unescaped backticks.
        assert line.replace("\\`", "").count("`") == 2
        assert pr_flow.pr_title(g).count("\n") == 0

    def test_redaction_patterns(self):
        from isitsecure.engine.fixes.pr_text import redact_secrets
        for secret in ("AKIAABCDEFGHIJKLMNOP", "password = hunter2hunter2",
                       "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc"):
            assert "[REDACTED]" in redact_secrets(f"found {secret} here")
        assert redact_secrets("plain title") == "plain title"


# ---------------------------------------------------------------------------
# 8. failed-commit isolation / unchanged / symlink
# ---------------------------------------------------------------------------

class FailingCommitGit(GitRunner):
    """Real git, except one commit is made to fail AFTER the file was staged."""

    async def run(self, cwd, *args, **kw):
        if args and args[0] == "commit" and "FAILME" in args[-1]:
            raise GitError("simulated commit failure")
        return await super().run(cwd, *args, **kw)


class TestCommitIsolation:
    async def test_failed_commit_does_not_leak_into_next_finding(self, origin):
        git = FailingCommitGit(TOKEN, allow_protocol="file")
        flow, _, _ = make_flow(origin, git=git)
        findings = [finding("a.py", "FAILME one"), finding("b.py", "second")]
        result = await run(flow, findings, strategy="single")
        assert any("commit failed" in e for e in result.errors)
        assert len(result.opened_prs) == 1
        changed = sh("diff", "--name-only", "main", result.opened_prs[0].branch, cwd=origin)
        assert changed.split() == ["b.py"], changed
        commits = sh("log", "--format=%s", f"main..{result.opened_prs[0].branch}", cwd=origin)
        assert len(commits.splitlines()) == 1

    async def test_unchanged_fix_is_skipped_not_a_commit_error(self, origin):
        gen = AppendGenerator(fixed=lambda f, content: content)
        flow, github, _ = make_flow(origin, generator=gen)
        result = await run(flow, [finding("a.py")])
        assert result.errors == [] and github.opened == []
        assert any("no change" in s for s in result.skipped)

    async def test_symlinked_path_is_refused(self, origin):
        flow, github, gen = make_flow(origin)
        result = await run(flow, [finding("link.py")])
        assert github.opened == [] and gen.calls == 0
        assert any("symlink" in s for s in result.skipped)


# ---------------------------------------------------------------------------
# 9. commit identity / hygiene
# ---------------------------------------------------------------------------

class TestCommitIdentity:
    async def test_bot_identity_and_no_hooks_or_signing(self, origin, tmp_path, monkeypatch):
        hooks = tmp_path / "hooks"
        hooks.mkdir()
        hook = hooks / "pre-commit"
        hook.write_text("#!/bin/sh\nexit 1\n")
        hook.chmod(0o755)
        cfg = tmp_path / "gitconfig"
        cfg.write_text(f"[user]\n\tname = Dev Person\n\temail = dev@corp.example\n"
                       f"[core]\n\thooksPath = {hooks}\n[commit]\n\tgpgsign = true\n"
                       "[gpg]\n\tprogram = /bin/false\n")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
        flow, _, _ = make_flow(origin)
        result = await run(flow, [finding("a.py")])
        assert result.errors == [], result.errors
        who = sh("log", "-1", "--format=%an <%ae> | %cn", result.opened_prs[0].branch, cwd=origin)
        assert who.startswith("isitsecure[bot] <isitsecure-bot@users.noreply.github.com>")
        assert "Dev Person" not in who


class TestRealCloneFunction:
    async def test_default_clone_rejects_unsafe_urls_and_branches(self, tmp_path):
        dest = tmp_path / "c"
        dest.mkdir()
        with pytest.raises(RuntimeError):
            await git_ops.clone_repo("ext::sh -c evil", "main", str(dest), TOKEN)
        with pytest.raises(RuntimeError):
            await git_ops.clone_repo("https://github.com/o/r", "--evil", str(dest), TOKEN)
