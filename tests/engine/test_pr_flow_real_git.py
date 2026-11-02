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
        self.open_prs: dict[str, str] = {}  # head branch -> open PR url
        self.on_open = None

    async def get_default_branch(self, ref):
        self.default_branch_calls += 1
        return self.default_branch

    async def find_open_pr(self, ref, *, head, base):
        return self.open_prs.get(head)

    async def open_pr(self, ref, *, title, body, head, base):
        if self.on_open:
            self.on_open()
        if self.fail_open:
            raise RuntimeError("GitHub PR creation failed (403): Resource not accessible")
        self.opened.append(dict(title=title, body=body, head=head, base=base))
        url = f"https://github.com/octo/app/pull/{len(self.opened)}"
        self.open_prs[head] = url
        return url


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
    async def test_open_pr_failure_reports_orphan_and_rerun_uses_next_free_name(self, origin):
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

        # Re-run: the stale branch (no open PR) is NEVER reused or overwritten; the
        # next free name is used with freshly generated content, so it isn't blocked.
        github.fail_open = False
        r2 = await run(flow, [finding("a.py")])
        assert r2.errors == [] and len(r2.opened_prs) == 1
        assert r2.opened_prs[0].branch == orphan + "-2"
        assert sh("rev-parse", orphan, cwd=origin) == sha_before

    async def test_rerun_after_merged_pr_is_not_blocked(self, origin):
        flow, github, _ = make_flow(origin)
        r1 = await run(flow, [finding("a.py")])
        first = r1.opened_prs[0].branch
        github.open_prs.clear()  # the PR was merged; GitHub kept the branch
        other = AppendGenerator(fixed=lambda f, c: c + "# second\n")
        flow2, _, _ = make_flow(origin, github=github, generator=other)
        r2 = await run(flow2, [finding("a.py")])
        assert r2.errors == [] and r2.opened_prs[0].branch == first + "-2"
        # and a third run is deduped against the still-open -2 PR, with no LLM spend
        other.calls = 0
        r3 = await run(flow2, [finding("a.py")])
        assert other.calls == 0 and r3.errors == [] and r3.opened_prs == []
        assert any(first + "-2" in s for s in r3.skipped)

    async def test_all_candidate_names_taken_is_a_clear_error(self, origin):
        flow, github, gen = make_flow(origin)
        names = ["isitsecure/fix-injection"] + [
            f"isitsecure/fix-injection-{n}" for n in range(2, pr_flow.MAX_BRANCH_SUFFIX + 1)
        ]
        for name in names:
            sh("branch", name, "main", cwd=origin)
        result = await run(flow, [finding("a.py")])
        assert gen.calls == 0 and github.opened == []
        assert "Delete the stale" in result.errors[0]

    def test_fixes_variant_is_in_the_candidate_list(self):
        g = group_findings([finding("a.py")])[0]
        root = f"isitsecure/fix-{g.branch_suffix}"
        names = pr_flow._candidate_branches(g, root)  # base equals the root name
        assert names[0] == root + "-fixes" and names[1] == root + "-fixes-2"

    def test_per_finding_branch_is_stable_across_rescans(self):
        # Two scans give the same finding different random ids.
        a = group_findings([finding("a.py", "t")], strategy="per-finding")[0]
        b = group_findings([finding("a.py", "t")], strategy="per-finding")[0]
        assert a.findings[0].id != b.findings[0].id
        assert a.branch_suffix == b.branch_suffix

    async def test_existing_branch_with_open_pr_is_skipped_not_an_error(self, origin):
        github = FakeGitHub()
        github.fail_open = True
        flow, _, gen = make_flow(origin, github=github)
        r1 = await run(flow, [finding("a.py")])
        gen.calls = 0
        github.open_prs[r1.orphaned_branches[0]] = "https://github.com/octo/app/pull/9"
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
        assert is_non_fast_forward(" ! [remote rejected] HEAD -> x (stale info)")
        # Hook output that merely quotes the phrases must NOT match.
        assert not is_non_fast_forward("remote: error: this is a non-fast-forward in hook msg")
        assert not is_non_fast_forward(
            "remote: ! [rejected] HEAD -> x (non-fast-forward)\n"
            " ! [remote rejected] HEAD -> x (pre-receive hook declined) stale info")
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


class TestBranchNameValidation:
    @pytest.mark.parametrize("name", [
        "main", "release/1.x", "rel/v1.0+b", "dep/foo@1.2", "feature/é", "a_b-c/d.e",
    ])
    def test_legit_names_are_accepted(self, name):
        assert git_ops.is_valid_branch_name(name)

    @pytest.mark.parametrize("name", [
        "", "-x", "--upload-pack=evil", "refs/heads/main", "a/.b", "x.lock/y",
        "a..b", "a b", "HEAD@{1}", "@", "a\x00b", "end/", "a" * 300, "x" + "\n",
    ])
    def test_bad_names_are_rejected(self, name):
        assert not git_ops.is_valid_branch_name(name)

    def test_resolve_scan_branch_falls_back_with_a_warning(self):
        assert pr_flow.resolve_scan_branch("develop") == ("develop", None)
        assert pr_flow.resolve_scan_branch("") == (None, None)
        assert pr_flow.resolve_scan_branch("HEAD") == (None, None)
        branch, warning = pr_flow.resolve_scan_branch("a/.b")
        assert branch is None and "default branch" in warning

    async def test_hostile_api_default_branch_is_refused(self, origin):
        flow, _, gen = make_flow(origin, github=FakeGitHub(default_branch="--upload-pack=x"))
        result = await run(flow, [finding("a.py")])
        assert "unusable default branch" in result.errors[0] and gen.calls == 0

    async def test_checkout_of_the_base_branch_uses_a_double_dash(self, origin):
        calls = []

        class Spy(GitRunner):
            async def run(self, cwd, *args, **kw):
                calls.append(args)
                return await super().run(cwd, *args, **kw)

        flow, _, _ = make_flow(origin, git=Spy(TOKEN, allow_protocol="file"))
        await run(flow, [finding("a.py")])
        assert ("checkout", "--force", "main", "--") in calls


class TestRemoteBranchesExactMatch:
    async def test_tail_pattern_matches_are_filtered_out(self, origin, tmp_path):
        # `ls-remote refs/heads/foo` also lists refs/heads/zzz/refs/heads/foo.
        sh("branch", "zzz/refs/heads/foo", "main", cwd=origin)
        clone = tmp_path / "c"
        sh("clone", "-q", origin, str(clone))
        git = GitRunner(None, allow_protocol="file")
        raw = await git.run(str(clone), "ls-remote", "--heads", "origin", "refs/heads/foo")
        assert "zzz/refs/heads/foo" in raw  # git's own matching is looser
        assert await git_ops.remote_branches(git, str(clone), ["foo"]) == set()
        sh("branch", "foo", "main", cwd=origin)
        assert await git_ops.remote_branches(git, str(clone), ["foo", "nope"]) == {"foo"}


class TestUniqueSuffix:
    def test_hash_is_part_of_the_suffix_without_any_dedupe(self):
        a = pr_flow._unique_suffix("src/a_b.py", "src/a_b.py")
        b = pr_flow._unique_suffix("src/a-b.py", "src/a-b.py")
        assert a != b and a.rsplit("-", 1)[1] == pr_flow._short_hash("src/a_b.py")
        assert len(pr_flow._short_hash("x")) == 8
        raw = pr_flow._build_raw_groups(
            [finding("src/a_b.py"), finding("src/a-b.py")], "per-file")
        assert len({g.branch_suffix for g in raw}) == 2


class TestTokenScrubbing:
    """Feed git output containing the token in every form through the REAL runner."""

    @pytest.mark.parametrize("form", ["raw", "b64", "header"])
    async def test_every_token_form_is_scrubbed_from_errors(self, tmp_path, form):
        import base64
        b64 = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
        payload = {"raw": TOKEN, "b64": b64, "header": f"AUTHORIZATION: basic {b64}"}[form]
        runner = GitRunner(TOKEN)
        with pytest.raises(GitError) as ei:
            await runner.run(str(tmp_path), "-c", f"alias.leak=!echo '{payload}' >&2; exit 3", "leak")
        assert TOKEN not in str(ei.value) and b64 not in str(ei.value)
        assert "***" in str(ei.value)

    async def test_token_is_scrubbed_from_successful_stdout_too(self, tmp_path):
        out = await GitRunner(TOKEN).run(
            str(tmp_path), "-c", f"alias.say=!echo {TOKEN}", "say")
        assert TOKEN not in out and "***" in out


class TestGlobalConfigIsolation:
    async def test_global_insteadof_cannot_redirect_the_remote(self, tmp_path, monkeypatch):
        cfg = tmp_path / "evil.gitconfig"
        cfg.write_text('[url "file:///nonexistent/"]\n\tinsteadOf = https://github.com/\n')
        url = "https://github.com/octo/app"
        sanity = subprocess.run(
            ["git", "ls-remote", "--get-url", url], capture_output=True, text=True,
            env={**os.environ, "GIT_CONFIG_GLOBAL": str(cfg)},
        ).stdout.strip()
        assert sanity != url  # the rewrite is real for plain git ...
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
        got = await GitRunner(TOKEN).run(str(tmp_path), "ls-remote", "--get-url", url)
        assert got == url  # ... and ignored by GitRunner

    def test_env_isolates_system_and_global_config(self):
        env = build_git_env(None)
        assert env["GIT_CONFIG_GLOBAL"] == os.devnull and env["GIT_CONFIG_NOSYSTEM"] == "1"
        assert env["GIT_AUTHOR_NAME"] == git_ops.BOT_NAME  # identity still applied

    async def test_bot_settings_still_apply_with_isolation(self, tmp_path):
        runner = GitRunner(None)
        assert await runner.run(str(tmp_path), "config", "--get", "core.hooksPath") == os.devnull
        assert await runner.run(str(tmp_path), "config", "--get", "commit.gpgsign") == "false"


class TestKillFallbacks:
    async def test_timeout_without_process_groups_still_kills_and_raises(
        self, tmp_path, monkeypatch
    ):
        # What Windows (and any platform lacking killpg) goes through.
        monkeypatch.setattr(git_ops, "_process_groups_supported", lambda: False)
        procs = []
        real_exec = asyncio.create_subprocess_exec

        async def spy(*args, **kw):
            assert kw["start_new_session"] is False
            p = await real_exec(*args, **kw)
            procs.append(p)
            return p

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)
        with pytest.raises(GitTimeoutError):
            await GitRunner(None, timeout=0.4).run(str(tmp_path), *HANG)
        assert procs[0].returncode is not None

    def test_missing_killpg_is_not_fatal(self, monkeypatch):
        killed = []

        class P:
            pid = 1
            def kill(self):
                killed.append(True)

        def boom(*a):
            raise AttributeError("no killpg on this platform")

        monkeypatch.setattr(os, "killpg", boom)
        git_ops._kill_tree(P())
        assert killed == [True]


class TestRealDefaultClone:
    async def test_default_clone_is_token_free_and_keeps_the_allowlist(
        self, origin, tmp_path, monkeypatch
    ):
        # Production allowlist never includes file:/ext:.
        assert build_git_env(TOKEN)["GIT_ALLOW_PROTOCOL"] == "https:http:ssh:git"
        # Test-only: map the canonical GitHub URL onto the local bare repo and
        # allow file for this one clone.
        monkeypatch.setattr(git_ops, "DEFAULT_ALLOW_PROTOCOL", "https:file")
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", f"url.{origin}.insteadOf")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", "https://github.com/octo/app.git")
        argvs = []
        real_exec = asyncio.create_subprocess_exec

        async def spy(*args, **kw):
            argvs.append(args)
            return await real_exec(*args, **kw)

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)
        parent = tmp_path / "w"
        parent.mkdir(mode=0o700)
        dest = parent / "repo"
        dest.mkdir(mode=0o700)
        await PRFlow._default_clone(REPO_URL, "main", str(dest), TOKEN)

        assert (dest / "a.py").exists()
        clone_argv = next(a for a in argvs if "clone" in a)
        assert "https://github.com/octo/app.git" in clone_argv  # canonical, token-free
        assert all(TOKEN not in " ".join(map(str, a)) for a in argvs)
        config = (dest / ".git" / "config").read_text()
        assert TOKEN not in config and "x-access-token" not in config
        assert "extraheader" not in config.lower()
        assert "https://github.com/octo/app.git" in config
        helper = await GitRunner(TOKEN, allow_protocol="file").run(
            str(dest), "config", "--get-all", "credential.helper")
        assert helper == ""  # credential helpers are disabled in every git child

    async def test_ssh_style_urls_are_canonicalised_to_https(self, origin, tmp_path, monkeypatch):
        monkeypatch.setattr(git_ops, "DEFAULT_ALLOW_PROTOCOL", "https:file")
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", f"url.{origin}.insteadOf")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", "https://github.com/octo/app.git")
        dest = tmp_path / "w2"
        dest.mkdir(mode=0o700)
        await PRFlow._default_clone("git@github.com:octo/app.git", "main", str(dest), TOKEN)
        assert "https://github.com/octo/app.git" in (dest / ".git" / "config").read_text()


class TestPrTextHardening:
    @pytest.mark.parametrize("secret", [
        "postgres://admin:s3cretpw@db.internal:5432/app",
        "mongodb+srv://u:secret123@cluster0.example.net/db",
        "postgres://user:p@ss@host/db",
        "Authorization: Bearer abcdEFGH12345678tokenvalue",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "pwd=hunter2hunter2",
        "password: swordfish99",
        "sk_" + "live_51H8abcdefghijkl",
        "sk_" + "test_4eC39HqLyjWDarjtT1zdp7dc",
    ])
    def test_secret_shapes_are_redacted(self, secret):
        from isitsecure.engine.fixes.pr_text import inline
        out = inline(f"leaked {secret} here", 300)
        assert "[REDACTED]" in out
        for needle in ("s3cretpw", "secret123", "p@ss", "abcdEFGH12345678tokenvalue",
                       "wJalrXUtnFEMI", "hunter2hunter2", "swordfish99",
                       "51H8abcdefghijkl", "4eC39HqLyjWDarjtT1zdp7dc"):
            assert needle not in out

    def test_autolinks_issue_refs_and_bidi_are_neutralised(self):
        from isitsecure.engine.fixes.pr_text import inline, md_text
        out = md_text("see https://evil.example/x and www.evil.example and GH-42 and &#64;bob")
        assert "https://" not in out and "www.evil" not in out
        assert "GH-42" not in out and "&#64;" not in out
        assert "\u202e" not in inline("abc\u202edef\u2066ghi\u200f")
        assert inline("abc\u202edef") == "abcdef"


class TestRealCloneFunction:
    async def test_default_clone_rejects_unsafe_urls_and_branches(self, tmp_path):
        dest = tmp_path / "c"
        dest.mkdir()
        with pytest.raises(RuntimeError):
            await git_ops.clone_repo("ext::sh -c evil", "main", str(dest), TOKEN)
        with pytest.raises(RuntimeError):
            await git_ops.clone_repo("https://github.com/o/r", "--evil", str(dest), TOKEN)
