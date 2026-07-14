"""Tests for the remote-repo fix → per-category PR flow.

Git push and the GitHub API are MOCKED throughout — no real network pushes,
no real pull requests.
"""

from __future__ import annotations

import pytest

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import CodeLocation, DeepFinding, FindingSource
from isitsecure.engine.fixes.fix_generator import FixResult
from isitsecure.engine.fixes import pr_flow
from isitsecure.engine.fixes.pr_flow import (
    GitError,
    GitRunner,
    OpenedPR,
    PRFlow,
    RepoRef,
    group_findings,
    is_remote_url,
    parse_github_url,
    pr_body,
    pr_title,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    category=FindingCategory.INJECTION_RISK,
    severity=SeverityLevel.CRITICAL,
    file_path="src/db.ts",
    title="SQL injection",
    line=10,
):
    return DeepFinding(
        source=FindingSource.SAST_CODE,
        category=category,
        severity=severity,
        title=title,
        description="desc",
        scanner_name="scanner",
        confidence=0.9,
        code_location=CodeLocation(
            file_path=file_path, line_number=line, code_snippet="bad()"
        ),
    )


def _dast_finding():
    return DeepFinding(
        source=FindingSource.DAST_URL,
        category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.HIGH,
        title="Reflected XSS",
        description="desc",
        scanner_name="dast",
        confidence=0.8,
        code_location=None,
    )


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------

class TestParsing:
    @pytest.mark.parametrize("url,owner,repo,host", [
        ("https://github.com/octocat/Hello-World", "octocat", "Hello-World", "github.com"),
        ("https://github.com/octocat/Hello-World.git", "octocat", "Hello-World", "github.com"),
        ("http://github.com/a/b/", "a", "b", "github.com"),
        ("git@github.com:octocat/Hello-World.git", "octocat", "Hello-World", "github.com"),
        ("ssh://git@github.com/octocat/Hello-World", "octocat", "Hello-World", "github.com"),
        ("github.com/octocat/Hello-World", "octocat", "Hello-World", "github.com"),
        ("https://github.com/o/r/tree/main/sub", "o", "r", "github.com"),
        ("https://gitlab.com/group/proj", "group", "proj", "gitlab.com"),
    ])
    def test_parse_ok(self, url, owner, repo, host):
        ref = parse_github_url(url)
        assert ref == RepoRef(host=host, owner=owner, repo=repo)

    def test_github_flag(self):
        assert parse_github_url("https://github.com/a/b").is_github is True
        assert parse_github_url("https://gitlab.com/a/b").is_github is False

    def test_token_in_url_not_leaked_into_owner(self):
        ref = parse_github_url("https://x-access-token:SECRET@github.com/a/b")
        assert ref.owner == "a" and ref.repo == "b" and ref.host == "github.com"

    @pytest.mark.parametrize("bad", ["", "   ", "https://github.com/onlyowner", "not a url"])
    def test_parse_bad(self, bad):
        with pytest.raises(ValueError):
            parse_github_url(bad)

    @pytest.mark.parametrize("url,remote", [
        ("https://github.com/a/b", True),
        ("git@github.com:a/b.git", True),
        ("ssh://git@github.com/a/b", True),
        ("file:///Users/me/app", False),
        ("/Users/me/app", False),
        ("./app", False),
        ("", False),
        (None, False),
    ])
    def test_is_remote_url(self, url, remote):
        assert is_remote_url(url) is remote


# ---------------------------------------------------------------------------
# Grouping algorithm
# ---------------------------------------------------------------------------

class TestGrouping:
    def test_per_category_one_pr_per_category(self):
        findings = [
            _finding(FindingCategory.INJECTION_RISK, title="sqli1"),
            _finding(FindingCategory.INJECTION_RISK, title="sqli2"),
            _finding(FindingCategory.IDOR, title="idor1"),
            _finding(FindingCategory.AUTH_WEAKNESS, title="auth1"),
        ]
        groups = group_findings(findings, strategy="per-category", max_prs=8)
        keys = {g.key for g in groups}
        assert keys == {"injection_risk", "idor", "auth_weakness"}
        inj = next(g for g in groups if g.key == "injection_risk")
        assert len(inj.findings) == 2

    def test_dependencies_collapse_into_one_pr(self):
        findings = [
            _finding(FindingCategory.DEPENDENCY_VULNERABILITY, title=f"dep{i}",
                     file_path=f"pkg{i}.json", severity=SeverityLevel.HIGH)
            for i in range(5)
        ]
        groups = group_findings(findings, strategy="per-category", max_prs=8)
        assert len(groups) == 1
        assert groups[0].key == "dependency_vuln"
        assert len(groups[0].findings) == 5

    def test_per_file(self):
        findings = [
            _finding(file_path="a.ts", title="x"),
            _finding(file_path="a.ts", title="y"),
            _finding(file_path="b.ts", title="z"),
        ]
        groups = group_findings(findings, strategy="per-file", max_prs=8)
        assert {g.key for g in groups} == {"a.ts", "b.ts"}

    def test_per_finding(self):
        findings = [_finding(title=f"f{i}") for i in range(3)]
        groups = group_findings(findings, strategy="per-finding", max_prs=8)
        assert len(groups) == 3

    def test_single(self):
        findings = [
            _finding(FindingCategory.INJECTION_RISK, title="a"),
            _finding(FindingCategory.IDOR, title="b"),
        ]
        groups = group_findings(findings, strategy="single", max_prs=8)
        assert len(groups) == 1
        assert len(groups[0].findings) == 2

    def test_skips_findings_without_code_location(self):
        findings = [_finding(), _dast_finding()]
        groups = group_findings(findings, strategy="per-category", max_prs=8)
        total = sum(len(g.findings) for g in groups)
        assert total == 1  # DAST finding dropped

    def test_priority_ordering_critical_first(self):
        findings = [
            _finding(FindingCategory.MISSING_HEADERS, severity=SeverityLevel.LOW, title="low"),
            _finding(FindingCategory.INJECTION_RISK, severity=SeverityLevel.CRITICAL, title="crit"),
        ]
        groups = group_findings(findings, strategy="per-category", max_prs=8)
        assert groups[0].key == "injection_risk"  # critical group first

    def test_invalid_strategy(self):
        with pytest.raises(ValueError):
            group_findings([_finding()], strategy="bogus", max_prs=8)

    def test_invalid_max_prs(self):
        with pytest.raises(ValueError):
            group_findings([_finding()], strategy="per-category", max_prs=0)

    def test_empty(self):
        assert group_findings([], strategy="per-category", max_prs=8) == []


class TestCapAndPrioritize:
    def test_cap_batches_low_severity_never_drops(self):
        """80-issue case: many categories capped → crit/high PRs + 1 low batch."""
        findings = []
        # 3 critical/high categories
        findings += [_finding(FindingCategory.INJECTION_RISK, SeverityLevel.CRITICAL,
                              title=f"inj{i}") for i in range(5)]
        findings += [_finding(FindingCategory.IDOR, SeverityLevel.HIGH,
                              title=f"idor{i}") for i in range(5)]
        findings += [_finding(FindingCategory.AUTH_WEAKNESS, SeverityLevel.CRITICAL,
                              title=f"auth{i}") for i in range(5)]
        # 10 distinct low/medium categories with lots of findings → ~65 issues
        low_cats = [
            FindingCategory.MISSING_HEADERS, FindingCategory.CLIENT_EXPOSURE,
            FindingCategory.SOURCE_MAP_LEAK, FindingCategory.CORS_MISCONFIGURATION,
            FindingCategory.OPEN_REDIRECT, FindingCategory.INFO_DISCLOSURE,
            FindingCategory.MISSING_SRI, FindingCategory.MIXED_CONTENT,
            FindingCategory.DEAD_FUNCTIONALITY, FindingCategory.EXPOSED_API_ENDPOINT,
        ]
        for ci, cat in enumerate(low_cats):
            findings += [_finding(cat, SeverityLevel.LOW,
                                  file_path=f"f{ci}_{i}.ts", title=f"{cat.value}{i}")
                         for i in range(6)]

        assert len(findings) == 15 + 60  # 75 findings

        groups = group_findings(findings, strategy="per-category", max_prs=4)
        assert len(groups) <= 4
        low_batches = [g for g in groups if g.is_low_batch]
        assert len(low_batches) == 1
        # Nothing dropped: total findings preserved.
        total = sum(len(g.findings) for g in groups)
        assert total == 75
        # The 3 priority groups are present (crit/high), plus the batch.
        priority_keys = {g.key for g in groups if not g.is_low_batch}
        assert "injection_risk" in priority_keys
        assert "auth_weakness" in priority_keys

    def test_cap_no_batch_when_everything_fits(self):
        findings = [
            _finding(FindingCategory.INJECTION_RISK, SeverityLevel.CRITICAL, title="a"),
            _finding(FindingCategory.IDOR, SeverityLevel.HIGH, title="b"),
        ]
        groups = group_findings(findings, strategy="per-category", max_prs=8)
        assert all(not g.is_low_batch for g in groups)
        assert len(groups) == 2

    def test_cap_of_one_batches_everything(self):
        findings = [
            _finding(FindingCategory.INJECTION_RISK, SeverityLevel.LOW, title="a"),
            _finding(FindingCategory.IDOR, SeverityLevel.LOW, title="b"),
        ]
        groups = group_findings(findings, strategy="per-category", max_prs=1)
        assert len(groups) == 1
        assert groups[0].is_low_batch
        assert len(groups[0].findings) == 2

    def test_priority_overflow_batch_is_labelled_honestly(self):
        """More critical/high categories than max_prs → batch must NOT be
        titled 'low-severity cleanup' since it carries critical fixes."""
        cats = [
            FindingCategory.INJECTION_RISK, FindingCategory.IDOR,
            FindingCategory.AUTH_WEAKNESS, FindingCategory.PRIVILEGE_ESCALATION,
            FindingCategory.OPEN_REDIRECT, FindingCategory.CORS_MISCONFIGURATION,
        ]
        findings = [
            _finding(c, SeverityLevel.CRITICAL, title=f"crit{i}", file_path=f"a{i}.ts")
            for i, c in enumerate(cats)
        ]
        groups = group_findings(findings, strategy="per-category", max_prs=3)
        # Nothing dropped.
        assert sum(len(g.findings) for g in groups) == len(findings)
        batch = next(g for g in groups if g.is_low_batch)
        assert batch.contains_priority is True
        title = pr_title(batch)
        assert "low-severity" not in title.lower()
        assert "batched security fixes" in title.lower()
        body = pr_body(batch)
        assert "critical/high" in body.lower()

    def test_low_only_batch_is_not_flagged_priority(self):
        findings = [
            _finding(FindingCategory.MISSING_HEADERS, SeverityLevel.LOW, title="h"),
            _finding(FindingCategory.CLIENT_EXPOSURE, SeverityLevel.LOW, title="c"),
        ]
        groups = group_findings(findings, strategy="per-category", max_prs=1)
        assert groups[0].is_low_batch
        assert groups[0].contains_priority is False
        assert "low-severity cleanup" in pr_title(groups[0]).lower()


# ---------------------------------------------------------------------------
# PR title / body generation
# ---------------------------------------------------------------------------

class TestPRText:
    def test_title_per_category(self):
        g = group_findings([_finding(title="a"), _finding(title="b")],
                           strategy="per-category", max_prs=8)[0]
        title = pr_title(g)
        assert "Injection" in title and "2 issues" in title

    def test_body_lists_each_finding_and_severity(self):
        findings = [
            _finding(title="sqli-A", file_path="a.ts", line=3),
            _finding(title="sqli-B", file_path="b.ts", line=7),
        ]
        g = group_findings(findings, strategy="per-category", max_prs=8)[0]
        body = pr_body(g)
        assert "sqli-A" in body and "sqli-B" in body
        assert "a.ts:3" in body and "b.ts:7" in body
        assert "critical" in body
        assert "one commit per finding" in body

    def test_low_batch_body(self):
        findings = [
            _finding(FindingCategory.MISSING_HEADERS, SeverityLevel.LOW, title="h"),
            _finding(FindingCategory.CLIENT_EXPOSURE, SeverityLevel.LOW, title="c"),
        ]
        groups = group_findings(findings, strategy="per-category", max_prs=1)
        assert groups[0].is_low_batch
        body = pr_body(groups[0])
        assert "low-severity" in body.lower()


# ---------------------------------------------------------------------------
# PRFlow orchestration — git + GitHub fully mocked
# ---------------------------------------------------------------------------

class FakeGit:
    """Records git invocations; never touches a real repo."""

    def __init__(self, token=None):
        self.calls: list[tuple[str, ...]] = []
        self.pushed_refs: list[str] = []

    async def run(self, cwd, *args):
        self.calls.append(args)
        if args and args[0] == "push":
            # Record the refspec pushed (last arg like "HEAD:refs/heads/branch").
            self.pushed_refs.append(args[-1])
        return ""


class FakeGitHub:
    def __init__(self, token=None, default_branch="main"):
        self.default_branch = default_branch
        self.opened: list[dict] = []

    async def get_default_branch(self, ref):
        return self.default_branch

    async def open_pr(self, ref, *, title, body, head, base):
        self.opened.append(
            {"title": title, "body": body, "head": head, "base": base,
             "slug": ref.slug}
        )
        return f"https://github.com/{ref.slug}/pull/{len(self.opened)}"


class FakeGenerator:
    """Always returns a successful fix rewriting the file."""

    def __init__(self, succeed=True):
        self.succeed = succeed
        self.seen: list[str] = []

    async def generate_fix(self, finding, content):
        self.seen.append(finding.title)
        if not self.succeed:
            return FixResult(
                finding_id=finding.id,
                file_path=finding.code_location.file_path,
                success=False,
                error="mock: no fix",
            )
        return FixResult(
            finding_id=finding.id,
            file_path=finding.code_location.file_path,
            success=True,
            original_code=content,
            fixed_code=content + "\n// fixed",
            diff="+ // fixed",
        )


def _make_flow(tmp_path, generator=None, git=None, github=None):
    """Build a PRFlow whose clone writes findings' files into a temp dir."""
    git = git or FakeGit()
    github = github or FakeGitHub()
    generator = generator or FakeGenerator()

    async def fake_clone(repo_url, branch, clone_dir, token):
        import os
        # Materialize each referenced file so _apply_and_commit can read it.
        for rel in _clone_files:
            full = os.path.join(clone_dir, rel)
            os.makedirs(os.path.dirname(full) or clone_dir, exist_ok=True)
            with open(full, "w") as fh:
                fh.write("original code\n")

    _clone_files: set[str] = set()

    flow = PRFlow(
        generator,
        github_factory=lambda tok: github,
        git_factory=lambda tok: git,
        clone_fn=fake_clone,
    )
    return flow, git, github, generator, _clone_files


@pytest.mark.asyncio
class TestPRFlowOrchestration:
    async def test_opens_one_pr_per_category(self, tmp_path):
        findings = [
            _finding(FindingCategory.INJECTION_RISK, file_path="a.ts", title="sqli"),
            _finding(FindingCategory.IDOR, file_path="b.ts", title="idor"),
        ]
        flow, git, github, gen, clone_files = _make_flow(tmp_path)
        clone_files.update({"a.ts", "b.ts"})

        result = await flow.run(
            repo_url="https://github.com/octo/app",
            findings=findings,
            github_token="TESTTOKEN",
            strategy="per-category",
            max_prs=8,
        )
        assert len(result.opened_prs) == 2
        assert result.fixed_count == 2
        assert {p.category for p in result.opened_prs} == {"injection_risk", "idor"}

    async def test_commit_per_finding(self, tmp_path):
        findings = [
            _finding(file_path="a.ts", title="sqli-A"),
            _finding(file_path="b.ts", title="sqli-B"),
        ]
        flow, git, github, gen, clone_files = _make_flow(tmp_path)
        clone_files.update({"a.ts", "b.ts"})
        await flow.run(
            repo_url="https://github.com/octo/app",
            findings=findings, github_token="T", strategy="per-category", max_prs=8,
        )
        commits = [c for c in git.calls if c and c[0] == "commit"]
        assert len(commits) == 2
        # Atomic conventional messages.
        msgs = [c[2] for c in commits]
        assert all(m.startswith("fix(") for m in msgs)

    async def test_never_pushes_to_default_branch(self, tmp_path):
        findings = [_finding(file_path="a.ts", title="sqli")]
        flow, git, github, gen, clone_files = _make_flow(tmp_path)
        clone_files.add("a.ts")
        await flow.run(
            repo_url="https://github.com/octo/app",
            findings=findings, github_token="T", strategy="per-category", max_prs=8,
        )
        # No push targets refs/heads/main (the default branch).
        assert git.pushed_refs, "expected at least one push"
        for ref in git.pushed_refs:
            target = ref.split(":")[-1]  # e.g. "refs/heads/isitsecure/fix-injection"
            assert target != "refs/heads/main"
            assert target.startswith("refs/heads/isitsecure/fix-")
        # And every PR's base is the default branch, head is a feature branch.
        for pr in github.opened:
            assert pr["base"] == "main"
            assert pr["head"].startswith("isitsecure/fix-")
            assert pr["head"] != "main"

    async def test_token_never_logged(self, tmp_path, caplog):
        import logging
        caplog.set_level(logging.DEBUG)
        findings = [_finding(file_path="a.ts", title="sqli")]
        flow, git, github, gen, clone_files = _make_flow(tmp_path)
        clone_files.add("a.ts")
        secret = "ghp_SUPERSECRET_TOKEN_VALUE"
        await flow.run(
            repo_url="https://github.com/octo/app",
            findings=findings, github_token=secret, strategy="per-category", max_prs=8,
        )
        assert secret not in caplog.text

    async def test_token_not_leaked_into_surfaced_errors(self, tmp_path):
        """A git failure whose message echoes the tokened remote URL must be
        scrubbed before it lands in result.errors (surfaced to the client)."""
        secret = "ghp_SUPERSECRET_TOKEN_VALUE"

        class LeakyGit(GitRunner):
            # Use the REAL GitRunner scrub, but simulate git echoing the token.
            async def run(self, cwd, *args):
                if args and args[0] == "push":
                    raise GitError(
                        self._scrub(
                            "fatal: unable to access "
                            f"'https://x-access-token:{secret}@github.com/o/r/': 403"
                        )
                    )
                return ""

        flow, _git, github, gen, clone_files = _make_flow(
            tmp_path, git=LeakyGit(secret)
        )
        clone_files.add("a.ts")
        result = await flow.run(
            repo_url="https://github.com/octo/app",
            findings=[_finding(file_path="a.ts", title="sqli")],
            github_token=secret,
        )
        blob = " ".join(result.errors) + " ".join(result.skipped) + result.summary
        assert secret not in blob
        assert result.errors  # the (scrubbed) push error was surfaced

    async def test_non_github_host_raises(self, tmp_path):
        flow, *_ = _make_flow(tmp_path)
        with pytest.raises(ValueError):
            await flow.run(
                repo_url="https://gitlab.com/octo/app",
                findings=[_finding(file_path="a.ts")],
                github_token="T",
            )

    async def test_missing_token_raises(self, tmp_path):
        flow, *_ = _make_flow(tmp_path)
        with pytest.raises(ValueError):
            await flow.run(
                repo_url="https://github.com/octo/app",
                findings=[_finding(file_path="a.ts")],
                github_token="",
            )

    async def test_dast_findings_skipped(self, tmp_path):
        flow, git, github, gen, clone_files = _make_flow(tmp_path)
        clone_files.add("a.ts")
        findings = [_finding(file_path="a.ts", title="sqli"), _dast_finding()]
        result = await flow.run(
            repo_url="https://github.com/octo/app",
            findings=findings, github_token="T",
        )
        assert any("DAST-only" in s for s in result.skipped)
        assert result.fixed_count == 1

    async def test_failed_fix_skipped_no_pr(self, tmp_path):
        gen = FakeGenerator(succeed=False)
        flow, git, github, _, clone_files = _make_flow(tmp_path, generator=gen)
        clone_files.add("a.ts")
        result = await flow.run(
            repo_url="https://github.com/octo/app",
            findings=[_finding(file_path="a.ts", title="sqli")],
            github_token="T",
        )
        assert result.opened_prs == []
        assert github.opened == []  # no PR opened when nothing committed

    async def test_temp_clone_cleaned_up_on_error(self, tmp_path, monkeypatch):
        import isitsecure.engine.fixes.pr_flow as mod
        created = {}
        real_mkdtemp = mod.tempfile.mkdtemp

        def spy_mkdtemp(*a, **k):
            d = real_mkdtemp(*a, **k)
            created["dir"] = d
            return d

        monkeypatch.setattr(mod.tempfile, "mkdtemp", spy_mkdtemp)

        gen = FakeGenerator()

        async def boom_clone(*a, **k):
            raise RuntimeError("clone failed")

        flow = PRFlow(
            gen,
            github_factory=lambda tok: FakeGitHub(),
            git_factory=lambda tok: FakeGit(),
            clone_fn=boom_clone,
        )
        import os
        with pytest.raises(RuntimeError):
            await flow.run(
                repo_url="https://github.com/octo/app",
                findings=[_finding(file_path="a.ts")], github_token="T",
            )
        assert not os.path.exists(created["dir"])

    async def test_push_is_not_force(self, tmp_path):
        """We must never force-push — that would clobber a pre-existing
        isitsecure/fix-* branch the user hasn't merged."""
        findings = [_finding(file_path="a.ts", title="sqli")]
        flow, git, github, gen, clone_files = _make_flow(tmp_path)
        clone_files.add("a.ts")
        await flow.run(
            repo_url="https://github.com/octo/app",
            findings=findings, github_token="T", strategy="per-category", max_prs=8,
        )
        pushes = [c for c in git.calls if c and c[0] == "push"]
        assert pushes, "expected a push"
        for p in pushes:
            assert "--force" not in p
            assert "--force-with-lease" not in p
            assert "-f" not in p

    async def test_existing_remote_branch_not_clobbered(self, tmp_path):
        """A non-fast-forward push rejection surfaces a clear 'already exists'
        error and opens no PR (rather than overwriting the branch)."""
        from isitsecure.engine.fixes.pr_flow import GitError

        class RejectingGit(FakeGit):
            async def run(self, cwd, *args):
                self.calls.append(args)
                if args and args[0] == "push":
                    raise GitError(
                        "! [rejected] HEAD -> isitsecure/fix-injection "
                        "(non-fast-forward)\nerror: failed to push some refs"
                    )
                return ""

        git = RejectingGit()
        flow, _git, github, gen, clone_files = _make_flow(tmp_path, git=git)
        clone_files.add("a.ts")
        result = await flow.run(
            repo_url="https://github.com/octo/app",
            findings=[_finding(file_path="a.ts", title="sqli")],
            github_token="T",
        )
        assert result.opened_prs == []
        assert github.opened == []
        assert any("already exists" in e for e in result.errors)

    async def test_summary_reports_cap_batching(self, tmp_path):
        findings = []
        findings += [_finding(FindingCategory.INJECTION_RISK, SeverityLevel.CRITICAL,
                              file_path=f"inj{i}.ts", title=f"inj{i}") for i in range(2)]
        findings += [_finding(FindingCategory.MISSING_HEADERS, SeverityLevel.LOW,
                              file_path=f"h{i}.ts", title=f"h{i}") for i in range(3)]
        findings += [_finding(FindingCategory.CLIENT_EXPOSURE, SeverityLevel.LOW,
                              file_path=f"c{i}.ts", title=f"c{i}") for i in range(3)]
        flow, git, github, gen, clone_files = _make_flow(tmp_path)
        clone_files.update(f.code_location.file_path for f in findings)
        result = await flow.run(
            repo_url="https://github.com/octo/app",
            findings=findings, github_token="T", strategy="per-category", max_prs=2,
        )
        assert "batched into" in result.summary
        low = [p for p in result.opened_prs if p.is_low_batch]
        assert len(low) == 1


# ---------------------------------------------------------------------------
# GitRunner token scrubbing (unit)
# ---------------------------------------------------------------------------

class TestGitRunnerScrub:
    def test_scrub_removes_token(self):
        runner = GitRunner(token="ghp_SECRET")
        assert "ghp_SECRET" not in runner._scrub("failed for ghp_SECRET@github.com")
        assert "***" in runner._scrub("ghp_SECRET")
