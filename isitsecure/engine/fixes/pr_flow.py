"""Remote-repo fix flow: clone → generate fixes → open per-category pull requests.

When a ``fix`` targets a REMOTE git URL (not a local path), we clone the repo to
a temp dir, generate SAST fixes with the existing :class:`FixGenerator`, group the
fixes into pull requests (default: one PR per vulnerability category), and open the
PRs on GitHub via the REST API. Local-path fixes keep their in-place behavior and
never reach this module.

Design (SRP / DIP / OCP):
    * ``parse_github_url``           — parse owner/repo/host from a URL.
    * ``group_findings``             — pure grouping algorithm (strategy + cap).
    * ``GitRunner`` / ``GitHubClient`` — injectable side-effect boundaries so tests
                                        MOCK git push + the GitHub API (no network).
    * ``PRFlow``                     — orchestrates clone → fix → group → branch →
                                        commit-per-finding → push → open PR.

SAFETY (see the module tests):
    * NEVER pushes to the default branch — always a feature branch + PR.
    * NEVER force-pushes: a pre-existing ``isitsecure/fix-*`` branch on the
      remote is reported, not clobbered.
    * The GitHub token is passed in, never persisted, never logged (git remote
      errors are scrubbed of the token before surfacing).
    * The temp clone is removed on success AND on error.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.fixes.fix_generator import FixGenerator, FixResult
from isitsecure.engine.models import DeepFinding

if TYPE_CHECKING:
    import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Config / constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_PRS = 8
DEFAULT_STRATEGY = "per-category"
VALID_STRATEGIES = ("per-category", "per-file", "per-finding", "single")

# Highest-priority first. Categories at critical/high severity are opened as
# their own PRs before the cap batches the rest.
_SEVERITY_RANK = {
    SeverityLevel.CRITICAL: 0,
    SeverityLevel.HIGH: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.LOW: 3,
    SeverityLevel.INFO: 4,
}
_PRIORITY_SEVERITIES = (SeverityLevel.CRITICAL, SeverityLevel.HIGH)

# Human-readable labels for branch/title text, keyed by category value.
_CATEGORY_LABELS: dict[str, str] = {
    "injection_risk": "Injection",
    "idor": "IDOR / broken access control",
    "auth_weakness": "Authentication weakness",
    "privilege_escalation": "Privilege escalation",
    "rls_misconfiguration": "Row-level security",
    "cors_misconfiguration": "CORS misconfiguration",
    "open_redirect": "Open redirect",
    "exposed_secrets": "Exposed secrets",
    "dependency_vuln": "Vulnerable dependencies",
    "missing_headers": "Missing security headers",
    "client_exposure": "Client-side exposure",
    "source_map_leak": "Source map leak",
    "unencrypted_pii": "Unencrypted PII",
    "exposed_api_endpoint": "Exposed API endpoint",
    "missing_sri": "Missing SRI",
    "mixed_content": "Mixed content",
    "info_disclosure": "Information disclosure",
    "dead_functionality": "Dead functionality",
}

# Categories whose findings always collapse into ONE pull request.
_COLLAPSE_CATEGORIES = {FindingCategory.DEPENDENCY_VULNERABILITY.value}

_LOW_BATCH_KEY = "__low_severity_cleanup__"


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RepoRef:
    """A parsed git remote reference."""

    host: str
    owner: str
    repo: str

    @property
    def is_github(self) -> bool:
        return self.host.lower() == "github.com"

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


def is_remote_url(target: str | None) -> bool:
    """True when ``target`` is a remote git URL rather than a local path.

    Mirrors ``RepoIngestionService._resolve_local_path``: ``file://`` and bare
    paths are local; anything else with a ``://`` scheme (or ``scp``-like
    ``git@host:owner/repo``) is remote.
    """
    if not target:
        return False
    if target.startswith("file://"):
        return False
    if "://" in target:
        return True
    # scp-like: git@github.com:owner/repo(.git)
    if re.match(r"^[\w.-]+@[\w.-]+:", target):
        return True
    return False


def parse_github_url(url: str) -> RepoRef:
    """Parse owner/repo/host from a git URL.

    Accepts ``https://github.com/owner/repo(.git)``, ``http://…``,
    ``ssh://git@github.com/owner/repo``, ``git@github.com:owner/repo.git``, and
    a bare ``github.com/owner/repo``. Raises ``ValueError`` for anything that
    doesn't yield a host + owner + repo.
    """
    if not url or not url.strip():
        raise ValueError("Empty repository URL")
    raw = url.strip()

    # scp-like: git@host:owner/repo(.git)
    scp = re.match(r"^[\w.-]+@([\w.-]+):(.+)$", raw)
    if scp and "://" not in raw:
        host = scp.group(1)
        path = scp.group(2)
    else:
        # Strip scheme (or supply a placeholder for bare host/owner/repo).
        m = re.match(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*://)?(.+)$", raw)
        rest = m.group(1) if m else raw
        # Drop optional userinfo (e.g. git@ or x-access-token:tok@).
        rest = re.sub(r"^[^/@]*@", "", rest)
        parts = rest.split("/", 1)
        if len(parts) != 2:
            raise ValueError(f"Cannot parse owner/repo from URL: {url}")
        host = parts[0]
        path = parts[1]

    # path is "owner/repo(/...)(.git)"
    path = path.strip("/")
    segments = [s for s in path.split("/") if s]
    if len(segments) < 2:
        raise ValueError(f"Cannot parse owner/repo from URL: {url}")
    owner = segments[0]
    repo = segments[1]
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]

    if not host or not owner or not repo:
        raise ValueError(f"Cannot parse owner/repo from URL: {url}")

    return RepoRef(host=host, owner=owner, repo=repo)


# ---------------------------------------------------------------------------
# Grouping algorithm (pure — no side effects, fully unit-testable)
# ---------------------------------------------------------------------------

@dataclass
class PRGroup:
    """One planned pull request: a labelled group of findings.

    ``category_key`` is the grouping key (a category value, a file path, a
    finding id, "single", or the low-severity batch sentinel). ``findings`` are
    the members, ordered by severity so commits read critical-first.
    """

    key: str
    title_label: str
    branch_suffix: str
    findings: list[DeepFinding] = field(default_factory=list)
    is_low_batch: bool = False
    # True when a capped "batch" PR actually contains critical/high findings
    # (i.e. the priority groups themselves overflowed ``max_prs``).
    contains_priority: bool = False

    @property
    def top_severity(self) -> SeverityLevel:
        if not self.findings:
            return SeverityLevel.INFO
        return min(
            (f.severity for f in self.findings),
            key=lambda s: _SEVERITY_RANK.get(s, 99),
        )


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "misc"


def _category_label(category: FindingCategory | str) -> str:
    value = category.value if isinstance(category, FindingCategory) else str(category)
    return _CATEGORY_LABELS.get(value, value.replace("_", " ").title())


def _sort_findings(findings: list[DeepFinding]) -> list[DeepFinding]:
    """Severity-first, then stable by title for deterministic commit order."""
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_RANK.get(f.severity, 99), f.title),
    )


def _is_priority(group: PRGroup) -> bool:
    """A group is high-priority if any member is critical or high."""
    return any(f.severity in _PRIORITY_SEVERITIES for f in group.findings)


def group_findings(
    findings: list[DeepFinding],
    *,
    strategy: str = DEFAULT_STRATEGY,
    max_prs: int = DEFAULT_MAX_PRS,
) -> list[PRGroup]:
    """Group findings into pull requests.

    Strategies:
        * ``per-category`` (default): one PR per :class:`FindingCategory`.
          Dependency findings always collapse into a single PR.
        * ``per-file``: one PR per source file.
        * ``per-finding``: one PR per finding.
        * ``single``: all findings in one PR.

    Cap + prioritize (``max_prs``): if grouping would exceed the cap, PRs whose
    findings include a critical/high issue are opened first; the remaining
    groups are merged into a SINGLE batch PR so nothing is EVER dropped. If even
    the priority groups exceed the cap, the overflow priority groups land in the
    batch too — in that case the batch is flagged ``contains_priority`` and
    titled "batched security fixes" (not "low-severity cleanup") so its urgency
    is not under-signalled.

    Returns an ordered list of :class:`PRGroup` (highest priority first).
    """
    if strategy not in VALID_STRATEGIES:
        raise ValueError(
            f"Unknown pr-strategy {strategy!r}; expected one of {VALID_STRATEGIES}"
        )
    if max_prs < 1:
        raise ValueError("max_prs must be >= 1")

    findings = [f for f in findings if f.code_location and f.code_location.file_path]
    if not findings:
        return []

    raw_groups = _build_raw_groups(findings, strategy)
    if not raw_groups:
        return []

    # Order groups: priority (critical/high) first, then by top severity, then key.
    raw_groups.sort(
        key=lambda g: (
            0 if _is_priority(g) else 1,
            _SEVERITY_RANK.get(g.top_severity, 99),
            g.key,
        )
    )

    if len(raw_groups) <= max_prs:
        return raw_groups

    return _apply_cap(raw_groups, max_prs)


def _build_raw_groups(findings: list[DeepFinding], strategy: str) -> list[PRGroup]:
    """Build the ungapped groups for a strategy (before the cap is applied)."""
    if strategy == "single":
        return [
            PRGroup(
                key="all",
                title_label="all findings",
                branch_suffix="all",
                findings=_sort_findings(findings),
            )
        ]

    if strategy == "per-finding":
        groups: list[PRGroup] = []
        for f in _sort_findings(findings):
            label = _category_label(f.category)
            groups.append(
                PRGroup(
                    key=f.id,
                    title_label=f"{label}: {f.title}",
                    branch_suffix=f"{_slugify(label)}-{f.id[:8]}",
                    findings=[f],
                )
            )
        return groups

    if strategy == "per-file":
        by_file: dict[str, list[DeepFinding]] = defaultdict(list)
        for f in findings:
            by_file[f.code_location.file_path].append(f)
        groups = []
        for path, group in by_file.items():
            groups.append(
                PRGroup(
                    key=path,
                    title_label=os.path.basename(path) or path,
                    branch_suffix=_slugify(path),
                    findings=_sort_findings(group),
                )
            )
        return groups

    # per-category (default): one PR per category; dependencies collapse.
    by_cat: dict[str, list[DeepFinding]] = defaultdict(list)
    for f in findings:
        by_cat[f.category.value].append(f)

    groups = []
    for cat_value, group in by_cat.items():
        label = _category_label(cat_value)
        groups.append(
            PRGroup(
                key=cat_value,
                title_label=label,
                branch_suffix=_slugify(label),
                findings=_sort_findings(group),
            )
        )
    return groups


def _apply_cap(groups: list[PRGroup], max_prs: int) -> list[PRGroup]:
    """Enforce ``max_prs`` by keeping priority groups and batching the rest.

    ``groups`` is already ordered priority-first. Priority (critical/high)
    groups are kept as-is up to ``max_prs - 1`` so there is always room for the
    low-severity batch; everything left over collapses into one cleanup PR.
    """
    priority = [g for g in groups if _is_priority(g)]
    non_priority = [g for g in groups if not _is_priority(g)]

    # Reserve one slot for the low-severity batch when there is anything to batch.
    kept: list[PRGroup] = []
    leftovers: list[PRGroup] = []

    budget = max_prs - 1  # reserve a slot for the batch PR
    for g in priority:
        if len(kept) < budget:
            kept.append(g)
        else:
            leftovers.append(g)
    leftovers.extend(non_priority)

    batch_findings: list[DeepFinding] = []
    for g in leftovers:
        batch_findings.extend(g.findings)

    if not batch_findings:
        # Everything fit in the priority slots; no batch needed.
        return kept[:max_prs]

    # If even the priority groups overflowed the cap, the batch will contain
    # critical/high findings. Label it honestly — a PR titled "low-severity
    # cleanup" that actually carries critical fixes would dangerously
    # under-signal urgency to a reviewer.
    has_priority = any(
        f.severity in _PRIORITY_SEVERITIES for f in batch_findings
    )
    if has_priority:
        title_label = "batched security fixes"
        branch_suffix = "batched-fixes"
    else:
        title_label = "low-severity cleanup"
        branch_suffix = "low-severity-cleanup"

    batch = PRGroup(
        key=_LOW_BATCH_KEY,
        title_label=title_label,
        branch_suffix=branch_suffix,
        findings=_sort_findings(batch_findings),
        is_low_batch=True,
        contains_priority=has_priority,
    )
    return kept + [batch]


# ---------------------------------------------------------------------------
# PR body / title generation
# ---------------------------------------------------------------------------

def _commit_message(finding: DeepFinding) -> str:
    """Atomic, revertable commit message for one finding."""
    label = _category_label(finding.category)
    scope = _slugify(label).replace("-", "")
    path = finding.code_location.file_path if finding.code_location else "code"
    fname = os.path.basename(path) or path
    return f"fix({scope}): {finding.title} in {fname}"


def pr_title(group: PRGroup) -> str:
    n = len(group.findings)
    plural = "issue" if n == 1 else "issues"
    if group.is_low_batch and not group.contains_priority:
        return f"isitsecure: low-severity cleanup ({n} {plural})"
    if group.is_low_batch:  # batch that overflowed the cap with priority issues
        return f"isitsecure: batched security fixes ({n} {plural})"
    return f"isitsecure: fix {group.title_label} ({n} {plural})"


def pr_body(group: PRGroup) -> str:
    """Human-readable PR body: the class + a per-finding checklist."""
    lines: list[str] = []
    if group.is_low_batch and group.contains_priority:
        lines.append(
            "**This PR includes critical/high-severity fixes.** Several "
            "vulnerability categories were batched into one pull request to stay "
            "under the configured PR cap — review it with the same urgency as a "
            "dedicated high-severity PR."
        )
    elif group.is_low_batch:
        lines.append(
            "Batched low-severity fixes grouped into a single pull request "
            "to keep the number of PRs manageable."
        )
    else:
        lines.append(
            f"Automated fixes for **{group.title_label}** findings "
            "generated by isitsecure."
        )
    lines.append("")
    lines.append(f"**{len(group.findings)} finding(s) in this PR** "
                 "— one commit per finding so each fix is individually revertable:")
    lines.append("")
    for f in group.findings:
        path = f.code_location.file_path if f.code_location else "?"
        loc = path
        if f.code_location and f.code_location.line_number:
            loc = f"{path}:{f.code_location.line_number}"
        sev = f.severity.value if isinstance(f.severity, SeverityLevel) else str(f.severity)
        lines.append(f"- [ ] **[{sev}]** {f.title} — `{loc}`")
    lines.append("")
    lines.append("---")
    lines.append(
        "Review each commit, run your tests, then merge. "
        "isitsecure never pushes to your default branch."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Side-effect boundaries (injected → mocked in tests)
# ---------------------------------------------------------------------------

class GitError(RuntimeError):
    """A git command failed. The message is already token-scrubbed."""


def _is_non_fast_forward(git_error: str) -> bool:
    """True when a push was rejected because the remote branch already exists.

    Detects git's rejection wording so we can report "branch already exists"
    instead of the raw error (and never fall back to a clobbering force-push).
    """
    lowered = git_error.lower()
    return (
        "non-fast-forward" in lowered
        or "fetch first" in lowered
        or "failed to push some refs" in lowered
        or "rejected" in lowered
    )


class GitRunner:
    """Runs git commands in a working tree. Token is scrubbed from any output."""

    def __init__(self, token: str | None = None) -> None:
        self._token = token

    def _scrub(self, text: str) -> str:
        if self._token and self._token in text:
            text = text.replace(self._token, "***")
        return text

    async def run(self, cwd: str, *args: str) -> str:
        # "--" is caller's responsibility; we never interpolate the token here.
        env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "https:http:ssh:git",
        }
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", cwd, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        out, err = await proc.communicate()
        stdout = out.decode(errors="replace").strip()
        stderr = err.decode(errors="replace").strip()
        if proc.returncode != 0:
            raise GitError(self._scrub(stderr or stdout or "git failed"))
        return self._scrub(stdout)


class GitHubClient:
    """Thin GitHub REST client for opening pull requests.

    The token is sent only in the ``Authorization`` header and never logged.
    """

    def __init__(self, token: str, *, api_base: str = "https://api.github.com") -> None:
        self._token = token
        self._api_base = api_base.rstrip("/")

    async def get_default_branch(self, ref: RepoRef) -> str | None:
        import httpx

        url = f"{self._api_base}/repos/{ref.owner}/{ref.repo}"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, headers=self._headers())
            if resp.status_code == 200:
                return resp.json().get("default_branch")
        return None

    async def open_pr(
        self,
        ref: RepoRef,
        *,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> str:
        """Open a PR and return its html_url. Raises on API error."""
        import httpx

        url = f"{self._api_base}/repos/{ref.owner}/{ref.repo}/pulls"
        payload = {"title": title, "body": body, "head": head, "base": base}
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, headers=self._headers(), json=payload)
        if resp.status_code not in (200, 201):
            # Never include the token; GitHub error bodies don't echo it.
            detail = _safe_github_error(resp)
            raise RuntimeError(f"GitHub PR creation failed ({resp.status_code}): {detail}")
        return resp.json().get("html_url", "")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }


def _safe_github_error(resp: "httpx.Response") -> str:
    try:
        data = resp.json()
        return str(data.get("message") or data)
    except Exception:
        return resp.text[:200]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class OpenedPR:
    category: str
    title: str
    branch: str
    url: str
    finding_count: int
    is_low_batch: bool = False


@dataclass
class PRFlowResult:
    mode: str = "pull_requests"
    repo: str = ""
    base_branch: str = ""
    opened_prs: list[OpenedPR] = field(default_factory=list)
    fixed_count: int = 0
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "repo": self.repo,
            "base_branch": self.base_branch,
            "fixed_count": self.fixed_count,
            "skipped": self.skipped,
            "errors": self.errors,
            "summary": self.summary,
            "pull_requests": [
                {
                    "category": p.category,
                    "title": p.title,
                    "branch": p.branch,
                    "url": p.url,
                    "finding_count": p.finding_count,
                    "is_low_batch": p.is_low_batch,
                }
                for p in self.opened_prs
            ],
        }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class PRFlow:
    """Clone a remote repo, generate fixes, and open per-category pull requests.

    Collaborators are injected (DIP) so tests mock git + the GitHub API:
        generator      — the existing :class:`FixGenerator`.
        github         — factory ``(token) -> GitHubClient`` (default: real).
        git            — factory ``(token) -> GitRunner`` (default: real).
        clone          — async ``(repo_url, branch, dir, token) -> None`` cloner
                         (default: reuses ``RepoIngestionService._clone_repo``).
    """

    def __init__(
        self,
        generator: FixGenerator,
        *,
        github_factory=None,
        git_factory=None,
        clone_fn=None,
    ) -> None:
        self._generator = generator
        self._github_factory = github_factory or (lambda tok: GitHubClient(tok))
        self._git_factory = git_factory or (lambda tok: GitRunner(tok))
        self._clone_fn = clone_fn or self._default_clone

    async def run(
        self,
        *,
        repo_url: str,
        findings: list[DeepFinding],
        github_token: str,
        strategy: str = DEFAULT_STRATEGY,
        max_prs: int = DEFAULT_MAX_PRS,
        emit=None,
    ) -> PRFlowResult:
        """Execute the full remote fix → PR flow.

        Raises ``ValueError`` for a non-GitHub host (caller should fall back to
        the fix-plan behavior). The temp clone is always cleaned up.
        """
        ref = parse_github_url(repo_url)
        if not ref.is_github:
            raise ValueError(
                f"Remote PR flow supports github.com only; got host {ref.host!r}."
            )
        if not github_token:
            raise ValueError("A GitHub token is required to open pull requests.")

        result = PRFlowResult(repo=ref.slug)
        github = self._github_factory(github_token)
        git = self._git_factory(github_token)

        clone_dir = tempfile.mkdtemp(prefix="isitsecure_prfix_")
        try:
            await self._maybe_emit(emit, "progress", "Detecting default branch…")
            base_branch = await github.get_default_branch(ref) or "main"
            result.base_branch = base_branch

            await self._maybe_emit(emit, "progress", f"Cloning {ref.slug}…")
            await self._clone_fn(repo_url, base_branch, clone_dir, github_token)

            # Only SAST findings with a code location are fixable here.
            fixable = [
                f for f in findings if f.code_location and f.code_location.file_path
            ]
            for f in findings:
                if not (f.code_location and f.code_location.file_path):
                    result.skipped.append(
                        f"{f.title} — no code location (DAST-only, no code fix)"
                    )

            if not fixable:
                result.summary = "No fixable SAST findings with a code location."
                return result

            groups = group_findings(
                fixable, strategy=strategy, max_prs=max_prs
            )

            for group in groups:
                await self._process_group(
                    group=group,
                    ref=ref,
                    base_branch=base_branch,
                    clone_dir=clone_dir,
                    git=git,
                    github=github,
                    result=result,
                    emit=emit,
                )

            result.summary = self._build_summary(result, groups)
            return result
        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)

    async def _process_group(
        self,
        *,
        group: PRGroup,
        ref: RepoRef,
        base_branch: str,
        clone_dir: str,
        git: GitRunner,
        github: GitHubClient,
        result: PRFlowResult,
        emit,
    ) -> None:
        branch = f"isitsecure/fix-{group.branch_suffix}"
        await self._maybe_emit(
            emit, "progress", f"Preparing {branch} ({len(group.findings)} finding(s))…"
        )

        # SAFETY: refuse to ever target the default branch.
        if branch == base_branch:
            branch = f"{branch}-fixes"
        if branch == base_branch:
            result.errors.append(
                f"Refusing to build a fix branch equal to default branch {base_branch}."
            )
            return

        # Start from a clean checkout of the default branch for each group.
        try:
            await git.run(clone_dir, "checkout", "--force", base_branch)
            await git.run(clone_dir, "checkout", "-B", branch)
        except GitError as e:
            result.errors.append(f"{group.key}: could not create branch — {e}")
            return

        committed = 0
        for finding in group.findings:
            ok = await self._apply_and_commit(
                finding=finding, clone_dir=clone_dir, git=git, result=result
            )
            if ok:
                committed += 1

        if committed == 0:
            result.skipped.append(
                f"{group.title_label} — no fixes could be generated"
            )
            return

        # SAFETY: push the FEATURE branch only, never base_branch.
        # We do NOT force-push: a non-force push of a *new* branch succeeds, but
        # if an ``isitsecure/fix-*`` branch already exists on the remote (e.g. a
        # prior run with work the user hasn't merged) git rejects the push rather
        # than silently clobbering it. We surface that clearly instead of forcing.
        try:
            await git.run(
                clone_dir, "push", "origin",
                f"HEAD:refs/heads/{branch}",
            )
        except GitError as e:
            msg = str(e)
            if _is_non_fast_forward(msg):
                result.errors.append(
                    f"{group.key}: branch {branch!r} already exists on the remote "
                    "with different commits — refusing to overwrite it. Delete or "
                    "merge that branch, then re-run."
                )
            else:
                result.errors.append(f"{group.key}: git push failed — {e}")
            return

        try:
            url = await github.open_pr(
                ref,
                title=pr_title(group),
                body=pr_body(group),
                head=branch,
                base=base_branch,
            )
        except Exception as e:  # noqa: BLE001 — surface API error, keep going.
            result.errors.append(f"{group.key}: opening PR failed — {e}")
            return

        result.fixed_count += committed
        result.opened_prs.append(
            OpenedPR(
                category=group.key,
                title=pr_title(group),
                branch=branch,
                url=url,
                finding_count=committed,
                is_low_batch=group.is_low_batch,
            )
        )
        await self._maybe_emit(emit, "progress", f"Opened PR: {url}")

    async def _apply_and_commit(
        self,
        *,
        finding: DeepFinding,
        clone_dir: str,
        git: GitRunner,
        result: PRFlowResult,
    ) -> bool:
        """Generate a fix for one finding, write it, and commit it atomically."""
        rel_path = finding.code_location.file_path
        full_path = os.path.join(clone_dir, rel_path)
        # Guard against path traversal from a malicious finding.
        if not os.path.realpath(full_path).startswith(os.path.realpath(clone_dir) + os.sep):
            result.skipped.append(f"{finding.title} — path escapes repo, skipped")
            return False
        if not os.path.isfile(full_path):
            result.skipped.append(f"{finding.title} — {rel_path} not found in repo")
            return False

        try:
            content = open(full_path, encoding="utf-8", errors="replace").read()
        except OSError as e:
            result.skipped.append(f"{finding.title} — could not read {rel_path}: {e}")
            return False

        fix: FixResult = await self._generator.generate_fix(finding, content)
        if not (fix.success and fix.fixed_code):
            result.skipped.append(
                f"{finding.title} — no fix generated"
                + (f" ({fix.error})" if fix.error else "")
            )
            return False

        try:
            with open(full_path, "w", encoding="utf-8") as fh:
                fh.write(fix.fixed_code)
            await git.run(clone_dir, "add", "--", rel_path)
            await git.run(clone_dir, "commit", "-m", _commit_message(finding))
        except (OSError, GitError) as e:
            result.errors.append(f"{finding.title} — commit failed: {e}")
            return False
        return True

    @staticmethod
    def _build_summary(result: PRFlowResult, groups: list[PRGroup]) -> str:
        n_prs = len(result.opened_prs)
        priority_prs = [p for p in result.opened_prs if not p.is_low_batch]
        low_prs = [p for p in result.opened_prs if p.is_low_batch]

        if n_prs == 0:
            return "No pull requests were opened."

        parts = [
            f"Opened {n_prs} pull request(s) for {result.fixed_count} finding(s)"
        ]
        if low_prs:
            batched = sum(p.finding_count for p in low_prs)
            parts = [
                f"Opened {len(priority_prs)} PR(s) for critical/high; "
                f"{batched} low-severity issue(s) batched into "
                f"{len(low_prs)} PR."
            ]
        return " ".join(parts) + "."

    # -- default clone (reuses RepoIngestionService's hardened clone) --------

    @staticmethod
    async def _default_clone(
        repo_url: str, branch: str, clone_dir: str, github_token: str | None
    ) -> None:
        from isitsecure.engine.code_analysis.repo_ingestion import (
            RepoIngestionService,
        )

        # We need full history (not --depth 1) so we can push a branch and the
        # remote 'origin' with the token baked in for the push.
        service = RepoIngestionService(framework_detector=None)  # type: ignore[arg-type]
        # Clone into a scratch dir, then move into clone_dir (mkdtemp made it).
        shutil.rmtree(clone_dir, ignore_errors=True)
        await service._clone_repo(  # noqa: SLF001 — intentional reuse.
            repo_url, branch, clone_dir, github_token, full_history=True
        )
        # Ensure 'origin' carries the token so the later push authenticates.
        if github_token and repo_url.startswith("https://"):
            authed = repo_url.replace(
                "https://", f"https://x-access-token:{github_token}@"
            )
            runner = GitRunner(github_token)
            await runner.run(clone_dir, "remote", "set-url", "origin", authed)

    @staticmethod
    async def _maybe_emit(emit, type_: str, message: str) -> None:
        if emit is None:
            return
        r = emit({"type": type_, "message": message})
        if asyncio.iscoroutine(r):
            await r
