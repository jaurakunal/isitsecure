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
    * NEVER pushes to the base branch — always a feature branch + PR.
    * NEVER force-pushes. The remote is checked (``ls-remote``) for each
      planned ``isitsecure/fix-*`` branch BEFORE any LLM spend. A branch that
      already exists with an OPEN pull request is noted and skipped (no
      duplicate); one that exists with NO open PR (merged earlier, or orphaned
      by a failed PR) is never reused or overwritten — the next free
      ``-2``/``-3``… name is used instead, so a re-run is never blocked.
    * The GitHub token is passed in, never persisted, never logged: it is not in
      the clone URL, argv or ``.git/config`` (see ``git_ops``), and git errors
      are scrubbed of it before surfacing.
    * The clone lives in a 0700 directory and is removed on success, on error
      and on cancellation.
    * Untrusted finding text is flattened/redacted/escaped (``pr_text``).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.fixes.fix_generator import (
    FixGenerator,
    FixResult,
    read_source_file,
    resolve_fix_target,
    write_source_file,
)
from isitsecure.engine.fixes.git_ops import (  # noqa: F401 — re-exported API
    GitError,
    GitRunner,
    clone_repo,
    is_non_fast_forward,
    is_valid_branch_name,
    remote_branches,
)
from isitsecure.engine.fixes.pr_text import inline, md_code, md_text
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
    "business_logic": "Business logic",
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


def normalize_repo_scheme(url: str) -> str:
    """Lowercase only the ``scheme://`` prefix (URL schemes are case-insensitive).

    ``HTTPS://github.com/o/r`` parses as GitHub; downstream code that matches
    ``https://`` literally (token injection, ``remote set-url``) must see the
    same spelling the parser accepted.
    """
    m = re.match(r"^\s*([A-Za-z][A-Za-z0-9+.-]*)://", url or "")
    if not m:
        return url
    return url.strip()[: len(m.group(1))].lower() + url.strip()[len(m.group(1)):]


def parse_github_url(url: str) -> RepoRef:
    """Parse owner/repo/host from a git URL, strictly.

    Accepts ``https://github.com/owner/repo(.git)``, ``ssh://git@github.com/
    owner/repo``, ``git@github.com:owner/repo.git`` and a bare
    ``github.com/owner/repo``. For github.com the path must be exactly
    ``owner/repo`` and the URL may carry no userinfo, query or fragment, so
    look-alikes such as ``https://evil.com#@github.com/o/r`` can never be
    mistaken for GitHub. Other hosts (http(s)/ssh/git) parse to their own host
    with ``is_github`` False. Raises ``ValueError`` for anything that doesn't
    yield a host + owner + repo.
    """
    if not url or not url.strip():
        raise ValueError("Empty repository URL")
    # Control characters (trailing newline, embedded tab, NUL ...) are never
    # part of a real repo URL; urlsplit would silently strip some of them.
    if any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError(f"Control characters in repository URL: {url!r}")
    raw = url.strip()

    # scp-like: git@host:owner/repo(.git)
    port: int | None = None
    scp = re.match(r"^[\w.-]+@([\w.-]+):(.+)$", raw)
    if scp and "://" not in raw:
        host = scp.group(1).lower()
        path = scp.group(2)
        scheme = "ssh"
    else:
        try:
            parts = urlsplit(raw if "://" in raw else f"https://{raw}")
            host = (parts.hostname or "").lower()
            username, password = parts.username, parts.password
        except ValueError as exc:
            raise ValueError(f"Cannot parse owner/repo from URL: {url}") from exc
        scheme = parts.scheme.lower()
        path = parts.path
        try:
            port = parts.port
        except ValueError as exc:  # non-numeric or out of range
            raise ValueError(f"Invalid port in repository URL: {url}") from exc
        if scheme not in ("https", "http", "ssh", "git"):
            raise ValueError(f"Unsupported URL scheme in: {url}")
        if parts.query or parts.fragment or password is not None:
            raise ValueError(f"Cannot parse owner/repo from URL: {url}")
        # Userinfo is only legitimate as the ssh login user ``git``.
        if username and not (scheme == "ssh" and username == "git"):
            raise ValueError(f"Unexpected credentials in repository URL: {url}")

    # path is "owner/repo(/...)(.git)"
    segments = [s for s in path.strip("/").split("/") if s]
    if len(segments) < 2:
        raise ValueError(f"Cannot parse owner/repo from URL: {url}")
    if any(s in (".", "..") for s in segments):
        raise ValueError(f"Dot segments in repository URL: {url}")
    owner = segments[0]
    repo = segments[1]
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]

    if host == "github.com":
        # Exactly github.com, default port only: ``github.com:8443`` is another
        # service and must not receive a GitHub token.
        if port not in (None, 443):
            raise ValueError(f"Unexpected port for github.com: {url}")
        if repo.endswith(".git"):
            raise ValueError(f"Cannot parse owner/repo from URL: {url}")
        if len(segments) != 2 or scheme == "http" or scheme == "git":
            raise ValueError(f"Not a plain https/ssh GitHub repo URL: {url}")
        if not re.fullmatch(r"[\w.-]+", owner) or not re.fullmatch(r"[\w.-]+", repo):
            raise ValueError(f"Cannot parse owner/repo from URL: {url}")

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


_MAX_SLUG_LEN = 48


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "misc"


def _finding_identity(f: DeepFinding) -> str:
    loc = f.code_location
    return f"{f.category.value}|{loc.file_path}|{loc.line_number}|{f.title}"


def _short_hash(text: str) -> str:
    """Stable 8-hex digest, used to keep branch names unique across groups."""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:8]


def _unique_suffix(label: str, identity: str) -> str:
    """Bounded ``<slug>-<hash>``: ``a_b.py`` and ``a-b.py`` slug alike but hash apart."""
    slug = _slugify(label)[:_MAX_SLUG_LEN].strip("-") or "misc"
    return f"{slug}-{_short_hash(identity)}"


def _dedupe_branch_suffixes(groups: list[PRGroup]) -> None:
    """Last line of defence: no two groups in one run may share a branch."""
    seen: set[str] = set()
    for g in groups:
        suffix, n = g.branch_suffix, 2
        while suffix in seen:
            suffix = f"{g.branch_suffix}-{n}"
            n += 1
        g.branch_suffix = suffix
        seen.add(suffix)


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

    groups = raw_groups if len(raw_groups) <= max_prs else _apply_cap(raw_groups, max_prs)
    _dedupe_branch_suffixes(groups)
    return groups


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
                    # Stable content identity (NOT f.id, a random uuid per
                    # scan) so a re-run maps the same finding to the same name.
                    branch_suffix=_unique_suffix(label, _finding_identity(f)),
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
                    branch_suffix=_unique_suffix(path, path),
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
    # Untrusted text: one bounded line, secrets redacted.
    return inline(f"fix({scope}): {inline(finding.title, 70)} in {inline(fname, 40)}", 120)


def pr_title(group: PRGroup) -> str:
    n = len(group.findings)
    plural = "issue" if n == 1 else "issues"
    if group.is_low_batch and not group.contains_priority:
        return f"isitsecure: low-severity cleanup ({n} {plural})"
    if group.is_low_batch:  # batch that overflowed the cap with priority issues
        return f"isitsecure: batched security fixes ({n} {plural})"
    return inline(f"isitsecure: fix {group.title_label} ({n} {plural})", 150)


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
            f"Automated fixes for **{md_text(group.title_label)}** findings "
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
        lines.append(f"- [ ] **[{sev}]** {md_text(f.title)} — `{md_code(loc)}`")
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

class GitHubClient:
    """Thin GitHub REST client for opening pull requests.

    The token is sent only in the ``Authorization`` header and never logged.
    """

    def __init__(self, token: str, *, api_base: str = "https://api.github.com") -> None:
        self._token = token
        self._api_base = api_base.rstrip("/")

    async def get_default_branch(self, ref: RepoRef) -> str:
        """The repo's default branch, or raise :class:`RepoAccessError`.

        Never guesses: a bad token, missing permission, renamed repo or network
        failure is reported as such rather than silently becoming ``main``.
        """
        import httpx

        url = f"{self._api_base}/repos/{ref.owner}/{ref.repo}"
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, headers=self._headers())
        except httpx.HTTPError as exc:
            raise RepoAccessError(
                f"Could not reach GitHub to look up {ref.slug} "
                f"({type(exc).__name__}); check your network and retry."
            ) from None
        if resp.status_code == 200:
            try:
                branch = resp.json().get("default_branch")
            except ValueError:
                branch = None
            if isinstance(branch, str) and branch:
                return branch
            raise RepoAccessError(
                f"GitHub returned no default branch for {ref.slug}."
            )
        raise RepoAccessError(_describe_repo_status(ref, resp))

    async def find_open_pr(self, ref: RepoRef, *, head: str, base: str) -> str | None:
        """html_url of an open PR from ``head`` into ``base``, if one exists.

        Best effort (``None`` on any failure): only used to word a message.
        """
        import httpx

        url = f"{self._api_base}/repos/{ref.owner}/{ref.repo}/pulls"
        params = {"head": f"{ref.owner}:{head}", "base": base, "state": "open"}
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(url, headers=self._headers(), params=params)
            if resp.status_code == 200 and resp.json():
                return resp.json()[0].get("html_url") or None
        except (httpx.HTTPError, ValueError, AttributeError, KeyError, IndexError):
            logger.debug("open-PR lookup failed", exc_info=True)
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


class RepoAccessError(RuntimeError):
    """The target repo could not be looked up (auth, permission, rename, network)."""


def _describe_repo_status(ref: RepoRef, resp: "httpx.Response") -> str:
    status = resp.status_code
    if status == 401:
        return (
            f"GitHub rejected the token (401) while looking up {ref.slug}: it is "
            "invalid, expired or revoked."
        )
    if status == 403:
        return (
            f"GitHub denied access to {ref.slug} (403): the token lacks "
            "permission, SSO authorization is missing, or the API rate limit was hit."
        )
    if status == 404:
        return (
            f"{ref.slug} was not found (404): it does not exist, or the token "
            "cannot see it (private repos need the 'repo' scope)."
        )
    if status in (301, 302, 307, 308):
        return (
            f"{ref.slug} has moved or been renamed ({status}, now "
            f"{resp.headers.get('location', 'a new location')}); use its current URL."
        )
    return f"Unexpected GitHub response ({status}) looking up {ref.slug}."


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
    # Branches pushed to the remote whose PR could not be opened.
    orphaned_branches: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "repo": self.repo,
            "base_branch": self.base_branch,
            "fixed_count": self.fixed_count,
            "skipped": self.skipped,
            "errors": self.errors,
            "orphaned_branches": self.orphaned_branches,
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


def resolve_scan_branch(branch: str | None) -> tuple[str | None, str | None]:
    """Vet the branch a scan ran on: ``(usable_branch_or_None, warning_or_None)``.

    An empty/detached value means "use the default branch" (no warning). A name
    git would reject falls back to the default branch WITH a warning rather than
    failing the whole fix job.
    """
    if branch in (None, "", "HEAD"):
        return None, None
    if is_valid_branch_name(branch):
        return branch, None
    return None, (
        f"Scanned branch {inline(branch, 60)!r} is not a usable branch name; "
        "falling back to the repository's default branch."
    )


# Free-name search depth: ``x``, ``x-2`` … ``x-9``.
MAX_BRANCH_SUFFIX = 9


def _branch_for(group: PRGroup, base_branch: str) -> str:
    """Feature-branch name for a group; never equal to the base branch."""
    branch = f"isitsecure/fix-{group.branch_suffix}"
    return f"{branch}-fixes" if branch == base_branch else branch


def _candidate_branches(group: PRGroup, base_branch: str) -> list[str]:
    """Names to try in order: the root name, then ``-2`` … ``-9``."""
    root = _branch_for(group, base_branch)
    return [root] + [f"{root}-{n}" for n in range(2, MAX_BRANCH_SUFFIX + 1)]


def _unfixable_path_reason(clone_dir: str, rel_path: str) -> str | None:
    """Why ``rel_path`` can't be safely rewritten in the clone, or ``None``."""
    shown = inline(rel_path, 120)
    try:
        full_path = resolve_fix_target(clone_dir, rel_path)
    except ValueError:
        return "path escapes repo, skipped"
    # resolve_fix_target follows symlinks, so inspect the raw components: a
    # symlinked file/dir would be written through but never staged by git.
    probe = clone_dir
    for part in rel_path.replace("\\", "/").split("/"):
        probe = os.path.join(probe, part)
        if os.path.islink(probe):
            return f"{shown} is (or is under) a symlink, skipped"
    if not os.path.isfile(full_path):
        return f"{shown} not found in repo"
    return None


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
        branch: str | None = None,
        emit=None,
    ) -> PRFlowResult:
        """Execute the full remote fix → PR flow.

        ``branch`` is the branch the scan ran on; fixes are cloned from and
        proposed against it. ``None`` means the repo's default branch, which is
        looked up (a lookup failure is reported, never guessed around).

        Raises ``ValueError`` for a non-GitHub host or an invalid ``branch``
        (caller should fall back to the fix-plan behavior). The temp clone is
        always cleaned up, including on cancellation.
        """
        repo_url = normalize_repo_scheme(repo_url)
        ref = parse_github_url(repo_url)
        if not ref.is_github:
            raise ValueError(
                f"Remote PR flow supports github.com only; got host {ref.host!r}."
            )
        if not github_token:
            raise ValueError("A GitHub token is required to open pull requests.")
        if branch in ("", "HEAD"):  # unknown / detached: use the default branch
            branch = None
        if branch is not None and not is_valid_branch_name(branch):
            raise ValueError(f"Invalid branch name: {inline(branch, 80)!r}")

        result = PRFlowResult(repo=ref.slug)
        github = self._github_factory(github_token)
        git = self._git_factory(github_token)

        try:
            base_branch = branch or await self._detect_default_branch(github, ref, emit)
        except RepoAccessError as exc:
            result.errors.append(str(exc))
            result.summary = "No pull requests were opened: could not look up the repository."
            return result
        result.base_branch = base_branch

        # 0700 parent + 0700 clone dir: no window where the checkout is readable
        # by other local users, and no rmtree/recreate gap.
        work_dir = tempfile.mkdtemp(prefix="isitsecure_prfix_")
        clone_dir = os.path.join(work_dir, "repo")
        try:
            os.mkdir(clone_dir, 0o700)
            await self._maybe_emit(emit, "progress", f"Cloning {ref.slug}@{base_branch}…")
            await self._clone_fn(repo_url, base_branch, clone_dir, github_token)

            fixable = self._split_fixable(findings, result)
            if not fixable:
                result.summary = "No fixable SAST findings with a code location."
                return result

            groups = group_findings(fixable, strategy=strategy, max_prs=max_prs)
            existing = await self._existing_branches(
                git, clone_dir, groups, base_branch, emit
            )

            taken: set[str] = set()
            for group in groups:
                branch_name = await self._select_branch(
                    group, base_branch, existing, taken, ref, github, result
                )
                if branch_name is None:
                    continue
                taken.add(branch_name)
                await self._process_group(
                    group=group,
                    branch=branch_name,
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
            shutil.rmtree(work_dir, ignore_errors=True)

    @staticmethod
    async def _detect_default_branch(github, ref: RepoRef, emit) -> str:
        await PRFlow._maybe_emit(emit, "progress", "Detecting default branch…")
        name = await github.get_default_branch(ref)
        if not is_valid_branch_name(name):
            raise RepoAccessError(
                f"GitHub returned an unusable default branch name for {ref.slug}."
            )
        return name

    @staticmethod
    def _split_fixable(
        findings: list[DeepFinding], result: PRFlowResult
    ) -> list[DeepFinding]:
        """Keep SAST findings with a code location; report the rest as skipped."""
        fixable: list[DeepFinding] = []
        for f in findings:
            if f.code_location and f.code_location.file_path:
                fixable.append(f)
            else:
                result.skipped.append(
                    f"{inline(f.title, 80)} — no code location (DAST-only, no code fix)"
                )
        return fixable

    async def _existing_branches(
        self, git, clone_dir: str, groups: list[PRGroup], base_branch: str, emit
    ) -> set[str]:
        """Candidate branches already on the remote, found BEFORE any LLM spend."""
        planned = [c for g in groups for c in _candidate_branches(g, base_branch)]
        try:
            return await remote_branches(git, clone_dir, planned)
        except GitError as exc:
            # Best effort: a failed lookup must not block the run. The push is
            # still non-force, so an existing branch is rejected, never clobbered.
            logger.warning("ls-remote pre-check failed: %s", inline(str(exc), 200))
            await self._maybe_emit(
                emit, "progress", "Could not pre-check existing branches; continuing."
            )
            return set()

    @staticmethod
    async def _select_branch(
        group: PRGroup,
        base_branch: str,
        existing: set[str],
        taken: set[str],
        ref: RepoRef,
        github,
        result: PRFlowResult,
    ) -> str | None:
        """Pick this group's branch, or ``None`` when it must not run.

        Walk ``x``, ``x-2`` … in order. A name that exists remotely with an
        OPEN pull request means the work is already proposed: skip the group
        (no duplicate). One that exists without an open PR (merged earlier, or
        orphaned by a failed PR) is never reused or overwritten: try the next
        name. The first free name wins.
        """
        for candidate in _candidate_branches(group, base_branch):
            if candidate in taken:
                continue
            if candidate not in existing:
                return candidate
            open_url = await github.find_open_pr(ref, head=candidate, base=base_branch)
            if open_url:
                result.skipped.append(
                    f"{group.title_label} — branch {candidate!r} already has an open "
                    f"pull request ({open_url}); nothing new was opened."
                )
                return None
        result.errors.append(
            f"{group.key}: every branch name up to {MAX_BRANCH_SUFFIX} variants of "
            f"{_branch_for(group, base_branch)!r} already exists on the remote with no "
            "open pull request. Delete the stale isitsecure/fix-* branches, then re-run."
        )
        return None

    async def _process_group(
        self,
        *,
        group: PRGroup,
        branch: str,
        ref: RepoRef,
        base_branch: str,
        clone_dir: str,
        git: GitRunner,
        github: GitHubClient,
        result: PRFlowResult,
        emit,
    ) -> None:
        await self._maybe_emit(
            emit, "progress", f"Preparing {branch} ({len(group.findings)} finding(s))…"
        )

        # SAFETY: refuse to ever target the default branch.
        if branch == base_branch:
            result.errors.append(
                f"Refusing to build a fix branch equal to default branch {base_branch}."
            )
            return

        # Start from a clean checkout of the base branch for each group.
        try:
            await git.run(clone_dir, "checkout", "--force", base_branch, "--")
            await git.run(clone_dir, "checkout", "-B", branch)
        except GitError as e:
            result.errors.append(f"{group.key}: could not create branch — {inline(str(e), 300)}")
            return

        committed = 0
        for finding in group.findings:
            if await self._apply_and_commit(
                finding=finding, clone_dir=clone_dir, git=git, result=result
            ):
                committed += 1

        if committed == 0:
            result.skipped.append(
                f"{group.title_label} — no fixes could be generated"
            )
            return

        if not await self._push(git, clone_dir, branch, group, result):
            return
        await self._open_pr(
            group=group, branch=branch, committed=committed, ref=ref,
            base_branch=base_branch, github=github, result=result, emit=emit,
        )

    @staticmethod
    async def _push(
        git: GitRunner, clone_dir: str, branch: str, group: PRGroup,
        result: PRFlowResult,
    ) -> bool:
        """Push the FEATURE branch (never the base, never forced)."""
        try:
            await git.run(clone_dir, "push", "origin", f"HEAD:refs/heads/{branch}")
        except GitError as e:
            msg = str(e)
            if is_non_fast_forward(msg):
                result.errors.append(
                    f"{group.key}: branch {branch!r} already exists on the remote "
                    "with different commits — refusing to overwrite it. Delete or "
                    "merge that branch, then re-run."
                )
            else:
                result.errors.append(
                    f"{group.key}: git push of {branch!r} failed — {inline(msg, 600)}"
                )
            return False
        return True

    async def _open_pr(
        self,
        *,
        group: PRGroup,
        branch: str,
        committed: int,
        ref: RepoRef,
        base_branch: str,
        github: GitHubClient,
        result: PRFlowResult,
        emit,
    ) -> None:
        title = pr_title(group)
        try:
            url = await github.open_pr(
                ref, title=title, body=pr_body(group), head=branch, base=base_branch,
            )
        except Exception as e:  # noqa: BLE001 — surface API error, keep going.
            result.orphaned_branches.append(branch)
            result.errors.append(
                f"{group.key}: opening the PR failed — {inline(str(e), 300)}. The branch "
                f"{branch!r} WAS pushed to the remote and is orphaned: open a PR from it "
                f"into {base_branch!r} yourself, or delete it before re-running (a re-run "
                "refuses to overwrite it)."
            )
            return

        result.fixed_count += committed
        result.opened_prs.append(
            OpenedPR(
                category=group.key,
                title=title,
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
        """Generate a fix for one finding, write it, and commit it atomically.

        Any failure leaves the working tree and index at HEAD, so one finding's
        half-applied edit can never be swept into the next finding's commit.
        """
        rel_path = finding.code_location.file_path
        label = inline(finding.title, 80)
        problem = _unfixable_path_reason(clone_dir, rel_path)
        if problem:
            result.skipped.append(f"{label} — {problem}")
            return False

        # Strict UTF-8, newlines untouched: a lossy decode would corrupt the
        # file when the fix is written back.
        content = read_source_file(clone_dir, rel_path)
        if content is None:
            result.skipped.append(
                f"{label} — {inline(rel_path, 120)} is not valid UTF-8 text, skipped"
            )
            return False

        fix: FixResult = await self._generator.generate_fix(finding, content)
        if not (fix.success and fix.fixed_code):
            result.skipped.append(
                f"{label} — no fix generated"
                + (f" ({inline(fix.error, 120)})" if fix.error else "")
            )
            return False

        try:
            write_source_file(clone_dir, rel_path, fix.fixed_code)
            if read_source_file(clone_dir, rel_path) == content:
                await self._discard_changes(git, clone_dir)
                result.skipped.append(f"{label} — fix made no change to the file, skipped")
                return False
            await git.run(clone_dir, "add", "--", rel_path)
            await git.run(clone_dir, "commit", "-m", _commit_message(finding))
        except (OSError, GitError) as e:
            await self._discard_changes(git, clone_dir)
            result.errors.append(f"{label} — commit failed: {inline(str(e), 300)}")
            return False
        return True

    @staticmethod
    async def _discard_changes(git: GitRunner, clone_dir: str) -> None:
        """Reset index + working tree to HEAD (the last good commit)."""
        try:
            await git.run(clone_dir, "reset", "--hard", "-q", "HEAD")
        except GitError:
            logger.warning("could not reset the temp clone after a failed commit")

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

    # -- default clone (token-free URL; auth rides on the git env) -----------

    @staticmethod
    async def _default_clone(
        repo_url: str, branch: str, clone_dir: str, github_token: str | None
    ) -> None:
        ref = parse_github_url(normalize_repo_scheme(repo_url))
        # Canonical https URL: the token only authenticates https, and nothing
        # token-bearing is written into the clone's config.
        url = f"https://github.com/{ref.owner}/{ref.repo}.git"
        await clone_repo(url, branch, clone_dir, github_token)

    @staticmethod
    async def _maybe_emit(emit, type_: str, message: str) -> None:
        if emit is None:
            return
        r = emit({"type": type_, "message": message})
        if asyncio.iscoroutine(r):
            await r
