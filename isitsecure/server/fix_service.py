"""Batch "Fix All" service for the web UI.

Given a completed scan report, generate fixes for the in-scope findings and
either:

- **apply** them to a *local git repo* on a fresh branch (leaving the user's
  current branch and working tree untouched), or
- **fall back** to a downloadable Markdown fix plan when the scan target is a
  live URL or a remote repo (no local files to write), or when the local tree
  is dirty / changed while the fixes were being generated.

The server that runs this lives on the user's own machine (``isitsecure
launch``), which is what makes safe local application possible.

Data-safety rules for the local apply path:

* Applying needs a clean tree, and the cleanliness (plus HEAD / branch) is
  re-checked right before the fix branch is created: generation takes minutes,
  and anything the user edited meanwhile is never touched -- we fall back to a
  plan instead.
* The user's branch is restored with a plain ``git checkout`` (never
  ``--force``). If that is refused because files changed, the user is left on
  the fix branch with an explicit message saying so.
* Files git does not track (gitignored / untracked), or tracks as
  skip-worktree / assume-unchanged, are never written.
* One apply at a time per repo (lock), writes are atomic and rolled back on
  failure.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Awaitable, Callable

from isitsecure.config import load_api_key
from isitsecure.engine.fixes.fix_generator import (
    FixGenerator,
    FixPlan,
    read_source_file,
)
from isitsecure.engine.fixes.markdown_exporter import FixPlanMarkdownExporter
from isitsecure.engine.fixes.pr_flow import (
    DEFAULT_MAX_PRS,
    DEFAULT_STRATEGY,
    VALID_STRATEGIES,
    PRFlow,
    is_remote_url,
    parse_github_url,
    resolve_scan_branch,
)
from isitsecure.engine.models import DeepFinding

logger = logging.getLogger(__name__)

Emit = Callable[[dict], Awaitable[None]]

DEFAULT_SEVERITIES = ("critical", "high")
VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
# Hard ceilings on a single job's cost (each LLM call is one paid request).
MAX_PRS_LIMIT = 50
DEFAULT_MAX_LLM_CALLS = 100
_MAX_FILE_SIZE = FixGenerator.MAX_FILE_SIZE


def _fixed_ids(plan, findings: list[DeepFinding]) -> set[str]:
    """Ids of findings whose fix was generated (their file has a final version)."""
    results = getattr(plan, "results", None)
    if results is not None:
        return {r.finding_id for r in results if r.success}
    return {f.id for f in findings if f.code_location.file_path in plan.files}


# ---------------------------------------------------------------------------
# Input validation, secret scrubbing, spend cap
# ---------------------------------------------------------------------------

def validate_fix_options(
    severities: tuple[str, ...] | list[str] | None,
    pr_strategy: str | None,
    max_prs: int | None,
) -> tuple[tuple[str, ...], str, int]:
    """Normalise + validate fix-all options; raise ``ValueError`` on bad input.

    Called before any paid work so a typo fails fast with a clear message.
    """
    sev = tuple(s.strip().lower() for s in severities) if severities else DEFAULT_SEVERITIES
    bad = [s for s in sev if s not in VALID_SEVERITIES]
    if bad:
        raise ValueError(
            f"Unknown severity {', '.join(map(repr, bad))}; use: {', '.join(VALID_SEVERITIES)}"
        )
    strategy = pr_strategy or DEFAULT_STRATEGY
    if strategy not in VALID_STRATEGIES:
        raise ValueError(
            f"Unknown pr_strategy {strategy!r}; use one of: {', '.join(VALID_STRATEGIES)}"
        )
    if max_prs is None:
        prs = DEFAULT_MAX_PRS
    elif isinstance(max_prs, bool) or not isinstance(max_prs, int) or not 1 <= max_prs <= MAX_PRS_LIMIT:
        raise ValueError(f"max_prs must be an integer between 1 and {MAX_PRS_LIMIT}")
    else:
        prs = max_prs
    return sev, strategy, prs


# Credential shapes that must never reach a log line, a stored error or a client.
_SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_\-]{12,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@"),  # user:token@host
)


def scrub_secrets(text: str, *secrets: str | None) -> str:
    """Remove the given secrets, and anything shaped like a credential, from ``text``."""
    out = str(text)
    for secret in secrets:
        if secret:
            out = out.replace(secret, "***")
    for pat in _SECRET_PATTERNS:
        out = pat.sub(lambda m: (m.group(1) + "***@") if m.re.groups else "***", out)
    return out


class FixBudgetExceeded(RuntimeError):
    """The per-job LLM call cap was reached."""


class BudgetedLLM:
    """Wraps an LLM client and refuses calls past ``max_calls`` (spend cap)."""

    def __init__(self, inner, max_calls: int) -> None:
        self._inner = inner
        self.max_calls = max_calls
        self.calls = 0

    @property
    def exhausted(self) -> bool:
        return self.calls >= self.max_calls

    async def generate_with_system(self, *args, **kwargs):
        if self.exhausted:
            raise FixBudgetExceeded(f"LLM call budget of {self.max_calls} reached for this job")
        self.calls += 1
        return await self._inner.generate_with_system(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._inner, name)


# ---------------------------------------------------------------------------
# git helpers (async subprocess; return (returncode, stdout, stderr))
# ---------------------------------------------------------------------------

async def _git(repo: str, *args: str) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        "git", "-C", repo, *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    return (
        proc.returncode,
        out.decode(errors="replace").strip(),
        scrub_secrets(err.decode(errors="replace").strip()),
    )


async def _is_git_repo(repo: str) -> bool:
    code, out, _ = await _git(repo, "rev-parse", "--is-inside-work-tree")
    return code == 0 and out == "true"


async def _working_tree_clean(repo: str) -> bool:
    code, out, _ = await _git(repo, "status", "--porcelain")
    return code == 0 and out == ""


async def _current_branch(repo: str) -> str:
    _, out, _ = await _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    return out or "HEAD"


async def _head_sha(repo: str) -> str:
    code, out, _ = await _git(repo, "rev-parse", "HEAD")
    return out if code == 0 else ""


async def _branch_exists(repo: str, name: str) -> bool:
    code, _, _ = await _git(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{name}")
    return code == 0


async def _pick_branch_name(repo: str, base: str) -> str:
    name = base
    n = 2
    while await _branch_exists(repo, name):
        name = f"{base}-{n}"
        n += 1
    return name


async def _is_plainly_tracked(repo: str, rel: str) -> bool:
    """True for a normal tracked file (git ls-files tag ``H``).

    Untracked and gitignored files are not in the index; ``S`` (skip-worktree)
    and lowercase (assume-unchanged) entries hide edits from ``git status``.
    Writing any of those would either fail the commit or hide the change.
    """
    code, out, _ = await _git(repo, "ls-files", "-v", "--", rel)
    lines = [ln for ln in out.splitlines() if ln]
    return code == 0 and bool(lines) and all(ln[:1] == "H" for ln in lines)


# One apply at a time per repository: branch picking + checkout + restore is not
# atomic, and two concurrent runs would race on HEAD and the branch name.
_repo_locks: dict[str, asyncio.Lock] = {}
# Strong refs so an apply continues to completion (and restores the user's
# branch) even if the surrounding job is cancelled mid-way.
_apply_tasks: set[asyncio.Task] = set()


def _repo_lock(repo: str) -> asyncio.Lock:
    key = os.path.realpath(repo)
    lock = _repo_locks.get(key)
    if lock is None:
        lock = _repo_locks[key] = asyncio.Lock()
    return lock


# ---------------------------------------------------------------------------
# Local-path resolution
# ---------------------------------------------------------------------------

def _resolve_local_repo(repo_url: str | None) -> str | None:
    """Return an absolute local path if repo_url points at a local directory."""
    if not repo_url:
        return None
    candidate = repo_url
    if candidate.startswith("file://"):
        candidate = candidate[len("file://"):]
    elif "://" in candidate:
        return None  # remote URL
    path = os.path.abspath(os.path.expanduser(candidate))
    return path if os.path.isdir(path) else None


# ---------------------------------------------------------------------------
# Fix generation (per-file sequential chaining so fixes don't clobber)
# ---------------------------------------------------------------------------

def _select_findings(report: dict, severities: tuple[str, ...]) -> list[DeepFinding]:
    out: list[DeepFinding] = []
    for f in report.get("findings", []):
        if f.get("severity") not in severities:
            continue
        loc = f.get("code_location") or {}
        if not loc.get("file_path"):
            continue
        try:
            out.append(DeepFinding.model_validate(f))
        except Exception:
            continue
    return out


# ---------------------------------------------------------------------------
# Plan mode (nothing is written)
# ---------------------------------------------------------------------------

async def _plan_result(
    *,
    findings: list[DeepFinding],
    generator: FixGenerator,
    local_repo: str | None,
    reason: str,
    emit: Emit,
    prebuilt: FixPlan | None = None,
) -> dict:
    """Build the markdown fix plan from the REAL file contents.

    Scan snippets carry ``NNN |`` / ``>>>`` line markers and are a few lines of a
    file; rewriting them yields a diff that cannot apply to anything. So the
    plan is generated only from files readable on this machine; findings whose
    source is not available are listed as skipped, with no fabricated diff.
    """
    if prebuilt is not None:
        plan = prebuilt
    else:
        file_contents: dict[str, str] = {}
        skipped: list[str] = []
        if local_repo:
            for fnd in findings:
                fp = fnd.code_location.file_path
                if fp in file_contents:
                    continue
                text = read_source_file(local_repo, fp)
                if text is not None:
                    file_contents[fp] = text
        for fnd in findings:
            fp = fnd.code_location.file_path
            if fp not in file_contents:
                skipped.append(
                    f"{fnd.title} ({fp}) — source not available locally "
                    "(missing, not UTF-8, or this scan is not of a local folder); "
                    "apply the remediation guidance from the report manually"
                )
        await emit({"type": "progress", "message": "Generating fix plan…",
                    "current": 0, "total": len(findings)})
        if file_contents:
            plan = await generator.generate_fix_plan(
                [f for f in findings if f.code_location.file_path in file_contents],
                file_contents,
            )
            plan.total_findings = len(findings)
            plan.skipped.extend(skipped)
        else:
            plan = FixPlan(total_findings=len(findings), skipped=skipped)
        await emit({"type": "progress", "message": "Fix plan ready",
                    "current": len(findings), "total": len(findings)})
    return {
        "mode": "plan",
        "reason": reason,
        "markdown": FixPlanMarkdownExporter().export(plan),
        "fixed_count": plan.fixed_count,
        "skipped": plan.skipped,
    }


# ---------------------------------------------------------------------------
# Local apply (clean git tree -> new branch -> commit -> switch back)
# ---------------------------------------------------------------------------

async def _restore_base(local_repo: str, base_branch: str, base_sha: str, detached: bool) -> tuple[bool, str]:
    """Switch back to the user's original branch WITHOUT --force.

    Returns (restored, message). A refusal (the user edited files meanwhile)
    leaves them on the fix branch with their edits intact.
    """
    if detached and base_sha:
        code, _, err = await _git(local_repo, "checkout", "--detach", base_sha)
    else:
        code, _, err = await _git(local_repo, "checkout", base_branch)
    if code == 0:
        return True, ""
    return False, (
        f"Could not switch back to '{base_branch if not detached else base_sha[:10]}' "
        f"(your files changed while fixes were being generated, so nothing was "
        f"overwritten): {err}"
    )


async def _apply_locally(
    *,
    local_repo: str,
    findings: list[DeepFinding],
    plan,
    start_head: str,
    start_branch: str,
    skipped: list[str],
    contents: dict[str, str],
    emit: Emit,
) -> dict:
    from isitsecure.engine.fixes.safe_apply import apply_file_fixes, rollback_applied
    from isitsecure.engine.fixes.safety_net import create_safety_net

    final = plan.files

    # Take a restorable backup BEFORE touching anything; without one we
    # change nothing (same rule as the CLI).
    net = await asyncio.to_thread(create_safety_net, local_repo, list(final.keys()))
    if net.kind == "none" or net.failed:
        return {"mode": "applied", "applied": False, "fixed_count": 0,
                "skipped": skipped,
                "message": "Could not make a safe backup of the original files, "
                           "so nothing was changed."
                           + (f" Not backed up: {', '.join(net.failed[:5])}" if net.failed else "")}

    async with _repo_lock(local_repo):
        # The tree was clean when generation STARTED; it may not be now. Anything
        # the user edited or committed meanwhile must not be touched, so fall
        # back to a plan built from the fixes we already paid for.
        changed = (
            not await _working_tree_clean(local_repo)
            or await _head_sha(local_repo) != start_head
            or await _current_branch(local_repo) != start_branch
        )
        if changed:
            return await _plan_result(
                findings=findings, generator=None, local_repo=local_repo,
                reason="the working tree changed while fixes were being generated, "
                       "so nothing was written (your files were left alone)",
                emit=emit,
                prebuilt=FixPlan(fixes=list(getattr(plan, "results", [])), skipped=list(skipped),
                                 total_findings=len(findings)),
            )

        base_branch, base_sha = start_branch, start_head
        detached = base_branch == "HEAD"
        branch = await _pick_branch_name(local_repo, "isitsecure/fixes")
        await emit({"type": "progress", "message": f"Committing to {branch}…",
                    "current": len(final), "total": len(final)})

        code, _, err = await _git(local_repo, "checkout", "-b", branch)
        if code != 0:
            raise RuntimeError(f"Could not create branch: {err}")

        verification = None
        outcome = None
        failure: Exception | None = None
        try:
            outcome = await asyncio.to_thread(apply_file_fixes, local_repo, final, contents)
            if not outcome.ok:
                await asyncio.to_thread(rollback_applied, local_repo, outcome)
                detail = "; ".join(
                    [f"{p}: changed on disk" for p in outcome.stale]
                    + [f"{p}: {e}" for p, e in outcome.failed.items()]
                )
                raise RuntimeError(f"Could not write the fixes ({detail}); nothing was kept")
            for path in outcome.written:
                code, _, err = await _git(local_repo, "add", "--", path)
                if code != 0:
                    raise RuntimeError(f"git add failed for {path}: {err}")
            fixed_n = len(_fixed_ids(plan, findings))
            msg = f"isitsecure: fix {fixed_n} finding(s) across {len(final)} file(s)"
            code, _, err = await _git(local_repo, "commit", "-m", msg)
            if code != 0:
                raise RuntimeError(f"Commit failed: {err}")

            # Re-scan the fixed working tree to confirm the findings are gone.
            try:
                await emit({"type": "progress", "message": "Verifying fixes…",
                            "current": len(final), "total": len(final)})
                from isitsecure.engine.fixes.verifier import verify_findings_resolved
                fixed_ids = _fixed_ids(plan, findings)
                fixed_findings = [f for f in findings if f.id in fixed_ids]
                verification = (await verify_findings_resolved(local_repo, fixed_findings, context=findings)).to_dict()
            except Exception as e:
                logger.warning("Fix verification skipped: %s", type(e).__name__)
        except BaseException as exc:  # noqa: BLE001 - cleaned up, then re-raised
            failure = exc if isinstance(exc, Exception) else None
            if outcome is not None and outcome.written:
                await asyncio.to_thread(rollback_applied, local_repo, outcome)
                await _git(local_repo, "reset", "-q", "HEAD", "--", *final.keys())
            raise
        finally:
            restored, restore_msg = await _restore_base(local_repo, base_branch, base_sha, detached)
            if failure is not None and restored and await _head_sha_of(local_repo, branch) == start_head:
                # The branch holds no commit of ours: don't leave an empty one behind.
                await _git(local_repo, "branch", "-D", branch)

    # Plain-language layer (#50): translate the fix + verify outcome into
    # git-free language the UI can show directly. The branch mechanics stay
    # in the payload for power users / backward-compat, but the UI leads
    # with `plain`.
    from isitsecure.engine.fixes import plain_results

    applied_ids = {
        f.id for f in findings
        if f.id in _fixed_ids(plan, findings) and f.code_location.file_path in outcome.written
    }
    attempted = len(findings)
    fixed_count = len(applied_ids)
    counts = plain_results.classify_verification(
        attempted=attempted,
        fix_failed=attempted - fixed_count,
        verification=verification,
    )
    next_step = plain_results.next_step_hint(
        counts, saved_hint="Your original code is safely backed up."
    )
    if not restored:
        next_step = (restore_msg + " " + next_step).strip()
    plain = {
        "summary": plain_results.summarize(counts),
        "next_step": next_step,
        "fixed": counts.fixed,
        "needs_review": counts.needs_review,
        "couldnt_fix": counts.couldnt_fix,
    }
    return {
        "mode": "applied",
        "applied": True,
        "branch": branch,
        "base_branch": base_branch,
        "restored_base_branch": restored,
        "message": restore_msg,
        "files_changed": sorted(final.keys()),
        "fixed_count": fixed_count,
        "skipped": skipped,
        "verification": verification,
        "plain": plain,
    }


async def _head_sha_of(repo: str, ref: str) -> str:
    code, out, _ = await _git(repo, "rev-parse", ref)
    return out if code == 0 else ""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

class ApplyFinishedBeforeCancel(asyncio.CancelledError):
    """The job was cancelled while its (shielded) apply was running; the apply
    finished anyway. ``result`` is its outcome (the fix branch, if one was made)."""

    def __init__(self, result: dict) -> None:
        super().__init__("fixes were applied before the job was cancelled")
        self.result = result


async def run_fix_all(
    *,
    report: dict,
    llm_provider: str,
    severities: tuple[str, ...] = DEFAULT_SEVERITIES,
    emit: Emit,
    github_token: str | None = None,
    pr_strategy: str = DEFAULT_STRATEGY,
    max_prs: int = DEFAULT_MAX_PRS,
    api_key: str | None = None,
    max_llm_calls: int = DEFAULT_MAX_LLM_CALLS,
) -> dict:
    """Generate and (when possible) apply fixes for a scan's findings.

    Emits progress events via ``emit`` and returns a result dict describing
    what happened (mode "applied", "plan", "pull_requests", or "none").

    When the scan target is a REMOTE GitHub URL and a ``github_token`` is
    supplied, fixes are grouped into per-category pull requests and opened on
    GitHub (delegated to :class:`PRFlow`). Local-path targets keep the existing
    in-place apply behavior.

    ``max_llm_calls`` caps the paid LLM requests one job may make.
    """
    # Validate BEFORE any paid work or clone.
    severities, pr_strategy, max_prs = validate_fix_options(severities, pr_strategy, max_prs)

    # A key supplied in the original scan request wins over server config.
    api_key = api_key or load_api_key(llm_provider)
    if not api_key:
        raise RuntimeError(
            f"No API key found for {llm_provider}. "
            f"Set {llm_provider.upper()}_API_KEY or run 'isitsecure setup'."
        )

    from isitsecure.llm.adapters import create_llm_client
    llm = BudgetedLLM(create_llm_client(llm_provider, api_key), max_llm_calls)
    generator = FixGenerator(llm)

    findings = _select_findings(report, severities)
    if not findings:
        return {"mode": "none", "message": "No fixable findings at the selected severities.",
                "fixed_count": 0, "skipped": []}

    # ---- REMOTE PR MODE: remote GitHub URL + token → per-category PRs ----
    repo_target = report.get("repo_url")
    if github_token and is_remote_url(repo_target):
        try:
            ref = parse_github_url(repo_target)
        except ValueError as exc:
            return {"mode": "none", "message": f"Could not parse repo URL: {exc}",
                    "fixed_count": 0, "skipped": []}
        if ref.is_github:
            flow = PRFlow(generator)
            scan_branch, branch_warning = resolve_scan_branch(report.get("repo_branch"))
            if branch_warning:
                await emit({"type": "progress", "message": branch_warning})
            result = await flow.run(
                repo_url=repo_target,
                findings=findings,
                github_token=github_token,
                strategy=pr_strategy,
                max_prs=max_prs,
                # Fix the branch that was scanned (None → the default branch).
                branch=scan_branch,
                emit=emit,
            )
            return result.to_dict()
        # Non-GitHub host → fall through to the fix-plan behavior below.
        await emit({"type": "progress",
                    "message": f"{ref.host} is not GitHub — generating a fix plan instead."})

    local_repo = _resolve_local_repo(report.get("repo_url"))
    is_git = bool(local_repo) and await _is_git_repo(local_repo)

    if not is_git:
        reason = (
            "the scan target isn't a git repo" if local_repo
            else "the scan target isn't a local git repo"
        )
        return await _plan_result(findings=findings, generator=generator,
                                  local_repo=local_repo, reason=reason, emit=emit)

    # ---- APPLY MODE: local git repo, clean tree ----
    if not await _working_tree_clean(local_repo):
        return await _plan_result(
            findings=findings, generator=generator, local_repo=local_repo,
            reason="the working tree has uncommitted changes", emit=emit,
        )

    start_head = await _head_sha(local_repo)
    start_branch = await _current_branch(local_repo)

    # Read full files from disk for the findings in scope. Strict UTF-8,
    # newlines untouched, .git refused: files that can't be read faithfully are
    # left out and REPORTED, never lossily decoded and written back corrupted.
    contents: dict[str, str] = {}
    skipped: list[str] = []
    for fnd in findings:
        fp = fnd.code_location.file_path
        if fp in contents or any(s.startswith(f"{fp} — ") for s in skipped):
            continue
        if not await _is_plainly_tracked(local_repo, fp):
            skipped.append(
                f"{fp} — not tracked by git (gitignored or untracked), so it was left alone"
            )
            continue
        text = read_source_file(local_repo, fp)
        if text is None:
            skipped.append(f"{fp} — unreadable, not valid UTF-8, or refused; left alone")
        elif len(text) > _MAX_FILE_SIZE:
            skipped.append(f"{fp} — too large to fix automatically; left alone")
        else:
            contents[fp] = text

    if not contents:
        return {"mode": "applied", "applied": False, "fixed_count": 0,
                "skipped": skipped, "message": "No fixes could be generated."}

    await emit({"type": "progress", "message": "Generating fixes…",
                "current": 0, "total": len(contents)})

    async def _on_file(done: int, total: int, path: str) -> None:
        await emit({"type": "progress", "message": f"Fixed {path}",
                    "current": done, "total": total})

    plan = await generator.generate_file_fixes(
        [f for f in findings if f.code_location.file_path in contents],
        contents, on_file_done=_on_file,
    )
    skipped = [*skipped, *plan.skipped]
    if llm.exhausted:
        skipped.append(
            f"LLM call budget ({llm.max_calls}) reached; remaining findings were not attempted"
        )

    if not plan.files:
        return {"mode": "applied", "applied": False, "fixed_count": 0,
                "skipped": skipped, "message": "No fixes could be generated."}

    # The apply runs as its own task and is shielded: cancelling the job (cancel
    # button, client gone) must not interrupt it half-way and strand the user on
    # the fix branch.
    task = asyncio.ensure_future(_apply_locally(
        local_repo=local_repo, findings=findings, plan=plan, start_head=start_head,
        start_branch=start_branch, skipped=skipped, contents=contents, emit=emit,
    ))
    _apply_tasks.add(task)
    task.add_done_callback(_apply_tasks.discard)
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError as cancel:
        if task.cancelled():
            raise
        # The job was cancelled but the apply (shielded) keeps going and may land
        # a commit on the fix branch. Wait for it, and hand its outcome to the
        # caller so the user is told where the fixes are.
        try:
            result = await task
        except BaseException:  # noqa: BLE001 - the apply itself failed: plain cancel
            raise cancel from None
        raise ApplyFinishedBeforeCancel(result) from cancel
