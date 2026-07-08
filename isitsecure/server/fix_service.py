"""Batch "Fix All" service for the web UI.

Given a completed scan report, generate fixes for the in-scope findings and
either:

- **apply** them to a *local git repo* on a fresh branch (leaving the user's
  current branch and working tree untouched), or
- **fall back** to a downloadable Markdown fix plan when the scan target is a
  live URL or a remote repo (no local files to write).

The server that runs this lives on the user's own machine (``isitsecure
launch``), which is what makes safe local application possible.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Awaitable, Callable

from isitsecure.config import load_api_key
from isitsecure.engine.shared.safe_path import resolve_within
from isitsecure.engine.fixes.fix_generator import FixGenerator, FixPlan
from isitsecure.engine.fixes.markdown_exporter import FixPlanMarkdownExporter
from isitsecure.engine.models import DeepFinding

logger = logging.getLogger(__name__)

Emit = Callable[[dict], Awaitable[None]]

DEFAULT_SEVERITIES = ("critical", "high")


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
    return proc.returncode, out.decode(errors="replace").strip(), err.decode(errors="replace").strip()


async def _is_git_repo(repo: str) -> bool:
    code, out, _ = await _git(repo, "rev-parse", "--is-inside-work-tree")
    return code == 0 and out == "true"


async def _working_tree_clean(repo: str) -> bool:
    code, out, _ = await _git(repo, "status", "--porcelain")
    return code == 0 and out == ""


async def _current_branch(repo: str) -> str:
    _, out, _ = await _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    return out or "HEAD"


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
# Entry point
# ---------------------------------------------------------------------------

async def run_fix_all(
    *,
    report: dict,
    llm_provider: str,
    severities: tuple[str, ...] = DEFAULT_SEVERITIES,
    emit: Emit,
) -> dict:
    """Generate and (when possible) apply fixes for a scan's findings.

    Emits progress events via ``emit`` and returns a result dict describing
    what happened (mode "applied" or "plan").
    """
    api_key = load_api_key(llm_provider)
    if not api_key:
        raise RuntimeError(
            f"No API key found for {llm_provider}. "
            f"Set {llm_provider.upper()}_API_KEY or run 'isitsecure setup'."
        )

    from isitsecure.llm.adapters import create_llm_client
    generator = FixGenerator(create_llm_client(llm_provider, api_key))

    findings = _select_findings(report, severities)
    if not findings:
        return {"mode": "none", "message": "No fixable findings at the selected severities.",
                "fixed_count": 0, "skipped": []}

    local_repo = _resolve_local_repo(report.get("repo_url"))
    can_apply = bool(local_repo) and await _is_git_repo(local_repo)

    # ---- APPLY MODE: local git repo, clean tree ----
    if can_apply:
        if not await _working_tree_clean(local_repo):
            can_apply = False  # fall through to plan mode with a note
            dirty_note = True
        else:
            dirty_note = False

    if can_apply:
        # Read full files from disk for the findings in scope.
        contents: dict[str, str] = {}
        for fnd in findings:
            fp = fnd.code_location.file_path
            if fp in contents:
                continue
            full = os.path.join(local_repo, fp)
            if os.path.isfile(full):
                try:
                    contents[fp] = open(full, encoding="utf-8", errors="replace").read()
                except Exception:
                    pass

        await emit({"type": "progress", "message": "Generating fixes…",
                    "current": 0, "total": len(contents)})

        async def _on_file(done: int, total: int, path: str) -> None:
            await emit({"type": "progress", "message": f"Fixed {path}",
                        "current": done, "total": total})

        plan = await generator.generate_file_fixes(findings, contents, on_file_done=_on_file)
        final, skipped = plan.files, plan.skipped
        fixed_count = plan.fixed_count

        if not final:
            return {"mode": "applied", "applied": False, "fixed_count": 0,
                    "skipped": skipped, "message": "No fixes could be generated."}

        # Isolate the changes on a fresh branch; restore the user's branch after.
        base_branch = await _current_branch(local_repo)
        branch = await _pick_branch_name(local_repo, "isitsecure/fixes")
        await emit({"type": "progress", "message": f"Committing to {branch}…",
                    "current": len(final), "total": len(final)})

        verification = None
        code, _, err = await _git(local_repo, "checkout", "-b", branch)
        if code != 0:
            raise RuntimeError(f"Could not create branch: {err}")
        try:
            for path, content in final.items():
                safe_path = resolve_within(local_repo, path)
                with open(safe_path, "w", encoding="utf-8") as fh:
                    fh.write(content)
                await _git(local_repo, "add", "--", path)
            msg = f"isitsecure: fix {fixed_count} finding(s) across {len(final)} file(s)"
            code, _, err = await _git(local_repo, "commit", "-m", msg)
            if code != 0:
                raise RuntimeError(f"Commit failed: {err}")

            # Re-scan the fixed working tree to confirm the findings are gone.
            try:
                await emit({"type": "progress", "message": "Verifying fixes…",
                            "current": len(final), "total": len(final)})
                from isitsecure.engine.fixes.verifier import verify_findings_resolved
                fixed_findings = [
                    f for f in findings if f.code_location.file_path in final
                ]
                verification = (await verify_findings_resolved(local_repo, fixed_findings)).to_dict()
            except Exception as e:
                logger.warning("Fix verification skipped: %s", e)
        finally:
            # Return the user to their original branch no matter what.
            await _git(local_repo, "checkout", "--force", base_branch)

        return {
            "mode": "applied",
            "applied": True,
            "branch": branch,
            "base_branch": base_branch,
            "files_changed": sorted(final.keys()),
            "fixed_count": fixed_count,
            "skipped": skipped,
            "verification": verification,
        }

    # ---- PLAN MODE: no local files (URL / remote repo) or dirty tree ----
    # Use the finding code snippets as the source, matching CLI `--output fixes`.
    file_contents: dict[str, str] = {}
    for fnd in findings:
        fp = fnd.code_location.file_path
        snippet = fnd.code_location.code_snippet if fnd.code_location else ""
        if fp and snippet and fp not in file_contents:
            file_contents[fp] = snippet

    await emit({"type": "progress", "message": "Generating fix plan…",
                "current": 0, "total": len(findings)})
    plan: FixPlan = await generator.generate_fix_plan(findings, file_contents)
    await emit({"type": "progress", "message": "Fix plan ready",
                "current": len(findings), "total": len(findings)})
    markdown = FixPlanMarkdownExporter().export(plan)

    reason = (
        "the working tree has uncommitted changes"
        if local_repo else
        "the scan target isn't a local git repo"
    )
    return {
        "mode": "plan",
        "reason": reason,
        "markdown": markdown,
        "fixed_count": plan.fixed_count,
        "skipped": plan.skipped,
    }
