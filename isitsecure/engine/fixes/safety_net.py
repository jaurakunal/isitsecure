"""Under-the-hood safety net for git-free fixes (#50).

A non-technical user running ``isitsecure fix`` shouldn't have to understand
git — but we still never want to lose their original code. This module keeps a
restorable snapshot of the code *before* fixes are applied, so we can offer a
plain-language "your original is safely backed up" guarantee without making the
user think about branches or commits.

Strategy, in order of preference:

1. **Git repo** — record the current commit + stash any uncommitted changes into
   a backup ref (``refs/isitsecure/backup/<timestamp>``). Nothing is lost; the
   user's branch, HEAD, and working tree are left exactly as they were, and the
   snapshot can be restored with a single command we surface only if asked.
2. **Not a git repo, or targets git can't snapshot** (untracked/ignored,
   skip-worktree, assume-unchanged, submodule files) — copy the files we're about
   to change into a timestamped backup directory **outside the repo tree**
   (``~/.isitsecure/backups/<repo>-<hash>/<stamp>``; override the root with
   ``ISITSECURE_BACKUP_DIR``). Keeping it out of the tree means it is never
   re-scanned, never shows up as an untracked directory, and ``git add -A`` can
   never commit the stale vulnerable copy.

Either way the caller applies fixes straight to the working tree (so the user
just sees their files fixed in place), and gets back a :class:`SafetyNet`
describing where the original is kept, phrased for a human.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field


@dataclass
class SafetyNet:
    """Describes the backup taken before fixes were applied."""

    kind: str  # "git" | "copy" | "none"
    location: str = ""  # backup ref (git) or backup dir (copy)
    files: list[str] = field(default_factory=list)  # files backed up (copy mode)
    failed: list[str] = field(default_factory=list)  # existing files we could NOT back up

    @property
    def restore_hint(self) -> str:
        """Plain-language one-liner: where the original is kept, if anywhere."""
        if self.failed:
            return (
                "Some original files could NOT be backed up: "
                + ", ".join(self.failed[:5])
            )
        if self.kind == "git":
            return "Your original code is safely backed up."
        if self.kind == "copy":
            return f"Your original files are safely backed up in {self.location}/."
        return ""


def _git(repo: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", repo, *args],
        capture_output=True,
        text=True,
    )


def backup_root_for(repo_path: str) -> str:
    """Per-repo backup root, outside the repo tree."""
    base = os.environ.get("ISITSECURE_BACKUP_DIR") or os.path.join(
        os.path.expanduser("~"), ".isitsecure", "backups"
    )
    real = os.path.realpath(repo_path)
    digest = hashlib.sha1(real.encode("utf-8", "surrogateescape")).hexdigest()[:8]
    name = os.path.basename(real.rstrip(os.sep)) or "repo"
    return os.path.join(base, f"{name}-{digest}")


def _git_snapshot_covers(repo_path: str, rel: str) -> bool:
    """True when ``git stash create`` will capture this file's current state.

    Needs a plain tracked entry (tag ``H``): untracked/ignored files, files in
    submodules, ``skip-worktree`` (``S``) and ``assume-unchanged`` (lowercase)
    entries are all invisible to ``stash create``.
    """
    r = _git(repo_path, "ls-files", "-v", "--", rel)
    if r.returncode != 0:
        return False
    lines = [ln for ln in r.stdout.splitlines() if ln]
    return bool(lines) and all(ln[:1] == "H" for ln in lines)


def _is_git_repo(repo: str) -> bool:
    r = _git(repo, "rev-parse", "--is-inside-work-tree")
    return r.returncode == 0 and r.stdout.strip() == "true"


def create_safety_net(repo_path: str, files: list[str]) -> SafetyNet:
    """Snapshot the original state before fixes are written.

    Args:
        repo_path: absolute path to the repo/dir being fixed.
        files: repo-relative paths that are about to be overwritten.

    Returns a :class:`SafetyNet` the caller surfaces in plain language. Best
    effort: on any failure we degrade to ``kind="none"`` rather than blocking
    the fix (the user explicitly asked to apply fixes).
    """
    stamp = time.strftime("%Y%m%d-%H%M%S") + f"-{time.time_ns() % 1_000_000:06d}"

    # `git stash create` only captures TRACKED files. If any file we are about
    # to overwrite is untracked/ignored, the git snapshot cannot restore it, so
    # use the file-copy backup instead.
    all_tracked = True
    if _is_git_repo(repo_path):
        for rel in files:
            if os.path.isfile(os.path.join(repo_path, rel)) and not _git_snapshot_covers(
                repo_path, rel
            ):
                all_tracked = False
                break

    if all_tracked and _is_git_repo(repo_path):
        ref = f"refs/isitsecure/backup/{stamp}"
        head = _git(repo_path, "rev-parse", "HEAD")
        if head.returncode == 0:
            # Capture the FULL pre-fix state — including any uncommitted
            # working-tree edits — so restoring the ref recovers exactly what
            # the user had before, not just the last commit. `git stash create`
            # writes a commit for the dirty tree WITHOUT touching the working
            # tree; on a clean tree it prints nothing and we fall back to HEAD.
            stash = _git(repo_path, "stash", "create", "isitsecure pre-fix backup")
            snapshot = stash.stdout.strip() if stash.returncode == 0 else ""
            # A failed stash (rc != 0) would silently drop uncommitted edits;
            # use the file copy instead of pretending HEAD is the pre-fix state.
            if stash.returncode == 0:
                if not snapshot:
                    snapshot = head.stdout.strip()
                # Point a private backup ref at that snapshot. This keeps it
                # reachable even if the user later commits over the fixes.
                up = _git(repo_path, "update-ref", ref, snapshot)
                if up.returncode == 0:
                    return SafetyNet(kind="git", location=ref)
        # Repo with no commits yet / git backup failed — fall through to a file copy.

    # Non-git, unborn, or has targets git can't snapshot: copy the to-be-changed
    # files aside, OUTSIDE the repo tree.
    from isitsecure.engine.fixes.fix_generator import resolve_fix_target

    backup_dir = os.path.join(backup_root_for(repo_path), stamp)
    saved: list[str] = []
    failed: list[str] = []
    for rel in files:
        try:
            # Follow a symlink to the real file (the one a write would change);
            # refuse paths that escape the repo or point into .git/.
            src = resolve_fix_target(repo_path, rel)
        except ValueError:
            failed.append(rel)
            continue
        if not os.path.isfile(src):
            continue
        dst = os.path.join(backup_dir, rel)
        try:
            os.makedirs(os.path.dirname(dst), mode=0o700, exist_ok=True)
            shutil.copy2(src, dst)
            saved.append(rel)
        except OSError:
            failed.append(rel)
    if saved:
        try:
            os.chmod(backup_dir, 0o700)  # holds the original (vulnerable, maybe secret) code
        except OSError:
            pass
        return SafetyNet(kind="copy", location=backup_dir, files=saved, failed=failed)
    return SafetyNet(kind="none", failed=failed)
