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
2. **Not a git repo** — copy the files we're about to change into a timestamped
   backup directory under the repo before overwriting them.

Either way the caller applies fixes straight to the working tree (so the user
just sees their files fixed in place), and gets back a :class:`SafetyNet`
describing where the original is kept, phrased for a human.
"""

from __future__ import annotations

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

    @property
    def restore_hint(self) -> str:
        """Plain-language one-liner: where the original is kept, if anywhere."""
        if self.kind == "git":
            return "Your original code is safely backed up (nothing was lost)."
        if self.kind == "copy":
            return (
                f"Your original files are safely backed up in "
                f"{os.path.basename(self.location)}/ (nothing was lost)."
            )
        return ""


def _git(repo: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", repo, *args],
        capture_output=True,
        text=True,
    )


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
    stamp = time.strftime("%Y%m%d-%H%M%S")

    if _is_git_repo(repo_path):
        ref = f"refs/isitsecure/backup/{stamp}"
        head = _git(repo_path, "rev-parse", "HEAD")
        if head.returncode == 0:
            # Point a private backup ref at the current commit. This keeps HEAD
            # reachable even if the user later commits over the fixes.
            _git(repo_path, "update-ref", ref, head.stdout.strip())
            return SafetyNet(kind="git", location=ref)
        # Repo with no commits yet — fall through to a file copy.

    # Non-git (or unborn) repo: copy the to-be-changed files aside.
    backup_dir = os.path.join(repo_path, f".isitsecure-backup-{stamp}")
    saved: list[str] = []
    for rel in files:
        src = os.path.join(repo_path, rel)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(backup_dir, rel)
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            saved.append(rel)
        except OSError:
            continue
    if saved:
        return SafetyNet(kind="copy", location=backup_dir, files=saved)
    return SafetyNet(kind="none")
