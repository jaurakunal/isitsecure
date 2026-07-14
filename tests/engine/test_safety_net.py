"""Tests for the git-free fix safety net (#50)."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from isitsecure.engine.fixes.safety_net import create_safety_net


def _run(cwd, *args):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True)


def test_git_repo_creates_backup_ref(tmp_path):
    repo = str(tmp_path)
    _run(repo, "git", "init")
    _run(repo, "git", "config", "user.email", "t@t.co")
    _run(repo, "git", "config", "user.name", "t")
    (tmp_path / "app.py").write_text("print('x')\n")
    _run(repo, "git", "add", "-A")
    _run(repo, "git", "commit", "-m", "init")

    head = subprocess.run(
        ["git", "-C", repo, "rev-parse", "HEAD"],
        capture_output=True, text=True,
    ).stdout.strip()

    net = create_safety_net(repo, ["app.py"])
    assert net.kind == "git"
    assert net.location.startswith("refs/isitsecure/backup/")
    # The backup ref points at the pre-fix HEAD.
    ref = subprocess.run(
        ["git", "-C", repo, "rev-parse", net.location],
        capture_output=True, text=True,
    ).stdout.strip()
    assert ref == head
    assert "safely backed up" in net.restore_hint


def test_non_git_dir_copies_files(tmp_path):
    (tmp_path / "app.py").write_text("original\n")
    net = create_safety_net(str(tmp_path), ["app.py"])
    assert net.kind == "copy"
    assert net.files == ["app.py"]
    backup_file = os.path.join(net.location, "app.py")
    assert os.path.isfile(backup_file)
    assert open(backup_file).read() == "original\n"
    assert "backed up" in net.restore_hint


def test_non_git_missing_file_yields_none(tmp_path):
    # Nothing exists to back up -> kind "none", no crash.
    net = create_safety_net(str(tmp_path), ["does-not-exist.py"])
    assert net.kind == "none"
    assert net.restore_hint == ""


# ---------------------------------------------------------------------------
# Restore ROUND-TRIP: backup -> mutate in place -> restore -> original.
# These prove the safety net actually protects the user's code, not just that
# a ref/copy was created.
# ---------------------------------------------------------------------------


def test_git_restore_round_trips_committed_state(tmp_path):
    """git path: backup -> overwrite in place -> restore recovers the original."""
    repo = str(tmp_path)
    _run(repo, "git", "init")
    _run(repo, "git", "config", "user.email", "t@t.co")
    _run(repo, "git", "config", "user.name", "t")
    (tmp_path / "app.py").write_text("original\n")
    _run(repo, "git", "add", "-A")
    _run(repo, "git", "commit", "-m", "init")

    net = create_safety_net(repo, ["app.py"])
    assert net.kind == "git"

    # Apply a "fix" straight to the working tree, the way the CLI does.
    (tmp_path / "app.py").write_text("FIXED-IN-PLACE\n")
    assert (tmp_path / "app.py").read_text() == "FIXED-IN-PLACE\n"

    # Restore via the exact command the CLI surfaces to the user.
    _run(repo, "git", "checkout", net.location, "--", ".")
    assert (tmp_path / "app.py").read_text() == "original\n"


def test_git_restore_recovers_uncommitted_work(tmp_path):
    """git path: uncommitted edits present at backup time are recovered too.

    The backup ref captures the FULL working-tree state (via ``git stash
    create``), so restoring gives back the user's *uncommitted* work — not just
    the last commit.
    """
    repo = str(tmp_path)
    _run(repo, "git", "init")
    _run(repo, "git", "config", "user.email", "t@t.co")
    _run(repo, "git", "config", "user.name", "t")
    (tmp_path / "app.py").write_text("committed\n")
    _run(repo, "git", "add", "-A")
    _run(repo, "git", "commit", "-m", "init")

    # Uncommitted edit present *before* the fix run.
    (tmp_path / "app.py").write_text("uncommitted-work\n")

    net = create_safety_net(repo, ["app.py"])
    assert net.kind == "git"

    # Apply a fix in place, then restore.
    (tmp_path / "app.py").write_text("FIXED-IN-PLACE\n")
    _run(repo, "git", "checkout", net.location, "--", ".")

    # The user's uncommitted work is back — not clobbered to the last commit.
    assert (tmp_path / "app.py").read_text() == "uncommitted-work\n"


def test_copy_restore_round_trips(tmp_path):
    """copy path: backup -> overwrite -> copy back recovers the original."""
    (tmp_path / "app.py").write_text("original\n")
    net = create_safety_net(str(tmp_path), ["app.py"])
    assert net.kind == "copy"

    # Apply a "fix" in place.
    (tmp_path / "app.py").write_text("FIXED-IN-PLACE\n")

    # Restore by copying the backed-up files back into the repo.
    for rel in net.files:
        shutil.copy2(os.path.join(net.location, rel), os.path.join(str(tmp_path), rel))
    assert (tmp_path / "app.py").read_text() == "original\n"
