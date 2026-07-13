"""Tests for the git-free fix safety net (#50)."""

from __future__ import annotations

import os
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
