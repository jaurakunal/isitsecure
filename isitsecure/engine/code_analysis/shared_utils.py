"""Shared utilities for route mappers and dependency scanners.

DRY: Extracts common patterns used across Django, FastAPI, and Spring mappers
and across Python and Java dependency scanners.
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import os
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

logger = logging.getLogger(__name__)

# Directories that should be skipped during code scanning across all languages
COMMON_SKIP_DIRS = frozenset({
    "node_modules", ".git", ".next", "dist", "build",
    "__pycache__", ".venv", "venv", "env",
    ".gradle", "target", ".idea",
    ".mypy_cache", ".pytest_cache",
    "migrations",
})


def is_plain_in_root(root: Path | str, path: Path | str) -> bool:
    """True when ``path`` sits under ``root`` without traversing any symlink.

    A symlinked file or directory (in-repo or not) makes the resolved path
    differ from the lexical one, so all symlinks are skipped: a scanned repo
    must never be able to point the scanner at files outside the clone.
    """
    real_root = os.path.realpath(root)
    try:
        rel = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
    except ValueError:
        return False
    if rel == os.pardir or rel.startswith(os.pardir + os.sep):
        return False
    return os.path.realpath(path) == os.path.normpath(os.path.join(real_root, rel))


def iter_repo_files(
    root: Path | str,
    patterns: Iterable[str] = ("*",),
    *,
    base: Path | str | None = None,
    skip_dirs: frozenset[str] = frozenset(),
    skip_hidden: bool = False,
) -> Iterator[Path]:
    """Yield regular files under ``base`` (default ``root``) that are safe to read.

    The single choke point for walking a scanned clone. Symlinked files and
    symlinked directories are never followed or yielded (in-repo ones too: a
    link is indistinguishable from an escape until resolved, and resolving is
    what the repo controls), and neither is anything whose real path leaves
    the real root. ``root`` itself may sit below symlinked parents (macOS
    ``/var`` -> ``/private/var``): only links *inside* the clone count.

    ``patterns`` are fnmatch globs on the file name; ``skip_hidden`` also
    prunes dot-directories. Output is sorted so the
    result is deterministic. One debug line reports how many links were
    skipped.
    """
    root_p = Path(root)
    start = Path(base) if base is not None else root_p
    pats = tuple(patterns)
    skipped = 0
    try:
        if not start.is_dir() or not is_plain_in_root(root_p, start):
            if start.is_symlink():
                skipped += 1
            return
        for dirpath, dirnames, filenames in os.walk(start, followlinks=False):
            kept: list[str] = []
            for d in sorted(dirnames):
                if os.path.islink(os.path.join(dirpath, d)):
                    skipped += 1
                elif d not in skip_dirs and not (skip_hidden and d.startswith(".")):
                    kept.append(d)
            dirnames[:] = kept
            for name in sorted(filenames):
                if not any(fnmatch.fnmatchcase(name, pat) for pat in pats):
                    continue
                path = Path(dirpath) / name
                if os.path.islink(path) or not is_plain_in_root(root_p, path):
                    skipped += 1
                    continue
                yield path
    finally:
        if skipped:
            logger.debug(
                "repo walk of %s skipped %d symlinked path(s)", start, skipped
            )


def read_repo_file(
    root: Path | str, path: Path | str, errors: str = "replace"
) -> str | None:
    """Read a text file of the scanned clone, or None if it is unsafe or unreadable.

    Refuses symlinks and anything resolving outside ``root``; the companion
    to :func:`iter_repo_files` for callers that got a path some other way.
    """
    if not is_plain_in_root(root, path):
        logger.debug("refusing to read %s: symlinked or outside the repo", path)
        return None
    try:
        return Path(path).read_text(encoding="utf-8", errors=errors)
    except OSError:
        return None


def should_skip_path(
    file_path: Path,
    extra_skip: frozenset[str] = frozenset(),
    root: Path | None = None,
) -> bool:
    """Check if a file path should be skipped during scanning.

    Args:
        file_path: The file path to check.
        extra_skip: Additional directory names to skip (scanner-specific).
        root: The scan root. When given, only the path *relative to it* is
            matched against the skip list (a clone living under a directory
            named ``build`` or ``env`` is still scanned) and anything reached
            through a symlink is skipped.
    """
    skip = COMMON_SKIP_DIRS | extra_skip
    parts = file_path.parts
    if root is not None:
        try:
            parts = file_path.relative_to(root).parts
        except ValueError:
            return True
        if not is_plain_in_root(root, file_path):
            return True
    return any(part in skip for part in parts)


async def kill_and_reap(proc: asyncio.subprocess.Process) -> None:
    """Kill a subprocess that outlived its timeout and wait for it to exit."""
    try:
        proc.kill()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=5)
    except (asyncio.TimeoutError, Exception):
        pass


def normalize_route_pattern(pattern: str) -> str:
    """Normalize a route pattern to the standard :param format.

    Handles:
    - Adds leading / if missing
    - {paramName} → :paramName (FastAPI, Spring)
    - {param:\\d+} → :param (Spring typed)
    - <int:param> → :param (Django, Flask typed)
    - <param> → :param (Django, Flask untyped)
    """
    if not pattern.startswith("/"):
        pattern = f"/{pattern}"
    # Spring/FastAPI: {param} or {param:regex}
    pattern = re.sub(r"\{(\w+)(?::[^}]*)?\}", r":\1", pattern)
    # Django/Flask: <type:param> or <param>
    pattern = re.sub(r"<(?:\w+:)?(\w+)>", r":\1", pattern)
    return pattern


def has_auth_patterns(content: str, patterns: tuple[str, ...]) -> bool:
    """Check if content contains any of the given auth patterns.

    Args:
        content: The source file content to check.
        patterns: Tuple of auth pattern strings to search for.
    """
    return any(pattern in content for pattern in patterns)


def is_version_vulnerable(installed: str, vuln_range: str) -> bool:
    """Check if an installed version falls within a vulnerable range.

    Currently supports only '<X.Y.Z' ranges (less-than comparison).

    Args:
        installed: The installed version string (e.g., "2.14.0").
        vuln_range: The vulnerability range (e.g., "<2.17.1").

    Returns:
        True if the installed version is vulnerable.
    """
    if not vuln_range.startswith("<"):
        return False
    threshold = vuln_range.lstrip("<").strip()
    try:
        inst_parts = [int(x) for x in installed.split(".")[:3]]
        thresh_parts = [int(x) for x in threshold.split(".")[:3]]
        while len(inst_parts) < 3:
            inst_parts.append(0)
        while len(thresh_parts) < 3:
            thresh_parts.append(0)
        return inst_parts < thresh_parts
    except (ValueError, IndexError):
        return False
