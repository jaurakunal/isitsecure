"""Shared utilities for route mappers and dependency scanners.

DRY: Extracts common patterns used across Django, FastAPI, and Spring mappers
and across Python and Java dependency scanners.
"""

from __future__ import annotations

import re
from pathlib import Path


# Directories that should be skipped during code scanning across all languages
COMMON_SKIP_DIRS = frozenset({
    "node_modules", ".git", ".next", "dist", "build",
    "__pycache__", ".venv", "venv", "env",
    ".gradle", "target", ".idea",
    ".mypy_cache", ".pytest_cache",
    "migrations",
})


def should_skip_path(file_path: Path, extra_skip: frozenset[str] = frozenset()) -> bool:
    """Check if a file path should be skipped during scanning.

    Args:
        file_path: The file path to check.
        extra_skip: Additional directory names to skip (scanner-specific).
    """
    skip = COMMON_SKIP_DIRS | extra_skip
    return any(part in skip for part in file_path.parts)


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
