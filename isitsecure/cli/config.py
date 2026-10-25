"""Config-directory and API-key access for the CLI.

Thin wrappers over ``isitsecure.config``, in their own module because both the
scan commands and ``setup`` need them — the alternative was each defining its
own copy.
"""

from __future__ import annotations

import os
from pathlib import Path

from isitsecure.config import CONFIG_DIR, CONFIG_FILE, load_api_key

__all__ = ["CONFIG_DIR", "CONFIG_FILE", "_ensure_config_dir", "_load_api_key", "write_secret_file"]


def _ensure_config_dir() -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    return CONFIG_DIR


def write_secret_file(path: Path, text: str) -> None:
    """Write a file that holds a secret, owner-only (0600) from creation.

    The mode is applied at ``open(2)`` time (and re-applied to a pre-existing
    loose file before any bytes are written), so the key is never readable by
    other users, not even briefly.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass  # non-POSIX filesystem: creation mode is the best we can do
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = -1
            fh.write(text)
    finally:
        if fd != -1:
            os.close(fd)


def _load_api_key(provider: str) -> str | None:
    """Load API key from env, .env file, or config (see isitsecure.config)."""
    return load_api_key(provider)
