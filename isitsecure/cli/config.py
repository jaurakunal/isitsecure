"""Config-directory and API-key access for the CLI.

Thin wrappers over ``isitsecure.config``, in their own module because both the
scan commands and ``setup`` need them — the alternative was each defining its
own copy.
"""

from __future__ import annotations

from pathlib import Path

from isitsecure.config import CONFIG_DIR, CONFIG_FILE, load_api_key

__all__ = ["CONFIG_DIR", "CONFIG_FILE", "_ensure_config_dir", "_load_api_key"]


def _ensure_config_dir() -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return CONFIG_DIR


def _load_api_key(provider: str) -> str | None:
    """Load API key from env, .env file, or config (see isitsecure.config)."""
    return load_api_key(provider)
