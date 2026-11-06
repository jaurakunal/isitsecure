"""Shared configuration: config paths and LLM API-key resolution.

Both the CLI and the web server resolve API keys the same way — from an
environment variable, a local ``.env`` file, or ``~/.isitsecure/config.toml``
(written by ``isitsecure setup``) — so scans and fixes behave identically
whether launched from the terminal or the web UI.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

CONFIG_DIR = Path.home() / ".isitsecure"
CONFIG_FILE = CONFIG_DIR / "config.toml"

_ENV_KEYS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GOOGLE_API_KEY",
}


def _resolve_setting(env_key: str, toml_key: str) -> str | None:
    """Resolve one setting: env var, then local ``.env``, then ``[llm]`` in config.toml."""
    # 1. Environment variable
    val = os.environ.get(env_key)
    if val:
        return val

    # 2. .env file in the current directory
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith(f"{env_key}="):
                return line.split("=", 1)[1].strip().strip("\"'")

    # 3. Config file (~/.isitsecure/config.toml)
    if CONFIG_FILE.exists():
        try:
            import tomllib

            with open(CONFIG_FILE, "rb") as f:
                config = tomllib.load(f)
            return config.get("llm", {}).get(toml_key)
        except Exception as exc:
            logger.debug("Could not read %s from %s: %s", toml_key, CONFIG_FILE, exc)

    return None


def load_api_key(provider: str) -> str | None:
    """Resolve an LLM API key from env var, local .env file, or config.toml.

    Returns None if no key is found for the given provider.
    """
    env_key = _ENV_KEYS.get(provider, "")
    if not env_key:
        return None
    return _resolve_setting(env_key, f"{provider}_api_key")


def load_workspace_id() -> str | None:
    """Resolve the Anthropic workspace id sent as the ``anthropic-workspace-id`` header.

    Resolved like the API key: ``ANTHROPIC_WORKSPACE_ID`` env var, local ``.env``, or
    config.toml (``[llm] anthropic_workspace_id``). Identity-linked keys (e.g. Cyber
    Verification Program enrollees, org-wide "All workspaces" keys) get a 400 without it.
    Returns None when unset.
    """
    return _resolve_setting("ANTHROPIC_WORKSPACE_ID", "anthropic_workspace_id")


def load_fallback_model() -> str | None:
    """Resolve an override for the refusal-fallback model (``ANTHROPIC_FALLBACK_MODEL``,
    ``.env``, or ``[llm] anthropic_fallback_model``). None means use the built-in default."""
    return _resolve_setting("ANTHROPIC_FALLBACK_MODEL", "anthropic_fallback_model")
