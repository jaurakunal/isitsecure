"""Shared configuration: config paths and LLM API-key resolution.

Both the CLI and the web server resolve API keys the same way — from an
environment variable, a local ``.env`` file, or ``~/.isitsecure/config.toml``
(written by ``isitsecure setup``) — so scans and fixes behave identically
whether launched from the terminal or the web UI.
"""

from __future__ import annotations

import os
from pathlib import Path

CONFIG_DIR = Path.home() / ".isitsecure"
CONFIG_FILE = CONFIG_DIR / "config.toml"

_ENV_KEYS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GOOGLE_API_KEY",
}


def load_api_key(provider: str) -> str | None:
    """Resolve an LLM API key from env var, local .env file, or config.toml.

    Returns None if no key is found for the given provider.
    """
    env_key = _ENV_KEYS.get(provider, "")
    if not env_key:
        return None

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
            return config.get("llm", {}).get(f"{provider}_api_key")
        except Exception:
            pass

    return None
