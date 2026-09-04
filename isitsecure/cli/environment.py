"""What is installed on this machine.

Detection only — no installing, no reporting. ``setup_lsp`` acts on what this
module finds, and the scan pre-flight warns about it; keeping the two apart
means the "is it there?" checks can be reused (and stubbed) without dragging
in the install machinery.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Language-server (LSP) setup
# ---------------------------------------------------------------------------

# The scan auto-detects each language server via shutil.which; this table drives
# `setup` installing/verifying them. `needs` is the tool that must be on PATH to
# run `cmd` (None = uses the current interpreter's pip, always available).
_LSP_SPECS = [
    {
        "lang": "Python",
        "bins": ("pylsp", "pyright-langserver", "basedpyright-langserver"),
        "runtime": (),
        "needs": None,
        "cmd": [sys.executable, "-m", "pip", "install", "python-lsp-server"],
        "hint": "pip install python-lsp-server",
    },
    {
        "lang": "TypeScript / JavaScript",
        "bins": ("typescript-language-server",),
        "runtime": ("node",),
        "needs": "npm",
        # No `typescript` here on purpose: `typescript@latest` is now 7.x (the
        # Go rewrite), which ships no lib/tsserver.js and can't drive the
        # language server. `_ensure_tsserver_runtime` provisions a private 5.x
        # runtime instead of touching the user's global install (issue #145).
        "cmd": ["npm", "install", "-g", "typescript-language-server"],
        "hint": {
            "macos": "install Node.js (`brew install node`), then re-run `isitsecure setup --lsp`",
            "windows": "install Node.js (`winget install OpenJS.NodeJS` or nodejs.org), then re-run `isitsecure setup --lsp`",
            "linux": "install Node.js (your package manager or nodejs.org), then re-run `isitsecure setup --lsp`",
        },
    },
    {
        "lang": "Java / Kotlin",
        "bins": ("jdtls", "jdt-language-server"),
        "runtime": ("java",),
        "needs": "brew",
        "cmd": ["brew", "install", "jdtls"],
        "hint": {
            "macos": "install a JDK (`brew install openjdk`) + jdtls — https://github.com/eclipse-jdtls/eclipse.jdt.ls#installation",
            "windows": "install a JDK (`winget install Microsoft.OpenJDK`) + jdtls — https://github.com/eclipse-jdtls/eclipse.jdt.ls#installation",
            "linux": "install a JDK + jdtls — https://github.com/eclipse-jdtls/eclipse.jdt.ls#installation",
        },
    },
]


def _os_key() -> str:
    import os
    if os.name == "nt":
        return "windows"
    return "macos" if sys.platform == "darwin" else "linux"


def _os_hint(spec) -> str:
    """The install hint for this OS (specs use a str or a per-OS dict)."""
    hint = spec["hint"]
    return hint if isinstance(hint, str) else hint.get(_os_key(), next(iter(hint.values())))


def _resolve_install_cmd(cmd):
    """Make an install command launchable across platforms.

    Resolves argv[0] to its real path (so PATHEXT lookups like npm.cmd resolve),
    and on Windows launches .cmd/.bat shims via ``cmd /c`` — CreateProcess can't
    run those directly, which is why a bare ["npm", ...] fails on Windows.
    """
    import os
    import shutil
    exe = shutil.which(cmd[0]) or cmd[0]
    if os.name == "nt" and exe.lower().endswith((".cmd", ".bat")):
        return ["cmd", "/c", exe, *cmd[1:]]
    return [exe, *cmd[1:]]


def _first_which(bins) -> Optional[str]:
    import shutil
    for b in bins:
        if shutil.which(b):
            return b
    return None


def _chromium_installed() -> bool:
    """True if Playwright's Chromium is installed (best effort, no launch)."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            return bool(p.chromium.executable_path) and Path(p.chromium.executable_path).exists()
    except Exception:
        return False
