"""Locate a TypeScript 5.x ``tsserver.js`` for the TypeScript language server.

Why this exists (issue #145):

``typescript-language-server`` ships no TypeScript of its own (v6 dropped the
bundled dependency).  It resolves ``typescript`` from the *workspace* and
refuses to start when it can't find one::

    Could not find a valid TypeScript installation. Please ensure that the
    "typescript" dependency is installed in the workspace or that a valid
    `tsserver.path` is specified. Exiting.

Repo scans always ingest into a fresh temp directory and drop ``node_modules``
(see ``repo_ingestion``), so the workspace *never* has a TypeScript install.
That made LSP initialization fail on every repo-mode scan of a TS project, on
every machine.  Passing an explicit ``tsserver.path`` through
``initializationOptions`` is the server's supported escape hatch.

The path must point at a TypeScript **5.x** install: ``typescript@latest`` is
now 7.x — the Go-native rewrite — which ships no ``lib/tsserver.js`` at all.
The presence of that file is therefore both the existence *and* the version
check; a 7.x install simply doesn't match and we keep looking.

SRP: this module only *finds* a runtime.  Installing one is
``isitsecure setup --lsp`` (see ``cli._ensure_tsserver_runtime``); using one is
``TypeScriptLSPClient``.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

from isitsecure.config import CONFIG_DIR

logger = logging.getLogger(__name__)

# Escape hatch: point isitsecure at a specific tsserver.js.
ENV_OVERRIDE = "ISITSECURE_TSSERVER_PATH"

# Where `isitsecure setup --lsp` provisions its own private TypeScript, so we
# never depend on — or disturb — whatever the user has installed globally.
PROVISIONED_ROOT = CONFIG_DIR / "lsp"

# npm spec for that private install. Pinned to 5.x on purpose: 6.x was never
# released as `latest` and 7.x is the Go rewrite with no tsserver.js.
TYPESCRIPT_PACKAGE_SPEC = "typescript@5"

# Path of tsserver.js inside a package root that has installed TypeScript.
_TSSERVER_REL = Path("node_modules") / "typescript" / "lib" / "tsserver.js"

# How far up from the language-server binary to look for a node_modules tree.
_MAX_ANCESTORS = 6

_NPM_ROOT_TIMEOUT_SECONDS = 15


def tsserver_js_in(package_root: str | Path) -> Path | None:
    """Return ``<package_root>/node_modules/typescript/lib/tsserver.js``.

    ``None`` when it isn't there — which is also how a TypeScript 7.x install
    is rejected, since it ships no ``lib/tsserver.js``.
    """
    try:
        candidate = Path(package_root) / _TSSERVER_REL
        return candidate if candidate.is_file() else None
    except OSError:
        return None


def find_tsserver_js(project_path: str | Path | None = None) -> Path | None:
    """Find a usable TypeScript 5.x ``tsserver.js``, or ``None``.

    Search order (first hit wins):

    1. ``$ISITSECURE_TSSERVER_PATH`` — explicit operator override.
    2. The scanned project itself, then its immediate subdirectories (a
       monorepo package may carry the only install).
    3. ``~/.isitsecure/lsp`` — provisioned by ``isitsecure setup --lsp``.
    4. Next to the ``typescript-language-server`` binary (a global
       ``npm i -g typescript-language-server typescript`` puts them as
       siblings in the same ``node_modules``).
    5. ``npm root -g`` — the global root, when the binary isn't on PATH or
       lives somewhere unrelated.

    Never raises; a broken environment just yields ``None``.
    """
    for finder in (
        _from_env,
        lambda: _from_project(project_path),
        _from_provisioned,
        _from_language_server_binary,
        _from_npm_global_root,
    ):
        try:
            found = finder()
        except Exception as exc:  # a hostile FS/PATH must not break the scan
            logger.debug("tsserver lookup step failed: %s", exc)
            continue
        if found:
            return found
    return None


def _from_env() -> Path | None:
    raw = os.environ.get(ENV_OVERRIDE, "").strip()
    if not raw:
        return None
    path = Path(raw).expanduser()
    if path.is_file():
        return path
    logger.warning(
        "%s is set to %s, which is not a file — ignoring it.", ENV_OVERRIDE, raw
    )
    return None


def _from_project(project_path: str | Path | None) -> Path | None:
    if not project_path:
        return None
    root = Path(project_path)
    found = tsserver_js_in(root)
    if found:
        return found
    # Monorepos: the install often lives in a package, not at the root.
    try:
        children = sorted(c for c in root.iterdir() if c.is_dir())
    except OSError:
        return None
    for child in children:
        found = tsserver_js_in(child)
        if found:
            return found
    return None


def _from_provisioned() -> Path | None:
    return tsserver_js_in(PROVISIONED_ROOT)


def _from_language_server_binary() -> Path | None:
    binary = shutil.which("typescript-language-server")
    if not binary:
        return None
    # The PATH entry is usually a symlink into the real package directory.
    real = Path(binary).resolve()
    for ancestor in list(real.parents)[:_MAX_ANCESTORS]:
        # …/node_modules/typescript/lib/tsserver.js (installed as a sibling)
        if ancestor.name == "node_modules":
            candidate = ancestor / "typescript" / "lib" / "tsserver.js"
            if candidate.is_file():
                return candidate
        # …/<pkg>/node_modules/typescript/lib/tsserver.js (nested install)
        found = tsserver_js_in(ancestor)
        if found:
            return found
    return None


def _from_npm_global_root() -> Path | None:
    npm = shutil.which("npm")
    if not npm:
        return None
    result = subprocess.run(
        [npm, "root", "-g"],
        capture_output=True,
        text=True,
        timeout=_NPM_ROOT_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        return None
    root = result.stdout.strip()
    if not root:
        return None
    candidate = Path(root) / "typescript" / "lib" / "tsserver.js"
    return candidate if candidate.is_file() else None
