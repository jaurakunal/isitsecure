"""isitsecure CLI - AI-powered security scanner for modern web apps.

Usage:
    isitsecure scan https://myapp.com                          # URL-only DAST scan
    isitsecure scan --repo github.com/me/app --mode code-only  # SAST only
    isitsecure scan https://myapp.com --repo github.com/me/app --mode full  # Full scan
    isitsecure launch                                          # Open web UI

Split by concern: ``environment`` detects what is installed on the machine,
``setup_lsp`` owns the ``setup`` command that acts on it, and ``main`` holds
the remaining commands.

This module is a façade over those: it exposes ``app`` for the entry point
(``isitsecure.cli:app``) and the shared consoles, and nothing else. Reach into
the owning module for anything internal — patching a name here would not
affect the module that actually uses it.

The command-module imports below are load-bearing, not incidental: importing
them is what registers their commands on ``app``, and their order is the order
``--help`` lists them in.
"""

from __future__ import annotations

from isitsecure.cli import main as _main_module  # noqa: F401  (registers commands)
from isitsecure.cli import setup_lsp as _setup_lsp_module  # noqa: F401  (registers `setup`)
from isitsecure.cli._app import app
from isitsecure.cli._io import console, err_console

__all__ = ["app", "console", "err_console"]
