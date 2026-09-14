"""Python LSP client using pylsp or pyright.

SRP: Language-specific details for Python LSP — command discovery,
     language IDs, virtual environment handling.

DIP: Implements LSPClientProtocol via BaseLSPClient.

Supports three servers (tried in order):
1. pyright (pyright-langserver) — best cross-file definition/reference
   resolution, which is what auth-flow tracing depends on
2. basedpyright (basedpyright-langserver) — permissively-licensed pyright
   fork with the same resolution engine
3. pylsp (python-lsp-server) — always pip-installable fallback; its
   rope-based def/ref is weaker, so it comes last
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from isitsecure.engine.code_analysis.lsp.base_client import BaseLSPClient

logger = logging.getLogger(__name__)


class PythonLSPClient(BaseLSPClient):
    """LSP client for Python projects using pylsp or pyright.

    Traces auth flows through:
    - Django: @login_required -> decorator implementation -> User check
    - FastAPI: Depends(get_current_user) -> function -> token verification
    - Flask: @login_required -> flask_login -> session check
    """

    # Server configurations: (binary_name, full_command_tuple).
    # Only tried if binary_name is found via shutil.which. pyright first —
    # its cross-file def/ref resolution is materially better than pylsp's for
    # tracing an auth check through a call chain; pylsp stays as the fallback.
    SERVER_OPTIONS = (
        ("pyright-langserver", ("pyright-langserver", "--stdio")),
        ("basedpyright-langserver", ("basedpyright-langserver", "--stdio")),
        ("pylsp", ("pylsp",)),
    )

    @staticmethod
    def is_runtime_available() -> bool:
        """Check if Python is available (it always is since we're running Python)."""
        return True

    @staticmethod
    def is_server_available() -> bool:
        """Check if any Python LSP server is installed."""
        return any(
            shutil.which(binary) is not None
            for binary, _ in PythonLSPClient.SERVER_OPTIONS
        )

    async def _find_server_command(self) -> tuple[str, ...] | None:
        """Find a working Python LSP server command."""
        for binary, cmd in self.SERVER_OPTIONS:
            if shutil.which(binary):
                logger.info("Found Python LSP: %s", " ".join(cmd))
                return cmd

        logger.warning(
            "No Python LSP server found. Install with: "
            "pip install pyright (preferred) or pip install python-lsp-server"
        )
        return None

    def _get_language_id(self, file_path: str) -> str:
        return "python"

    def _pre_initialize(self, project_path: str) -> None:
        """Detect virtual environment for proper import resolution."""
        venv_paths = [
            Path(project_path) / ".venv",
            Path(project_path) / "venv",
            Path(project_path) / "env",
        ]
        for venv in venv_paths:
            if (venv / "bin" / "python").exists() or (venv / "Scripts" / "python.exe").exists():
                logger.info("Detected Python venv at: %s", venv)
                break
