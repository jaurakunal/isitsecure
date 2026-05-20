"""Python LSP client using pylsp or pyright.

SRP: Language-specific details for Python LSP — command discovery,
     language IDs, virtual environment handling.

DIP: Implements LSPClientProtocol via BaseLSPClient.

Supports two servers (tried in order):
1. pylsp (python-lsp-server) — more common, pip installable
2. pyright (basedpyright / pyright-langserver) — faster, better type checking
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path

from isitsecure.engine.code_analysis.lsp.base_client import BaseLSPClient

logger = logging.getLogger(__name__)


class PythonLSPClient(BaseLSPClient):
    """LSP client for Python projects using pylsp or pyright.

    Traces auth flows through:
    - Django: @login_required → decorator implementation → User check
    - FastAPI: Depends(get_current_user) → function → token verification
    - Flask: @login_required → flask_login → session check
    """

    # Server commands to try (in order of preference)
    SERVER_COMMANDS = (
        ("pylsp",),
        ("python", "-m", "pylsp"),
        ("pyright-langserver", "--stdio"),
        ("basedpyright-langserver", "--stdio"),
        ("npx", "pyright-langserver", "--stdio"),
    )

    @staticmethod
    def is_runtime_available() -> bool:
        """Check if Python is available (it always is since we're running Python)."""
        return True

    @staticmethod
    def is_server_available() -> bool:
        """Check if any Python LSP server is installed."""
        return (
            shutil.which("pylsp") is not None
            or shutil.which("pyright-langserver") is not None
            or shutil.which("basedpyright-langserver") is not None
        )

    async def _find_server_command(self) -> tuple[str, ...] | None:
        """Find a working Python LSP server command."""
        for cmd in self.SERVER_COMMANDS:
            try:
                # Test if the command exists and responds
                test_cmd = cmd[0]
                if not shutil.which(test_cmd) and test_cmd not in ("python", "npx"):
                    continue

                proc = await asyncio.create_subprocess_exec(
                    *cmd, "--help" if "pylsp" in cmd else "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=5)
                if proc.returncode is not None:
                    logger.info("Found Python LSP: %s", " ".join(cmd))
                    return cmd
            except (FileNotFoundError, asyncio.TimeoutError):
                continue
            except Exception:
                continue

        logger.warning(
            "No Python LSP server found. Install with: pip install python-lsp-server"
        )
        return None

    def _get_language_id(self, file_path: str) -> str:
        return "python"

    def _pre_initialize(self, project_path: str) -> None:
        """Detect virtual environment for proper import resolution."""
        # pylsp uses the Python from its own environment, but we can hint
        # at the project's venv for better import resolution
        venv_paths = [
            Path(project_path) / ".venv",
            Path(project_path) / "venv",
            Path(project_path) / "env",
        ]
        for venv in venv_paths:
            if (venv / "bin" / "python").exists() or (venv / "Scripts" / "python.exe").exists():
                logger.info("Detected Python venv at: %s", venv)
                break
