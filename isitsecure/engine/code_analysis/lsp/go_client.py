"""Go LSP client using gopls.

SRP: Language-specific details for Go LSP — command discovery, language IDs.

DIP: Implements LSPClientProtocol via BaseLSPClient.

gopls is the official Go language server; it serves LSP over stdio when run
with no arguments, and its cross-file definition/reference resolution is
excellent, which is what auth-flow tracing depends on.
"""

from __future__ import annotations

import logging
import shutil

from isitsecure.engine.code_analysis.lsp.base_client import BaseLSPClient

logger = logging.getLogger(__name__)


class GoLSPClient(BaseLSPClient):
    """LSP client for Go projects using gopls.

    Traces auth flows through:
    - net/http:  middleware wrapping (func(http.Handler) http.Handler)
    - Gin/Echo:  router.Use(AuthMiddleware()) + handler chains
    - context:   r.Context().Value(userKey) ownership checks
    """

    SERVER_COMMANDS = (
        ("gopls",),
    )

    @staticmethod
    def is_runtime_available() -> bool:
        """gopls needs the ``go`` toolchain on PATH to load and type-check
        packages; without it gopls starts but resolves nothing (a confident
        silence). So the Go toolchain IS a runtime requirement, and the router
        must not route to gopls when ``go`` is absent — it should fall back to
        regex auth detection instead.
        """
        return shutil.which("go") is not None

    @staticmethod
    def is_server_available() -> bool:
        """Check if gopls is installed."""
        return shutil.which("gopls") is not None

    async def _find_server_command(self) -> tuple[str, ...] | None:
        """Find a working gopls command (serves LSP over stdio by default)."""
        for cmd in self.SERVER_COMMANDS:
            if shutil.which(cmd[0]):
                logger.info("Found Go LSP: %s", " ".join(cmd))
                return cmd
        logger.warning(
            "No Go LSP server found. Install gopls: "
            "go install golang.org/x/tools/gopls@latest (or) brew install gopls"
        )
        return None

    def _get_language_id(self, file_path: str) -> str:
        return "go"
