"""No-op LSP client for graceful degradation.

LSP: When Node.js or tsserver is unavailable, this client provides
     empty results for all operations.  The scan falls back to
     regex-only analysis — identical to pre-LSP behavior.

SRP: This class has one responsibility — returning empty results.
     It does not log warnings, attempt retries, or check for Node.js.
     Those decisions belong to the factory that selects which client
     to instantiate.
"""

from __future__ import annotations

from isitsecure.engine.code_analysis.lsp.protocols import (
    LSPLocation,
)


class NoOpLSPClient:
    """Fallback LSP client that returns empty results.

    Conforms to ``LSPClientProtocol``.  Used when the LSP server is
    unavailable (no Node.js, tsserver not installed, or initialization
    failed).
    """

    @property
    def is_available(self) -> bool:
        return False

    async def initialize(self, project_path: str) -> bool:
        return False

    async def get_definition(
        self, file_path: str, line: int, character: int
    ) -> list[LSPLocation] | None:
        return None

    async def get_references(
        self, file_path: str, line: int, character: int
    ) -> list[LSPLocation] | None:
        return None

    async def get_hover(
        self, file_path: str, line: int, character: int
    ) -> str | None:
        return None

    async def shutdown(self) -> None:
        pass
