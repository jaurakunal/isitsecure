"""LSP protocols and shared data models.

DIP: All LSP consumers depend on ``LSPClientProtocol``, never on
     concrete implementations (``TypeScriptLSPClient`` or ``NoOpLSPClient``).

ISP: ``LSPClientProtocol`` exposes only the 4 operations needed by the
     security scanner — not the full 100+ method LSP specification.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Data models (shared across all LSP clients and consumers)
# ---------------------------------------------------------------------------


class LSPLocation(BaseModel):
    """A location in source code returned by LSP operations."""

    file_path: str
    line: int
    character: int
    end_line: int | None = None
    end_character: int | None = None


class AuthFlowResult(BaseModel):
    """Result of tracing an authentication flow for a route.

    Populated by ``AuthFlowTracer`` using LSP go-to-definition to
    follow middleware chains and confirm whether real auth verification
    happens.
    """

    has_verified_auth: bool = False
    auth_method: str = ""
    middleware_chain: list[str] = Field(default_factory=list)

    has_ownership_check: bool = False
    ownership_method: str = ""

    type_info: dict[str, str] = Field(default_factory=dict)
    confidence: float = 0.0
    trace_depth: int = 0


# ---------------------------------------------------------------------------
# LSP client protocol (DIP — consumers depend on this, not concretions)
# ---------------------------------------------------------------------------


@runtime_checkable
class LSPClientProtocol(Protocol):
    """Protocol for Language Server Protocol clients.

    ISP: only exposes the operations needed by the security scanner.
    Concrete implementations: ``TypeScriptLSPClient``, ``NoOpLSPClient``.
    """

    @property
    def is_available(self) -> bool:
        """Whether the LSP server is available and initialized."""
        ...

    async def initialize(self, project_path: str) -> bool:
        """Initialize the LSP server for a project.

        Args:
            project_path: Absolute path to the project root.

        Returns:
            True if initialization succeeded.
        """
        ...

    async def get_definition(
        self, file_path: str, line: int, character: int
    ) -> list[LSPLocation] | None:
        """Go to definition of a symbol at the given position.

        Args:
            file_path: Absolute path to the file.
            line: Zero-based line number.
            character: Zero-based character offset.

        Returns:
            List of definition locations, or None on failure.
        """
        ...

    async def get_references(
        self, file_path: str, line: int, character: int
    ) -> list[LSPLocation] | None:
        """Find all references to a symbol at the given position.

        Args:
            file_path: Absolute path to the file.
            line: Zero-based line number.
            character: Zero-based character offset.

        Returns:
            List of reference locations, or None on failure.
        """
        ...

    async def get_hover(
        self, file_path: str, line: int, character: int
    ) -> str | None:
        """Get hover information (type info) for a symbol.

        Args:
            file_path: Absolute path to the file.
            line: Zero-based line number.
            character: Zero-based character offset.

        Returns:
            Hover text (usually type signature), or None on failure.
        """
        ...

    async def shutdown(self) -> None:
        """Shutdown the LSP server and clean up resources."""
        ...
