"""Tests for NoOpLSPClient — the fallback LSP client.

Verifies that all operations return empty/false results and that the
class conforms to ``LSPClientProtocol``.
"""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.lsp.noop_client import (
    NoOpLSPClient,
)
from isitsecure.engine.code_analysis.lsp.protocols import (
    LSPClientProtocol,
)


@pytest.fixture()
def client() -> NoOpLSPClient:
    return NoOpLSPClient()


class TestNoOpLSPClient:
    """Unit tests for NoOpLSPClient."""

    def test_is_available_returns_false(self, client: NoOpLSPClient) -> None:
        assert client.is_available is False

    @pytest.mark.asyncio
    async def test_initialize_returns_false(self, client: NoOpLSPClient) -> None:
        result = await client.initialize("/some/project")
        assert result is False

    @pytest.mark.asyncio
    async def test_get_definition_returns_none(self, client: NoOpLSPClient) -> None:
        result = await client.get_definition("/file.ts", 0, 0)
        assert result is None

    @pytest.mark.asyncio
    async def test_get_references_returns_none(self, client: NoOpLSPClient) -> None:
        result = await client.get_references("/file.ts", 10, 5)
        assert result is None

    @pytest.mark.asyncio
    async def test_get_hover_returns_none(self, client: NoOpLSPClient) -> None:
        result = await client.get_hover("/file.ts", 3, 12)
        assert result is None

    @pytest.mark.asyncio
    async def test_shutdown_does_nothing(self, client: NoOpLSPClient) -> None:
        # Should complete without raising
        await client.shutdown()

    def test_conforms_to_protocol(self, client: NoOpLSPClient) -> None:
        """NoOpLSPClient must satisfy the runtime-checkable LSPClientProtocol."""
        assert isinstance(client, LSPClientProtocol)
