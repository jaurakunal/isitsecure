"""Tests for LSP protocol data models.

Verifies default values, field assignment, and Pydantic behavior for
``LSPLocation`` and ``AuthFlowResult``.
"""

from __future__ import annotations

from isitsecure.engine.code_analysis.lsp.protocols import (
    AuthFlowResult,
    LSPLocation,
)


class TestLSPLocation:
    """Tests for the LSPLocation data model."""

    def test_creation(self) -> None:
        loc = LSPLocation(file_path="/src/index.ts", line=10, character=5)
        assert loc.file_path == "/src/index.ts"
        assert loc.line == 10
        assert loc.character == 5

    def test_defaults(self) -> None:
        loc = LSPLocation(file_path="/src/app.ts", line=0, character=0)
        assert loc.end_line is None
        assert loc.end_character is None

    def test_with_end_position(self) -> None:
        loc = LSPLocation(
            file_path="/src/utils.ts",
            line=5,
            character=10,
            end_line=5,
            end_character=20,
        )
        assert loc.end_line == 5
        assert loc.end_character == 20


class TestAuthFlowResult:
    """Tests for the AuthFlowResult data model."""

    def test_defaults_false(self) -> None:
        result = AuthFlowResult()
        assert result.has_verified_auth is False
        assert result.auth_method == ""
        assert result.middleware_chain == []
        assert result.has_ownership_check is False
        assert result.ownership_method == ""

    def test_confidence_default(self) -> None:
        result = AuthFlowResult()
        assert result.confidence == 0.0
        assert result.trace_depth == 0

    def test_with_verified_auth(self) -> None:
        result = AuthFlowResult(
            has_verified_auth=True,
            auth_method="supabase.auth.getUser()",
            confidence=0.95,
        )
        assert result.has_verified_auth is True
        assert result.auth_method == "supabase.auth.getUser()"
        assert result.confidence == 0.95

    def test_with_middleware_chain(self) -> None:
        chain = ["requireAuth", "verifyToken"]
        result = AuthFlowResult(middleware_chain=chain)
        assert result.middleware_chain == chain
        assert len(result.middleware_chain) == 2

    def test_with_ownership(self) -> None:
        result = AuthFlowResult(
            has_ownership_check=True,
            ownership_method="user_id filter",
        )
        assert result.has_ownership_check is True
        assert result.ownership_method == "user_id filter"

    def test_with_type_info(self) -> None:
        type_info = {"param": "string", "return": "User"}
        result = AuthFlowResult(type_info=type_info)
        assert result.type_info == type_info
        assert result.type_info["param"] == "string"

    def test_type_info_default_empty(self) -> None:
        result = AuthFlowResult()
        assert result.type_info == {}

    def test_full_construction(self) -> None:
        result = AuthFlowResult(
            has_verified_auth=True,
            auth_method="jwt.verify()",
            middleware_chain=["authenticate"],
            has_ownership_check=True,
            ownership_method=".eq('user_id')",
            type_info={"session": "Session"},
            confidence=0.95,
            trace_depth=2,
        )
        assert result.has_verified_auth is True
        assert result.trace_depth == 2
        assert result.has_ownership_check is True
