"""Tests for JSON-RPC error rendering (issue #145).

Collapsing an error response to ``None`` is what hid the language server's own
explanation of why it wouldn't start, so these pin the "did this fail, and
what did the server say?" contract.
"""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.lsp.rpc_errors import format_rpc_error


class TestSuccessfulMessages:
    @pytest.mark.parametrize(
        "message",
        [
            {"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}},
            {"jsonrpc": "2.0", "id": 1, "result": None},
            {"jsonrpc": "2.0", "method": "window/logMessage", "params": {}},
            {},
        ],
    )
    def test_returns_none(self, message: dict) -> None:
        assert format_rpc_error(message) is None

    @pytest.mark.parametrize("message", [None, "not a message", 42, []])
    def test_non_message_returns_none(self, message: object) -> None:
        assert format_rpc_error(message) is None


class TestErrorMessages:
    def test_renders_code_and_message(self) -> None:
        rendered = format_rpc_error(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32603, "message": "Could not find a valid "
                                                     "TypeScript installation."},
            }
        )
        assert rendered == (
            "[-32603] Could not find a valid TypeScript installation."
        )

    def test_includes_data_when_present(self) -> None:
        rendered = format_rpc_error(
            {"error": {"code": -1, "message": "boom", "data": "stack trace"}}
        )
        assert rendered == "[-1] boom (stack trace)"

    def test_omits_empty_data(self) -> None:
        rendered = format_rpc_error(
            {"error": {"code": -1, "message": "boom", "data": None}}
        )
        assert rendered == "[-1] boom"

    def test_message_without_code(self) -> None:
        assert format_rpc_error({"error": {"message": "boom"}}) == "boom"

    def test_error_without_message_still_reports_a_failure(self) -> None:
        """An empty message must not read as success."""
        assert format_rpc_error({"error": {"code": -5}}) == "[-5] unknown error"

    def test_non_dict_error_is_stringified(self) -> None:
        assert format_rpc_error({"error": "server exploded"}) == "server exploded"
