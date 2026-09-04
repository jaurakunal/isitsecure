"""Tests for LSP message framing.

The bug these exist to prevent: the readers took ``Content-Length`` and then
consumed exactly one line as the separator, which silently truncated every
message from any server that sends a second header. pylsp sends the
``Content-Type`` the spec permits, so the Python language server never worked.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from isitsecure.engine.code_analysis.lsp.framing import read_message


def _stream(raw: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    reader.feed_eof()
    return reader


def _framed(payload: dict, *, extra_headers: tuple[str, ...] = ()) -> bytes:
    body = json.dumps(payload).encode()
    head = f"Content-Length: {len(body)}\r\n"
    for h in extra_headers:
        head += f"{h}\r\n"
    return head.encode() + b"\r\n" + body


class TestReadMessage:
    @pytest.mark.asyncio
    async def test_content_length_only(self) -> None:
        """The shape typescript-language-server and jdtls send."""
        msg = {"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}}
        assert await read_message(_stream(_framed(msg))) == msg

    @pytest.mark.asyncio
    async def test_content_type_header_is_tolerated(self) -> None:
        """The shape pylsp sends — the case that was broken."""
        msg = {"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}}
        raw = _framed(
            msg,
            extra_headers=("Content-Type: application/vscode-jsonrpc; charset=utf8",),
        )
        assert await read_message(_stream(raw)) == msg

    @pytest.mark.asyncio
    async def test_many_headers_in_any_order(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 7, "result": "ok"}
        raw = _framed(
            msg,
            extra_headers=(
                "Content-Type: application/vscode-jsonrpc; charset=utf8",
                "X-Something: whatever",
            ),
        )
        assert await read_message(_stream(raw)) == msg

    @pytest.mark.asyncio
    async def test_header_name_is_case_insensitive(self) -> None:
        body = json.dumps({"id": 1}).encode()
        raw = b"content-length: %d\r\nCONTENT-TYPE: x\r\n\r\n" % len(body) + body
        assert await read_message(_stream(raw)) == {"id": 1}

    @pytest.mark.asyncio
    async def test_length_counts_bytes_not_characters(self) -> None:
        """A non-ASCII body must not be truncated."""
        msg = {"jsonrpc": "2.0", "id": 1, "result": "héllo → wörld ✓"}
        assert await read_message(_stream(_framed(msg))) == msg

    @pytest.mark.asyncio
    async def test_two_messages_back_to_back(self) -> None:
        first = {"id": 1, "result": "a"}
        second = {"id": 2, "result": "b"}
        raw = _framed(first, extra_headers=("Content-Type: x",)) + _framed(second)
        stream = _stream(raw)
        assert await read_message(stream) == first
        assert await read_message(stream) == second

    @pytest.mark.asyncio
    async def test_leading_noise_is_skipped(self) -> None:
        """npx and friends print to stdout before the server speaks."""
        msg = {"id": 1, "result": "ok"}
        raw = b"npm WARN: something\r\n" + _framed(msg)
        assert await read_message(_stream(raw)) == msg

    @pytest.mark.asyncio
    async def test_eof_returns_none(self) -> None:
        assert await read_message(_stream(b"")) is None

    @pytest.mark.asyncio
    async def test_eof_after_headers_raises(self) -> None:
        """A half-written message is an error, not a silent empty read."""
        with pytest.raises(asyncio.IncompleteReadError):
            await read_message(_stream(b"Content-Length: 99\r\n\r\n{}"))

    @pytest.mark.asyncio
    async def test_non_json_body_raises(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            await read_message(_stream(b"Content-Length: 3\r\n\r\nnot"))
