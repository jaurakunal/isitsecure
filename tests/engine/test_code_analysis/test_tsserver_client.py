"""Tests for TypeScriptLSPClient.

Tests static/class methods, instance state management, and response
parsing without spawning a real tsserver subprocess.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import pytest

from isitsecure.engine.code_analysis.lsp import tsserver_client
from isitsecure.engine.code_analysis.lsp.tsserver_client import (
    TypeScriptLSPClient,
)
from isitsecure.engine.constants import LSPConfig


# ------------------------------------------------------------------
# TestNodeAvailability
# ------------------------------------------------------------------


class TestNodeAvailability:
    """Tests for the static ``is_node_available`` check."""

    def test_is_node_available_returns_bool(self) -> None:
        """is_node_available must return a bool, regardless of environment."""
        result = TypeScriptLSPClient.is_node_available()
        assert isinstance(result, bool)

    def test_is_available_false_before_init(self) -> None:
        """A freshly-created client should report is_available=False."""
        client = TypeScriptLSPClient()
        assert client.is_available is False


# ------------------------------------------------------------------
# TestClientLifecycle
# ------------------------------------------------------------------


class TestClientLifecycle:
    """Tests for instance state immediately after construction."""

    def test_initial_state(self) -> None:
        """Verify all default values on a brand-new client."""
        client = TypeScriptLSPClient()
        assert client._process is None
        assert client._initialized is False
        assert client._opened_files == set()
        assert isinstance(client._opened_files, set)

    def test_is_available_requires_both_initialized_and_process(self) -> None:
        """is_available should be True only when BOTH _initialized and
        _process are truthy."""
        client = TypeScriptLSPClient()

        # Neither set
        assert client.is_available is False

        # Only _initialized
        client._initialized = True
        assert client.is_available is False

        # Only _process (reset _initialized)
        client._initialized = False
        client._process = object()  # type: ignore[assignment]
        assert client.is_available is False

        # Both set
        client._initialized = True
        assert client.is_available is True

    def test_opened_files_is_instance_variable(self) -> None:
        """Each client instance must have its own _opened_files set."""
        client_a = TypeScriptLSPClient()
        client_b = TypeScriptLSPClient()

        client_a._opened_files.add("/tmp/a.ts")

        assert "/tmp/a.ts" in client_a._opened_files
        assert "/tmp/a.ts" not in client_b._opened_files


# ------------------------------------------------------------------
# TestLanguageDetection
# ------------------------------------------------------------------


class TestLanguageDetection:
    """Tests for the static ``_detect_language`` helper."""

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("src/index.ts", "typescript"),
            ("src/App.tsx", "typescript"),
            ("lib/utils.js", "javascript"),
            ("lib/App.jsx", "javascript"),
            ("lib/helpers.mjs", "javascript"),
            ("data/config.py", "plaintext"),
        ],
        ids=[
            "dot_ts",
            "dot_tsx",
            "dot_js",
            "dot_jsx",
            "dot_mjs",
            "dot_py_unknown",
        ],
    )
    def test_detect_language(self, path: str, expected: str) -> None:
        result = TypeScriptLSPClient._detect_language(path)
        assert result == expected


# ------------------------------------------------------------------
# TestLocationParsing
# ------------------------------------------------------------------


class TestLocationParsing:
    """Tests for the static ``_parse_locations`` response parser."""

    def test_parse_locations_none_returns_none(self) -> None:
        assert TypeScriptLSPClient._parse_locations(None) is None

    def test_parse_locations_empty_list_returns_none(self) -> None:
        assert TypeScriptLSPClient._parse_locations([]) is None

    def test_parse_locations_single_location(self) -> None:
        raw = {
            "uri": "file:///tmp/test.ts",
            "range": {
                "start": {"line": 5, "character": 10},
                "end": {"line": 5, "character": 20},
            },
        }
        result = TypeScriptLSPClient._parse_locations(raw)

        assert result is not None
        assert len(result) == 1

        loc = result[0]
        assert loc.file_path == "/tmp/test.ts"
        assert loc.line == 5
        assert loc.character == 10
        assert loc.end_line == 5
        assert loc.end_character == 20

    def test_parse_locations_array_of_locations(self) -> None:
        raw = [
            {
                "uri": "file:///a.ts",
                "range": {
                    "start": {"line": 1, "character": 0},
                    "end": {"line": 1, "character": 5},
                },
            },
            {
                "uri": "file:///b.ts",
                "range": {
                    "start": {"line": 10, "character": 3},
                    "end": {"line": 12, "character": 0},
                },
            },
        ]
        result = TypeScriptLSPClient._parse_locations(raw)

        assert result is not None
        assert len(result) == 2
        assert result[0].file_path == "/a.ts"
        assert result[1].file_path == "/b.ts"
        assert result[1].line == 10
        assert result[1].end_line == 12

    def test_parse_locations_strips_file_prefix(self) -> None:
        raw = {
            "uri": "file:///home/user/project/src/auth.ts",
            "range": {
                "start": {"line": 0, "character": 0},
                "end": {"line": 0, "character": 0},
            },
        }
        result = TypeScriptLSPClient._parse_locations(raw)

        assert result is not None
        assert result[0].file_path == "/home/user/project/src/auth.ts"
        assert not result[0].file_path.startswith("file://")


# ------------------------------------------------------------------
# TestTsconfigManagement
# ------------------------------------------------------------------


class TestTsconfigManagement:
    """Tests for ``_ensure_tsconfig`` using the ``tmp_path`` fixture."""

    def test_ensure_tsconfig_creates_temp(self, tmp_path: Path) -> None:
        """When no tsconfig.json exists, a temporary one is created."""
        client = TypeScriptLSPClient()
        tsconfig_path = tmp_path / "tsconfig.json"
        assert not tsconfig_path.exists()

        client._ensure_tsconfig(str(tmp_path))

        assert tsconfig_path.exists()
        assert client._temp_tsconfig == tsconfig_path

        content = json.loads(tsconfig_path.read_text())
        assert content == LSPConfig.DEFAULT_TSCONFIG

    def test_ensure_tsconfig_skips_existing(self, tmp_path: Path) -> None:
        """When tsconfig.json already exists, it is not overwritten."""
        client = TypeScriptLSPClient()
        tsconfig_path = tmp_path / "tsconfig.json"
        original = {"compilerOptions": {"strict": False}}
        tsconfig_path.write_text(json.dumps(original))

        client._ensure_tsconfig(str(tmp_path))

        # Should not have been touched
        assert client._temp_tsconfig is None
        content = json.loads(tsconfig_path.read_text())
        assert content == original


# ------------------------------------------------------------------
# TestInitializeParams (issue #145)
# ------------------------------------------------------------------


class TestInitializeParams:
    """Tests for the ``initialize`` params, especially ``tsserver.path``.

    typescript-language-server refuses to start when it can't resolve a
    TypeScript, and a scanned tree never has ``node_modules`` — so the
    explicit path is the whole reason repo-mode scans work at all.
    """

    def test_includes_tsserver_path_when_a_runtime_is_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        runtime = tmp_path / "typescript" / "lib" / "tsserver.js"
        runtime.parent.mkdir(parents=True)
        runtime.write_text("// tsserver")
        monkeypatch.setattr(
            tsserver_client, "find_tsserver_js", lambda _p: runtime
        )

        params = TypeScriptLSPClient()._initialize_params(str(tmp_path))

        assert params["initializationOptions"] == {
            "tsserver": {"path": str(runtime)}
        }

    def test_omits_tsserver_path_when_no_runtime_is_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without a runtime we still try — a workspace may resolve one."""
        monkeypatch.setattr(
            tsserver_client, "find_tsserver_js", lambda _p: None
        )

        params = TypeScriptLSPClient()._initialize_params(str(tmp_path))

        assert "initializationOptions" not in params

    def test_keeps_the_standard_handshake_fields(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            tsserver_client, "find_tsserver_js", lambda _p: None
        )

        params = TypeScriptLSPClient()._initialize_params(str(tmp_path))

        assert params["processId"] is None
        assert params["rootPath"] == str(tmp_path)
        assert params["rootUri"] == f"file://{tmp_path}"
        assert "definition" in params["capabilities"]["textDocument"]


# ------------------------------------------------------------------
# TestErrorReporting (issue #145)
# ------------------------------------------------------------------


class _FakeStdout:
    """Minimal stdout stub that replays framed LSP messages."""

    def __init__(self, messages: list[dict]) -> None:
        payload = b""
        for message in messages:
            body = json.dumps(message).encode()
            payload += b"Content-Length: %d\r\n\r\n" % len(body) + body
        self._buffer = payload

    async def readline(self) -> bytes:
        index = self._buffer.find(b"\r\n")
        if index == -1:
            return b""
        line, self._buffer = self._buffer[: index + 2], self._buffer[index + 2:]
        return line

    async def readexactly(self, count: int) -> bytes:
        chunk, self._buffer = self._buffer[:count], self._buffer[count:]
        return chunk


class _FakeProcess:
    def __init__(self, messages: list[dict]) -> None:
        self.stdout = _FakeStdout(messages)
        self.stdin = None
        self.stderr = None
        self.returncode = None


class TestErrorReporting:
    """The server's own explanation must survive the reader loop."""

    def test_last_error_is_none_before_anything_happens(self) -> None:
        assert TypeScriptLSPClient().last_error is None

    @pytest.mark.asyncio
    async def test_reader_keeps_the_server_error(self) -> None:
        client = TypeScriptLSPClient()
        client._process = _FakeProcess([  # type: ignore[assignment]
            {
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": -32603,
                    "message": (
                        "Request initialize failed with message: Could not "
                        "find a valid TypeScript installation."
                    ),
                },
            }
        ])
        client._pending_methods[1] = "initialize"

        await client._read_responses()

        assert client.last_error is not None
        assert "-32603" in client.last_error
        assert "valid TypeScript installation" in client.last_error

    @pytest.mark.asyncio
    async def test_error_response_still_resolves_the_request_to_none(
        self,
    ) -> None:
        """Callers keep their result-or-None contract."""
        client = TypeScriptLSPClient()
        client._process = _FakeProcess([  # type: ignore[assignment]
            {"jsonrpc": "2.0", "id": 7, "error": {"code": -1, "message": "no"}}
        ])
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        client._pending[7] = future

        await client._read_responses()

        assert future.result() is None

    @pytest.mark.asyncio
    async def test_successful_response_leaves_last_error_unset(self) -> None:
        client = TypeScriptLSPClient()
        client._process = _FakeProcess([  # type: ignore[assignment]
            {"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {}}}
        ])
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        client._pending[1] = future

        await client._read_responses()

        assert client.last_error is None
        assert future.result() == {"capabilities": {}}

    @pytest.mark.asyncio
    async def test_failure_report_uses_the_server_error(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        client = TypeScriptLSPClient()
        client._last_error = (
            "[-32603] Could not find a valid TypeScript installation."
        )

        with caplog.at_level(logging.WARNING):
            await client._report_initialize_failure()

        assert "valid TypeScript installation" in caplog.text
        # …and it points at the fix rather than at a missing install.
        assert "setup --lsp" in caplog.text

    @pytest.mark.asyncio
    async def test_failure_report_without_a_server_error(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A dead/silent server must not be reported as an RPC error."""
        client = TypeScriptLSPClient()

        with caplog.at_level(logging.WARNING):
            await client._report_initialize_failure()

        assert "no response" in caplog.text

    @pytest.mark.asyncio
    async def test_failure_report_omits_the_runtime_hint_when_one_was_used(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A runtime we already supplied isn't the thing to go install."""
        client = TypeScriptLSPClient()
        client._tsserver_js = tmp_path / "tsserver.js"
        client._last_error = "[-1] something else went wrong"

        with caplog.at_level(logging.WARNING):
            await client._report_initialize_failure()

        assert "something else went wrong" in caplog.text
        assert "setup --lsp" not in caplog.text


# ------------------------------------------------------------------
# TestReaderFailure — a dead reader must say so, fast
# ------------------------------------------------------------------


class _BrokenStdout:
    """A stream whose body never matches its declared Content-Length."""

    def __init__(self) -> None:
        self._buffer = b"Content-Length: 500\r\n\r\n{truncated"

    async def readline(self) -> bytes:
        index = self._buffer.find(b"\r\n")
        if index == -1:
            chunk, self._buffer = self._buffer, b""
            return chunk
        line, self._buffer = self._buffer[: index + 2], self._buffer[index + 2:]
        return line

    async def readexactly(self, count: int) -> bytes:
        if count > len(self._buffer):
            raise asyncio.IncompleteReadError(self._buffer, count)
        chunk, self._buffer = self._buffer[:count], self._buffer[count:]
        return chunk


class TestReaderFailure:
    """A reader that dies used to leave every request to time out and then
    report "no response from the server" — pointing at the wrong problem."""

    @pytest.mark.asyncio
    async def test_reader_crash_is_recorded_and_releases_waiters(self) -> None:
        client = TypeScriptLSPClient()
        client._process = _FakeProcess([])  # type: ignore[assignment]
        client._process.stdout = _BrokenStdout()  # type: ignore[assignment]
        waiting: asyncio.Future = asyncio.get_running_loop().create_future()
        client._pending[1] = waiting

        await client._read_responses()

        assert client.last_error is not None
        assert "reader stopped" in client.last_error
        # The waiter is resolved rather than left to burn its full timeout.
        assert waiting.done() and waiting.result() is None

    @pytest.mark.asyncio
    async def test_clean_eof_is_not_reported_as_a_failure(self) -> None:
        """A server exiting normally at shutdown is not a reader crash."""
        client = TypeScriptLSPClient()
        client._process = _FakeProcess([])  # type: ignore[assignment]

        await client._read_responses()

        assert client.last_error is None
