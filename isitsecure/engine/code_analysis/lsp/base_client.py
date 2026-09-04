"""Base LSP client with shared JSON-RPC communication.

DRY: Extracts the JSON-RPC protocol, subprocess management, and message
parsing shared by all LSP clients (TypeScript, Python, Java).

SRP: This class handles ONLY LSP protocol communication. Language-specific
details (command discovery, config files, language IDs) are in subclasses.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import Any

from isitsecure.engine.code_analysis.lsp.framing import read_message
from isitsecure.engine.code_analysis.lsp.protocols import LSPLocation
from isitsecure.engine.code_analysis.lsp.rpc_errors import format_rpc_error
from isitsecure.engine.constants import LSPConfig

logger = logging.getLogger(__name__)


class BaseLSPClient:
    """Base LSP client with JSON-RPC over stdin/stdout.

    Subclasses must implement:
    - _find_server_command() → command tuple to spawn
    - _get_language_id(file_path) → LSP language ID string
    - _pre_initialize(project_path) → optional setup before LSP init
    - is_runtime_available() → static check if the language runtime exists
    """

    MAX_FILES_TO_OPEN = 50

    def __init__(self) -> None:
        self._process: asyncio.subprocess.Process | None = None
        self._request_id = 0
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._initialized = False
        self._project_path: str = ""
        self._lock = asyncio.Lock()
        self._opened_files: set[str] = set()
        self._last_error: str | None = None

    @property
    def is_available(self) -> bool:
        return self._initialized and self._process is not None

    @property
    def last_error(self) -> str | None:
        """The most recent server-reported failure, for diagnostics.

        A language server explains its own refusals better than we can guess
        at them, so callers surface this rather than speculating (issue #145).
        """
        return self._last_error

    async def initialize(self, project_path: str) -> bool:
        """Spawn LSP server and initialize the session."""
        self._project_path = project_path
        self._last_error = None

        try:
            self._pre_initialize(project_path)

            cmd = await self._find_server_command()
            if not cmd:
                return False

            cmd_str = " ".join(cmd)
            logger.info("Spawning LSP: %s (cwd: %s)", cmd_str, project_path)
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=project_path,
            )

            await asyncio.sleep(0.5)

            if self._process.returncode is not None:
                stderr_out = ""
                if self._process.stderr:
                    stderr_out = (await self._process.stderr.read()).decode(errors="replace")[:500]
                logger.warning("LSP process exited immediately (code %d): %s", self._process.returncode, stderr_out)
                return False

            self._reader_task = asyncio.create_task(self._read_responses())

            result = await self._send_request(
                "initialize",
                {
                    "processId": None,
                    "rootUri": f"file://{project_path}",
                    "rootPath": project_path,
                    "capabilities": {
                        "textDocument": {
                            "definition": {"dynamicRegistration": False},
                            "references": {"dynamicRegistration": False},
                            "hover": {"dynamicRegistration": False},
                        }
                    },
                },
                timeout=LSPConfig.INIT_TIMEOUT_SECONDS,
            )

            if result is None:
                logger.warning(
                    "LSP initialize failed: %s",
                    self._last_error or "no response from the server",
                )
                await self.shutdown()
                return False

            await self._send_notification("initialized", {})
            self._initialized = True
            return True

        except Exception as e:
            logger.warning("LSP initialization failed: %s", e)
            await self.shutdown()
            return False

    async def get_definition(self, file_path: str, line: int, character: int) -> list[LSPLocation] | None:
        if not self.is_available:
            return None
        await self._open_file(file_path)
        result = await self._send_request("textDocument/definition", {
            "textDocument": {"uri": f"file://{file_path}"},
            "position": {"line": line, "character": character},
        })
        return self._parse_locations(result)

    async def get_references(self, file_path: str, line: int, character: int) -> list[LSPLocation] | None:
        if not self.is_available:
            return None
        await self._open_file(file_path)
        result = await self._send_request("textDocument/references", {
            "textDocument": {"uri": f"file://{file_path}"},
            "position": {"line": line, "character": character},
            "context": {"includeDeclaration": True},
        })
        return self._parse_locations(result)

    async def get_hover(self, file_path: str, line: int, character: int) -> str | None:
        if not self.is_available:
            return None
        await self._open_file(file_path)
        result = await self._send_request("textDocument/hover", {
            "textDocument": {"uri": f"file://{file_path}"},
            "position": {"line": line, "character": character},
        })
        if not result or "contents" not in result:
            return None
        contents = result["contents"]
        if isinstance(contents, str):
            return contents
        if isinstance(contents, dict):
            return contents.get("value", "")
        if isinstance(contents, list):
            return "\n".join(c.get("value", c) if isinstance(c, dict) else str(c) for c in contents)
        return None

    async def shutdown(self) -> None:
        self._initialized = False
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        if self._process:
            try:
                await self._send_request("shutdown", None, timeout=LSPConfig.SHUTDOWN_TIMEOUT_SECONDS)
                await self._send_notification("exit", None)
            except Exception:
                pass
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=LSPConfig.SHUTDOWN_TIMEOUT_SECONDS)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass
            self._process = None
        for future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()

    # --- Subclass hooks ---

    async def _find_server_command(self) -> tuple[str, ...] | None:
        raise NotImplementedError

    def _get_language_id(self, file_path: str) -> str:
        raise NotImplementedError

    def _pre_initialize(self, project_path: str) -> None:
        """Optional setup before LSP initialization (e.g., create config files)."""
        pass

    # --- JSON-RPC ---

    async def _send_request(self, method: str, params: Any, timeout: float = LSPConfig.REQUEST_TIMEOUT_SECONDS) -> Any | None:
        if not self._process or not self._process.stdin:
            return None
        async with self._lock:
            self._request_id += 1
            req_id = self._request_id
        message: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            message["params"] = params
        future: asyncio.Future[Any] = asyncio.get_event_loop().create_future()
        self._pending[req_id] = future
        try:
            self._write_message(message)
            return await asyncio.wait_for(future, timeout=timeout)
        except (asyncio.TimeoutError, Exception):
            return None
        finally:
            self._pending.pop(req_id, None)

    async def _send_notification(self, method: str, params: Any) -> None:
        if not self._process or not self._process.stdin:
            return
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._write_message(message)

    def _write_message(self, message: dict[str, Any]) -> None:
        if not self._process or not self._process.stdin:
            return
        body = json.dumps(message)
        header = f"Content-Length: {len(body)}\r\n\r\n"
        self._process.stdin.write(header.encode() + body.encode())

    async def _read_responses(self) -> None:
        if not self._process or not self._process.stdout:
            return
        try:
            while True:
                data = await read_message(self._process.stdout)
                if data is None:
                    break
                req_id = data.get("id")
                rpc_error = format_rpc_error(data)
                if rpc_error:
                    # Keep the server's own explanation — dropping it is what
                    # made #145 look like a missing install.
                    self._last_error = rpc_error
                    logger.debug("LSP request returned an error: %s", rpc_error)
                if req_id is not None and req_id in self._pending:
                    future = self._pending[req_id]
                    if not future.done():
                        future.set_result(None if rpc_error else data.get("result"))
        except asyncio.CancelledError:
            pass
        except Exception as e:
            # The reader dying means no request can ever complete. Say so and
            # release the waiters, instead of letting each one burn its full
            # timeout and report "no response from the server".
            self._fail_pending(f"LSP reader stopped: {e}")

    def _fail_pending(self, reason: str) -> None:
        """Record why the session is dead and unblock every waiting request."""
        self._last_error = reason
        logger.warning("%s", reason)
        for future in self._pending.values():
            if not future.done():
                future.set_result(None)

    # --- File management ---

    async def _open_file(self, file_path: str) -> None:
        if file_path in self._opened_files or len(self._opened_files) >= self.MAX_FILES_TO_OPEN:
            return
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        await self._send_notification("textDocument/didOpen", {
            "textDocument": {
                "uri": f"file://{file_path}",
                "languageId": self._get_language_id(file_path),
                "version": 1,
                "text": content,
            }
        })
        self._opened_files.add(file_path)

    # --- Response parsing ---

    @staticmethod
    def _parse_locations(result: Any) -> list[LSPLocation] | None:
        if result is None:
            return None
        locations: list[LSPLocation] = []
        items = result if isinstance(result, list) else [result]
        for item in items:
            if not isinstance(item, dict):
                continue
            uri = item.get("uri", "")
            file_path = uri.replace("file://", "") if uri.startswith("file://") else uri
            range_data = item.get("range", {})
            start = range_data.get("start", {})
            end = range_data.get("end", {})
            locations.append(LSPLocation(
                file_path=file_path,
                line=start.get("line", 0),
                character=start.get("character", 0),
                end_line=end.get("line"),
                end_character=end.get("character"),
            ))
        return locations if locations else None

    @staticmethod
    def _check_command_available(name: str) -> bool:
        return shutil.which(name) is not None
