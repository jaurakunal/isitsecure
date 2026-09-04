"""TypeScript LSP client using tsserver subprocess.

SRP: This class handles ONLY the LSP protocol communication —
     spawning the subprocess, sending JSON-RPC requests, and parsing
     responses.  Auth flow tracing logic lives in ``AuthFlowTracer``.

DIP: Implements ``LSPClientProtocol``.  All consumers depend on the
     protocol, not on this class directly.

Lifecycle:
    1. ``is_node_available()`` — static check, called by factory
    2. ``initialize(project_path)`` — spawns tsserver, sends init
    3. ``get_definition/get_references/get_hover`` — LSP requests
    4. ``shutdown()`` — kills subprocess, cleans temp files
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import Any

from isitsecure.engine.code_analysis.lsp.protocols import (
    LSPLocation,
)
from isitsecure.engine.code_analysis.lsp.rpc_errors import format_rpc_error
from isitsecure.engine.code_analysis.lsp.tsserver_locator import (
    find_tsserver_js,
)
from isitsecure.engine.constants import LSPConfig

logger = logging.getLogger(__name__)


class TypeScriptLSPClient:
    """Concrete LSP client using typescript-language-server subprocess.

    Communicates via JSON-RPC over stdin/stdout.  Conforms to
    ``LSPClientProtocol``.
    """

    def __init__(self) -> None:
        self._process: asyncio.subprocess.Process | None = None
        self._request_id = 0
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._initialized = False
        self._project_path: str = ""
        self._temp_tsconfig: Path | None = None
        self._lock = asyncio.Lock()
        self._opened_files: set[str] = set()  # instance variable, not class
        self._last_error: str | None = None
        self._pending_methods: dict[int, str] = {}
        self._tsserver_js: Path | None = None

    # ------------------------------------------------------------------
    # Static availability check (called by factory)
    # ------------------------------------------------------------------

    @staticmethod
    def is_node_available() -> bool:
        """Check if Node.js is installed on the system."""
        return shutil.which("node") is not None

    # ------------------------------------------------------------------
    # LSPClientProtocol implementation
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        return self._initialized and self._process is not None

    @property
    def last_error(self) -> str | None:
        """The most recent server-reported failure, for diagnostics.

        The server explains its own refusals far better than we can guess at
        them, so callers surface this instead of speculating (issue #145).
        """
        return self._last_error

    async def initialize(self, project_path: str) -> bool:
        """Spawn tsserver and initialize the LSP session."""
        self._project_path = project_path
        self._last_error = None
        self._tsserver_js = None

        if not self.is_node_available():
            logger.info(LSPConfig.MSG_UNAVAILABLE)
            return False

        try:
            # Ensure tsconfig.json exists
            self._ensure_tsconfig(project_path)

            # Find a working tsserver command
            cmd = await self._find_tsserver_command()
            if not cmd:
                logger.warning("No typescript-language-server found")
                return False

            # Spawn the subprocess
            cmd_str = " ".join(cmd)
            logger.info("Spawning LSP: %s (cwd: %s)", cmd_str, project_path)
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=project_path,
            )

            # Give the process a moment to start (npx needs time)
            await asyncio.sleep(0.5)

            # Check if process already exited
            if self._process.returncode is not None:
                stderr_out = ""
                if self._process.stderr:
                    stderr_out = (await self._process.stderr.read()).decode(
                        errors="replace"
                    )[:500]
                logger.warning(
                    "LSP process exited immediately with code %d: %s",
                    self._process.returncode,
                    stderr_out,
                )
                return False

            # Start background reader
            self._reader_task = asyncio.create_task(self._read_responses())

            # Send LSP initialize request
            result = await self._send_request(
                "initialize",
                self._initialize_params(project_path),
                timeout=LSPConfig.INIT_TIMEOUT_SECONDS,
            )

            if result is None:
                await self._report_initialize_failure()
                await self.shutdown()
                return False

            # Send initialized notification (no response expected)
            await self._send_notification("initialized", {})

            self._initialized = True
            return True

        except Exception as e:
            logger.warning(
                LSPConfig.ERROR_SUBPROCESS_FAILED.format(error=str(e))
            )
            await self.shutdown()
            return False

    def _initialize_params(self, project_path: str) -> dict[str, Any]:
        """Build the ``initialize`` params, including ``tsserver.path``.

        typescript-language-server resolves TypeScript from the workspace and
        refuses to start when it can't find one.  Scans always run against a
        freshly-ingested copy with no ``node_modules``, so we hand it an
        explicit ``tsserver.path`` — the server's own supported escape hatch
        (issue #145).
        """
        params: dict[str, Any] = {
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
        }

        self._tsserver_js = find_tsserver_js(project_path)
        if self._tsserver_js:
            logger.info("Using TypeScript runtime: %s", self._tsserver_js)
            params["initializationOptions"] = {
                "tsserver": {"path": str(self._tsserver_js)}
            }
        else:
            # Not fatal on its own — the workspace may still resolve one. If
            # it doesn't, the failure report below names this as the cause.
            logger.debug(LSPConfig.MSG_NO_TYPESCRIPT_RUNTIME)
        return params

    async def _report_initialize_failure(self) -> None:
        """Log why initialization failed, using the server's own words."""
        if self._last_error:
            logger.warning(
                "LSP initialize failed: %s%s",
                self._last_error,
                (
                    ""
                    if self._tsserver_js
                    else f" — {LSPConfig.MSG_NO_TYPESCRIPT_RUNTIME}"
                ),
            )
            return

        stderr_out = ""
        if self._process and self._process.stderr:
            try:
                stderr_data = await asyncio.wait_for(
                    self._process.stderr.read(2000), timeout=1
                )
                stderr_out = stderr_data.decode(errors="replace")
            except Exception:
                pass
        logger.warning(
            "LSP initialize got no response (timed out or the server died). "
            "Stderr: %s",
            stderr_out[:300] if stderr_out else "(empty)",
        )

    async def get_definition(
        self, file_path: str, line: int, character: int
    ) -> list[LSPLocation] | None:
        """Go to definition of a symbol."""
        if not self.is_available:
            return None

        await self._open_file(file_path)

        result = await self._send_request(
            "textDocument/definition",
            {
                "textDocument": {"uri": f"file://{file_path}"},
                "position": {"line": line, "character": character},
            },
        )

        return self._parse_locations(result)

    async def get_references(
        self, file_path: str, line: int, character: int
    ) -> list[LSPLocation] | None:
        """Find all references to a symbol."""
        if not self.is_available:
            return None

        await self._open_file(file_path)

        result = await self._send_request(
            "textDocument/references",
            {
                "textDocument": {"uri": f"file://{file_path}"},
                "position": {"line": line, "character": character},
                "context": {"includeDeclaration": True},
            },
        )

        return self._parse_locations(result)

    async def get_hover(
        self, file_path: str, line: int, character: int
    ) -> str | None:
        """Get hover (type) information for a symbol."""
        if not self.is_available:
            return None

        await self._open_file(file_path)

        result = await self._send_request(
            "textDocument/hover",
            {
                "textDocument": {"uri": f"file://{file_path}"},
                "position": {"line": line, "character": character},
            },
        )

        if not result or "contents" not in result:
            return None

        contents = result["contents"]
        if isinstance(contents, str):
            return contents
        if isinstance(contents, dict):
            return contents.get("value", "")
        if isinstance(contents, list):
            return "\n".join(
                c.get("value", c) if isinstance(c, dict) else str(c)
                for c in contents
            )
        return None

    async def shutdown(self) -> None:
        """Shutdown the LSP server and clean up."""
        self._initialized = False

        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

        if self._process:
            try:
                await self._send_request(
                    "shutdown", None,
                    timeout=LSPConfig.SHUTDOWN_TIMEOUT_SECONDS,
                )
                await self._send_notification("exit", None)
            except Exception:
                pass

            try:
                self._process.terminate()
                await asyncio.wait_for(
                    self._process.wait(),
                    timeout=LSPConfig.SHUTDOWN_TIMEOUT_SECONDS,
                )
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass

            self._process = None

        # Clean up temp tsconfig
        if self._temp_tsconfig and self._temp_tsconfig.exists():
            try:
                self._temp_tsconfig.unlink()
            except OSError:
                pass
            self._temp_tsconfig = None

        # Cancel pending futures
        for future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()
        self._pending_methods.clear()

    # ------------------------------------------------------------------
    # JSON-RPC communication
    # ------------------------------------------------------------------

    async def _send_request(
        self,
        method: str,
        params: Any,
        timeout: float = LSPConfig.REQUEST_TIMEOUT_SECONDS,
    ) -> Any | None:
        """Send a JSON-RPC request and wait for the response."""
        if not self._process or not self._process.stdin:
            return None

        async with self._lock:
            self._request_id += 1
            req_id = self._request_id

        message: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
        }
        if params is not None:
            message["params"] = params

        future: asyncio.Future[Any] = asyncio.get_event_loop().create_future()
        self._pending[req_id] = future
        self._pending_methods[req_id] = method

        try:
            self._write_message(message)
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            logger.debug(
                LSPConfig.ERROR_REQUEST_TIMEOUT.format(
                    timeout=timeout, method=method
                )
            )
            return None
        except Exception as e:
            logger.debug("LSP request failed: %s", e)
            return None
        finally:
            self._pending.pop(req_id, None)
            self._pending_methods.pop(req_id, None)

    async def _send_notification(
        self, method: str, params: Any
    ) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        if not self._process or not self._process.stdin:
            return

        message: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            message["params"] = params

        self._write_message(message)

    def _write_message(self, message: dict[str, Any]) -> None:
        """Write a JSON-RPC message to the subprocess stdin."""
        if not self._process or not self._process.stdin:
            return

        body = json.dumps(message)
        header = f"Content-Length: {len(body)}\r\n\r\n"
        self._process.stdin.write(header.encode() + body.encode())

    async def _read_responses(self) -> None:
        """Background task: continuously read and dispatch LSP responses."""
        if not self._process or not self._process.stdout:
            return

        try:
            while True:
                # Read Content-Length header
                header = await self._process.stdout.readline()
                if not header:
                    break

                header_str = header.decode().strip()
                if not header_str.startswith("Content-Length:"):
                    if header_str:
                        logger.debug("LSP stdout (non-header): %s", header_str[:200])
                    continue

                content_length = int(header_str.split(":")[1].strip())

                # Read blank line separator
                await self._process.stdout.readline()

                # Read body
                body = await self._process.stdout.readexactly(content_length)
                data = json.loads(body.decode())

                # Dispatch response to pending future
                req_id = data.get("id")
                rpc_error = format_rpc_error(data)
                if rpc_error:
                    # Keep the server's own explanation — collapsing it to
                    # None is what made #145 invisible.
                    self._last_error = rpc_error
                    logger.debug(
                        "LSP %s returned an error: %s",
                        self._pending_methods.get(req_id, "request"),
                        rpc_error,
                    )
                if req_id is not None and req_id in self._pending:
                    future = self._pending[req_id]
                    if not future.done():
                        future.set_result(
                            None if rpc_error else data.get("result")
                        )

        except (asyncio.CancelledError, asyncio.IncompleteReadError):
            pass
        except Exception as e:
            logger.debug("LSP reader error: %s", e)

    # ------------------------------------------------------------------
    # File management
    # ------------------------------------------------------------------

    async def _open_file(self, file_path: str) -> None:
        """Open a file in the LSP server (textDocument/didOpen)."""
        if file_path in self._opened_files:
            return

        if len(self._opened_files) >= LSPConfig.MAX_FILES_TO_OPEN:
            return

        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        await self._send_notification(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": f"file://{file_path}",
                    "languageId": self._detect_language(file_path),
                    "version": 1,
                    "text": content,
                }
            },
        )
        self._opened_files.add(file_path)

    @staticmethod
    def _detect_language(file_path: str) -> str:
        """Detect language ID from file extension."""
        if file_path.endswith((".ts", ".tsx")):
            return "typescript"
        if file_path.endswith((".js", ".jsx", ".mjs")):
            return "javascript"
        return "plaintext"

    # ------------------------------------------------------------------
    # tsconfig management
    # ------------------------------------------------------------------

    def _ensure_tsconfig(self, project_path: str) -> None:
        """Create a temporary tsconfig.json if the project doesn't have one."""
        tsconfig_path = Path(project_path) / "tsconfig.json"
        if tsconfig_path.exists():
            return

        # Check workspaces too
        for child in Path(project_path).iterdir():
            if child.is_dir() and (child / "tsconfig.json").exists():
                return

        # Create a minimal temporary tsconfig
        tsconfig_path.write_text(
            json.dumps(LSPConfig.DEFAULT_TSCONFIG, indent=2)
        )
        self._temp_tsconfig = tsconfig_path

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_locations(result: Any) -> list[LSPLocation] | None:
        """Parse LSP location response into LSPLocation list."""
        if result is None:
            return None

        locations: list[LSPLocation] = []

        # Handle both single Location and Location[]
        items = result if isinstance(result, list) else [result]

        for item in items:
            if not isinstance(item, dict):
                continue

            uri = item.get("uri", "")
            file_path = uri.replace("file://", "") if uri.startswith("file://") else uri

            range_data = item.get("range", {})
            start = range_data.get("start", {})
            end = range_data.get("end", {})

            locations.append(
                LSPLocation(
                    file_path=file_path,
                    line=start.get("line", 0),
                    character=start.get("character", 0),
                    end_line=end.get("line"),
                    end_character=end.get("character"),
                )
            )

        return locations if locations else None

    # ------------------------------------------------------------------
    # tsserver command discovery
    # ------------------------------------------------------------------

    @staticmethod
    async def _find_tsserver_command() -> tuple[str, ...] | None:
        """Find a working typescript-language-server command."""
        for cmd in LSPConfig.TSSERVER_COMMANDS:
            cmd_str = " ".join(cmd)
            try:
                proc = await asyncio.create_subprocess_exec(
                    cmd[0], "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=5
                )
                if proc.returncode == 0:
                    version = stdout.decode().strip() or stderr.decode().strip()
                    logger.info(
                        "Found tsserver command: %s (version: %s)",
                        cmd_str,
                        version[:50],
                    )
                    return cmd
                else:
                    logger.debug(
                        "tsserver command '%s --version' returned %d: %s",
                        cmd_str,
                        proc.returncode,
                        stderr.decode().strip()[:100],
                    )
            except FileNotFoundError:
                logger.debug("tsserver command not found: %s", cmd_str)
            except asyncio.TimeoutError:
                logger.debug("tsserver command timed out: %s", cmd_str)
            except Exception as e:
                logger.debug(
                    "tsserver command '%s' failed: %s", cmd_str, str(e)
                )

        logger.warning(
            "No typescript-language-server command found. "
            "Tried: %s",
            ", ".join(" ".join(c) for c in LSPConfig.TSSERVER_COMMANDS),
        )
        return None
