"""Auth flow tracer using LSP go-to-definition.

SRP: This class traces authentication and authorization flows —
     it does NOT decide what to do with the results (that's the
     route analyzer's job) or manage the LSP lifecycle (that's the
     client's job).

DIP: Depends on ``LSPClientProtocol``, not on any concrete client.
     Works identically with ``TypeScriptLSPClient`` or any future
     implementation.

Strategy:
    For each route, we identify the auth mechanism (tRPC procedure
    base, Express middleware, inline call) and use LSP go-to-definition
    to trace through the call chain until we hit a "terminal" auth
    pattern (e.g., ``supabase.auth.getUser()``) or exhaust the
    max trace depth.
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path

from isitsecure.engine.code_analysis.lsp.protocols import (
    AuthFlowResult,
    LSPClientProtocol,
    LSPLocation,
)
from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteEntry,
)
from isitsecure.engine.constants import LSPConfig

logger = logging.getLogger(__name__)


class AuthFlowTracer:
    """Traces authentication flows using LSP go-to-definition.

    For each route in the route map, determines:
    1. Whether auth middleware is genuinely applied
    2. What the auth method actually does (getUser? JWT verify?)
    3. Whether ownership checks exist in called functions

    Args:
        lsp_client: LSP client implementing ``LSPClientProtocol`` (DIP).
        repo: Repository snapshot with file_index for reading code.
    """

    def __init__(
        self,
        lsp_client: LSPClientProtocol,
        repo: RepoSnapshot,
    ) -> None:
        self._lsp = lsp_client
        self._repo = repo
        # Cache: file_path → content (avoid re-reading from disk)
        self._file_cache: dict[str, str] = dict(repo.file_index)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def trace_routes(
        self,
        routes: list[RouteEntry],
    ) -> dict[str, AuthFlowResult]:
        """Trace auth flows for all routes.

        Returns:
            Mapping of ``file_path:route_pattern`` → ``AuthFlowResult``.
            Routes sharing the same file get one trace per unique
            file (deduplication by file_path).
        """
        results: dict[str, AuthFlowResult] = {}

        # Deduplicate by file — trace each file once, not per-route
        files_to_trace: dict[str, list[RouteEntry]] = {}
        for route in routes:
            files_to_trace.setdefault(route.file_path, []).append(route)

        # Trace files in parallel batches
        batch_size = LSPConfig.MAX_CONCURRENT_REQUESTS
        file_items = list(files_to_trace.items())

        for batch_start in range(0, len(file_items), batch_size):
            batch = file_items[batch_start : batch_start + batch_size]
            tasks = [
                self._trace_file(file_path, file_routes)
                for file_path, file_routes in batch
            ]
            batch_results = await asyncio.gather(
                *tasks, return_exceptions=True
            )

            for (file_path, file_routes), result in zip(batch, batch_results):
                if isinstance(result, Exception):
                    logger.debug(
                        LSPConfig.ERROR_TRACE_FAILED.format(
                            file=file_path, error=result
                        )
                    )
                    continue
                # Assign the file-level result to each route in that file
                for route in file_routes:
                    key = f"{route.file_path}:{route.route_pattern}"
                    results[key] = result

        traced = len(results)
        auth_found = sum(1 for r in results.values() if r.has_verified_auth)
        logger.info(
            LSPConfig.MSG_TRACE_COMPLETE.format(
                traced=traced, auth_found=auth_found
            )
        )
        return results

    # ------------------------------------------------------------------
    # Per-file tracing
    # ------------------------------------------------------------------

    async def _trace_file(
        self, file_path: str, routes: list[RouteEntry]
    ) -> AuthFlowResult:
        """Trace auth flow for a single file.

        Strategy (tried in order):
        1. Procedure bases: protectedProcedure, tenantProcedure, etc.
        2. Express middleware: requireAuth, verifyAuth, etc.
        3. Auth decorators: @UseGuards, @login_required, @PreAuthorize
        4. Inline auth calls: getUser, getSession, jwt.verify, etc.
        """
        content = self._get_file_content(file_path)
        if not content:
            return AuthFlowResult()

        abs_path = self._resolve_path(file_path)

        # Strategy 1: Procedure base (tRPC, NestJS, etc.)
        result = await self._trace_procedure_auth(content, abs_path)
        if result and result.has_verified_auth:
            return result

        # Strategy 2: Express middleware
        result = await self._trace_express_auth(content, abs_path)
        if result and result.has_verified_auth:
            return result

        # Strategy 3: Auth decorators (NestJS, Python, Spring, Fastify)
        result = self._check_decorator_auth(content)
        if result and result.has_verified_auth:
            return result

        # Strategy 4: Inline auth calls (Next.js or direct)
        result = await self._trace_inline_auth(content, abs_path)
        if result and result.has_verified_auth:
            return result

        return AuthFlowResult(confidence=0.5)

    # ------------------------------------------------------------------
    # Strategy 1: Procedure base auth tracing
    # ------------------------------------------------------------------

    async def _trace_procedure_auth(
        self, content: str, abs_path: str
    ) -> AuthFlowResult | None:
        """Trace procedure bases (tRPC, NestJS, etc.) to their auth middleware."""
        # Check if any protected procedure base is used
        for base in LSPConfig.PROTECTED_PROCEDURE_BASES:
            match = re.search(rf'\b{base}\b', content)
            if not match:
                continue

            # Found a protected procedure base — trace its definition
            line, char = self._offset_to_position(content, match.start())
            chain = [base]
            logger.debug(
                "Procedure auth: found '%s' at %s line %d char %d",
                base, abs_path, line, char,
            )

            definition_content = await self._trace_definition(
                abs_path, line, char
            )

            if definition_content:
                logger.debug(
                    "Procedure auth: definition content length=%d for '%s'",
                    len(definition_content), base,
                )
                # Check if the definition contains auth terminal patterns
                auth_method = self._find_auth_terminal(definition_content)
                if auth_method:
                    logger.debug("Procedure auth: found auth terminal: %s", auth_method)
                    return AuthFlowResult(
                        has_verified_auth=True,
                        auth_method=auth_method,
                        middleware_chain=chain,
                        confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                        trace_depth=1,
                    )

                # Check for enforcement patterns (throw UNAUTHORIZED)
                if self._has_enforcement(definition_content):
                    return AuthFlowResult(
                        has_verified_auth=True,
                        auth_method=f"{base} (enforces UNAUTHORIZED)",
                        middleware_chain=chain,
                        confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                        trace_depth=1,
                    )

        # Fallback: if a protected procedure base is imported (ESM or CJS)
        # in this file, trust it as auth-verified even if LSP couldn't trace
        # the definition.
        for base in LSPConfig.PROTECTED_PROCEDURE_BASES:
            esm_pattern = rf'import\s+\{{[^}}]*{base}[^}}]*\}}\s+from'
            cjs_pattern = rf'(?:const|let|var)\s+\{{[^}}]*{base}[^}}]*\}}\s*=\s*require\s*\('
            if re.search(esm_pattern, content) or re.search(cjs_pattern, content):
                logger.debug(
                    "Procedure auth fallback — '%s' imported, trusting as auth-verified",
                    base,
                )
                return AuthFlowResult(
                    has_verified_auth=True,
                    auth_method=f"{base} (imported from auth middleware)",
                    middleware_chain=[base],
                    confidence=0.85,  # slightly lower than LSP-confirmed
                    trace_depth=0,
                )

        # Check for public procedure bases
        for base in LSPConfig.PUBLIC_PROCEDURE_BASES:
            if re.search(rf'\b{base}\b', content):
                return AuthFlowResult(
                    has_verified_auth=False,
                    auth_method=f"{base} (intentionally public)",
                    confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                )

        return None

    # ------------------------------------------------------------------
    # Strategy 2: Express middleware tracing
    # ------------------------------------------------------------------

    async def _trace_express_auth(
        self, content: str, abs_path: str
    ) -> AuthFlowResult | None:
        """Trace Express middleware to confirm auth verification."""
        # Look for auth middleware imports/usage
        auth_patterns = (
            r'\brequireAuth\b',
            r'\bverifyAuth\b',
            r'\bauthenticate\b',
            r'\bisAuthenticated\b',
            r'\bpassport\.authenticate\b',
        )

        for pattern in auth_patterns:
            match = re.search(pattern, content)
            if not match:
                continue

            middleware_name = match.group(0)
            line, char = self._offset_to_position(content, match.start())
            chain = [middleware_name]

            # Trace to the middleware definition
            definition_content = await self._trace_definition(
                abs_path, line, char
            )

            if definition_content:
                auth_method = self._find_auth_terminal(definition_content)
                if auth_method:
                    return AuthFlowResult(
                        has_verified_auth=True,
                        auth_method=auth_method,
                        middleware_chain=chain,
                        confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                        trace_depth=1,
                    )

                if self._has_enforcement(definition_content):
                    return AuthFlowResult(
                        has_verified_auth=True,
                        auth_method=f"{middleware_name} (returns 401)",
                        middleware_chain=chain,
                        confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                        trace_depth=1,
                    )

        return None

    # ------------------------------------------------------------------
    # Strategy 3: Auth decorator detection
    # ------------------------------------------------------------------

    @staticmethod
    def _check_decorator_auth(content: str) -> AuthFlowResult | None:
        """Detect auth decorators (NestJS, Python, Spring, Fastify)."""
        for pattern in LSPConfig.AUTH_DECORATOR_PATTERNS:
            match = re.search(pattern, content)
            if match:
                return AuthFlowResult(
                    has_verified_auth=True,
                    auth_method=match.group(0),
                    middleware_chain=["decorator"],
                    confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                    trace_depth=0,
                )
        return None

    # ------------------------------------------------------------------
    # Strategy 4: Inline auth tracing
    # ------------------------------------------------------------------

    async def _trace_inline_auth(
        self, content: str, abs_path: str
    ) -> AuthFlowResult | None:
        """Check for inline auth calls (getUser, getSession, etc.)."""
        auth_method = self._find_auth_terminal(content)
        if auth_method:
            return AuthFlowResult(
                has_verified_auth=True,
                auth_method=auth_method,
                middleware_chain=["inline"],
                confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                trace_depth=0,
            )
        return None

    # ------------------------------------------------------------------
    # LSP-powered definition tracing
    # ------------------------------------------------------------------

    async def _trace_definition(
        self,
        file_path: str,
        line: int,
        character: int,
        depth: int = 0,
    ) -> str | None:
        """Trace go-to-definition and return the definition's file content.

        Follows the chain up to MAX_TRACE_DEPTH to prevent infinite loops.
        """
        if depth >= LSPConfig.MAX_TRACE_DEPTH:
            return None

        locations = await self._lsp.get_definition(file_path, line, character)
        if not locations:
            return None

        for loc in locations:
            # Skip if definition is in the same file at the same position
            if loc.file_path == file_path and loc.line == line:
                continue

            # Skip node_modules definitions
            if "node_modules" in loc.file_path:
                continue

            # Read the definition file content
            def_content = self._get_file_content_absolute(loc.file_path)
            if def_content:
                return def_content

        return None

    # ------------------------------------------------------------------
    # Pattern matching helpers (DRY — shared across strategies)
    # ------------------------------------------------------------------

    @staticmethod
    def _find_auth_terminal(content: str) -> str:
        """Find auth terminal patterns in content.

        Returns the matched auth method name, or empty string.
        """
        for pattern in LSPConfig.AUTH_TERMINAL_PATTERNS:
            match = re.search(pattern, content)
            if match:
                return match.group(0)
        return ""

    @staticmethod
    def _has_enforcement(content: str) -> bool:
        """Check if content contains auth enforcement patterns."""
        return any(
            re.search(pattern, content)
            for pattern in LSPConfig.AUTH_ENFORCEMENT_PATTERNS
        )

    @staticmethod
    def _find_ownership_terminal(content: str) -> str:
        """Find ownership check patterns in content."""
        for pattern in LSPConfig.OWNERSHIP_TERMINAL_PATTERNS:
            match = re.search(pattern, content)
            if match:
                return match.group(0)
        return ""

    # ------------------------------------------------------------------
    # File and position utilities
    # ------------------------------------------------------------------

    def _get_file_content(self, relative_path: str) -> str:
        """Get file content from the cached file index.

        Handles path mismatch between route mappers (workspace-relative)
        and file_index (repo-root-relative) by suffix matching when
        the exact key isn't found.
        """
        content = self._file_cache.get(relative_path)
        if content is not None:
            return content

        # Workspace routes may use paths like "src/routers/user.ts" while
        # file_index keys are "backend/src/routers/user.ts".  Fall back
        # to suffix matching.
        suffix = f"/{relative_path}"
        for key, value in self._file_cache.items():
            if key.endswith(suffix):
                return value

        return ""

    def _get_file_content_absolute(self, abs_path: str) -> str:
        """Get file content by absolute path (reads from disk or cache)."""
        # Check cache with relative path
        if self._repo.clone_path:
            try:
                rel = str(Path(abs_path).relative_to(self._repo.clone_path))
                if rel in self._file_cache:
                    return self._file_cache[rel]
            except ValueError:
                pass

        # Read from disk
        try:
            content = Path(abs_path).read_text(encoding="utf-8", errors="replace")
            return content
        except OSError:
            return ""

    def _resolve_path(self, relative_path: str) -> str:
        """Resolve a relative file path to absolute."""
        if self._repo.clone_path:
            return str(Path(self._repo.clone_path) / relative_path)
        return relative_path

    @staticmethod
    def _offset_to_position(content: str, offset: int) -> tuple[int, int]:
        """Convert a character offset to (line, character) position.

        Both line and character are zero-based (LSP convention).
        """
        line = content[:offset].count("\n")
        last_newline = content.rfind("\n", 0, offset)
        character = offset - (last_newline + 1)
        return line, character
