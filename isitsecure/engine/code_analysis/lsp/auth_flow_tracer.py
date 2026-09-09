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
from isitsecure.engine.constants import LSPConfig, SharedPatterns

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
                for route in file_routes:
                    for method in route.http_methods:
                        key = self.result_key(
                            route.file_path, method, route.route_pattern
                        )
                        results[key] = result.get(
                            (method, route.route_pattern), AuthFlowResult()
                        )

        traced = len(results)
        auth_found = sum(1 for r in results.values() if r.has_verified_auth)
        logger.info(
            LSPConfig.MSG_TRACE_COMPLETE.format(
                traced=traced, auth_found=auth_found
            )
        )
        return results

    @staticmethod
    def result_key(file_path: str, method: str, route_pattern: str) -> str:
        """The key one route's verdict is filed under.

        The method is part of it because a verdict is per method: one path is
        routinely mounted twice with different guards, and a single key let
        whichever was traced last answer for both.
        """
        return f"{file_path}:{method} {route_pattern}"

    # ------------------------------------------------------------------
    # Per-file tracing
    # ------------------------------------------------------------------

    async def _trace_file(
        self, file_path: str, routes: list[RouteEntry]
    ) -> dict[tuple[str, str], AuthFlowResult]:
        """Trace auth flow for one file, per route.

        A file that mounts its routes explicitly — the Express shape, where
        one ``server.ts`` can carry a hundred of them — is answered per route
        from its own mount line. That distinction is the whole point: in Juice
        Shop 20 of 150 mounts are guarded, so a single verdict for the file
        would either miss all twenty or vouch for the other hundred and
        thirty. Vouching is the dangerous direction, because a suppressed
        finding is a vulnerability the report no longer mentions.

        Files without mounts fall back to whole-file strategies, in order:
        1. Procedure bases: protectedProcedure, tenantProcedure, etc.
        2. Express middleware: requireAuth, verifyAuth, etc.
        3. Auth decorators: @UseGuards, @login_required, @PreAuthorize
        4. Inline auth calls, following project-local helpers one hop.
        """
        content = self._get_file_content(file_path)
        if not content:
            return {}

        abs_path = self._resolve_path(file_path)

        # Middleware applied without a path guards every route on the router,
        # so it settles the whole file regardless of what the mounts say.
        router_wide = await self._trace_express_auth(content, abs_path)
        if router_wide and router_wide.has_verified_auth:
            return self._for_every_method(routes, router_wide)

        mounts = self._route_mounts(content)
        if mounts:
            # Authoritative: this file says which middleware guards what, so
            # a route with no auth on its mount line has none. Falling back to
            # a file-wide scan here is what would let one guarded route vouch
            # for its unguarded neighbours.
            per_route: dict[tuple[str, str], AuthFlowResult] = {}
            for route in routes:
                for method in route.http_methods:
                    per_route[(method, route.route_pattern)] = (
                        await self._verify_route_mount(
                            mounts, method, route.route_pattern,
                            content, abs_path,
                        )
                    )
            return per_route

        result = await self._trace_whole_file(content, abs_path)
        return self._for_every_method(routes, result)

    async def _verify_route_mount(
        self,
        mounts: dict[tuple[str, str], str],
        method: str,
        route_pattern: str,
        content: str,
        abs_path: str,
    ) -> AuthFlowResult:
        """The verdict for one method of one route, from its mount lines.

        A path may be mounted twice over: `app.use('/api/BasketItems',
        security.isAuthorized())` guards every method on that path, and
        `app.post('/api/BasketItems', handler)` still runs through it. So the
        path-wide mount is asked first and settles the route when it verifies
        — treating it as a fallback for methods with no mount of their own had
        an unguarded handler override the guard standing in front of it.

        The method's own mount answers when the path-wide one does not.
        """
        path_wide = mounts.get((LSPConfig.MOUNT_ANY_METHOD, route_pattern))
        if path_wide:
            result = await self._verify_mount_middleware(
                path_wide, content, abs_path, path_wide=True
            )
            if result.has_verified_auth:
                return result

        own = mounts.get((method, route_pattern))
        if own:
            return await self._verify_mount_middleware(own, content, abs_path)

        return AuthFlowResult(confidence=0.5)

    @staticmethod
    def _for_every_method(
        routes: list[RouteEntry], result: AuthFlowResult
    ) -> dict[tuple[str, str], AuthFlowResult]:
        """One verdict, filed against every method of every route in it.

        Router-wide middleware and whole-file strategies answer the file, not
        a mount line, so no method on it is distinguished.
        """
        return {
            (method, route.route_pattern): result
            for route in routes
            for method in route.http_methods
        }

    @staticmethod
    def _route_mounts(content: str) -> dict[tuple[str, str], str]:
        """Map each mounted (method, path) to the middleware named beside it.

        Keyed by method as well as path, because one path is routinely mounted
        several times with different guards::

            app.get('/api/Recycles', recycles.blockRecycleItems())
            app.post('/api/Recycles', security.isAuthorized())

        Keying by path alone let the first line settle the second, so a guarded
        POST was reported as unauthenticated. `.use` and `.all` take
        ``MOUNT_ANY_METHOD``: they apply to every method on that path and
        answer whichever ones have no mount of their own.
        """
        mounts: dict[tuple[str, str], str] = {}
        for match in re.finditer(LSPConfig.ROUTE_MOUNT_PATTERN, content):
            verb = match.group("verb").lower()
            method = (
                LSPConfig.MOUNT_ANY_METHOD
                if verb in ("use", "all")
                else verb.upper()
            )
            key = (method, match.group("path"))
            # First mount wins; later ones are usually narrower duplicates.
            mounts.setdefault(key, match.group("middleware"))
        return mounts

    async def _verify_mount_middleware(
        self, middleware: str, content: str, abs_path: str,
        path_wide: bool = False,
    ) -> AuthFlowResult:
        """Resolve the middleware on a mount line and look for auth in it.

        Two shapes count, the same two the router-wide path accepts. A
        middleware that calls a *terminal* — `expressJwt`, `jwt.verify` — is
        verifying a token itself. One that *rejects* — a 401 or 403 on the
        failing branch — has decided the request may not proceed, which is
        equally an auth decision though it names no library:

            if (decodedToken?.data?.role === roles.accounting) next()
            else res.status(403).json({ error: 'Malicious activity detected' })

        Only the terminal was checked here, so role guards like that one read
        as unguarded and their routes were reported as having no auth at all.

        Rejection only counts for something that actually *guards* the route,
        which on a method mount means: not the last argument. The last one is
        the handler, and every handler has an error path — `changePassword`
        answers 401 to "current password is not correct", which says nothing
        about whether the route is authenticated. Accepting that suppressed
        four routes on the strength of their own validation errors.

        `.use` and `.all` mount middleware rather than a handler, so on those
        every argument is a guard.
        """
        names = self._middleware_names(middleware)
        for index, name in enumerate(names):
            position = self._locate_symbol(content, name)
            if position is None:
                continue
            line, char = position
            definition = await self._trace_definition_body(abs_path, line, char)
            if not definition:
                continue

            auth_method = self._find_auth_terminal(definition)
            if auth_method:
                return AuthFlowResult(
                    has_verified_auth=True,
                    auth_method=auth_method,
                    middleware_chain=[name],
                    confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                    trace_depth=1,
                )

            guards_route = path_wide or index < len(names) - 1
            if guards_route and self._has_enforcement(definition):
                return AuthFlowResult(
                    has_verified_auth=True,
                    auth_method=f"{name} (rejects unauthorized)",
                    middleware_chain=[name],
                    confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                    trace_depth=1,
                )
        return AuthFlowResult(confidence=0.5)

    @staticmethod
    def _applied_middleware(content: str) -> list[str]:
        """Middleware applied to a whole router, in application order.

        Only path-less ``.use(...)`` calls: a ``.use('/admin', guard)`` is a
        mount and belongs to its route, not to the file.
        """
        names: list[str] = []
        for match in re.finditer(LSPConfig.MIDDLEWARE_USE_PATTERN, content):
            for name in AuthFlowTracer._middleware_names(
                match.group("middleware")
            ):
                if name not in names:
                    names.append(name)
        return names[: LSPConfig.MAX_MOUNT_MIDDLEWARE]

    @staticmethod
    def _middleware_names(middleware: str) -> list[str]:
        """The callables named on a mount line, in order.

        Both shapes are common and both must resolve::

            app.use('/x', security.isAuthorized())   -> isAuthorized
            router.get('/x', requireAuth, handler)   -> requireAuth, handler

        Taking the last identifier of each argument yields the member for a
        qualified call and the name itself for a bare reference. The route
        handler comes along too; it simply contains no auth terminal.

        Comments are stripped first. Juice Shop annotates its mounts, and
        ``app.post('/api/Products', security.isAuthorized()) //
        vuln-code-snippet neutral-line changeProductChallenge`` yielded
        ``changeProductChallenge`` — the annotation, with the guard beside it
        dropped entirely, so the route read as unguarded.
        """
        middleware = re.sub(
            SharedPatterns.JS_COMMENT_PATTERN, "", middleware, flags=re.DOTALL
        )
        names: list[str] = []
        for argument in middleware.split(","):
            identifiers = re.findall(r"[A-Za-z_]\w*", argument)
            if identifiers and identifiers[-1] not in names:
                names.append(identifiers[-1])
        return names[: LSPConfig.MAX_MOUNT_MIDDLEWARE]

    @staticmethod
    def _locate_symbol(content: str, name: str) -> tuple[int, int] | None:
        """Position of ``name`` at a use site, preferring not the import line.

        Asking for the definition of an import specifier is answered with the
        import itself, which is the shape ``_is_unresolved`` waits on — so
        query where the symbol is used instead.
        """
        fallback: tuple[int, int] | None = None
        for line_number, line in enumerate(content.split("\n")):
            for match in re.finditer(rf"\b{re.escape(name)}\b", line):
                position = (line_number, match.start())
                if line.lstrip().startswith("import"):
                    fallback = fallback or position
                    continue
                return position
        return fallback

    async def _trace_whole_file(
        self, content: str, abs_path: str
    ) -> AuthFlowResult:
        """Whole-file strategies, for files that do not mount routes."""

        # Strategy 1: Procedure base (tRPC, NestJS, etc.)
        result = await self._trace_procedure_auth(content, abs_path)
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
        """Trace Express middleware to confirm auth verification.

        The fallback for files that do not mount their routes explicitly.
        Centrally-mounted routes are attributed per route; what reaches here
        is middleware applied without a path — ``router.use(requireAuth)`` —
        which guards every route on that router, so one verdict for the file
        is the right shape.

        Which middleware is found by *where it is applied*, not by a list of
        names. A list can only recognise vocabulary someone thought of in
        advance: it had five entries, so a project calling its guard
        ``ensureMember`` was invisible, while the entry ``authenticate``
        matched that word anywhere in the file, including inside an import it
        never used.
        """
        for middleware_name in self._applied_middleware(content):
            position = self._locate_symbol(content, middleware_name)
            if position is None:
                continue
            line, char = position
            chain = [middleware_name]

            # Only the middleware's own body counts. Auth helpers cluster in
            # one module, so searching the whole definition file would let a
            # sibling's terminal vouch for this middleware — the same way a
            # login route importing `signToken` once looked authenticated.
            definition_content = await self._trace_definition_body(
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
        """Check for inline auth calls, following local helpers one hop.

        A route may verify auth itself (``supabase.auth.getUser()`` in the
        handler), which the terminal patterns catch directly. Far more often
        it calls the project's own helper::

            import { getUserFromRequest } from "@/lib/auth"
            const user = getUserFromRequest(request)   // -> verifyToken()

        The terminal is then a file away, and no pattern list can name it —
        ``getUserFromRequest`` is this project's invention. Resolving it is
        exactly what go-to-definition is for, and not doing so meant every
        such route looked unauthenticated.
        """
        auth_method = self._find_auth_terminal(content)
        if auth_method:
            return AuthFlowResult(
                has_verified_auth=True,
                auth_method=auth_method,
                middleware_chain=["inline"],
                confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                trace_depth=0,
            )

        for symbol in self._called_local_imports(content):
            match = re.search(rf"\b{re.escape(symbol)}\s*\(", content)
            if not match:
                continue
            line, char = self._offset_to_position(content, match.start())
            definition = await self._trace_definition_body(abs_path, line, char)
            if not definition:
                continue

            auth_method = self._find_auth_terminal(definition)
            if auth_method:
                return AuthFlowResult(
                    has_verified_auth=True,
                    auth_method=auth_method,
                    middleware_chain=[symbol],
                    confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                    trace_depth=1,
                )
        return None

    @staticmethod
    def _called_local_imports(content: str) -> list[str]:
        """Named imports from the project's own modules that this file calls.

        Package imports are skipped: a helper that verifies *this* app's
        sessions lives in the app. Note ``@/lib/auth`` is a project alias
        while ``@supabase/supabase-js`` is a package — only the former starts
        with ``@/``.
        """
        symbols: list[str] = []
        for match in re.finditer(
            r"import\s*\{([^}]*)\}\s*from\s*[\'\"]([^\'\"]+)[\'\"]", content
        ):
            names, module = match.group(1), match.group(2)
            if not module.startswith(LSPConfig.LOCAL_MODULE_PREFIXES):
                continue
            for raw in names.split(","):
                # `foo as bar` is called as `bar`
                name = raw.split(" as ")[-1].strip()
                if not name or name in symbols:
                    continue
                if re.search(rf"\b{re.escape(name)}\s*\(", content):
                    symbols.append(name)
        return symbols[: LSPConfig.MAX_INLINE_TRACE_SYMBOLS]

    # ------------------------------------------------------------------
    # LSP-powered definition tracing
    # ------------------------------------------------------------------

    async def _resolve_definition(
        self, file_path: str, line: int, character: int
    ) -> list | None:
        """Go-to-definition, waiting out the project load if it isn't ready.

        tsserver builds its program asynchronously after the first
        ``didOpen``. Until that finishes it still answers definition
        requests — by pointing at the *import statement* in the querying
        file rather than the declaration it names. That answer is
        indistinguishable from success unless you look at where it landed,
        so every trace silently stopped at the import and no route ever
        looked authenticated.

        A loaded project answers correctly on the first try and pays
        nothing here; a cold one is retried until it does.
        """
        for attempt in range(LSPConfig.PROJECT_LOAD_RETRIES):
            locations = await self._lsp.get_definition(
                file_path, line, character
            )
            if not locations or not self._is_unresolved(locations, file_path):
                return locations
            await asyncio.sleep(
                LSPConfig.PROJECT_LOAD_BACKOFF_SECONDS * (attempt + 1)
            )
        return locations

    def _is_unresolved(self, locations: list, file_path: str) -> bool:
        """True when every location is an import line in the querying file.

        That is the shape tsserver returns before its program is built. A
        genuinely local declaration also lands in the same file, so the
        import check is what separates "not ready" from "defined here".
        """
        content = self._get_file_content_absolute(file_path)
        if not content:
            return False
        for loc in locations:
            if loc.file_path != file_path:
                return False
            if not self._is_import_line(content, loc.line):
                return False
        return True

    @staticmethod
    def _is_import_line(content: str, line: int) -> bool:
        """True when ``line`` is an import statement rather than a body."""
        lines = content.split("\n")
        if not (0 <= line < len(lines)):
            return False
        return lines[line].lstrip().startswith(("import ", "import{"))

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

        locations = await self._resolve_definition(file_path, line, character)
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

    async def _trace_definition_body(
        self,
        file_path: str,
        line: int,
        character: int,
        depth: int = 0,
        seen: frozenset[tuple[str, int, int]] = frozenset(),
    ) -> str | None:
        """Go-to-definition, returning only the resolved symbol's own body.

        Scoping matters: helper functions cluster in one module, so a file
        reached by resolving *any* symbol usually also contains the auth
        terminals belonging to its siblings. Searching the whole file made a
        login route — which imports ``signToken`` from the same module that
        defines ``verifyToken`` — look authenticated.

        A declaration that is only another name for something else is
        followed, up to ``MAX_TRACE_DEPTH`` hops. One hop lands on the
        alias, not the implementation::

            const isLoggedIn = sessionHandler.isLoggedInMiddleware;

        Stopping there reads an assignment with no auth in it and concludes
        the route is unguarded — the dangerous direction, since the route
        *is* guarded. Local aliases like this are how a project shortens a
        name it uses twenty times, so they sit directly between the route
        and every guard it applies. ``seen`` closes the cycle a
        self-referential alias would otherwise open.
        """
        key = (file_path, line, character)
        if key in seen or depth >= LSPConfig.MAX_TRACE_DEPTH:
            return None
        seen = seen | {key}

        locations = await self._resolve_definition(file_path, line, character)
        if not locations:
            return None

        for loc in locations:
            if "node_modules" in loc.file_path:
                continue
            content = self._get_file_content_absolute(loc.file_path)
            if not content:
                continue
            # A location on an import line in the file we asked from is the
            # unresolved answer, not a declaration; its "body" would be
            # whatever happens to follow the import. A location that lands
            # back on the query itself is not: that is a symbol declared
            # right there, and reading it is the whole point.
            if loc.file_path == file_path and self._is_import_line(
                content, loc.line
            ):
                continue

            block = self._enclosing_block(content, loc.line)
            alias_column = self._alias_target_column(block)
            if alias_column is not None:
                followed = await self._trace_definition_body(
                    loc.file_path, loc.line, alias_column, depth + 1, seen
                )
                if followed:
                    return followed
            return block
        return None

    @staticmethod
    def _alias_target_column(block: str) -> int | None:
        """Column of the symbol an alias declaration points at, if it is one.

        An alias is a declaration whose whole right-hand side is a name —
        ``const isLoggedIn = sessionHandler.isLoggedInMiddleware;``. Anything
        with a call or a function body is the implementation itself and is
        answered where it stands.

        The column returned is the *last* segment of a dotted path, because
        that is the member whose definition is wanted:
        ``sessionHandler.isLoggedInMiddleware`` resolves to the assignment in
        the session module, while ``sessionHandler`` resolves only to the
        local variable holding the object.
        """
        first_line = block.split("\n", 1)[0]
        match = re.match(LSPConfig.ALIAS_DECLARATION_PATTERN, first_line)
        if not match:
            return None
        target = match.group("target")
        return match.start("target") + target.rfind(".") + 1

    @staticmethod
    def _enclosing_block(content: str, line: int) -> str:
        """The declaration starting at ``line``, up to its closing brace.

        Ends at the first closing brace in the declaration's own column, so a
        top-level function stops before its neighbours. Trailing punctuation
        is ignored, so an assigned function — which closes on ``};`` or
        ``});`` rather than a bare brace — ends where it actually ends
        instead of running to the end of the file and picking up whatever
        its neighbours do.

        Falls back to the remainder of the file if no such brace is found.
        """
        lines = content.split("\n")
        if not (0 <= line < len(lines)):
            return content

        start = lines[line]
        # A statement that opens no block is the whole declaration. Scanning
        # on for a closing brace it never opened runs into the *next*
        # declaration's brace and returns a block that includes neighbours —
        # which is how an alias to something unguarded could be vouched for
        # by a guard defined twenty lines below it.
        if start.count("{") <= start.count("}"):
            return start

        indent = len(start) - len(start.lstrip())
        closing = (" " * indent) + "}"
        for end in range(line + 1, len(lines)):
            if lines[end].rstrip().rstrip(";,)") == closing:
                return "\n".join(lines[line : end + 1])
        return "\n".join(lines[line:])

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
