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
import bisect
import functools
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
from isitsecure.engine.code_analysis.shared_utils import read_repo_file
from isitsecure.engine.constants import LSPConfig, SharedPatterns

logger = logging.getLogger(__name__)


class _FileIndex:
    """Per-file lookup tables, built once and shared by every route.

    Judging each (route, method) used to re-split the whole file, re-scan it
    for classes / handler exports and compare every decorator stack, which is
    quadratic in the number of routes (4000 routes took minutes).
    """

    def __init__(self, text: str, stacks: list[dict]) -> None:
        self.text = text
        self.stacks = stacks
        self.lines = text.split("\n")
        offsets = [0]
        for line in self.lines:
            offsets.append(offsets[-1] + len(line) + 1)
        self.line_offsets = offsets
        self.class_positions = [
            m.start() for m in re.finditer(r"\bclass\s+\w+", text)
        ]
        self.class_auth: dict[int, str] = {}
        for st in stacks:
            if st["class_pos"] is not None:
                self.class_auth.setdefault(st["class_pos"], st["auth"])
        self.route_stacks = [st for st in stacks if st["routes"]]
        self.by_want: dict[str, list[tuple[int, str]]] = {}
        for i, st in enumerate(stacks):
            for deco_method, deco_path in st["routes"]:
                want = AuthFlowTracer._normalise_route_path(deco_path)
                self.by_want.setdefault(want, []).append((i, deco_method))
        # Cheap pre-check: every procedure base name contains "rocedure".
        self.has_procedure = "rocedure" in text
        self.own_handler: dict[str, re.Match | None] = {}
        self.own_scope: dict[str, tuple[str, int] | None] = {}
        self.other_handler_export: bool | None = None

    def line_of(self, offset: int) -> int:
        """Zero-based line number of ``offset`` (== newlines before it)."""
        return bisect.bisect_right(self.line_offsets, offset) - 1

    def class_guard(self, position: int) -> str:
        """Auth decorator on the class declaration enclosing ``position``."""
        idx = bisect.bisect_left(self.class_positions, position) - 1
        if idx < 0:
            return ""
        return self.class_auth.get(self.class_positions[idx], "")

    def matching_stacks(self, route: RouteEntry, method: str) -> list[int]:
        """Indices (in stack order) of the stacks declaring this route+method."""
        have = AuthFlowTracer._normalise_route_path(route.route_pattern)
        wants = {"", have}
        wants.update(have[i + 1:] for i, ch in enumerate(have) if ch == "/")
        verb = method.upper()
        hits = {
            i
            for want in wants
            for i, deco_method in self.by_want.get(want, ())
            if deco_method in ("*", verb)
        }
        return sorted(hits)


@functools.lru_cache(maxsize=8)
def _local_import_names(content: str) -> tuple[str, ...]:
    """Names imported with ``import {..} from`` a project-local module."""
    names: list[str] = []
    for match in re.finditer(
        r"import\s*\{([^}]*)\}\s*from\s*[\'\"]([^\'\"]+)[\'\"]", content
    ):
        if not match.group(2).startswith(LSPConfig.LOCAL_MODULE_PREFIXES):
            continue
        for raw in match.group(1).split(","):
            # `foo as bar` is called as `bar`
            name = raw.split(" as ")[-1].strip()
            if name and name not in names:
                names.append(name)
    return tuple(names)


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
        abs_path = self._resolve_path(file_path)

        # Go has its own idioms (router/group .Use middleware, in-handler and
        # cross-function auth helpers) that the Express mount model doesn't fit.
        # Dispatched before the file_index lookup below: each Go RouteEntry
        # already carries its file `content` and `handler_source` from the
        # mapper, so Go does not depend on file_index resolving this path.
        if file_path.endswith(".go"):
            return await self._trace_go_file(routes, abs_path)

        content = self._get_file_content(file_path)
        if not content:
            return {}
        # Commented-out guards and mounts are not code (offsets are preserved).
        content = self._strip_comments(content)

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

        return await self._trace_routes_in_file(routes, content, abs_path)

    # ------------------------------------------------------------------
    # Go strategy: per-route, from the handler the mapper recorded
    # ------------------------------------------------------------------

    async def _trace_go_file(
        self, routes: list[RouteEntry], abs_path: str
    ) -> dict[tuple[str, str], AuthFlowResult]:
        """Per-route auth verdict for a Go file.

        Each Go route carries its own ``handler_source`` AND its file
        ``content`` (from GoRouteMapper), so the verdict is per handler — one
        guarded handler never vouches for an unguarded neighbour in the same
        file — and Go does not depend on the file_index. Verification, in order:
        1. router/group ``.Use(authMiddleware)`` — the mapper already set
           ``has_auth_check`` True for those;
        2. the handler itself identifies a caller AND refuses (inline);
        3. the handler calls an auth-naming helper that go-to-definition
           resolves to a body with an auth terminal — the cross-file case
           gopls exists for.
        """
        results: dict[tuple[str, str], AuthFlowResult] = {}
        for route in routes:
            result = await self._verify_go_route(route, route.content, abs_path)
            for method in route.http_methods:
                results[(method, route.route_pattern)] = result
        return results

    async def _verify_go_route(
        self, route: RouteEntry, content: str, abs_path: str
    ) -> AuthFlowResult:
        # 1. Router/group middleware guard (definite, set by the mapper).
        if route.has_auth_check is True:
            return AuthFlowResult(
                has_verified_auth=True,
                auth_method="router-middleware",
                middleware_chain=["Use"],
                confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                trace_depth=0,
            )

        body = route.handler_source or ""

        # 2. Handler identifies AND refuses inline.
        terminal = self._find_auth_terminal(body)
        if terminal and self._has_enforcement(body):
            return AuthFlowResult(
                has_verified_auth=True,
                auth_method=terminal,
                middleware_chain=["inline"],
                confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                trace_depth=0,
            )

        # 3. Follow an auth-naming helper the handler calls to its definition.
        for name in self._go_auth_helper_calls(body):
            match = re.search(rf"\b{re.escape(name)}\s*\(", content)
            if not match:
                continue
            line, char = self._offset_to_position(content, match.start())
            definition = await self._trace_definition_body(abs_path, line, char)
            if definition and self._find_auth_terminal(definition):
                return AuthFlowResult(
                    has_verified_auth=True,
                    auth_method=name,
                    middleware_chain=[name],
                    confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                    trace_depth=1,
                )

        return AuthFlowResult(confidence=0.5)

    @staticmethod
    def _go_auth_helper_calls(body: str) -> list[str]:
        """Auth-naming functions the handler calls (``requireAuth(r)`` etc.).

        Deliberately auth-specific so an ordinary helper is not chased, and
        deduplicated in call order. The resolved body still has to contain an
        auth terminal before the route is credited, so a mis-named function
        cannot vouch for auth on its own.
        """
        names: list[str] = []
        for match in re.finditer(
            r"\b(\w*(?:[Aa]uth|[Ll]ogin|[Tt]oken|[Ss]ession)\w*)\s*\(", body
        ):
            name = match.group(1)
            if name not in names:
                names.append(name)
        return names[: LSPConfig.MAX_MOUNT_MIDDLEWARE]

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

    async def _trace_routes_in_file(
        self, routes: list[RouteEntry], content: str, abs_path: str
    ) -> dict[tuple[str, str], AuthFlowResult]:
        """Whole-file strategies, judged per route and method.

        Evidence found somewhere in the file is only credited to the routes it
        can be attributed to: a guard on one handler, one decorator stack or
        one tRPC procedure never vouches for its unguarded neighbours. When the
        shape of the file does not let a route be attributed, it is not
        vouched for (the finding stays, which is the safe direction).
        """
        text = self._strip_comments(content)
        stacks = self._decorator_stacks(text)
        patterns = {route.route_pattern for route in routes}
        pairs = sum(len(route.http_methods) for route in routes)
        index = _FileIndex(text, stacks)
        results: dict[tuple[str, str], AuthFlowResult] = {}
        for route in routes:
            for method in route.http_methods:
                results[(method, route.route_pattern)] = (
                    await self._trace_route_in_file(
                        route, method, text, stacks, abs_path,
                        sole_pattern=len(patterns) == 1,
                        sole_pair=pairs == 1,
                        is_python=route.file_path.endswith(".py"),
                        index=index,
                    )
                )
        return results

    async def _trace_route_in_file(
        self,
        route: RouteEntry,
        method: str,
        text: str,
        stacks: list[dict],
        abs_path: str,
        *,
        sole_pattern: bool,
        sole_pair: bool,
        is_python: bool,
        index: _FileIndex | None = None,
    ) -> AuthFlowResult:
        index = index or _FileIndex(text, stacks)
        # Strategy 1: Procedure base (tRPC, NestJS, etc.)
        result = None
        if index.has_procedure:
            result = await self._trace_procedure_auth(
                text, abs_path, self._procedure_name(route.route_pattern)
            )
        if result and result.has_verified_auth:
            return result

        # Strategy 3: Auth decorators (NestJS, Python, Spring, Fastify)
        result = self._decorator_auth_for_route(
            text, stacks, route, method, sole_pair, index
        )
        if result and result.has_verified_auth:
            return result

        # Strategy 4: Inline auth calls (Next.js or direct), inside the
        # handler that serves this route.
        scope = self._handler_scope(
            text, stacks, route, method,
            sole_pattern=sole_pattern, is_python=is_python, index=index,
        )
        if scope is not None:
            result = await self._trace_inline_auth(text, abs_path, scope)
            if result and result.has_verified_auth:
                return result

        return AuthFlowResult(confidence=0.5)

    @staticmethod
    def _procedure_name(route_pattern: str) -> str:
        """``/trpc/user.wipe`` -> ``wipe``: the key the procedure is declared under."""
        last = route_pattern.rstrip("/").rsplit("/", 1)[-1]
        return last.rsplit(".", 1)[-1]

    # ------------------------------------------------------------------
    # Strategy 1: Procedure base auth tracing
    # ------------------------------------------------------------------

    async def _trace_procedure_auth(
        self, content: str, abs_path: str, route_name: str = ""
    ) -> AuthFlowResult | None:
        """Trace procedure bases (tRPC, NestJS, etc.) to their auth middleware.

        With ``route_name`` the verdict is the one for the procedure declared
        under that key (``wipe: publicProcedure.mutation(...)``): a protected
        neighbour never vouches for a public procedure. When the route cannot
        be found in the file, a file that mixes public and protected bases is
        ambiguous and is not vouched for.
        """
        protected_bases = LSPConfig.PROTECTED_PROCEDURE_BASES
        if route_name:
            declared = re.search(
                rf'\b{re.escape(route_name)}\s*[:=]\s*(?P<base>[\w.]*[Pp]rocedure)\b',
                content,
            )
            if declared:
                base = declared.group("base")
                if base in LSPConfig.PUBLIC_PROCEDURE_BASES:
                    return AuthFlowResult(
                        has_verified_auth=False,
                        auth_method=f"{base} (intentionally public)",
                        confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                    )
                if base not in protected_bases:
                    return None
                protected_bases = (base,)
            elif self._mixes_public_and_protected(content):
                return None
        elif self._mixes_public_and_protected(content):
            return None

        # Check if any protected procedure base is used
        for base in protected_bases:
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
        for base in protected_bases:
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

    @staticmethod
    def _mixes_public_and_protected(content: str) -> bool:
        """True when the file uses both public and protected procedure bases."""
        public = any(
            re.search(rf'\b{re.escape(base)}\b', content)
            for base in LSPConfig.PUBLIC_PROCEDURE_BASES
        )
        protected = any(
            re.search(rf'\b{base}\b', content)
            for base in LSPConfig.PROTECTED_PROCEDURE_BASES
        )
        return public and protected

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

    def _decorator_auth_for_route(
        self,
        text: str,
        stacks: list[dict],
        route: RouteEntry,
        method: str,
        sole_pair: bool,
        index: _FileIndex | None = None,
    ) -> AuthFlowResult | None:
        """The auth decorator that sits on *this* route, or its class.

        A guard on another handler of the same file does not count. Routes the
        file never declares through a recognised route decorator (Django views,
        Fastify option objects) fall back to the old file-wide check only when
        the file serves a single route.
        """
        index = index or _FileIndex(text, stacks)
        if not index.route_stacks:
            return self._check_decorator_auth(text) if sole_pair else None

        matched = [stacks[i] for i in index.matching_stacks(route, method)]
        if not matched:
            return None

        guards = []
        for st in matched:
            guard = st["auth"] or index.class_guard(st["start"])
            if not guard:
                return None
            guards.append(guard)
        return AuthFlowResult(
            has_verified_auth=True,
            auth_method=guards[0],
            middleware_chain=["decorator"],
            confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
            trace_depth=0,
        )

    @staticmethod
    def _class_guard(stacks: list[dict], text: str, position: int) -> str:
        """Auth decorator on the class declaration that encloses ``position``."""
        enclosing = [
            m.start() for m in re.finditer(r"\bclass\s+\w+", text)
            if m.start() < position
        ]
        if not enclosing:
            return ""
        class_pos = enclosing[-1]
        for st in stacks:
            if st["class_pos"] == class_pos:
                return st["auth"]
        return ""

    @staticmethod
    def _normalise_route_path(path: str) -> str:
        """Collapse path parameters so ``:id``, ``{id}`` and ``<int:id>`` agree."""
        path = re.sub(r"<[^>]*>|\{[^}]*\}|:\w+|\[[^\]]*\]", "*", path)
        return path.strip("/")

    def _route_decorator_matches(
        self, decorator: tuple[str, str], route: RouteEntry, method: str
    ) -> bool:
        """Does a route decorator's (method, path) describe this route entry?"""
        deco_method, deco_path = decorator
        if deco_method not in ("*", method.upper()):
            return False
        want = self._normalise_route_path(deco_path)
        have = self._normalise_route_path(route.route_pattern)
        return not want or have == want or have.endswith("/" + want)

    @staticmethod
    def _route_of_decorator(name: str, args: str) -> tuple[str, str] | None:
        """(method, path) when the decorator declares a route, else None."""
        path_match = re.search(r"""['"`]([^'"`]*)['"`]""", args)
        path = path_match.group(1) if path_match else ""
        verb = re.match(LSPConfig.ROUTE_DECORATOR_MAPPING, name) or re.match(
            LSPConfig.ROUTE_DECORATOR_VERB, name
        )
        if verb:
            v = verb.group("verb").upper()
            return ("*" if v == "ALL" else v, path)
        if re.match(LSPConfig.ROUTE_DECORATOR_ANY, name):
            methods = re.search(r"methods\s*=\s*\[([^\]]*)\]", args)
            if methods:
                found = re.findall(r"[A-Za-z]+", methods.group(1))
                if len(found) == 1:
                    return (found[0].upper(), path)
                return ("*", path)
            enum = re.search(r"RequestMethod\.(\w+)", args)
            if enum:
                return (enum.group(1).upper(), path)
            return ("GET" if name.endswith("route") else "*", path)
        return None

    @staticmethod
    def _decorator_stacks(text: str) -> list[dict]:
        """Group consecutive ``@decorator(...)`` lines into stacks.

        Each stack records the auth decorator it carries (``auth``), the routes
        it declares (``routes``: list of (method, path)), where it starts and,
        when it sits on a class, the offset of that ``class`` keyword.
        """
        stacks: list[dict] = []
        current: dict | None = None
        pos = 0
        for match in re.finditer(r"^[ \t]*@(?P<name>[\w.]+)", text, re.MULTILINE):
            if match.start() < pos:
                continue  # inside the previous decorator's arguments
            end = match.end()
            args = ""
            if text[end:end + 1] == "(":
                depth, i = 0, end
                while i < len(text):
                    if text[i] == "(":
                        depth += 1
                    elif text[i] == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    i += 1
                args = text[end + 1:i]
                end = min(i + 1, len(text))
            else:
                end = text.find("\n", end)
                end = len(text) if end < 0 else end
            pos = end
            full = text[match.start():end].strip()
            if current is not None and not text[current["end"]:match.start()].strip():
                stack = current
            else:
                stack = {
                    "start": match.start(), "end": end, "auth": "",
                    "routes": [], "class_pos": None,
                }
                stacks.append(stack)
                current = stack
            stack["end"] = end
            if not stack["auth"]:
                for pattern in LSPConfig.AUTH_DECORATOR_PATTERNS:
                    found = re.search(pattern, full)
                    if found:
                        stack["auth"] = found.group(0)
                        break
            route = AuthFlowTracer._route_of_decorator(match.group("name"), args)
            if route:
                stack["routes"].append(route)
        for stack in stacks:
            following = re.match(
                r"\s*(?:export\s+|default\s+|public\s+|abstract\s+|final\s+)*"
                r"(?P<kw>class)\b",
                text[stack["end"]:],
            )
            if following:
                stack["class_pos"] = stack["end"] + following.start("kw")
        return stacks

    # ------------------------------------------------------------------
    # Strategy 4: Inline auth tracing
    # ------------------------------------------------------------------

    async def _trace_inline_auth(
        self,
        content: str,
        abs_path: str,
        scope: tuple[str, int] | None = None,
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

        ``scope`` is (handler text, its offset in ``content``): only that text
        is searched, so a guard in one handler never vouches for another.
        """
        scope_text, scope_offset = scope if scope else (content, 0)
        auth_method = self._find_auth_terminal(scope_text)
        if auth_method:
            return AuthFlowResult(
                has_verified_auth=True,
                auth_method=auth_method,
                middleware_chain=["inline"],
                confidence=LSPConfig.CONFIDENCE_LSP_CONFIRMED,
                trace_depth=0,
            )

        for symbol in self._called_local_imports(content, scope_text):
            match = re.search(rf"\b{re.escape(symbol)}\s*\(", scope_text)
            if not match:
                continue
            line, char = self._offset_to_position(
                content, scope_offset + match.start()
            )
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
    def _called_local_imports(
        content: str, scope_text: str | None = None
    ) -> list[str]:
        """Named imports from the project's own modules that this file calls.

        Package imports are skipped: a helper that verifies *this* app's
        sessions lives in the app. Note ``@/lib/auth`` is a project alias
        while ``@supabase/supabase-js`` is a package — only the former starts
        with ``@/``. Imports are read from ``content``; a call only counts when
        it appears in ``scope_text`` (the handler under analysis, default all).
        """
        scope_text = content if scope_text is None else scope_text
        symbols: list[str] = []
        for name in _local_import_names(content):
            if re.search(rf"\b{re.escape(name)}\s*\(", scope_text):
                symbols.append(name)
        return symbols[: LSPConfig.MAX_INLINE_TRACE_SYMBOLS]

    _HANDLER_METHODS = "GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"

    def _handler_scope(
        self,
        text: str,
        stacks: list[dict],
        route: RouteEntry,
        method: str,
        *,
        sole_pattern: bool,
        is_python: bool,
        index: _FileIndex | None = None,
    ) -> tuple[str, int] | None:
        """The code that serves ``method`` of ``route``, as (text, offset).

        None means the file's shape does not say which code that is, so no
        inline evidence may be credited to the route.
        """
        index = index or _FileIndex(text, stacks)
        verb = method.upper()
        # Next.js route handlers: `export async function POST(...)`. The
        # answer depends only on the method, so it is computed once per file.
        if verb not in index.own_handler:
            index.own_handler[verb] = re.search(
                rf"export\s+(?:async\s+)?(?:function\s+{re.escape(verb)}\b"
                rf"|const\s+{re.escape(verb)}\s*=)",
                text,
            )
        own = index.own_handler[verb]
        if own:
            if verb not in index.own_scope:
                span = self._block_span(text, index.line_of(own.start()), index)
                block = text[span[0]:span[1]]
                if "{" not in block:
                    index.own_scope[verb] = (text, 0)  # body is elsewhere
                else:
                    index.own_scope[verb] = self._with_local_helpers(
                        text, block, span[0]
                    )
            return index.own_scope[verb]
        if index.other_handler_export is None:
            index.other_handler_export = bool(re.search(
                rf"export\s+(?:async\s+)?(?:function|const)\s+(?:{self._HANDLER_METHODS})\b",
                text,
            ))
        if index.other_handler_export:
            return None  # other methods have handlers, this one does not

        # A recognised route decorator: the function that follows it.
        matching = index.matching_stacks(route, method)
        if matching:
            stack = stacks[matching[0]]
            lines = index.lines
            line = index.line_of(stack["end"]) + 1
            while line < len(lines) and not lines[line].strip():
                line += 1
            span = (
                self._indent_span(text, line, index)
                if is_python
                else self._block_span(text, line, index)
            )
            return text[span[0]:span[1]], span[0]

        return (text, 0) if sole_pattern else None

    def _with_local_helpers(
        self, text: str, block: str, offset: int
    ) -> tuple[str, int]:
        """A handler's text plus the bodies of same-file helpers it calls.

        The offset stays the handler's own; helper bodies are appended so a
        guard factored into ``requireUser()`` still vouches for its caller.
        """
        extra: list[str] = []
        for decl in re.finditer(
            r"(?:async\s+)?function\s+(\w+)|(?:const|let)\s+(\w+)\s*=\s*(?:async\s*)?\(",
            text,
        ):
            name = decl.group(1) or decl.group(2)
            if not re.search(rf"\b{re.escape(name)}\s*\(", block):
                continue
            if decl.start() >= offset and decl.start() < offset + len(block):
                continue  # the handler itself
            line = text.count("\n", 0, decl.start())
            a, b = self._block_span(text, line)
            extra.append(text[a:b])
        return block + "\n" + "\n".join(extra), offset

    @staticmethod
    def _indent_span(
        text: str, line: int, index: _FileIndex | None = None
    ) -> tuple[int, int]:
        """Offsets of the indentation-delimited block starting at ``line``."""
        lines = index.lines if index else text.split("\n")
        if not (0 <= line < len(lines)):
            return 0, len(text)
        base = len(lines[line].expandtabs(4)) - len(lines[line].expandtabs(4).lstrip())
        end = line + 1
        while end < len(lines):
            current = lines[end].expandtabs(4)
            if current.strip() and (len(current) - len(current.lstrip())) <= base:
                break
            end += 1
        if index:
            return index.line_offsets[line], min(index.line_offsets[end], len(text))
        start_offset = sum(len(l) + 1 for l in lines[:line])
        end_offset = sum(len(l) + 1 for l in lines[:end])
        return start_offset, min(end_offset, len(text))

    @classmethod
    def _block_span(
        cls, text: str, line: int, index: _FileIndex | None = None
    ) -> tuple[int, int]:
        """Offsets of the declaration at ``line`` (see ``_enclosing_block``)."""
        lines = index.lines if index else text.split("\n")
        if not (0 <= line < len(lines)):
            return 0, len(text)
        end = cls._block_end_line(lines, line)
        if index:
            return (
                index.line_offsets[line],
                min(index.line_offsets[end + 1] - 1, len(text)),
            )
        start_offset = sum(len(l) + 1 for l in lines[:line])
        end_offset = sum(len(l) + 1 for l in lines[: end + 1]) - 1
        return start_offset, min(end_offset, len(text))

    @staticmethod
    def _strip_comments(content: str) -> str:
        """Blank out comments, keeping every offset and newline in place.

        A comment is not code: ``// TODO: add jwt.verify( here`` must not make
        a route look guarded. String literals are respected (a ``//`` inside a
        URL stays); a ' or " string ends at its line, so a stray apostrophe
        cannot swallow the rest of the file. ``#`` only comments out whole
        lines (Python/shell); trailing ``#`` is left alone because it is also
        valid in JS (``this.#field``).
        """
        out: list[str] = []
        i, n = 0, len(content)
        quote = ""
        line_start = True
        while i < n:
            c = content[i]
            if quote:
                out.append(c)
                if c == "\\" and i + 1 < n:
                    out.append(content[i + 1])
                    i += 2
                    continue
                if c == quote or (c == "\n" and quote != "`"):
                    quote = ""
                line_start = c == "\n"
                i += 1
                continue
            if c in "'\"`":
                quote = c
                out.append(c)
                line_start = False
                i += 1
                continue
            if content.startswith("//", i) or (c == "#" and line_start):
                j = content.find("\n", i)
                j = n if j < 0 else j
                out.append(" " * (j - i))
                i = j
                continue
            if content.startswith("/*", i):
                j = content.find("*/", i + 2)
                j = n if j < 0 else j + 2
                out.append("".join("\n" if ch == "\n" else " " for ch in content[i:j]))
                i = j
                continue
            out.append(c)
            if c == "\n":
                line_start = True
            elif not c.isspace():
                line_start = False
            i += 1
        return "".join(out)

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
    def _block_end_line(lines: list[str], line: int) -> int:
        """Index of the last line of the declaration starting at ``line``."""
        start = lines[line]
        # A statement that opens no block is the whole declaration.
        if start.count("{") <= start.count("}"):
            return line
        # Compare tab-expanded widths: a closing brace indented with tabs is
        # at the same column as its opener whichever characters were used.
        expanded = start.expandtabs(4)
        indent = len(expanded) - len(expanded.lstrip())
        for end in range(line + 1, len(lines)):
            candidate = lines[end].expandtabs(4).rstrip().rstrip(";,)")
            if candidate.strip() == "}" and len(candidate) - 1 == indent:
                return end
        return len(lines) - 1

    @staticmethod
    def _enclosing_block(content: str, line: int) -> str:
        """The declaration starting at ``line``, up to its closing brace.

        Ends at the first closing brace in the declaration's own column, so a
        top-level function stops before its neighbours. Trailing punctuation
        is ignored, so an assigned function — which closes on ``};`` or
        ``});`` rather than a bare brace — ends where it actually ends
        instead of running to the end of the file and picking up whatever
        its neighbours do. Columns are compared tab-expanded, so a file
        indented with tabs delimits the same way as one indented with spaces.

        Falls back to the remainder of the file if no such brace is found.
        """
        lines = content.split("\n")
        if not (0 <= line < len(lines)):
            return content

        end = AuthFlowTracer._block_end_line(lines, line)
        if end == line:
            return lines[line]
        return "\n".join(lines[line : end + 1])

    # ------------------------------------------------------------------
    # Pattern matching helpers (DRY — shared across strategies)
    # ------------------------------------------------------------------

    @staticmethod
    def _find_auth_terminal(content: str) -> str:
        """Find auth terminal patterns in content.

        Comments are ignored. Generic lookups (``getUser(``, ``authenticate(``,
        ``getToken(``, ``getSession(``) only count when the same code also
        rejects the caller. Returns the matched auth method name, or "".
        """
        content = AuthFlowTracer._strip_comments(content)
        for pattern in LSPConfig.AUTH_TERMINAL_PATTERNS:
            match = re.search(pattern, content)
            if match:
                return match.group(0)
        if AuthFlowTracer._has_enforcement(content) or any(
            re.search(p, content) for p in LSPConfig.AUTH_REJECTION_PATTERNS
        ):
            for pattern in LSPConfig.AUTH_WEAK_TERMINAL_PATTERNS:
                match = re.search(pattern, content)
                if match:
                    return match.group(0)
        return ""

    @staticmethod
    def _has_enforcement(content: str) -> bool:
        """Check if content contains auth enforcement patterns (outside comments)."""
        content = AuthFlowTracer._strip_comments(content)
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

        # Read from disk. Paths come from the language server, which resolves
        # symlinks itself, so keep reads inside the clone and off links.
        if self._repo.clone_path:
            return read_repo_file(self._repo.clone_path, abs_path) or ""
        try:
            return Path(abs_path).read_text(encoding="utf-8", errors="replace")
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
