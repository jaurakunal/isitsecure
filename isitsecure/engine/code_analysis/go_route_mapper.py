"""Maps Go web-framework route definitions to API routes.

SRP: Detects route definitions from Go source (net/http, gorilla/mux, Gin,
     Echo, chi, Fiber).
OCP: Implements RouteMapperProtocol — added to the mapper list without
     modifying existing code.
DIP: Depends on RouteMapperProtocol abstraction.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from isitsecure.engine.code_analysis.protocols import RouteEntry
from isitsecure.engine.code_analysis.shared_utils import (
    normalize_route_pattern,
    should_skip_path,
)

logger = logging.getLogger(__name__)

# A Go string literal: interpreted "..." or raw `...` (no interior quote of the
# same kind). Captured group 1 is the path.
_STR = r"""(?:"([^"]+)"|`([^`]+)`)"""


class GoRouteMapper:
    """Detects Go route definitions across the common web frameworks.

    Handles:
    - Gin/Echo/Fiber verb calls:  r.GET("/path", h) / e.POST("/p", h)
    - chi/gorilla verb calls:      r.Get("/path", h) / r.HandleFunc(...)
    - net/http:                    mux.HandleFunc("/path", h)
    - Route groups:                v1 := r.Group("/api") ; v1.GET("/users", h)
      (the group prefix is prepended to routes registered on that variable)
    - File-level auth heuristic:   auth middleware / JWT / session lookups
    """

    GO_EXTENSIONS = (".go",)

    # `recv.VERB("path"` — Gin/Echo/Fiber use UPPER verbs, chi/gorilla use Title
    # verbs; we accept both and upper-case the method.
    VERB_PATTERN = re.compile(
        r"""(\w+)\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"""
        r"""|Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*""" + _STR,
        re.MULTILINE,
    )

    # `recv.HandleFunc("path"` / `recv.Handle("path"` — method unknown (net/http
    # multiplexers dispatch every method to the handler).
    HANDLE_PATTERN = re.compile(
        r"""(\w+)\.(?:HandleFunc|Handle)\s*\(\s*""" + _STR,
        re.MULTILINE,
    )

    # `v1 := r.Group("/api")` / `v1 = r.Group("/api")` — captures the group's
    # receiver variable and its path prefix.
    GROUP_PATTERN = re.compile(
        r"""(\w+)\s*:?=\s*[\w.]+\.Group\(\s*""" + _STR,
        re.MULTILINE,
    )

    # `recv.Use(Middleware())` — router/group-wide middleware application.
    USE_PATTERN = re.compile(r"""(\w+)\.Use\s*\(([^)]*)\)""", re.MULTILINE)

    # A middleware/handler name that names authentication. Deliberately
    # auth-specific — a bare `.Use(` is also logging/CORS/recovery, which must
    # not credit a route with auth.
    _AUTH_NAME = re.compile(
        r"(?i)(auth|login|jwt|token|session|protected|require[-_]?(?:auth|login))"
    )
    # A handler is credited with auth only when its body both looks up an
    # identity AND refuses — checked by the route analyzer via handler_source;
    # the mapper only decides the definite router/group-middleware case itself.

    def map_routes(self, clone_path: str) -> list[RouteEntry]:
        """Scan Go source for route definitions."""
        root = Path(clone_path)
        routes: list[RouteEntry] = []

        for file_path in root.rglob("*.go"):
            # Go tests live in *_test.go; skip them and vendored/test trees.
            if file_path.name.endswith("_test.go"):
                continue
            if should_skip_path(file_path, frozenset({"vendor", "test", "tests"})):
                continue
            try:
                content = file_path.read_text(errors="replace")
            except Exception:
                continue
            if not self._has_routes(content):
                continue
            relative = str(file_path.relative_to(root))
            routes.extend(self._extract_routes(relative, content))

        logger.info("Go route mapper found %d routes", len(routes))
        return routes

    def _has_routes(self, content: str) -> bool:
        return bool(
            self.VERB_PATTERN.search(content)
            or self.HANDLE_PATTERN.search(content)
        )

    def _extract_routes(self, file_path: str, content: str) -> list[RouteEntry]:
        routes: list[RouteEntry] = []
        groups = self._group_prefixes(content)
        auth_receivers = self._auth_receivers(content)

        def _entry(recv: str, methods: list[str], path: str, body: str):
            full = normalize_route_pattern(self._prefix(groups, recv) + path)
            # A router/group with auth middleware guards every route on it —
            # that is definite. Otherwise leave the per-route verdict to the
            # route analyzer, which re-examines handler_source for an
            # identity-check-AND-refusal (and the LSP tracer follows helpers
            # across files). None of `content`'s other handlers can vouch here.
            group_auth = recv in auth_receivers
            return RouteEntry(
                file_path=file_path,
                http_methods=methods,
                route_pattern=full,
                has_auth_check=True if group_auth else False,
                content=content,
                handler_source=body,
            )

        for match in self.VERB_PATTERN.finditer(content):
            recv, verb = match.group(1), match.group(2)
            path = match.group(3) or match.group(4)
            # A real route registration passes a handler after the path — this
            # separates `r.GET("/p", h)` from `r.Header.Get("X")` / `c.Get("u")`.
            is_route, body = self._resolve_handler(content, match.end())
            if not is_route:
                continue
            routes.append(_entry(recv, [verb.upper()], path, body))

        for match in self.HANDLE_PATTERN.finditer(content):
            recv = match.group(1)
            path = match.group(2) or match.group(3)
            is_route, body = self._resolve_handler(content, match.end())
            if not is_route:
                continue
            # net/http muxes accept any method — wildcard so every verb reads
            # as reachable.
            routes.append(_entry(recv, ["ANY"], path, body))

        return routes

    def _auth_receivers(self, content: str) -> set[str]:
        """Router/group variables that apply an auth-naming middleware via
        ``.Use(...)`` — those guard every route registered on them."""
        receivers: set[str] = set()
        for match in self.USE_PATTERN.finditer(content):
            recv, arg = match.group(1), match.group(2)
            if self._AUTH_NAME.search(arg):
                receivers.add(recv)
        return receivers

    def _resolve_handler(self, content: str, after: int) -> tuple[bool, str]:
        """Resolve the handler following a route registration's path arg.

        Returns ``(is_route, handler_source)``:
        - named handler ``, getUser)`` → (True, body of ``func getUser``) — or
          (True, "") when it is package-qualified/defined elsewhere (the LSP
          tracer resolves those cross-file);
        - inline ``, func(...) {...}`` → (True, the literal's body);
        - no handler (``r.Header.Get("X")``, ``c.Get("user")``) → (False, "").
        """
        tail = content[after:after + 160]
        m = re.match(r"\s*,\s*([A-Za-z_]\w*(?:\.\w+)?)\s*[),]", tail)
        if m:
            return True, self._func_body(content, m.group(1))
        inline = re.match(r"\s*,\s*func\s*\(", tail)
        if inline:
            brace = content.find("{", after + inline.end())
            return True, self._brace_block(content, brace) if brace != -1 else ""
        return False, ""

    @classmethod
    def _func_body(cls, content: str, handler: str) -> str:
        """The body of ``func <handler>(...) { ... }`` in this file, or "".

        Package-qualified handlers (``pkg.Handler``) live in another file and
        are left to the LSP tracer's go-to-definition; here they resolve to "".
        """
        if not handler or "." in handler:
            return ""
        m = re.search(rf"\bfunc\s+{re.escape(handler)}\s*\(", content)
        if not m:
            return ""
        brace = content.find("{", m.end())
        if brace == -1:
            return ""
        block = cls._brace_block(content, brace)
        return content[m.start():brace] + block if block else ""

    @staticmethod
    def _brace_block(content: str, brace: int) -> str:
        """The ``{...}`` block starting at ``brace``, brace-matched, or ""."""
        depth = 0
        for i in range(brace, len(content)):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    return content[brace:i + 1]
        return content[brace:]  # unbalanced — return what we have

    def _group_prefixes(self, content: str) -> dict[str, str]:
        """Map a group variable to its path prefix (best-effort, one level)."""
        groups: dict[str, str] = {}
        for match in self.GROUP_PATTERN.finditer(content):
            var = match.group(1)
            prefix = match.group(2) or match.group(3)
            groups[var] = prefix
        return groups

    @staticmethod
    def _prefix(groups: dict[str, str], recv: str) -> str:
        prefix = groups.get(recv, "")
        if prefix and not prefix.startswith("/"):
            prefix = "/" + prefix
        return prefix
