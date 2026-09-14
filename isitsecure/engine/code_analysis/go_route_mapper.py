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
    has_auth_patterns,
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

    # File-level auth-enforcement signals. Kept auth-specific (not a bare
    # ``.Use(``, which is also logging/CORS) so a file without auth isn't
    # miscredited; the LSP auth-flow tracer refines per-route afterwards.
    AUTH_PATTERNS = (
        "AuthMiddleware",
        "AuthRequired",
        "RequireAuth",
        "RequireLogin",
        "Authenticate",
        "Authorized",
        "middleware.JWT",
        "jwtMiddleware",
        "JWTAuth",
        "IsAuthenticated",
        "GetUserID",
        "c.Get(\"user\")",
        "r.Context().Value",
        "Authorization",
        "VerifyToken",
        "ValidateToken",
        "session.Get",
    )

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
        has_auth = has_auth_patterns(content, self.AUTH_PATTERNS)
        groups = self._group_prefixes(content)

        for match in self.VERB_PATTERN.finditer(content):
            recv, verb = match.group(1), match.group(2)
            path = match.group(3) or match.group(4)  # "..." or `...`
            full = normalize_route_pattern(self._prefix(groups, recv) + path)
            routes.append(RouteEntry(
                file_path=file_path,
                http_methods=[verb.upper()],
                route_pattern=full,
                has_auth_check=has_auth,
                content=content,
            ))

        for match in self.HANDLE_PATTERN.finditer(content):
            recv = match.group(1)
            path = match.group(2) or match.group(3)
            full = normalize_route_pattern(self._prefix(groups, recv) + path)
            routes.append(RouteEntry(
                file_path=file_path,
                # net/http muxes accept any method — record the wildcard so the
                # analyzer treats every verb as reachable.
                http_methods=["ANY"],
                route_pattern=full,
                has_auth_check=has_auth,
                content=content,
            ))

        return routes

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
