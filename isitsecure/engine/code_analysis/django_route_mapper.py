"""Maps Django URL patterns to API routes.

SRP: Detects Django route definitions from urls.py files.
OCP: Implements RouteMapperProtocol — added to mapper list without modifying others.
DIP: Depends on RouteMapperProtocol abstraction.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from isitsecure.engine.code_analysis.protocols import RouteEntry

logger = logging.getLogger(__name__)


class DjangoRouteMapper:
    """Detects Django URL patterns from urls.py files.

    Handles:
    - path('url/', view) and re_path(r'^url/$', view)
    - Class-based views (as_view())
    - Include patterns: path('api/', include('app.urls'))
    - DRF router.register() patterns
    - Auth decorators: @login_required, @permission_required
    """

    # path('pattern/', view_func) or path('pattern/', ViewClass.as_view())
    PATH_PATTERN = re.compile(
        r"""(?:path|re_path)\s*\(\s*['"]([^'"]*)['"]\s*,\s*(\w[\w.]*(?:\.as_view\(\))?)""",
        re.MULTILINE,
    )

    # include('app.urls') with optional namespace
    INCLUDE_PATTERN = re.compile(
        r"""path\s*\(\s*['"]([^'"]*)['"]\s*,\s*include\s*\(\s*['"]([^'"]+)['"]""",
        re.MULTILINE,
    )

    # DRF: router.register(r'pattern', ViewSet)
    DRF_ROUTER_PATTERN = re.compile(
        r"""router\.register\s*\(\s*r?['"]([^'"]*)['"]\s*,\s*(\w+)""",
        re.MULTILINE,
    )

    # HTTP method decorators
    METHOD_DECORATORS = re.compile(
        r"""@(?:api_view|action)\s*\(\s*\[([^\]]+)\]""",
        re.MULTILINE,
    )

    # Auth patterns
    AUTH_PATTERNS = (
        "login_required",
        "permission_required",
        "IsAuthenticated",
        "IsAdminUser",
        "AllowAny",
        "authentication_classes",
        "permission_classes",
        "@login_required",
        "@permission_required",
        "@staff_member_required",
        "request.user.is_authenticated",
    )

    def map_routes(self, clone_path: str) -> list[RouteEntry]:
        """Scan for Django URL patterns."""
        root = Path(clone_path)
        routes: list[RouteEntry] = []
        prefixes: dict[str, str] = {}  # module -> url prefix

        urls_files = list(root.rglob("urls.py"))
        urls_files.extend(root.rglob("**/urls/*.py"))

        for file_path in urls_files:
            if "node_modules" in str(file_path) or ".venv" in str(file_path):
                continue
            try:
                content = file_path.read_text(errors="replace")
            except Exception:
                continue

            relative = str(file_path.relative_to(root))

            # Detect include prefixes
            for match in self.INCLUDE_PATTERN.finditer(content):
                prefix, module = match.group(1), match.group(2)
                prefixes[module] = prefix

            # Detect path() routes
            for match in self.PATH_PATTERN.finditer(content):
                pattern, view = match.group(1), match.group(2)
                route_pattern = self._normalize_pattern(pattern)
                methods = self._detect_methods(content, view)
                has_auth = self._has_auth_check(content)

                routes.append(RouteEntry(
                    file_path=relative,
                    http_methods=methods,
                    route_pattern=route_pattern,
                    has_auth_check=has_auth,
                    content=content,
                ))

            # Detect DRF router.register() routes
            for match in self.DRF_ROUTER_PATTERN.finditer(content):
                pattern = match.group(1)
                route_pattern = f"/{pattern}/" if not pattern.startswith("/") else f"{pattern}/"
                routes.append(RouteEntry(
                    file_path=relative,
                    http_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
                    route_pattern=route_pattern,
                    has_auth_check=self._has_auth_check(content),
                    content=content,
                ))

        logger.info("Django route mapper found %d routes", len(routes))
        return routes

    @staticmethod
    def _normalize_pattern(pattern: str) -> str:
        """Normalize Django URL pattern to a standard format."""
        if not pattern.startswith("/"):
            pattern = f"/{pattern}"
        # Convert <int:pk> to :pk, <str:slug> to :slug
        pattern = re.sub(r"<\w+:(\w+)>", r":\1", pattern)
        # Convert <pk> to :pk
        pattern = re.sub(r"<(\w+)>", r":\1", pattern)
        return pattern

    def _detect_methods(self, content: str, view_name: str) -> list[str]:
        """Detect HTTP methods from view definitions."""
        methods = []

        # Check @api_view(['GET', 'POST'])
        for match in self.METHOD_DECORATORS.finditer(content):
            raw = match.group(1)
            for m in re.findall(r"'(\w+)'", raw):
                methods.append(m.upper())

        # Check class-based view methods (def get, def post, etc.)
        if ".as_view()" in view_name or not methods:
            for method in ("get", "post", "put", "patch", "delete", "head", "options"):
                if re.search(rf"\bdef\s+{method}\s*\(", content):
                    methods.append(method.upper())

        return methods or ["GET"]

    def _has_auth_check(self, content: str) -> bool:
        """Check if the file contains auth decorators or permission checks."""
        return any(pattern in content for pattern in self.AUTH_PATTERNS)
