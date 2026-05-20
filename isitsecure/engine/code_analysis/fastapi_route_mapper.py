"""Maps FastAPI/Flask route definitions to API routes.

SRP: Detects Python web framework route definitions.
OCP: Implements RouteMapperProtocol — added to mapper list without modifying others.
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


class FastAPIRouteMapper:
    """Detects FastAPI and Flask route definitions.

    Handles:
    - FastAPI: @app.get('/path'), @router.post('/path')
    - Flask: @app.route('/path', methods=['GET', 'POST'])
    - APIRouter includes
    - Depends() for dependency injection (auth detection)
    """

    # @app.get('/path') or @router.post('/path')
    DECORATOR_PATTERN = re.compile(
        r"""@\w+\.(get|post|put|patch|delete|head|options)\s*\(\s*['"]([^'"]+)['"]""",
        re.MULTILINE,
    )

    # Flask: @app.route('/path', methods=['GET', 'POST'])
    FLASK_ROUTE_PATTERN = re.compile(
        r"""@\w+\.route\s*\(\s*['"]([^'"]+)['"](?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?""",
        re.MULTILINE,
    )

    # FastAPI APIRouter prefix
    ROUTER_PREFIX_PATTERN = re.compile(
        r"""APIRouter\s*\([^)]*prefix\s*=\s*['"]([^'"]+)['"]""",
        re.MULTILINE,
    )

    # Auth patterns in FastAPI/Flask
    AUTH_PATTERNS = (
        "Depends(get_current_user",
        "Depends(auth",
        "Depends(verify_token",
        "Depends(require_auth",
        "login_required",
        "@login_required",
        "current_user",
        "get_current_user",
        "verify_token",
        "HTTPBearer",
        "OAuth2PasswordBearer",
        "Security(",
    )


    def map_routes(self, clone_path: str) -> list[RouteEntry]:
        """Scan for FastAPI/Flask route definitions."""
        root = Path(clone_path)
        routes: list[RouteEntry] = []

        for file_path in root.rglob("*.py"):
            if should_skip_path(file_path):
                continue

            try:
                content = file_path.read_text(errors="replace")
            except Exception:
                continue

            # Skip if this doesn't look like a routes file
            if not self._is_route_file(content):
                continue

            relative = str(file_path.relative_to(root))

            # Detect router prefix
            prefix = ""
            prefix_match = self.ROUTER_PREFIX_PATTERN.search(content)
            if prefix_match:
                prefix = prefix_match.group(1)

            # FastAPI decorator routes
            for match in self.DECORATOR_PATTERN.finditer(content):
                method, path = match.group(1).upper(), match.group(2)
                route_pattern = prefix + path if not path.startswith(prefix) else path
                route_pattern = normalize_route_pattern(route_pattern)

                routes.append(RouteEntry(
                    file_path=relative,
                    http_methods=[method],
                    route_pattern=route_pattern,
                    has_auth_check=self._has_auth_near_position(content, match.start()),
                    content=content,
                ))

            # Flask @app.route() routes
            for match in self.FLASK_ROUTE_PATTERN.finditer(content):
                path = match.group(1)
                methods_str = match.group(2) or "'GET'"
                methods = [m.strip().strip("'\"").upper() for m in methods_str.split(",")]
                route_pattern = normalize_route_pattern(path)

                routes.append(RouteEntry(
                    file_path=relative,
                    http_methods=methods,
                    route_pattern=route_pattern,
                    has_auth_check=self._has_auth_near_position(content, match.start()),
                    content=content,
                ))

        logger.info("FastAPI/Flask route mapper found %d routes", len(routes))
        return routes

    @staticmethod
    def _is_route_file(content: str) -> bool:
        """Quick check if file contains route definitions."""
        route_indicators = (
            "@app.", "@router.", "APIRouter", "Blueprint",
            ".route(", ".get(", ".post(", ".put(",
        )
        return any(indicator in content for indicator in route_indicators)

    def _has_auth_near_position(self, content: str, decorator_pos: int) -> bool:
        """Check if the handler near this decorator position has auth."""
        context = content[max(0, decorator_pos - 200):decorator_pos + 500]
        return has_auth_patterns(context, self.AUTH_PATTERNS)
