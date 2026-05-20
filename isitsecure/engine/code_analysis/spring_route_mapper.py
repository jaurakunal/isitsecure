"""Maps Spring Boot route definitions to API routes.

SRP: Detects Spring MVC/WebFlux route definitions from Java/Kotlin files.
OCP: Implements RouteMapperProtocol — added to mapper list without modifying others.
DIP: Depends on RouteMapperProtocol abstraction.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from isitsecure.engine.code_analysis.protocols import RouteEntry

logger = logging.getLogger(__name__)


class SpringRouteMapper:
    """Detects Spring Boot route definitions from Java and Kotlin files.

    Handles:
    - @RequestMapping("/path") at class and method level
    - @GetMapping, @PostMapping, @PutMapping, @PatchMapping, @DeleteMapping
    - Path variables: @GetMapping("/{id}") or @GetMapping("/{id:\\\\d+}")
    - @RestController vs @Controller detection
    - DRY: class-level prefix + method-level path = full route
    """

    # Class-level @RequestMapping("prefix")
    CLASS_MAPPING_PATTERN = re.compile(
        r"""@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']""",
        re.MULTILINE,
    )

    # Method-level mapping annotations (excludes @RequestMapping which is class-level)
    METHOD_MAPPING_PATTERN = re.compile(
        r"""@(Get|Post|Put|Patch|Delete)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']""",
        re.MULTILINE,
    )

    # Method mapping with no path (just the annotation)
    METHOD_MAPPING_NO_PATH = re.compile(
        r"""@(Get|Post|Put|Patch|Delete)Mapping\s*(?:\(\s*\))?\s*$""",
        re.MULTILINE,
    )

    # @RequestMapping with method attribute
    REQUEST_MAPPING_WITH_METHOD = re.compile(
        r"""@RequestMapping\s*\([^)]*method\s*=\s*RequestMethod\.(\w+)""",
        re.MULTILINE,
    )

    # Auth annotations
    AUTH_PATTERNS = (
        "@PreAuthorize",
        "@Secured",
        "@RolesAllowed",
        "SecurityContext",
        "Authentication",
        ".authenticated()",
        "hasRole(",
        "hasAuthority(",
        "isAuthenticated()",
        "@WithMockUser",
        "SecurityFilterChain",
        "HttpSecurity",
        "WebSecurityConfigurerAdapter",
    )

    # Directories to skip
    SKIP_DIRS = ("node_modules", ".gradle", "build", "target", ".idea", "test", "tests")

    # File extensions
    JAVA_EXTENSIONS = (".java", ".kt")

    def map_routes(self, clone_path: str) -> list[RouteEntry]:
        """Scan for Spring route definitions."""
        root = Path(clone_path)
        routes: list[RouteEntry] = []

        for ext in self.JAVA_EXTENSIONS:
            for file_path in root.rglob(f"*{ext}"):
                if any(skip in file_path.parts for skip in self.SKIP_DIRS):
                    continue

                try:
                    content = file_path.read_text(errors="replace")
                except Exception:
                    continue

                if not self._is_controller_file(content):
                    continue

                relative = str(file_path.relative_to(root))
                file_routes = self._extract_routes(relative, content)
                routes.extend(file_routes)

        logger.info("Spring route mapper found %d routes", len(routes))
        return routes

    def _extract_routes(self, file_path: str, content: str) -> list[RouteEntry]:
        """Extract routes from a single controller file."""
        routes: list[RouteEntry] = []

        # Get class-level prefix
        class_prefix = ""
        class_match = self.CLASS_MAPPING_PATTERN.search(content)
        if class_match:
            class_prefix = class_match.group(1)

        has_auth = self._has_auth_check(content)

        # Method-level mappings with path
        for match in self.METHOD_MAPPING_PATTERN.finditer(content):
            annotation = match.group(1)
            path = match.group(2)
            method = self._annotation_to_method(annotation)
            full_path = self._combine_paths(class_prefix, path)
            full_path = self._normalize_pattern(full_path)

            routes.append(RouteEntry(
                file_path=file_path,
                http_methods=[method],
                route_pattern=full_path,
                has_auth_check=has_auth,
                content=content,
            ))

        # Method-level mappings without path (just @GetMapping on class prefix)
        for match in self.METHOD_MAPPING_NO_PATH.finditer(content):
            annotation = match.group(1)
            method = self._annotation_to_method(annotation)
            full_path = self._normalize_pattern(class_prefix or "/")

            routes.append(RouteEntry(
                file_path=file_path,
                http_methods=[method],
                route_pattern=full_path,
                has_auth_check=has_auth,
                content=content,
            ))

        return routes

    @staticmethod
    def _annotation_to_method(annotation: str) -> str:
        """Convert Spring annotation prefix to HTTP method."""
        mapping = {
            "Get": "GET",
            "Post": "POST",
            "Put": "PUT",
            "Patch": "PATCH",
            "Delete": "DELETE",
            "Request": "REQUEST",
        }
        return mapping.get(annotation, "GET")

    def _detect_request_methods(self, content: str, pos: int) -> list[str]:
        """Detect methods from @RequestMapping(method = RequestMethod.X)."""
        context = content[max(0, pos - 50):pos + 200]
        methods = []
        for match in self.REQUEST_MAPPING_WITH_METHOD.finditer(context):
            methods.append(match.group(1))
        return methods or ["GET"]

    @staticmethod
    def _combine_paths(prefix: str, path: str) -> str:
        """Combine class-level prefix with method-level path."""
        prefix = prefix.rstrip("/")
        if not path.startswith("/"):
            path = f"/{path}"
        return f"{prefix}{path}"

    @staticmethod
    def _normalize_pattern(pattern: str) -> str:
        """Normalize Spring path variables to standard :param format."""
        if not pattern.startswith("/"):
            pattern = f"/{pattern}"
        # Convert {paramName} to :paramName
        pattern = re.sub(r"\{(\w+)(?::[^}]*)?\}", r":\1", pattern)
        return pattern

    @staticmethod
    def _is_controller_file(content: str) -> bool:
        """Check if file contains Spring controller annotations."""
        return any(marker in content for marker in (
            "@RestController",
            "@Controller",
            "@RequestMapping",
            "@GetMapping",
            "@PostMapping",
        ))

    def _has_auth_check(self, content: str) -> bool:
        """Check if the controller has security annotations."""
        return any(pattern in content for pattern in self.AUTH_PATTERNS)
