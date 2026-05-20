"""Detects web framework, backend, and auth provider from project files.

Supports both JavaScript (package.json) and Python (requirements.txt,
pyproject.toml) projects.
"""

from __future__ import annotations

import logging
import re

from isitsecure.engine.constants import FrameworkDetectorConfig
from isitsecure.engine.enums import BackendType, FrameworkType

logger = logging.getLogger(__name__)


# Python framework indicators: (package_name → FrameworkType)
_PYTHON_FRAMEWORK_MAP = {
    "django": FrameworkType.DJANGO,
    "djangorestframework": FrameworkType.DJANGO,
    "django-rest-framework": FrameworkType.DJANGO,
    "fastapi": FrameworkType.FASTAPI,
    "flask": FrameworkType.FLASK,
}

# Python backend indicators: (package_name → BackendType)
_PYTHON_BACKEND_MAP = {
    "supabase": BackendType.SUPABASE,
    "firebase-admin": BackendType.FIREBASE,
    "sqlalchemy": BackendType.CUSTOM,
    "psycopg2": BackendType.CUSTOM,
    "psycopg2-binary": BackendType.CUSTOM,
    "asyncpg": BackendType.CUSTOM,
    "tortoise-orm": BackendType.CUSTOM,
    "databases": BackendType.CUSTOM,
    "prisma": BackendType.PRISMA,
}


class FrameworkDetector:
    """Detects web framework, backend, and auth provider from project files.

    Supports JavaScript (package.json) and Python (requirements.txt,
    pyproject.toml) projects.
    """

    def detect_framework(self, package_json: dict) -> FrameworkType:
        """Identify the web framework from package.json dependencies."""
        for key, indicator in FrameworkDetectorConfig.FRAMEWORK_INDICATORS.items():
            if self._has_dependency(
                package_json, indicator["package"], indicator["section"]
            ):
                logger.debug("Detected framework: %s", key)
                return FrameworkType(key)
        return FrameworkType.UNKNOWN

    def detect_framework_python(self, file_index: dict[str, str]) -> FrameworkType:
        """Identify the Python web framework from requirements or pyproject.

        Args:
            file_index: Mapping of file_path → content from the repo.

        Returns:
            Detected FrameworkType or UNKNOWN.
        """
        deps = self._extract_python_deps(file_index)
        for pkg, framework in _PYTHON_FRAMEWORK_MAP.items():
            if pkg in deps:
                logger.debug("Detected Python framework: %s", framework.value)
                return framework
        return FrameworkType.UNKNOWN

    def detect_backend(self, package_json: dict) -> BackendType:
        """Identify the backend/database provider from package.json dependencies."""
        for key, indicator in FrameworkDetectorConfig.BACKEND_INDICATORS.items():
            if self._has_dependency(
                package_json, indicator["package"], indicator["section"]
            ):
                logger.debug("Detected backend: %s", key)
                return BackendType(key)
        return BackendType.UNKNOWN

    def detect_backend_python(self, file_index: dict[str, str]) -> BackendType:
        """Identify the backend from Python dependencies."""
        deps = self._extract_python_deps(file_index)
        for pkg, backend in _PYTHON_BACKEND_MAP.items():
            if pkg in deps:
                logger.debug("Detected Python backend: %s", backend.value)
                return backend
        return BackendType.UNKNOWN

    def detect_auth_provider(self, package_json: dict) -> str:
        """Identify the auth provider from package.json dependencies."""
        all_deps: dict = {
            **package_json.get("dependencies", {}),
            **package_json.get("devDependencies", {}),
        }
        for key, package_name in FrameworkDetectorConfig.AUTH_INDICATORS.items():
            if package_name in all_deps:
                logger.debug("Detected auth provider: %s", key)
                return key
        return ""

    @staticmethod
    def _has_dependency(package_json: dict, package: str, section: str) -> bool:
        """Check if a package exists in the specified section."""
        return package in package_json.get(section, {})

    @staticmethod
    def _extract_python_deps(file_index: dict[str, str]) -> set[str]:
        """Extract Python package names from requirements.txt or pyproject.toml."""
        deps: set[str] = set()

        for file_path, content in file_index.items():
            name = file_path.rsplit("/", 1)[-1].lower()

            if name == "requirements.txt" or (name.startswith("requirements") and name.endswith(".txt")):
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    match = re.match(r"^([a-zA-Z0-9_-]+)", line)
                    if match:
                        deps.add(match.group(1).lower().replace("-", "").replace("_", ""))

            elif name == "pyproject.toml":
                in_deps = False
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped in ("[project.dependencies]", "dependencies = ["):
                        in_deps = True
                        continue
                    if in_deps and stripped.startswith("[") and not stripped.startswith('"'):
                        in_deps = False
                        continue
                    if in_deps and stripped.startswith('"'):
                        dep = stripped.strip('",').strip()
                        match = re.match(r"^([a-zA-Z0-9_-]+)", dep)
                        if match:
                            deps.add(match.group(1).lower().replace("-", "").replace("_", ""))

        return deps
