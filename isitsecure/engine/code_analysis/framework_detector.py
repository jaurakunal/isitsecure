"""Detects web framework, backend, and auth provider from package.json."""

from __future__ import annotations

import logging

from isitsecure.engine.constants import FrameworkDetectorConfig
from isitsecure.engine.enums import BackendType, FrameworkType

logger = logging.getLogger(__name__)


class FrameworkDetector:
    """Detects web framework, backend, and auth provider from package.json."""

    def detect_framework(self, package_json: dict) -> FrameworkType:
        """Identify the web framework from package.json dependencies."""
        for key, indicator in FrameworkDetectorConfig.FRAMEWORK_INDICATORS.items():
            if self._has_dependency(
                package_json, indicator["package"], indicator["section"]
            ):
                logger.debug("Detected framework: %s", key)
                return FrameworkType(key)
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

    def detect_auth_provider(self, package_json: dict) -> str:
        """Identify the auth provider from package.json dependencies.

        Returns the auth indicator key (e.g. 'nextauth', 'clerk') or empty
        string when no known provider is found.
        """
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
