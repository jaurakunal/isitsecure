"""Java/Kotlin LSP client using jdtls (Eclipse JDT Language Server).

SRP: Language-specific details for Java LSP — command discovery,
     workspace setup, language IDs for .java and .kt files.

DIP: Implements LSPClientProtocol via BaseLSPClient.

Supports:
1. jdtls (Eclipse JDT Language Server) — standard Java LSP
2. kotlin-language-server — for Kotlin-specific features
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
from pathlib import Path

from isitsecure.engine.code_analysis.lsp.base_client import BaseLSPClient

logger = logging.getLogger(__name__)


class JavaLSPClient(BaseLSPClient):
    """LSP client for Java/Kotlin projects using jdtls.

    Traces auth flows through:
    - Spring: @PreAuthorize → SecurityConfig → role hierarchy
    - Spring Security: SecurityFilterChain → authentication filters
    - Custom: @Secured → role check implementation
    """

    # JDTLS requires a workspace directory
    _workspace_dir: str | None = None

    SERVER_COMMANDS = (
        ("jdtls",),
        ("jdt-language-server",),
    )

    # Kotlin language server — preferred for Kotlin-dominant projects, fallback
    # for Java projects when jdtls is absent.
    KOTLIN_SERVER_COMMANDS = (
        ("kotlin-language-server",),
    )

    # Bounds for the cheap Kotlin-vs-Java dominance walk.
    _SCAN_SKIP_DIRS = frozenset({
        "node_modules", "build", "target", "out", "bin", "dist",
        ".gradle", ".idea", "vendor", "__pycache__",
    })
    _SCAN_MAX_FILES = 5000

    @staticmethod
    def is_runtime_available() -> bool:
        """Check if Java runtime is available."""
        return shutil.which("java") is not None

    @staticmethod
    def is_server_available() -> bool:
        """Check if jdtls or kotlin-language-server is installed."""
        return (
            shutil.which("jdtls") is not None
            or shutil.which("jdt-language-server") is not None
            or shutil.which("kotlin-language-server") is not None
        )

    async def _find_server_command(self) -> tuple[str, ...] | None:
        """Find a working LSP server command for this project.

        jdtls resolves Kotlin poorly, so a Kotlin-dominant project prefers
        ``kotlin-language-server`` when it is installed and only falls back to
        jdtls. A Java-dominant (or mixed) project keeps the reverse order —
        jdtls is the stronger Java server. This is why installing the Kotlin
        server actually changes anything: without the reorder, jdtls (if present)
        would always win and the Kotlin server would sit idle.
        """
        if self._project_is_kotlin_dominant():
            kotlin = self._first_available(self.KOTLIN_SERVER_COMMANDS)
            if kotlin:
                logger.info("Kotlin-dominant project — using Kotlin LSP: %s",
                            " ".join(kotlin))
                return kotlin

        # jdtls (needs a workspace dir), then kotlin-language-server as fallback.
        for cmd in self.SERVER_COMMANDS:
            if shutil.which(cmd[0]):
                self._workspace_dir = tempfile.mkdtemp(prefix="isitsecure_jdtls_")
                full_cmd = cmd + ("-data", self._workspace_dir)
                logger.info("Found Java LSP: %s", " ".join(full_cmd))
                return full_cmd

        kotlin = self._first_available(self.KOTLIN_SERVER_COMMANDS)
        if kotlin:
            logger.info("Found Kotlin LSP: %s", " ".join(kotlin))
            return kotlin

        logger.warning(
            "No Java/Kotlin LSP server found. Install jdtls "
            "(https://github.com/eclipse-jdtls/eclipse.jdt.ls#installation) "
            "or kotlin-language-server."
        )
        return None

    @staticmethod
    def _first_available(
        commands: tuple[tuple[str, ...], ...],
    ) -> tuple[str, ...] | None:
        """Return the first command whose binary is on PATH, else None."""
        for cmd in commands:
            if shutil.which(cmd[0]):
                return cmd
        return None

    def _project_is_kotlin_dominant(self) -> bool:
        """True when the project has more Kotlin source than Java source.

        A bounded walk (skips vendor/build dirs, caps files scanned) so this
        stays cheap on large repos; ties and empty projects favour Java, which
        keeps jdtls as the default.
        """
        if not self._project_path:
            return False
        kotlin = java = 0
        seen = 0
        for _root, dirnames, filenames in os.walk(self._project_path):
            dirnames[:] = [
                d for d in dirnames
                if d not in self._SCAN_SKIP_DIRS and not d.startswith(".")
            ]
            for name in filenames:
                if name.endswith((".kt", ".kts")):
                    kotlin += 1
                elif name.endswith(".java"):
                    java += 1
                seen += 1
            if seen >= self._SCAN_MAX_FILES:
                break
        return kotlin > java

    def _get_language_id(self, file_path: str) -> str:
        if file_path.endswith(".kt") or file_path.endswith(".kts"):
            return "kotlin"
        return "java"

    def _pre_initialize(self, project_path: str) -> None:
        """Check for build tool configuration."""
        has_maven = (Path(project_path) / "pom.xml").exists()
        has_gradle = (
            (Path(project_path) / "build.gradle").exists()
            or (Path(project_path) / "build.gradle.kts").exists()
        )
        if has_maven:
            logger.info("Detected Maven project")
        elif has_gradle:
            logger.info("Detected Gradle project")
        else:
            logger.info("No Maven/Gradle build file found — LSP may have limited functionality")

    async def shutdown(self) -> None:
        """Shutdown and clean up workspace directory."""
        await super().shutdown()
        if self._workspace_dir and os.path.isdir(self._workspace_dir):
            try:
                shutil.rmtree(self._workspace_dir, ignore_errors=True)
            except Exception:
                pass
            self._workspace_dir = None
