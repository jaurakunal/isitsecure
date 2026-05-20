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

    # Kotlin language server as fallback for .kt files
    KOTLIN_SERVER_COMMANDS = (
        ("kotlin-language-server",),
    )

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
        """Find a working Java LSP server command."""
        # Try jdtls first
        for cmd in self.SERVER_COMMANDS:
            if shutil.which(cmd[0]):
                # jdtls needs a workspace directory
                self._workspace_dir = tempfile.mkdtemp(prefix="isitsecure_jdtls_")
                full_cmd = cmd + (
                    "-data", self._workspace_dir,
                )
                logger.info("Found Java LSP: %s", " ".join(full_cmd))
                return full_cmd

        # Try kotlin-language-server as fallback
        for cmd in self.KOTLIN_SERVER_COMMANDS:
            if shutil.which(cmd[0]):
                logger.info("Found Kotlin LSP: %s", " ".join(cmd))
                return cmd

        logger.warning(
            "No Java LSP server found. Install jdtls: "
            "https://github.com/eclipse-jdtls/eclipse.jdt.ls#installation"
        )
        return None

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
