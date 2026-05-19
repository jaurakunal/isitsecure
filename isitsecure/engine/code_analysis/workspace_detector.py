"""Detects monorepo workspace structure from a cloned repository.

SRP: This class is responsible ONLY for detecting workspace boundaries
     and classifying their type.  Framework/backend detection within each
     workspace is delegated to FrameworkDetector (which is injected via
     the constructor — DIP).

OCP: New workspace detection strategies (e.g. Bazel, Rush) can be added
     by extending the ``_DETECTION_STRATEGIES`` list without modifying
     existing detection logic.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from isitsecure.engine.code_analysis.protocols import WorkspaceInfo
from isitsecure.engine.constants import WorkspaceDetectorConfig
from isitsecure.engine.enums import (
    BackendType,
    FrameworkType,
    WorkspaceType,
)

if TYPE_CHECKING:
    from isitsecure.engine.code_analysis.framework_detector import (
        FrameworkDetector,
    )

logger = logging.getLogger(__name__)


class WorkspaceDetector:
    """Detects workspaces inside a monorepo and classifies each one.

    Detection is tried in priority order — the first strategy that finds
    workspaces wins.  If no explicit workspace definition is found, a
    heuristic scan for directories containing ``package.json`` is used.

    Dependencies:
        framework_detector (FrameworkDetector): Injected via constructor
            (DIP).  Used to detect framework/backend/auth per workspace.
    """

    def __init__(self, framework_detector: FrameworkDetector) -> None:
        self._framework_detector = framework_detector

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, clone_path: str) -> list[WorkspaceInfo]:
        """Detect workspaces in the cloned repo.

        Returns an empty list when the repo is not a monorepo.

        Args:
            clone_path: Absolute path to the cloned repo root.

        Returns:
            List of ``WorkspaceInfo`` for each discovered workspace.
        """
        root = Path(clone_path)

        # Try explicit workspace definitions first (deterministic)
        workspaces = (
            self._detect_from_npm_workspaces(root)
            or self._detect_from_pnpm_workspace(root)
            or self._detect_from_turbo_json(root)
            or self._detect_from_nx_json(root)
        )

        # Fallback: heuristic detection
        if not workspaces:
            workspaces = self._detect_heuristic(root)

        # Cap at MAX_WORKSPACES
        workspaces = workspaces[: WorkspaceDetectorConfig.MAX_WORKSPACES]

        # Enrich each workspace with framework/backend/auth detection
        for ws in workspaces:
            self._enrich_workspace(ws, root)

        if workspaces:
            logger.info(
                WorkspaceDetectorConfig.LOG_MONOREPO_DETECTED.format(
                    method=self._detection_method,
                    count=len(workspaces),
                )
            )
            for ws in workspaces:
                logger.info(
                    WorkspaceDetectorConfig.LOG_WORKSPACE_FOUND.format(
                        name=ws.name,
                        path=ws.path,
                        workspace_type=ws.workspace_type.value,
                        framework=ws.framework.value,
                        backend=ws.backend.value,
                    )
                )
        else:
            logger.info(WorkspaceDetectorConfig.LOG_NOT_MONOREPO)

        return workspaces

    # ------------------------------------------------------------------
    # Explicit workspace detection strategies
    # ------------------------------------------------------------------

    _detection_method: str = "heuristic"

    def _detect_from_npm_workspaces(
        self, root: Path
    ) -> list[WorkspaceInfo]:
        """Detect from ``workspaces`` field in root ``package.json``.

        Supports both array and object formats:
            - ``"workspaces": ["packages/*", "apps/*"]``
            - ``"workspaces": {"packages": ["packages/*"]}``
        """
        pkg_path = root / "package.json"
        pkg = self._read_json(pkg_path)
        if not pkg:
            return []

        workspaces_field = pkg.get("workspaces")
        if not workspaces_field:
            return []

        # Normalise to list of glob patterns
        patterns: list[str] = []
        if isinstance(workspaces_field, list):
            patterns = workspaces_field
        elif isinstance(workspaces_field, dict):
            for globs in workspaces_field.values():
                if isinstance(globs, list):
                    patterns.extend(globs)

        if not patterns:
            return []

        self._detection_method = "npm workspaces"
        return self._resolve_glob_patterns(root, patterns)

    def _detect_from_pnpm_workspace(
        self, root: Path
    ) -> list[WorkspaceInfo]:
        """Detect from ``pnpm-workspace.yaml``."""
        ws_path = root / "pnpm-workspace.yaml"
        if not ws_path.is_file():
            return []

        try:
            content = ws_path.read_text(encoding="utf-8")
        except OSError:
            return []

        # Simple YAML parsing for packages list (avoids PyYAML dep)
        patterns = self._parse_pnpm_workspace_yaml(content)
        if not patterns:
            return []

        self._detection_method = "pnpm-workspace.yaml"
        return self._resolve_glob_patterns(root, patterns)

    def _detect_from_turbo_json(self, root: Path) -> list[WorkspaceInfo]:
        """Detect from ``turbo.json`` — presence implies npm/pnpm workspaces.

        Turborepo relies on the package manager's workspace config, so
        we fall through to ``_detect_from_npm_workspaces`` or heuristic.
        However, the existence of ``turbo.json`` confirms monorepo intent.
        """
        turbo_path = root / "turbo.json"
        if not turbo_path.is_file():
            return []

        # turbo.json doesn't define workspaces itself — it uses npm/pnpm
        # But its presence confirms monorepo intent.  Try npm first.
        workspaces = self._detect_from_npm_workspaces(root)
        if workspaces:
            self._detection_method = "turbo.json + npm workspaces"
            return workspaces

        # turbo.json exists but no npm workspaces — use heuristic
        self._detection_method = "turbo.json + heuristic"
        return self._detect_heuristic(root)

    def _detect_from_nx_json(self, root: Path) -> list[WorkspaceInfo]:
        """Detect from ``nx.json``."""
        nx_path = root / "nx.json"
        if not nx_path.is_file():
            return []

        # Nx can define projects in nx.json or via project.json files
        workspaces = self._find_nx_projects(root)
        if workspaces:
            self._detection_method = "nx.json"
        return workspaces

    # ------------------------------------------------------------------
    # Heuristic detection
    # ------------------------------------------------------------------

    def _detect_heuristic(self, root: Path) -> list[WorkspaceInfo]:
        """Find directories containing ``package.json`` within max depth.

        This is the fallback when no explicit workspace config exists.
        A repo is considered a monorepo if it has 2+ directories with
        ``package.json`` within ``MAX_HEURISTIC_DEPTH`` levels.
        """
        candidates: list[WorkspaceInfo] = []

        for depth in range(1, WorkspaceDetectorConfig.MAX_HEURISTIC_DEPTH + 1):
            pattern = "/".join(["*"] * depth) + "/package.json"
            for pkg_path in root.glob(pattern):
                relative_dir = pkg_path.parent.relative_to(root)
                dir_name = str(relative_dir)

                # Skip excluded directories
                if any(
                    part in WorkspaceDetectorConfig.SKIP_DIRECTORIES
                    for part in relative_dir.parts
                ):
                    continue

                candidates.append(
                    WorkspaceInfo(
                        name=relative_dir.parts[-1],
                        path=dir_name,
                    )
                )

        # Also detect IaC directories (no package.json but contain .tf files)
        for depth in range(1, WorkspaceDetectorConfig.MAX_HEURISTIC_DEPTH + 1):
            pattern = "/".join(["*"] * depth)
            for dir_path in root.glob(pattern):
                if not dir_path.is_dir():
                    continue

                relative_dir = dir_path.relative_to(root)
                dir_name = str(relative_dir)

                # Skip if already found via package.json
                if any(c.path == dir_name for c in candidates):
                    continue

                # Skip excluded directories
                if any(
                    part in WorkspaceDetectorConfig.SKIP_DIRECTORIES
                    for part in relative_dir.parts
                ):
                    continue

                # Check if it's an IaC directory
                if self._is_iac_directory(dir_path):
                    candidates.append(
                        WorkspaceInfo(
                            name=relative_dir.parts[-1],
                            path=dir_name,
                            workspace_type=WorkspaceType.INFRASTRUCTURE,
                        )
                    )

        # Only treat as monorepo if 2+ workspaces found
        if len(candidates) < 2:
            return []

        self._detection_method = "heuristic"
        return candidates

    # ------------------------------------------------------------------
    # Workspace enrichment (delegates to FrameworkDetector — DIP)
    # ------------------------------------------------------------------

    def _enrich_workspace(
        self, workspace: WorkspaceInfo, root: Path
    ) -> None:
        """Populate framework, backend, auth, and type for a workspace.

        Reads the workspace's ``package.json`` and delegates detection to
        ``FrameworkDetector`` (DIP — depends on abstraction, not concretion).
        """
        if workspace.workspace_type == WorkspaceType.INFRASTRUCTURE:
            # Already classified — no package.json to read
            return

        pkg_path = root / workspace.path / "package.json"
        pkg = self._read_json(pkg_path)
        workspace.package_json = pkg

        if not pkg:
            # No package.json — classify by directory name
            workspace.workspace_type = self._classify_by_dir_name(
                workspace.name, workspace.path
            )
            return

        workspace.framework = self._framework_detector.detect_framework(pkg)
        workspace.backend = self._framework_detector.detect_backend(pkg)
        workspace.auth_provider = self._framework_detector.detect_auth_provider(
            pkg
        )
        workspace.workspace_type = self._classify_workspace(workspace, pkg)

    def _classify_workspace(
        self, workspace: WorkspaceInfo, package_json: dict
    ) -> WorkspaceType:
        """Classify a workspace's type from its dependencies.

        Priority: explicit indicators > framework-based > directory name.
        """
        all_deps = {
            **package_json.get("dependencies", {}),
            **package_json.get("devDependencies", {}),
        }

        # Check for frontend indicators
        if any(
            dep in all_deps
            for dep in WorkspaceDetectorConfig.FRONTEND_INDICATORS
        ):
            return WorkspaceType.FRONTEND

        # Check for backend indicators
        if any(
            dep in all_deps
            for dep in WorkspaceDetectorConfig.BACKEND_INDICATORS
        ):
            return WorkspaceType.BACKEND

        # Check for lambda/serverless indicators
        if any(
            dep in all_deps
            for dep in WorkspaceDetectorConfig.LAMBDA_INDICATORS
        ):
            return WorkspaceType.LAMBDA

        # Fallback to directory name heuristic
        return self._classify_by_dir_name(workspace.name, workspace.path)

    @staticmethod
    def _classify_by_dir_name(name: str, path: str = "") -> WorkspaceType:
        """Classify workspace by its directory name as a fallback.

        Also checks parent directory names for nested workspaces
        (e.g. ``lambda/scale-up-ecs`` → LAMBDA).
        """
        # Check both the workspace name and all path parts
        parts_to_check = [name.lower()]
        if path:
            parts_to_check.extend(p.lower() for p in Path(path).parts)

        for part in parts_to_check:
            if part in ("frontend", "web", "client", "ui", "app"):
                return WorkspaceType.FRONTEND
            if part in ("backend", "api", "server", "service"):
                return WorkspaceType.BACKEND
            if part in ("lambda", "functions", "lambdas"):
                return WorkspaceType.LAMBDA
            if part in WorkspaceDetectorConfig.INFRASTRUCTURE_DIR_INDICATORS:
                return WorkspaceType.INFRASTRUCTURE
            if part in ("shared", "common", "lib", "packages", "utils"):
                return WorkspaceType.SHARED

        return WorkspaceType.UNKNOWN

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_glob_patterns(
        self, root: Path, patterns: list[str]
    ) -> list[WorkspaceInfo]:
        """Resolve workspace glob patterns to actual directories.

        Handles patterns like ``"packages/*"`` and ``"apps/*"``.
        """
        workspaces: list[WorkspaceInfo] = []
        seen_paths: set[str] = set()

        for pattern in patterns:
            # Resolve glob (e.g., "packages/*" -> packages/ui, packages/api)
            for matched in sorted(root.glob(pattern)):
                if not matched.is_dir():
                    continue

                relative = str(matched.relative_to(root))
                if relative in seen_paths:
                    continue

                # Skip excluded directories
                if any(
                    part in WorkspaceDetectorConfig.SKIP_DIRECTORIES
                    for part in matched.relative_to(root).parts
                ):
                    continue

                seen_paths.add(relative)
                workspaces.append(
                    WorkspaceInfo(
                        name=matched.name,
                        path=relative,
                    )
                )

        return workspaces

    def _find_nx_projects(self, root: Path) -> list[WorkspaceInfo]:
        """Find Nx project directories via ``project.json`` files."""
        workspaces: list[WorkspaceInfo] = []
        seen_paths: set[str] = set()

        for depth in range(
            1, WorkspaceDetectorConfig.MAX_HEURISTIC_DEPTH + 1
        ):
            pattern = "/".join(["*"] * depth) + "/project.json"
            for proj_path in root.glob(pattern):
                relative_dir = str(proj_path.parent.relative_to(root))
                if relative_dir in seen_paths:
                    continue
                if any(
                    part in WorkspaceDetectorConfig.SKIP_DIRECTORIES
                    for part in proj_path.parent.relative_to(root).parts
                ):
                    continue

                seen_paths.add(relative_dir)
                workspaces.append(
                    WorkspaceInfo(
                        name=proj_path.parent.name,
                        path=relative_dir,
                    )
                )

        return workspaces

    @staticmethod
    def _is_iac_directory(dir_path: Path) -> bool:
        """Check if a directory contains Infrastructure-as-Code files."""
        # Check directory name
        if dir_path.name.lower() in (
            WorkspaceDetectorConfig.INFRASTRUCTURE_DIR_INDICATORS
        ):
            return True

        # Check for IaC file extensions
        for ext in WorkspaceDetectorConfig.IAC_FILE_EXTENSIONS:
            if any(dir_path.glob(f"*{ext}")):
                return True

        return False

    @staticmethod
    def _parse_pnpm_workspace_yaml(content: str) -> list[str]:
        """Parse pnpm-workspace.yaml without a YAML library.

        Handles the common format::

            packages:
              - 'packages/*'
              - 'apps/*'
        """
        patterns: list[str] = []
        in_packages = False

        for line in content.splitlines():
            stripped = line.strip()

            if stripped == "packages:":
                in_packages = True
                continue

            if in_packages:
                # End of packages section
                if stripped and not stripped.startswith("-"):
                    break

                if stripped.startswith("- "):
                    value = stripped[2:].strip().strip("'\"")
                    if value:
                        patterns.append(value)

        return patterns

    @staticmethod
    def _read_json(path: Path) -> dict:
        """Read and parse a JSON file, returning empty dict on failure."""
        if not path.is_file():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                WorkspaceDetectorConfig.ERROR_PACKAGE_JSON_PARSE_FAILED.format(
                    path=path, error=exc
                )
            )
            return {}
