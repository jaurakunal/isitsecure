"""Tests for WorkspaceDetector."""

from __future__ import annotations

import json
from pathlib import Path

from isitsecure.engine.code_analysis.framework_detector import (
    FrameworkDetector,
)
from isitsecure.engine.code_analysis.workspace_detector import (
    WorkspaceDetector,
)
from isitsecure.engine.constants import WorkspaceDetectorConfig
from isitsecure.engine.enums import (
    BackendType,
    FrameworkType,
    WorkspaceType,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_detector() -> WorkspaceDetector:
    """Create a WorkspaceDetector with a real FrameworkDetector."""
    return WorkspaceDetector(framework_detector=FrameworkDetector())


def _make_package_json(path: Path, content: dict | None = None) -> None:
    """Write a package.json file at the given path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(content or {}), encoding="utf-8")


def _make_pnpm_workspace(root: Path, patterns: list[str]) -> None:
    """Write a pnpm-workspace.yaml at *root*."""
    lines = ["packages:"]
    for p in patterns:
        lines.append(f"  - '{p}'")
    (root / "pnpm-workspace.yaml").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def _make_workspace_dir(
    root: Path,
    relative: str,
    deps: dict | None = None,
    dev_deps: dict | None = None,
) -> None:
    """Create a workspace directory with a package.json."""
    ws_dir = root / relative
    ws_dir.mkdir(parents=True, exist_ok=True)
    pkg: dict = {}
    if deps:
        pkg["dependencies"] = deps
    if dev_deps:
        pkg["devDependencies"] = dev_deps
    _make_package_json(ws_dir / "package.json", pkg)


def _make_terraform_dir(root: Path, relative: str) -> None:
    """Create a directory containing a .tf file (no package.json)."""
    tf_dir = root / relative
    tf_dir.mkdir(parents=True, exist_ok=True)
    (tf_dir / "main.tf").write_text("# terraform", encoding="utf-8")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestWorkspaceDetectorSingle:
    """Single-repo (no workspaces) returns empty list."""

    def test_empty_directory_returns_empty(self, tmp_path: Path) -> None:
        """An empty directory has no workspaces."""
        detector = _make_detector()
        result = detector.detect(str(tmp_path))
        assert result == []

    def test_single_package_json_returns_empty(self, tmp_path: Path) -> None:
        """A repo with only a root package.json is not a monorepo."""
        _make_package_json(tmp_path / "package.json", {"name": "my-app"})
        detector = _make_detector()
        result = detector.detect(str(tmp_path))
        assert result == []

    def test_single_nested_package_json_returns_empty(
        self, tmp_path: Path
    ) -> None:
        """A repo with only one nested package.json is not a monorepo."""
        _make_workspace_dir(tmp_path, "frontend", deps={"react": "18.0.0"})
        detector = _make_detector()
        result = detector.detect(str(tmp_path))
        assert result == []


class TestNpmWorkspaces:
    """Detects workspaces from package.json ``workspaces`` field."""

    def test_array_format(self, tmp_path: Path) -> None:
        """Should detect workspaces from array-format ``workspaces`` field."""
        _make_package_json(
            tmp_path / "package.json",
            {"workspaces": ["packages/*"]},
        )
        _make_workspace_dir(tmp_path, "packages/ui")
        _make_workspace_dir(tmp_path, "packages/api")

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        assert len(result) == 2
        names = {ws.name for ws in result}
        assert names == {"ui", "api"}

    def test_object_format(self, tmp_path: Path) -> None:
        """Should detect workspaces from object-format ``workspaces`` field."""
        _make_package_json(
            tmp_path / "package.json",
            {"workspaces": {"packages": ["apps/*"]}},
        )
        _make_workspace_dir(tmp_path, "apps/web")
        _make_workspace_dir(tmp_path, "apps/docs")

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        assert len(result) == 2
        paths = {ws.path for ws in result}
        assert paths == {"apps/web", "apps/docs"}

    def test_skips_excluded_directories(self, tmp_path: Path) -> None:
        """Should skip directories listed in SKIP_DIRECTORIES."""
        _make_package_json(
            tmp_path / "package.json",
            {"workspaces": ["packages/*"]},
        )
        _make_workspace_dir(tmp_path, "packages/ui")
        # Create a workspace inside a skip directory
        skip_dir = WorkspaceDetectorConfig.SKIP_DIRECTORIES[0]
        _make_workspace_dir(tmp_path, f"packages/{skip_dir}")

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        result_names = {ws.name for ws in result}
        assert skip_dir not in result_names
        assert "ui" in result_names


class TestPnpmWorkspace:
    """Detects workspaces from pnpm-workspace.yaml."""

    def test_pnpm_workspace_yaml(self, tmp_path: Path) -> None:
        """Should detect workspaces from pnpm-workspace.yaml."""
        _make_pnpm_workspace(tmp_path, ["packages/*", "apps/*"])
        _make_workspace_dir(tmp_path, "packages/shared")
        _make_workspace_dir(tmp_path, "apps/web")

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        assert len(result) == 2
        names = {ws.name for ws in result}
        assert names == {"shared", "web"}

    def test_pnpm_takes_precedence_over_heuristic(
        self, tmp_path: Path
    ) -> None:
        """pnpm-workspace.yaml should be used instead of heuristic."""
        _make_pnpm_workspace(tmp_path, ["apps/*"])
        _make_workspace_dir(tmp_path, "apps/web")
        _make_workspace_dir(tmp_path, "apps/api")
        # This dir exists but is NOT in pnpm-workspace.yaml
        _make_workspace_dir(tmp_path, "extra/tool")

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        paths = {ws.path for ws in result}
        assert "extra/tool" not in paths
        assert "apps/web" in paths
        assert "apps/api" in paths


class TestHeuristicDetection:
    """Finds directories with package.json at depth 1-2."""

    def test_detects_multiple_nested_package_json(
        self, tmp_path: Path
    ) -> None:
        """Should find 2+ dirs with package.json as heuristic monorepo."""
        _make_workspace_dir(tmp_path, "frontend", deps={"react": "18.0.0"})
        _make_workspace_dir(
            tmp_path, "backend", deps={"express": "4.18.0"}
        )

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        assert len(result) >= 2
        names = {ws.name for ws in result}
        assert "frontend" in names
        assert "backend" in names

    def test_respects_max_heuristic_depth(self, tmp_path: Path) -> None:
        """Should not detect workspaces beyond MAX_HEURISTIC_DEPTH."""
        max_depth = WorkspaceDetectorConfig.MAX_HEURISTIC_DEPTH
        # Create one workspace at valid depth
        _make_workspace_dir(tmp_path, "packages/valid")
        _make_workspace_dir(tmp_path, "apps/also-valid")
        # Create a workspace beyond max depth
        deep_path = "/".join(["deep"] * (max_depth + 1))
        _make_workspace_dir(tmp_path, deep_path)

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        found_paths = {ws.path for ws in result}
        assert deep_path not in found_paths


class TestWorkspaceClassification:
    """Classifies FRONTEND/BACKEND/LAMBDA/INFRASTRUCTURE/SHARED/UNKNOWN."""

    def test_frontend_by_dependency(self, tmp_path: Path) -> None:
        """Should classify as FRONTEND when a frontend indicator is present."""
        frontend_indicator = WorkspaceDetectorConfig.FRONTEND_INDICATORS[0]
        _make_pnpm_workspace(tmp_path, ["packages/*"])
        _make_workspace_dir(
            tmp_path,
            "packages/web",
            deps={frontend_indicator: "1.0.0"},
        )
        _make_workspace_dir(tmp_path, "packages/other", deps={"lodash": "4.0.0"})

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        web_ws = next(ws for ws in result if ws.name == "web")
        assert web_ws.workspace_type == WorkspaceType.FRONTEND

    def test_backend_by_dependency(self, tmp_path: Path) -> None:
        """Should classify as BACKEND when a backend indicator is present."""
        backend_indicator = WorkspaceDetectorConfig.BACKEND_INDICATORS[0]
        _make_pnpm_workspace(tmp_path, ["packages/*"])
        _make_workspace_dir(
            tmp_path,
            "packages/api",
            deps={backend_indicator: "1.0.0"},
        )
        _make_workspace_dir(tmp_path, "packages/other", deps={"lodash": "4.0.0"})

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        api_ws = next(ws for ws in result if ws.name == "api")
        assert api_ws.workspace_type == WorkspaceType.BACKEND

    def test_lambda_by_dependency(self, tmp_path: Path) -> None:
        """Should classify as LAMBDA when a lambda indicator is present."""
        lambda_indicator = WorkspaceDetectorConfig.LAMBDA_INDICATORS[0]
        _make_pnpm_workspace(tmp_path, ["packages/*"])
        _make_workspace_dir(
            tmp_path,
            "packages/fn",
            deps={lambda_indicator: "1.0.0"},
        )
        _make_workspace_dir(tmp_path, "packages/other", deps={"lodash": "4.0.0"})

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        fn_ws = next(ws for ws in result if ws.name == "fn")
        assert fn_ws.workspace_type == WorkspaceType.LAMBDA

    def test_classify_by_dir_name_fallback(self, tmp_path: Path) -> None:
        """Should use directory name when dependencies are ambiguous."""
        _make_pnpm_workspace(tmp_path, ["packages/*"])
        # "shared" dir with no indicator deps
        _make_workspace_dir(
            tmp_path, "packages/shared", deps={"lodash": "4.0.0"}
        )
        _make_workspace_dir(
            tmp_path, "packages/other", deps={"lodash": "4.0.0"}
        )

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        shared_ws = next(ws for ws in result if ws.name == "shared")
        assert shared_ws.workspace_type == WorkspaceType.SHARED


class TestFrameworkEnrichment:
    """Enriches workspaces with framework/backend/auth via FrameworkDetector."""

    def test_enriches_framework(self, tmp_path: Path) -> None:
        """Should populate framework field from package.json dependencies."""
        _make_pnpm_workspace(tmp_path, ["packages/*"])
        _make_workspace_dir(
            tmp_path,
            "packages/web",
            deps={"next": "14.0.0", "react": "18.0.0"},
        )
        _make_workspace_dir(tmp_path, "packages/lib", deps={"lodash": "4.0.0"})

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        web_ws = next(ws for ws in result if ws.name == "web")
        assert web_ws.framework == FrameworkType.NEXTJS

    def test_enriches_backend(self, tmp_path: Path) -> None:
        """Should populate backend field from package.json dependencies."""
        _make_pnpm_workspace(tmp_path, ["packages/*"])
        _make_workspace_dir(
            tmp_path,
            "packages/api",
            deps={"@supabase/supabase-js": "2.0.0"},
        )
        _make_workspace_dir(tmp_path, "packages/lib", deps={"lodash": "4.0.0"})

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        api_ws = next(ws for ws in result if ws.name == "api")
        assert api_ws.backend == BackendType.SUPABASE

    def test_enriches_auth_provider(self, tmp_path: Path) -> None:
        """Should populate auth_provider field from package.json."""
        _make_pnpm_workspace(tmp_path, ["packages/*"])
        _make_workspace_dir(
            tmp_path,
            "packages/web",
            deps={"next-auth": "4.0.0"},
        )
        _make_workspace_dir(tmp_path, "packages/lib", deps={"lodash": "4.0.0"})

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        web_ws = next(ws for ws in result if ws.name == "web")
        assert web_ws.auth_provider == "nextauth"

    def test_unknown_when_no_framework_detected(
        self, tmp_path: Path
    ) -> None:
        """Should default to UNKNOWN framework when nothing matches."""
        _make_pnpm_workspace(tmp_path, ["packages/*"])
        _make_workspace_dir(
            tmp_path, "packages/lib", deps={"lodash": "4.0.0"}
        )
        _make_workspace_dir(
            tmp_path, "packages/utils", deps={"chalk": "5.0.0"}
        )

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        lib_ws = next(ws for ws in result if ws.name == "lib")
        assert lib_ws.framework == FrameworkType.UNKNOWN
        assert lib_ws.backend == BackendType.UNKNOWN


class TestIaCDirectoryDetection:
    """Detects terraform/infra dirs without package.json."""

    def test_terraform_dir_detected(self, tmp_path: Path) -> None:
        """Should detect a directory containing .tf files as INFRASTRUCTURE."""
        _make_workspace_dir(tmp_path, "frontend", deps={"react": "18.0.0"})
        _make_terraform_dir(tmp_path, "terraform")

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        tf_ws = next(
            (ws for ws in result if ws.name == "terraform"), None
        )
        assert tf_ws is not None
        assert tf_ws.workspace_type == WorkspaceType.INFRASTRUCTURE

    def test_infra_dir_by_name(self, tmp_path: Path) -> None:
        """Should detect directory named after INFRASTRUCTURE_DIR_INDICATORS."""
        infra_name = WorkspaceDetectorConfig.INFRASTRUCTURE_DIR_INDICATORS[0]
        infra_dir = tmp_path / infra_name
        infra_dir.mkdir()
        # Put a dummy file so directory is not empty
        (infra_dir / "readme.txt").write_text("infra", encoding="utf-8")

        # Need a second workspace so heuristic triggers (>=2 candidates)
        _make_workspace_dir(tmp_path, "backend", deps={"express": "4.0.0"})

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        infra_ws = next(
            (ws for ws in result if ws.name == infra_name), None
        )
        assert infra_ws is not None
        assert infra_ws.workspace_type == WorkspaceType.INFRASTRUCTURE

    def test_iac_not_enriched_with_package_json(
        self, tmp_path: Path
    ) -> None:
        """IaC workspaces should skip framework enrichment."""
        _make_workspace_dir(tmp_path, "frontend", deps={"react": "18.0.0"})
        _make_terraform_dir(tmp_path, "infra")

        detector = _make_detector()
        result = detector.detect(str(tmp_path))

        infra_ws = next(
            (ws for ws in result if ws.name == "infra"), None
        )
        assert infra_ws is not None
        assert infra_ws.framework == FrameworkType.UNKNOWN
        assert infra_ws.backend == BackendType.UNKNOWN
