"""Clones a GitHub repository and builds a RepoSnapshot for analysis.

SRP: This service is responsible ONLY for cloning a repo and building
     the indexed ``RepoSnapshot``.  Framework detection is delegated to
     ``FrameworkDetector``, workspace detection to ``WorkspaceDetector``,
     and route mapping to implementations of ``RouteMapperProtocol``.

DIP: All collaborators are injected via the constructor as abstractions.
     The service never instantiates concrete dependencies internally.

OCP: New route mappers are added to the ``route_mappers`` list without
     modifying this class.  Monorepo support is additive — single-repo
     scanning behavior is unchanged when no workspaces are detected.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from isitsecure.engine.code_analysis.protocols import (
    RepoSnapshot,
    RouteMapperProtocol,
)
from isitsecure.engine.constants import RepoIngestionConfig

if TYPE_CHECKING:
    from isitsecure.engine.code_analysis.framework_detector import (
        FrameworkDetector,
    )
    from isitsecure.engine.code_analysis.workspace_detector import (
        WorkspaceDetector,
    )

logger = logging.getLogger(__name__)

# Heavy or generated directories that should never be scanned when copying a
# local tree (git clone excludes these naturally via .gitignore / the index).
_LOCAL_COPY_IGNORE = shutil.ignore_patterns(
    "node_modules", ".next", "dist", "build", "out", "target",
    ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".DS_Store", "*.pyc",
)


class RepoIngestionService:
    """Clones a GitHub repo and builds a RepoSnapshot.

    Args:
        framework_detector: Detects framework/backend/auth from package.json.
        route_mappers: List of route mappers (OCP — extend by adding
            new mappers to this list).
        workspace_detector: Optional monorepo workspace detector.  When
            provided, the service will detect workspaces and run
            framework detection + route mapping per workspace.
    """

    def __init__(
        self,
        framework_detector: FrameworkDetector,
        route_mappers: list[RouteMapperProtocol] | None = None,
        workspace_detector: WorkspaceDetector | None = None,
    ) -> None:
        self._framework_detector = framework_detector
        self._route_mappers: list[RouteMapperProtocol] = route_mappers or []
        self._workspace_detector = workspace_detector

    async def ingest(
        self,
        repo_url: str,
        branch: str = "main",
        github_token: str | None = None,
        full_history: bool = False,
    ) -> RepoSnapshot:
        """Clone a repo and return an indexed RepoSnapshot.

        Steps:
            1. Create temp directory and git clone
            2. Detect workspaces (if workspace_detector provided)
            3. Read package.json (root or primary workspace)
            4. Detect framework + backend + auth
            5. Map API routes (per workspace for monorepos)
            6. Index key files (middleware, config, migrations, env)
            7. Return RepoSnapshot
        """
        clone_dir = tempfile.mkdtemp(prefix="deep_scan_")
        try:
            await self._clone_repo(
                repo_url, branch, clone_dir, github_token, full_history
            )

            # Capture the exact commit hash for the report
            commit_hash = await self._get_commit_hash(clone_dir)

            # Detect workspaces (monorepo support)
            workspaces = []
            is_monorepo = False
            if self._workspace_detector:
                workspaces = self._workspace_detector.detect(clone_dir)
                is_monorepo = len(workspaces) >= 2

            # Read root package.json
            root_package_json = self._read_package_json(clone_dir)

            # Determine primary package.json for backward compat:
            # For monorepos, use the first workspace that has a detectable
            # framework (frontend-first priority), falling back to root.
            primary_pkg = self._select_primary_package_json(
                root_package_json, workspaces
            )

            framework = self._framework_detector.detect_framework(primary_pkg)
            backend = self._framework_detector.detect_backend(primary_pkg)
            auth_provider = self._framework_detector.detect_auth_provider(
                primary_pkg
            )

            # Map routes — per workspace for monorepos, root for single repos
            route_map = self._map_all_routes(clone_dir, workspaces)

            file_index, total_files, total_size = self._index_key_files(
                clone_dir
            )
            migration_files = self._find_all_migration_files(
                clone_dir, workspaces
            )
            env_files = self._find_env_files(clone_dir)

            return RepoSnapshot(
                repo_url=repo_url,
                branch=branch,
                commit_hash=commit_hash,
                clone_path=clone_dir,
                framework=framework,
                backend=backend,
                auth_provider=auth_provider,
                package_json=primary_pkg,
                file_index=file_index,
                route_map=route_map,
                migration_files=migration_files,
                env_files=env_files,
                total_files=total_files,
                total_size_bytes=total_size,
                is_monorepo=is_monorepo,
                workspaces=workspaces,
            )
        except Exception:
            # Clean up on failure
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise

    # ------------------------------------------------------------------
    # Route mapping (OCP — new mappers added to list, not modifying code)
    # ------------------------------------------------------------------

    def _map_all_routes(
        self,
        clone_path: str,
        workspaces: list,
    ) -> list:
        """Run all route mappers across root and workspace directories.

        For monorepos: each mapper runs against each workspace directory.
        For single repos: each mapper runs against the repo root.
        This ensures backward compatibility — single repos behave exactly
        as before.

        Routes are deduplicated by (file_path, route_pattern, methods) to
        prevent duplicates when workspace dirs overlap with the root scan.
        """
        from isitsecure.engine.code_analysis.protocols import (
            RouteEntry,
        )

        all_routes: list[RouteEntry] = []

        if not self._route_mappers:
            return all_routes

        # Determine which directories to scan
        scan_dirs: list[str] = []
        if workspaces:
            for ws in workspaces:
                ws_dir = str(Path(clone_path) / ws.path)
                scan_dirs.append(ws_dir)
        # Always include root (handles single repos and monorepos with
        # root-level routes like supabase/functions)
        scan_dirs.append(clone_path)

        # Deduplicate scan directories
        seen_dirs: set[str] = set()
        # Deduplicate routes by (file_path, route_pattern, methods_key)
        seen_routes: set[tuple[str, str, str]] = set()

        for scan_dir in scan_dirs:
            if scan_dir in seen_dirs:
                continue
            seen_dirs.add(scan_dir)

            for mapper in self._route_mappers:
                routes = mapper.map_routes(scan_dir)
                for route in routes:
                    route_key = (
                        route.file_path,
                        route.route_pattern,
                        ",".join(sorted(route.http_methods)),
                    )
                    if route_key not in seen_routes:
                        seen_routes.add(route_key)
                        all_routes.append(route)

        return all_routes

    # ------------------------------------------------------------------
    # Primary package.json selection (backward compat for monorepos)
    # ------------------------------------------------------------------

    @staticmethod
    def _select_primary_package_json(
        root_pkg: dict,
        workspaces: list,
    ) -> dict:
        """Select the primary package.json for top-level detection.

        Priority:
        1. First FRONTEND workspace with a detectable framework
        2. First BACKEND workspace
        3. Root package.json (fallback — always works for single repos)
        """
        if not workspaces:
            return root_pkg

        from isitsecure.engine.enums import WorkspaceType

        # Try frontend first (most likely to have the main framework)
        for ws in workspaces:
            if (
                ws.workspace_type == WorkspaceType.FRONTEND
                and ws.package_json
            ):
                return ws.package_json

        # Then backend
        for ws in workspaces:
            if (
                ws.workspace_type == WorkspaceType.BACKEND
                and ws.package_json
            ):
                return ws.package_json

        # Fallback to root
        return root_pkg

    # ------------------------------------------------------------------
    # Migration file discovery (extended for monorepos)
    # ------------------------------------------------------------------

    def _find_all_migration_files(
        self,
        clone_path: str,
        workspaces: list,
    ) -> list[str]:
        """Find migration files across root and workspace directories.

        Searches standard Supabase migration paths as well as common
        ORM migration directories (Drizzle, Prisma, etc.).
        """
        from isitsecure.engine.constants import (
            WorkspaceDetectorConfig,
        )

        migration_files: list[str] = []
        root = Path(clone_path)

        # Search paths: root + each workspace
        search_roots = [root]
        for ws in workspaces:
            ws_path = root / ws.path
            if ws_path.is_dir():
                search_roots.append(ws_path)

        seen: set[str] = set()
        for search_root in search_roots:
            for pattern in WorkspaceDetectorConfig.MIGRATION_DIR_PATTERNS:
                migrations_dir = search_root / pattern
                if not migrations_dir.is_dir():
                    continue
                for f in sorted(migrations_dir.rglob("*.sql")):
                    if f.is_file():
                        relative = str(f.relative_to(root))
                        if relative not in seen:
                            seen.add(relative)
                            migration_files.append(relative)

        # Also check legacy root path for backward compat
        legacy_dir = root / "supabase" / "migrations"
        if legacy_dir.is_dir():
            for f in sorted(legacy_dir.rglob("*.sql")):
                if f.is_file():
                    relative = str(f.relative_to(root))
                    if relative not in seen:
                        seen.add(relative)
                        migration_files.append(relative)

        return sorted(migration_files)

    # ------------------------------------------------------------------
    # Existing methods (unchanged behavior)
    # ------------------------------------------------------------------

    _SCP_LIKE = re.compile(r"^[\w.-]+@[\w.-]+:")   # git@host:path

    @classmethod
    def _validate_remote(cls, url: str, branch: str) -> None:
        """Reject repository URLs/branches that could inject git options or
        reach unsafe transports (ext::/fd:: run commands; file:// reads local)."""
        for label, value in (("repository URL", url), ("branch", branch)):
            if value.startswith("-"):
                raise RuntimeError(f"Refusing {label} that begins with '-'.")
        lowered = url.lower()
        if "::" in url or lowered.startswith(("file:", "ext:", "fd:")):
            raise RuntimeError("Refusing unsafe repository URL transport.")
        if not (
            lowered.startswith(("https://", "http://", "ssh://", "git://"))
            or cls._SCP_LIKE.match(url)
        ):
            raise RuntimeError("Unsupported repository URL scheme.")

    async def _clone_repo(
        self,
        repo_url: str,
        branch: str,
        clone_path: str,
        github_token: str | None,
        full_history: bool,
    ) -> None:
        """Fetch the repo into ``clone_path``.

        Remote URLs are ``git clone``d.  Local directories (a ``file://`` URL
        or a filesystem path to an existing directory) are copied instead, so
        that non-git folders and uncommitted working-tree changes can be
        scanned. The ``.git`` directory is preserved when present so git
        history secret scanning still works.
        """
        local_path = self._resolve_local_path(repo_url)
        if local_path is not None:
            shutil.copytree(
                local_path,
                clone_path,
                ignore=_LOCAL_COPY_IGNORE,
                dirs_exist_ok=True,
                symlinks=True,
            )
            return

        # Untrusted repo_url/branch: block git arg-injection (leading "-",
        # transport helpers like ext::/fd::, and file://), which can be RCE.
        self._validate_remote(repo_url, branch)

        url = repo_url
        if github_token and url.startswith("https://"):
            # Inject token for private repository access
            url = url.replace(
                "https://", f"https://x-access-token:{github_token}@"
            )

        cmd = ["git", "clone"]
        if not full_history:
            cmd.extend(["--depth", "1"])
        # "--" ends option parsing so the URL/path can't be read as flags.
        cmd.extend(["--branch", branch, "--", url, clone_path])
        # Restrict git to safe transports; never prompt for credentials.
        env = {
            **os.environ,
            "GIT_ALLOW_PROTOCOL": "https:http:ssh:git",
            "GIT_TERMINAL_PROMPT": "0",
        }

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            _, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=RepoIngestionConfig.CLONE_TIMEOUT_SECONDS,
            )
            if process.returncode != 0:
                error_msg = stderr.decode(errors="replace").strip()
                # git echoes the remote URL (with the injected token) in errors.
                if github_token:
                    error_msg = error_msg.replace(github_token, "***")
                if "not found" in error_msg.lower():
                    raise RuntimeError(
                        RepoIngestionConfig.ERROR_BRANCH_NOT_FOUND.format(
                            branch=branch
                        )
                    )
                raise RuntimeError(
                    RepoIngestionConfig.ERROR_CLONE_FAILED.format(
                        error=error_msg
                    )
                )
        except asyncio.TimeoutError:
            raise RuntimeError(
                RepoIngestionConfig.ERROR_CLONE_TIMEOUT.format(
                    timeout=RepoIngestionConfig.CLONE_TIMEOUT_SECONDS
                )
            )

    @staticmethod
    def _resolve_local_path(repo_url: str) -> str | None:
        """Return an absolute path if ``repo_url`` refers to a local directory.

        Handles ``file://`` URLs and bare filesystem paths. Returns ``None``
        for remote URLs (anything containing a ``://`` scheme other than
        ``file``) so they fall through to ``git clone``.
        """
        candidate = repo_url
        if candidate.startswith("file://"):
            candidate = candidate[len("file://"):]
        elif "://" in candidate:
            return None

        path = Path(candidate).expanduser()
        if path.is_dir():
            return str(path.resolve())
        return None

    @staticmethod
    async def _get_commit_hash(clone_path: str) -> str:
        """Read the HEAD commit hash from a cloned repo."""
        try:
            process = await asyncio.create_subprocess_exec(
                "git", "rev-parse", "HEAD",
                cwd=clone_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                process.communicate(), timeout=5
            )
            if process.returncode == 0:
                return stdout.decode().strip()
        except Exception:
            pass
        return ""

    def _read_package_json(self, clone_path: str) -> dict:
        """Read and parse package.json."""
        pkg_path = Path(clone_path) / "package.json"
        if not pkg_path.is_file():
            logger.warning("No package.json found at %s", clone_path)
            return {}
        try:
            return json.loads(pkg_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to parse package.json: %s", exc)
            return {}

    def _index_key_files(
        self, clone_path: str
    ) -> tuple[dict[str, str], int, int]:
        """Index important files for downstream analysis.

        Returns:
            Tuple of (file_index, total_files, total_size_bytes).
        """
        file_index: dict[str, str] = {}
        total_files = 0
        total_size = 0
        root = Path(clone_path)

        for path in root.rglob("*"):
            if not path.is_file():
                continue

            # Check if any parent directory should be skipped
            relative = path.relative_to(root)
            parts = relative.parts
            if any(
                part in RepoIngestionConfig.SKIP_DIRECTORIES
                for part in parts
            ):
                continue

            total_files += 1
            file_size = path.stat().st_size
            total_size += file_size

            # Skip files exceeding size limit
            if file_size > RepoIngestionConfig.MAX_FILE_SIZE_BYTES:
                continue

            file_name = path.name
            is_key_file = file_name in RepoIngestionConfig.KEY_FILE_NAMES
            has_code_ext = any(
                file_name.endswith(ext)
                for ext in RepoIngestionConfig.CODE_EXTENSIONS
            )

            if is_key_file or has_code_ext:
                try:
                    content = path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                    file_index[str(relative)] = content
                except OSError:
                    logger.warning("Failed to read file: %s", path)

        return file_index, total_files, total_size

    def _find_env_files(self, clone_path: str) -> list[str]:
        """Find .env files (names only, for secret scanning)."""
        root = Path(clone_path)
        env_files: list[str] = []
        for path in root.iterdir():
            if path.is_file() and path.name.startswith(".env"):
                env_files.append(path.name)
        return sorted(env_files)
