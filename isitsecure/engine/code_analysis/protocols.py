"""Protocols and shared models for code analysis scanners.

Defines the shared data models and protocol abstractions used by all
code analysis scanners.  Every scanner depends on these abstractions
(DIP), never on concrete implementations.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from isitsecure.engine.enums import (
    BackendType,
    FrameworkType,
    WorkspaceType,
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class RouteEntry(BaseModel):
    """A single API route discovered from the file system."""

    file_path: str
    http_methods: list[str] = Field(default_factory=list)
    route_pattern: str  # e.g., /api/users/:id
    has_auth_check: bool | None = None
    content: str = ""


class WorkspaceInfo(BaseModel):
    """Metadata for a single workspace inside a monorepo.

    Each workspace maps to a directory that has its own ``package.json``
    and may contain its own framework, backend, and auth provider.
    """

    name: str
    path: str  # relative to repo root, e.g. "frontend"
    workspace_type: WorkspaceType = WorkspaceType.UNKNOWN
    package_json: dict = Field(default_factory=dict)
    framework: FrameworkType = FrameworkType.UNKNOWN
    backend: BackendType = BackendType.UNKNOWN
    auth_provider: str = ""


class RepoSnapshot(BaseModel):
    """Indexed representation of a cloned repository.

    Backward compatible: ``workspaces`` defaults to an empty list and
    ``is_monorepo`` defaults to ``False``.  Existing scanners that only
    read ``file_index``, ``route_map``, or ``package_json`` continue to
    work without modification.
    """

    repo_url: str
    branch: str
    commit_hash: str = ""
    clone_path: str
    framework: FrameworkType = FrameworkType.UNKNOWN
    backend: BackendType = BackendType.UNKNOWN
    auth_provider: str = ""
    package_json: dict = Field(default_factory=dict)
    file_index: dict[str, str] = Field(default_factory=dict)  # path -> content
    route_map: list[RouteEntry] = Field(default_factory=list)
    migration_files: list[str] = Field(default_factory=list)
    env_files: list[str] = Field(default_factory=list)
    total_files: int = 0
    total_size_bytes: int = 0

    # Monorepo extensions (backward-compatible defaults)
    is_monorepo: bool = False
    workspaces: list[WorkspaceInfo] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Scanner protocols (DIP — scanners depend on these, not concretions)
# ---------------------------------------------------------------------------


@runtime_checkable
class CodeScannerProtocol(Protocol):
    """Protocol for static code analysis scanners."""

    @property
    def scanner_name(self) -> str: ...

    async def scan(self, repo: RepoSnapshot) -> list: ...


@runtime_checkable
class RouteMapperProtocol(Protocol):
    """Protocol for route mappers (OCP — new mappers added without
    modifying existing code)."""

    def map_routes(self, clone_path: str) -> list[RouteEntry]: ...
