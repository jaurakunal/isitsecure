"""State threaded through the phases of a scan.

``DeepSecurityScanAgent.scan()`` runs nineteen phases in sequence, and
twenty-six values cross a phase boundary: what was ingested, what was
discovered, which sessions were established, what each scanner found. Held as
locals they were invisible — you could not tell, short of reading all 870
lines, whether a phase read something an earlier one had set or quietly
depended on ordering.

Naming them here makes the seams explicit, which is what lets a phase move
into its own method. It is deliberately a plain mutable dataclass and not a
frozen one: phases accumulate into it, which is the shape the scan already
has.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from isitsecure.engine.auth.protocols import AuthCredentials, AuthSession
    from isitsecure.engine.code_analysis.lsp.protocols import AuthFlowResult
    from isitsecure.engine.code_analysis.models import CodeFinding
    from isitsecure.engine.code_analysis.protocols import RepoSnapshot
    from isitsecure.engine.enums import ScanMode
    from isitsecure.engine.models import (
        CodebaseSnapshot,
        DeepFinding,
        DiscoveredEndpoint,
        IDORTestResult,
        OwnerSummary,
        SecurityTheme,
    )


@dataclass
class ScanContext:
    """What one scan knows, as it comes to know it."""

    # --- what was asked for ---------------------------------------------
    mode: ScanMode
    target_url: str | None = None
    repo_url: str | None = None
    repo_branch: str | None = None
    github_token: str | None = None
    credentials_a: AuthCredentials | None = None
    credentials_b: AuthCredentials | None = None

    # Set by a phase that has ended the scan — url ingestion failing, or a
    # repo that could not be read in code-only mode. A phase is an async
    # generator, so returning from one only ends that phase; the caller has
    # to be told to stop.
    aborted: bool = False

    # --- what the scan produces -----------------------------------------
    all_findings: list[DeepFinding] = field(default_factory=list)
    scanners_run: list[str] = field(default_factory=list)
    # What we were asked to scan but could not read. A repo that failed to
    # clone must not leave behind a clean-looking report (#147).
    ingestion_errors: list[str] = field(default_factory=list)

    # --- what was ingested ----------------------------------------------
    snapshot: CodebaseSnapshot | None = None
    repo_snapshot: RepoSnapshot | None = None
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)

    # --- who we are, once authenticated ---------------------------------
    session_a: AuthSession | None = None
    session_b: AuthSession | None = None
    crawl_result: Any = None

    # --- what the target turned out to be built on ----------------------
    supabase_url: str | None = None
    anon_key: str | None = None
    tables: list[str] = field(default_factory=list)

    # --- per-phase results later phases depend on ------------------------
    oob_service: Any = None
    lsp_initialized: bool = False
    auth_flow_results: dict[str, AuthFlowResult] = field(default_factory=dict)
    sast_code_findings: list[CodeFinding] = field(default_factory=list)
    idor_results: list[IDORTestResult] = field(default_factory=list)
    owner_summary: OwnerSummary | None = None
    themes: list[SecurityTheme] = field(default_factory=list)
