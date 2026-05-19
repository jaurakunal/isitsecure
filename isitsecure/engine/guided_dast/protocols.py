"""Protocols and models for SAST-guided DAST test generation.

Defines the test case model and strategy protocol that all guided
DAST strategies implement (DIP + LSP).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable
from uuid import uuid4

from pydantic import BaseModel, Field

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.models import DiscoveredEndpoint


class GuidedTestCase(BaseModel):
    """A single DAST test case generated from a SAST finding."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    source_finding_id: str
    source_scanner: str
    test_type: str
    target_url: str
    http_method: str
    payload: dict | None = None
    headers: dict = Field(default_factory=dict)
    description: str = ""
    expected_behavior: str = ""
    dry_run: bool = False


@runtime_checkable
class GuidedTestStrategy(Protocol):
    """Protocol for strategies that generate guided DAST test cases.

    Each strategy handles findings from specific SAST scanners and
    produces targeted test cases (OCP — new strategies added without
    modifying existing code).
    """

    @property
    def handles_scanner_names(self) -> list[str]:
        """Scanner names whose findings this strategy can handle."""
        ...

    def generate_tests(
        self,
        code_findings: list[CodeFinding],
        endpoints: list[DiscoveredEndpoint],
        repo_snapshot: RepoSnapshot,
    ) -> list[GuidedTestCase]:
        """Generate targeted test cases from SAST findings.

        Args:
            code_findings: Findings from the SAST scanners this strategy handles.
            endpoints: Discovered live endpoints to target.
            repo_snapshot: Repository snapshot for additional context.

        Returns:
            List of test cases to execute against the running application.
        """
        ...
