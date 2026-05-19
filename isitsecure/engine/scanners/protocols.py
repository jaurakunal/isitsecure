"""Protocols for deep security scan DAST scanners."""

from typing import Protocol, runtime_checkable

from isitsecure.engine.models import DeepFinding, DiscoveredEndpoint
from isitsecure.engine.enums import FindingCategory
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot


@runtime_checkable
class DASTScannerProtocol(Protocol):
    """Protocol for DAST (Dynamic Application Security Testing) scanners.

    All DAST scanners in the deep scan agent implement this interface.
    The orchestrator calls scan() and collects DeepFinding results.
    """

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        ...

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        ...

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run the scanner against discovered endpoints.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot for code-aware scanning.

        Returns:
            List of unified findings from this scanner.
        """
        ...
