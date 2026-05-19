"""Project and scan management models."""

from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, Field

from isitsecure.engine.enums import (
    PlanTier,
    ScanMode,
    ScanStatus,
    ScanTrigger,
)


class Project(BaseModel):
    """A customer's application being monitored."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    owner_id: str
    target_url: str | None = None
    repo_url: str | None = None
    framework: str = ""
    backend: str = ""
    plan_tier: PlanTier = PlanTier.FREE
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_scan_at: datetime | None = None
    scan_count: int = 0
    ownership_verified: bool = False

    @property
    def is_active(self) -> bool:
        """Whether the project has a paid plan."""
        return self.plan_tier != PlanTier.FREE


class ScanRecord(BaseModel):
    """A single scan execution within a project."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    project_id: str
    scan_mode: ScanMode = ScanMode.URL_ONLY
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    duration_seconds: float = 0.0
    finding_counts: dict[str, int] = Field(default_factory=dict)
    report_url: str | None = None
    report_data: dict | None = None
    triggered_by: ScanTrigger = ScanTrigger.MANUAL
    commit_sha: str | None = None
    grade: str | None = None

    @property
    def is_complete(self) -> bool:
        """Whether the scan has finished (successfully or not)."""
        return self.status in (ScanStatus.COMPLETE, ScanStatus.FAILED)
