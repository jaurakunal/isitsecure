"""Project management service.

Manages projects and scan records. In-memory for now,
can be backed by a database later.
"""

import logging
from datetime import UTC, datetime

from isitsecure.engine.constants import ProjectConfig
from isitsecure.engine.enums import (
    PlanTier,
    ScanMode,
    ScanStatus,
    ScanTrigger,
)
from isitsecure.engine.models import DeepScanReport
from isitsecure.engine.projects.models import Project, ScanRecord

logger = logging.getLogger(__name__)


class ProjectService:
    """Manages projects and their scan history.

    In-memory storage for now. Can be backed by database,
    Supabase, or any persistence layer.
    """

    def __init__(self) -> None:
        self._projects: dict[str, Project] = {}
        self._scans: dict[str, ScanRecord] = {}

    def create_project(
        self,
        name: str,
        owner_id: str,
        target_url: str | None = None,
        repo_url: str | None = None,
        plan_tier: PlanTier = PlanTier.FREE,
    ) -> Project:
        """Create a new project."""
        owner_projects = [
            p for p in self._projects.values() if p.owner_id == owner_id
        ]
        max_projects = self._max_projects(plan_tier)
        if len(owner_projects) >= max_projects:
            raise ValueError(
                ProjectConfig.ERROR_PROJECT_LIMIT.format(
                    tier=plan_tier.value, max=max_projects,
                )
            )

        project = Project(
            name=name,
            owner_id=owner_id,
            target_url=target_url,
            repo_url=repo_url,
            plan_tier=plan_tier,
        )
        self._projects[project.id] = project
        return project

    def get_project(self, project_id: str) -> Project | None:
        """Get a project by ID."""
        return self._projects.get(project_id)

    def list_projects(self, owner_id: str) -> list[Project]:
        """List all projects for an owner."""
        return [p for p in self._projects.values() if p.owner_id == owner_id]

    def start_scan(
        self,
        project_id: str,
        scan_mode: ScanMode = ScanMode.URL_ONLY,
        triggered_by: ScanTrigger = ScanTrigger.MANUAL,
        commit_sha: str | None = None,
    ) -> ScanRecord:
        """Start a new scan for a project."""
        project = self._projects.get(project_id)
        if not project:
            raise ValueError(
                ProjectConfig.ERROR_PROJECT_NOT_FOUND.format(
                    project_id=project_id,
                )
            )

        project_scans = [
            s for s in self._scans.values() if s.project_id == project_id
        ]
        max_scans = self._max_scans(project.plan_tier)
        if len(project_scans) >= max_scans:
            raise ValueError(
                ProjectConfig.ERROR_SCAN_LIMIT.format(
                    tier=project.plan_tier.value, max=max_scans,
                )
            )

        scan = ScanRecord(
            project_id=project_id,
            scan_mode=scan_mode,
            status=ScanStatus.RUNNING,
            triggered_by=triggered_by,
            commit_sha=commit_sha,
        )
        self._scans[scan.id] = scan

        project.scan_count += 1
        project.last_scan_at = datetime.now(UTC)
        project.updated_at = datetime.now(UTC)

        return scan

    def complete_scan(
        self,
        scan_id: str,
        report: DeepScanReport,
        grade: str = "",
    ) -> ScanRecord:
        """Mark a scan as complete with results."""
        scan = self._scans.get(scan_id)
        if not scan:
            raise ValueError(
                ProjectConfig.ERROR_SCAN_NOT_FOUND.format(scan_id=scan_id)
            )

        scan.status = ScanStatus.COMPLETE
        scan.completed_at = datetime.now(UTC)
        scan.duration_seconds = report.scan_duration_seconds
        scan.grade = grade
        scan.finding_counts = {
            "total": len(report.findings),
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
        }
        return scan

    def fail_scan(self, scan_id: str, error: str = "") -> ScanRecord:
        """Mark a scan as failed."""
        scan = self._scans.get(scan_id)
        if not scan:
            raise ValueError(
                ProjectConfig.ERROR_SCAN_NOT_FOUND.format(scan_id=scan_id)
            )
        scan.status = ScanStatus.FAILED
        scan.completed_at = datetime.now(UTC)
        return scan

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        """Get a scan record by ID."""
        return self._scans.get(scan_id)

    def list_scans(self, project_id: str) -> list[ScanRecord]:
        """List all scans for a project, most recent first."""
        return sorted(
            [s for s in self._scans.values() if s.project_id == project_id],
            key=lambda s: s.started_at,
            reverse=True,
        )

    def _max_projects(self, tier: PlanTier) -> int:
        """Get max projects allowed for a plan tier."""
        return {
            PlanTier.FREE: ProjectConfig.MAX_PROJECTS_FREE,
            PlanTier.PRO: ProjectConfig.MAX_PROJECTS_PRO,
            PlanTier.CERTIFICATION: ProjectConfig.MAX_PROJECTS_CERTIFICATION,
        }.get(tier, ProjectConfig.MAX_PROJECTS_FREE)

    def _max_scans(self, tier: PlanTier) -> int:
        """Get max scans allowed for a plan tier."""
        return {
            PlanTier.FREE: ProjectConfig.MAX_SCANS_FREE,
            PlanTier.PRO: ProjectConfig.MAX_SCANS_PRO,
            PlanTier.CERTIFICATION: ProjectConfig.MAX_SCANS_CERTIFICATION,
        }.get(tier, ProjectConfig.MAX_SCANS_FREE)
