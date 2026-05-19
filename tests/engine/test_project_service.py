"""Tests for project management service."""

import pytest

from isitsecure.engine.constants import ProjectConfig
from isitsecure.engine.enums import (
    PlanTier,
    ScanMode,
    ScanStatus,
    ScanTrigger,
)
from isitsecure.engine.models import DeepScanReport
from isitsecure.engine.projects.models import Project, ScanRecord
from isitsecure.engine.projects.project_service import ProjectService


class TestProjectService:
    """Tests for ProjectService."""

    def setup_method(self) -> None:
        self.service = ProjectService()

    def test_create_project(self) -> None:
        project = self.service.create_project(
            name="My App", owner_id="owner-1",
        )
        assert project.name == "My App"
        assert project.owner_id == "owner-1"
        assert project.plan_tier == PlanTier.FREE
        assert project.id is not None

    def test_create_project_with_url(self) -> None:
        project = self.service.create_project(
            name="My App",
            owner_id="owner-1",
            target_url="https://example.com",
            repo_url="https://github.com/example/repo",
        )
        assert project.target_url == "https://example.com"
        assert project.repo_url == "https://github.com/example/repo"

    def test_list_projects(self) -> None:
        self.service.create_project(
            name="App 1", owner_id="owner-1", plan_tier=PlanTier.PRO,
        )
        self.service.create_project(
            name="App 2", owner_id="owner-1", plan_tier=PlanTier.PRO,
        )
        self.service.create_project(
            name="App 3", owner_id="owner-2", plan_tier=PlanTier.PRO,
        )

        owner1_projects = self.service.list_projects("owner-1")
        assert len(owner1_projects) == 2

        owner2_projects = self.service.list_projects("owner-2")
        assert len(owner2_projects) == 1

    def test_get_project(self) -> None:
        project = self.service.create_project(
            name="My App", owner_id="owner-1",
        )
        found = self.service.get_project(project.id)
        assert found is not None
        assert found.id == project.id

        not_found = self.service.get_project("nonexistent")
        assert not_found is None

    def test_project_limit_free(self) -> None:
        self.service.create_project(name="App 1", owner_id="owner-1")
        with pytest.raises(ValueError, match="Project limit reached"):
            self.service.create_project(name="App 2", owner_id="owner-1")

    def test_project_limit_pro(self) -> None:
        for i in range(ProjectConfig.MAX_PROJECTS_PRO):
            self.service.create_project(
                name=f"App {i}", owner_id="owner-1", plan_tier=PlanTier.PRO,
            )
        with pytest.raises(ValueError, match="Project limit reached"):
            self.service.create_project(
                name="Over limit", owner_id="owner-1", plan_tier=PlanTier.PRO,
            )

    def test_start_scan(self) -> None:
        project = self.service.create_project(
            name="My App", owner_id="owner-1",
        )
        scan = self.service.start_scan(project.id)
        assert scan.project_id == project.id
        assert scan.status == ScanStatus.RUNNING
        assert scan.triggered_by == ScanTrigger.MANUAL

        updated_project = self.service.get_project(project.id)
        assert updated_project is not None
        assert updated_project.scan_count == 1
        assert updated_project.last_scan_at is not None

    def test_complete_scan(self) -> None:
        project = self.service.create_project(
            name="My App", owner_id="owner-1",
        )
        scan = self.service.start_scan(project.id)
        report = DeepScanReport(
            target_url="https://example.com",
            scan_duration_seconds=42.5,
        )
        completed = self.service.complete_scan(scan.id, report, grade="A")
        assert completed.status == ScanStatus.COMPLETE
        assert completed.grade == "A"
        assert completed.duration_seconds == 42.5
        assert completed.completed_at is not None

    def test_fail_scan(self) -> None:
        project = self.service.create_project(
            name="My App", owner_id="owner-1",
        )
        scan = self.service.start_scan(project.id)
        failed = self.service.fail_scan(scan.id, error="timeout")
        assert failed.status == ScanStatus.FAILED
        assert failed.completed_at is not None

    def test_list_scans_sorted(self) -> None:
        project = self.service.create_project(
            name="My App", owner_id="owner-1",
        )
        scan1 = self.service.start_scan(project.id)
        scan2 = self.service.start_scan(project.id)

        scans = self.service.list_scans(project.id)
        assert len(scans) == 2
        # Most recent first
        assert scans[0].id == scan2.id
        assert scans[1].id == scan1.id

    def test_scan_limit(self) -> None:
        project = self.service.create_project(
            name="My App", owner_id="owner-1",
        )
        for _ in range(ProjectConfig.MAX_SCANS_FREE):
            self.service.start_scan(project.id)
        with pytest.raises(ValueError, match="Scan limit reached"):
            self.service.start_scan(project.id)

    def test_project_not_found(self) -> None:
        with pytest.raises(ValueError, match="Project not found"):
            self.service.start_scan("nonexistent")

    def test_scan_not_found(self) -> None:
        with pytest.raises(ValueError, match="Scan not found"):
            self.service.complete_scan(
                "nonexistent", DeepScanReport(), grade="A",
            )

    def test_project_is_active(self) -> None:
        free_project = self.service.create_project(
            name="Free App", owner_id="owner-1",
        )
        assert not free_project.is_active

        pro_project = self.service.create_project(
            name="Pro App",
            owner_id="owner-2",
            plan_tier=PlanTier.PRO,
        )
        assert pro_project.is_active


class TestScanRecord:
    """Tests for ScanRecord model."""

    def test_model_defaults(self) -> None:
        record = ScanRecord(project_id="proj-1")
        assert record.status == ScanStatus.PENDING
        assert record.scan_mode == ScanMode.URL_ONLY
        assert record.triggered_by == ScanTrigger.MANUAL
        assert record.completed_at is None
        assert record.grade is None

    def test_is_complete(self) -> None:
        record = ScanRecord(project_id="proj-1", status=ScanStatus.COMPLETE)
        assert record.is_complete

        failed = ScanRecord(project_id="proj-1", status=ScanStatus.FAILED)
        assert failed.is_complete

        running = ScanRecord(project_id="proj-1", status=ScanStatus.RUNNING)
        assert not running.is_complete

    def test_auto_id(self) -> None:
        r1 = ScanRecord(project_id="proj-1")
        r2 = ScanRecord(project_id="proj-1")
        assert r1.id != r2.id


class TestProject:
    """Tests for Project model."""

    def test_model_defaults(self) -> None:
        project = Project(name="Test", owner_id="owner-1")
        assert project.plan_tier == PlanTier.FREE
        assert project.scan_count == 0
        assert not project.ownership_verified
        assert project.id is not None

    def test_is_active_free(self) -> None:
        project = Project(name="Test", owner_id="owner-1")
        assert not project.is_active

    def test_is_active_pro(self) -> None:
        project = Project(
            name="Test", owner_id="owner-1", plan_tier=PlanTier.PRO,
        )
        assert project.is_active
