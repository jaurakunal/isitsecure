"""Tests for PythonDependencyScanner."""

import pytest

from isitsecure.engine.code_analysis.python_dependency_scanner import PythonDependencyScanner
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.enums import FrameworkType, BackendType


@pytest.fixture
def scanner():
    return PythonDependencyScanner()


def _make_snapshot(files: dict[str, str]) -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        commit_hash="abc123",
        clone_path="/tmp/test",
        framework=FrameworkType.UNKNOWN,
        backend=BackendType.UNKNOWN,
        auth_provider="",
        package_json={},
        file_index=files,
        route_map=[],
        migration_files=[],
        env_files=[],
        total_files=len(files),
        total_size_bytes=0,
    )


class TestRequirementsTxt:
    @pytest.mark.asyncio
    async def test_detects_vulnerable_django(self, scanner):
        snapshot = _make_snapshot({"requirements.txt": "django==3.2.0\n"})
        findings = await scanner.scan(snapshot)
        assert len(findings) >= 1
        assert any("django" in f.title.lower() for f in findings)
        assert any(f.severity.value == "critical" for f in findings)

    @pytest.mark.asyncio
    async def test_detects_vulnerable_pyjwt(self, scanner):
        snapshot = _make_snapshot({"requirements.txt": "PyJWT==2.1.0\n"})
        findings = await scanner.scan(snapshot)
        assert len(findings) >= 1
        assert any("pyjwt" in f.title.lower() for f in findings)

    @pytest.mark.asyncio
    async def test_detects_unpinned_dependency(self, scanner):
        snapshot = _make_snapshot({"requirements.txt": "requests\nflask\n"})
        findings = await scanner.scan(snapshot)
        assert len(findings) == 2
        assert all("unpinned" in f.title.lower() for f in findings)

    @pytest.mark.asyncio
    async def test_safe_version_no_findings(self, scanner):
        snapshot = _make_snapshot({"requirements.txt": "django==5.0.0\nflask==3.0.0\n"})
        findings = await scanner.scan(snapshot)
        # No vulnerable versions
        vuln_findings = [f for f in findings if "vulnerable" in f.title.lower()]
        assert len(vuln_findings) == 0

    @pytest.mark.asyncio
    async def test_skips_comments_and_flags(self, scanner):
        snapshot = _make_snapshot({
            "requirements.txt": "# This is a comment\n-r base.txt\ndjango==5.0.0\n"
        })
        findings = await scanner.scan(snapshot)
        vuln_findings = [f for f in findings if "vulnerable" in f.title.lower()]
        assert len(vuln_findings) == 0

    @pytest.mark.asyncio
    async def test_handles_dashes_and_underscores(self, scanner):
        snapshot = _make_snapshot({"requirements.txt": "Django-Rest-Framework==3.14.0\n"})
        findings = await scanner.scan(snapshot)
        # Should not crash, may or may not find vulnerabilities
        assert isinstance(findings, list)


class TestPyprojectToml:
    @pytest.mark.asyncio
    async def test_detects_vulnerable_in_pyproject(self, scanner):
        snapshot = _make_snapshot({
            "pyproject.toml": """
[project]
dependencies = [
    "flask==2.0.0",
    "requests==2.28.0",
]
"""
        })
        findings = await scanner.scan(snapshot)
        assert len(findings) >= 1
        assert any("flask" in f.title.lower() for f in findings)


class TestVersionComparison:
    """Version comparison tests (shared utility)."""

    def test_vulnerable_version(self):
        from isitsecure.engine.code_analysis.shared_utils import is_version_vulnerable
        assert is_version_vulnerable("3.2.0", "<3.2.23") is True

    def test_safe_version(self):
        from isitsecure.engine.code_analysis.shared_utils import is_version_vulnerable
        assert is_version_vulnerable("5.0.0", "<4.2.8") is False

    def test_exact_threshold(self):
        from isitsecure.engine.code_analysis.shared_utils import is_version_vulnerable
        assert is_version_vulnerable("4.2.8", "<4.2.8") is False

    def test_handles_short_versions(self):
        from isitsecure.engine.code_analysis.shared_utils import is_version_vulnerable
        assert is_version_vulnerable("2.0", "<2.3.2") is True

    def test_handles_invalid_version(self):
        from isitsecure.engine.code_analysis.shared_utils import is_version_vulnerable
        assert is_version_vulnerable("abc", "<2.0") is False


class TestPackageNormalization:
    def test_normalizes_dashes(self):
        assert PythonDependencyScanner._normalize_package_name("Django-Rest") == "djangorest"

    def test_normalizes_underscores(self):
        assert PythonDependencyScanner._normalize_package_name("my_package") == "mypackage"

    def test_lowercases(self):
        assert PythonDependencyScanner._normalize_package_name("PyJWT") == "pyjwt"


class TestIsRequirementsFile:
    def test_requirements_txt(self):
        assert PythonDependencyScanner._is_requirements_file("requirements.txt") is True

    def test_requirements_dev(self):
        assert PythonDependencyScanner._is_requirements_file("requirements-dev.txt") is True

    def test_not_requirements(self):
        assert PythonDependencyScanner._is_requirements_file("package.json") is False

    def test_nested_path(self):
        assert PythonDependencyScanner._is_requirements_file("backend/requirements.txt") is True
