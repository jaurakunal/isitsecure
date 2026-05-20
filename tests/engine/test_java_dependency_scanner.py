"""Tests for JavaDependencyScanner."""

import pytest

from isitsecure.engine.code_analysis.java_dependency_scanner import JavaDependencyScanner
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.enums import FrameworkType, BackendType


@pytest.fixture
def scanner():
    return JavaDependencyScanner()


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


class TestMavenPom:
    @pytest.mark.asyncio
    async def test_detects_log4j_vulnerability(self, scanner):
        snapshot = _make_snapshot({"pom.xml": """
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.0</version>
    </dependency>
  </dependencies>
</project>
"""})
        findings = await scanner.scan(snapshot)
        assert len(findings) >= 1
        assert any("log4j" in f.title.lower() for f in findings)
        assert any(f.severity.value == "critical" for f in findings)

    @pytest.mark.asyncio
    async def test_detects_spring_vulnerability(self, scanner):
        snapshot = _make_snapshot({"pom.xml": """
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter</artifactId>
      <version>2.7.0</version>
    </dependency>
  </dependencies>
</project>
"""})
        findings = await scanner.scan(snapshot)
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_safe_version_no_findings(self, scanner):
        snapshot = _make_snapshot({"pom.xml": """
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.21.0</version>
    </dependency>
  </dependencies>
</project>
"""})
        findings = await scanner.scan(snapshot)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_skips_property_version(self, scanner):
        snapshot = _make_snapshot({"pom.xml": """
<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${log4j.version}</version>
    </dependency>
  </dependencies>
</project>
"""})
        findings = await scanner.scan(snapshot)
        assert len(findings) == 0


class TestGradle:
    @pytest.mark.asyncio
    async def test_detects_gradle_vulnerability(self, scanner):
        snapshot = _make_snapshot({"build.gradle": """
dependencies {
    implementation 'org.apache.logging.log4j:log4j-core:2.14.0'
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.13.0'
}
"""})
        findings = await scanner.scan(snapshot)
        assert len(findings) >= 2

    @pytest.mark.asyncio
    async def test_detects_gradle_kts(self, scanner):
        snapshot = _make_snapshot({"build.gradle.kts": """
dependencies {
    implementation("org.apache.commons:commons-text:1.9.0")
}
"""})
        findings = await scanner.scan(snapshot)
        assert len(findings) >= 1
        assert any("text4shell" in f.description.lower() or "commons-text" in f.title.lower() for f in findings)


class TestVersionComparison:
    """Version comparison tests (shared utility)."""

    def test_vulnerable(self):
        from isitsecure.engine.code_analysis.shared_utils import is_version_vulnerable
        assert is_version_vulnerable("2.14.0", "<2.17.1") is True

    def test_safe(self):
        from isitsecure.engine.code_analysis.shared_utils import is_version_vulnerable
        assert is_version_vulnerable("2.21.0", "<2.17.1") is False

    def test_exact(self):
        from isitsecure.engine.code_analysis.shared_utils import is_version_vulnerable
        assert is_version_vulnerable("2.17.1", "<2.17.1") is False

    def test_invalid(self):
        from isitsecure.engine.code_analysis.shared_utils import is_version_vulnerable
        assert is_version_vulnerable("RELEASE", "<2.0") is False
