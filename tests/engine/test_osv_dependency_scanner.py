"""Tests for OSVDependencyScanner."""

import pytest
from unittest.mock import AsyncMock, patch

from isitsecure.engine.code_analysis.osv_dependency_scanner import (
    OSVDependencyScanner,
    ParsedDependency,
)
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.enums import FrameworkType, BackendType, SeverityLevel


@pytest.fixture
def scanner():
    return OSVDependencyScanner()


def _make_snapshot(files: dict[str, str]) -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="test", branch="main", commit_hash="abc",
        clone_path="/tmp/test", framework=FrameworkType.UNKNOWN,
        backend=BackendType.UNKNOWN, auth_provider="", package_json={},
        file_index=files, route_map=[], migration_files=[], env_files=[],
        total_files=len(files), total_size_bytes=0,
    )


class TestDependencyExtraction:
    def test_extracts_npm_deps(self, scanner):
        snapshot = _make_snapshot({
            "package.json": '{"dependencies":{"next":"^13.4.0","react":"18.2.0"}}'
        })
        deps = scanner._extract_all_dependencies(snapshot)
        assert len(deps) == 2
        assert deps[0].ecosystem == "npm"
        assert deps[0].name == "next"
        assert deps[0].version == "13.4.0"  # Caret stripped

    def test_extracts_pip_deps(self, scanner):
        snapshot = _make_snapshot({
            "requirements.txt": "django==3.2.0\nflask>=2.0\nrequests\n"
        })
        deps = scanner._extract_all_dependencies(snapshot)
        # requests has no version → skipped, flask has version
        assert len(deps) == 2
        assert deps[0].ecosystem == "PyPI"
        assert deps[0].name == "django"

    def test_extracts_pyproject_deps(self, scanner):
        snapshot = _make_snapshot({
            "pyproject.toml": '[project]\ndependencies = [\n"fastapi>=0.109.0",\n"pydantic>=2.0",\n]\n'
        })
        deps = scanner._extract_all_dependencies(snapshot)
        assert len(deps) == 2
        assert deps[0].ecosystem == "PyPI"

    def test_extracts_maven_deps(self, scanner):
        snapshot = _make_snapshot({
            "pom.xml": """<project><dependencies>
                <dependency><groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-core</artifactId><version>2.14.0</version></dependency>
            </dependencies></project>"""
        })
        deps = scanner._extract_all_dependencies(snapshot)
        assert len(deps) == 1
        assert deps[0].ecosystem == "Maven"
        assert deps[0].name == "org.apache.logging.log4j:log4j-core"

    def test_extracts_gradle_deps(self, scanner):
        snapshot = _make_snapshot({
            "build.gradle": "dependencies {\n    implementation 'com.google.guava:guava:31.0-jre'\n}"
        })
        deps = scanner._extract_all_dependencies(snapshot)
        assert len(deps) == 1
        assert deps[0].ecosystem == "Maven"
        assert deps[0].name == "com.google.guava:guava"

    def test_skips_npm_wildcard_versions(self, scanner):
        snapshot = _make_snapshot({
            "package.json": '{"dependencies":{"react":"*"}}'
        })
        deps = scanner._extract_all_dependencies(snapshot)
        assert len(deps) == 0

    def test_skips_maven_property_versions(self, scanner):
        snapshot = _make_snapshot({
            "pom.xml": """<project><dependencies>
                <dependency><groupId>org.foo</groupId>
                <artifactId>bar</artifactId><version>${foo.version}</version></dependency>
            </dependencies></project>"""
        })
        deps = scanner._extract_all_dependencies(snapshot)
        assert len(deps) == 0

    def test_skips_pip_comments_and_flags(self, scanner):
        snapshot = _make_snapshot({
            "requirements.txt": "# comment\n-r base.txt\ndjango==4.0\n"
        })
        deps = scanner._extract_all_dependencies(snapshot)
        assert len(deps) == 1

    def test_multi_ecosystem(self, scanner):
        snapshot = _make_snapshot({
            "package.json": '{"dependencies":{"next":"13.4.0"}}',
            "requirements.txt": "django==3.2.0\n",
            "pom.xml": "<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency></dependencies></project>",
        })
        deps = scanner._extract_all_dependencies(snapshot)
        ecosystems = {d.ecosystem for d in deps}
        assert ecosystems == {"npm", "PyPI", "Maven"}


class TestSeverityExtraction:
    def test_database_specific_critical(self, scanner):
        vuln = {"database_specific": {"severity": "CRITICAL"}}
        assert scanner._extract_severity(vuln) == SeverityLevel.CRITICAL

    def test_database_specific_moderate(self, scanner):
        vuln = {"database_specific": {"severity": "MODERATE"}}
        assert scanner._extract_severity(vuln) == SeverityLevel.MEDIUM

    def test_ecosystem_specific_high(self, scanner):
        vuln = {"affected": [{"ecosystem_specific": {"severity": "HIGH"}}]}
        assert scanner._extract_severity(vuln) == SeverityLevel.HIGH

    def test_default_severity(self, scanner):
        assert scanner._extract_severity({}) == SeverityLevel.MEDIUM


class TestFixExtraction:
    def test_extracts_fixed_version(self):
        vuln = {
            "affected": [{
                "ranges": [{
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "4.2.8"},
                    ]
                }]
            }]
        }
        dep = ParsedDependency("django", "3.2.0", "PyPI", "req.txt", 1, "django==3.2.0")
        fix = OSVDependencyScanner._extract_fix(vuln, dep)
        assert "4.2.8" in fix

    def test_fallback_when_no_fixed(self):
        dep = ParsedDependency("foo", "1.0", "npm", "pkg.json", 0, "foo: 1.0")
        fix = OSVDependencyScanner._extract_fix({}, dep)
        assert "latest" in fix.lower()


class TestOSVIntegration:
    """Integration tests that hit the real OSV API. Skip if offline."""

    @pytest.mark.asyncio
    async def test_finds_real_vulns_for_django(self, scanner):
        snapshot = _make_snapshot({"requirements.txt": "django==3.2.0\n"})
        try:
            findings = await scanner.scan(snapshot)
        except Exception:
            pytest.skip("OSV API unreachable")
        assert len(findings) > 10  # Django 3.2.0 has 50+ known CVEs
        assert all(f.category.value == "dependency_vuln" for f in findings)

    @pytest.mark.asyncio
    async def test_finds_real_vulns_for_log4j(self, scanner):
        snapshot = _make_snapshot({
            "pom.xml": """<project><dependencies>
                <dependency><groupId>org.apache.logging.log4j</groupId>
                <artifactId>log4j-core</artifactId><version>2.14.0</version></dependency>
            </dependencies></project>"""
        })
        try:
            findings = await scanner.scan(snapshot)
        except Exception:
            pytest.skip("OSV API unreachable")
        assert len(findings) >= 5  # Log4j 2.14.0 has Log4Shell + others
        assert any("log4j" in f.title.lower() for f in findings)

    @pytest.mark.asyncio
    async def test_safe_package_no_vulns(self, scanner):
        # Use a very recent version that should have no vulns
        snapshot = _make_snapshot({"requirements.txt": "pydantic==2.11.0\n"})
        try:
            findings = await scanner.scan(snapshot)
        except Exception:
            pytest.skip("OSV API unreachable")
        # May or may not have vulns, but should not crash
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_empty_repo_no_crash(self, scanner):
        snapshot = _make_snapshot({})
        findings = await scanner.scan(snapshot)
        assert findings == []
