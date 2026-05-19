"""Tests for the DependencyScanner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from isitsecure.engine.code_analysis.dependency_scanner import (
    DependencyScanner,
    _cvss_to_severity,
)
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import DependencyScannerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VULNERABLE_OSV_RESPONSE = {
    "results": [
        {
            "vulns": [
                {
                    "id": "GHSA-xxxx-yyyy-zzzz",
                    "summary": "Prototype pollution in lodash",
                    "severity": [{"score": "9.8"}],
                    "database_specific": {"severity": "CRITICAL"},
                }
            ]
        },
        {"vulns": []},  # react is safe
    ]
}

NO_VULNS_RESPONSE = {
    "results": [
        {"vulns": []},
        {"vulns": []},
    ]
}


def _make_repo(package_json: dict | None = None) -> RepoSnapshot:
    """Create a minimal RepoSnapshot."""
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        package_json=package_json or {},
    )


def _mock_client(response_json: dict, status_code: int = 200) -> httpx.AsyncClient:
    """Create a mock httpx.AsyncClient that returns the given response."""
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = status_code
    mock_response.json.return_value = response_json
    mock_response.raise_for_status = MagicMock()

    client = AsyncMock(spec=httpx.AsyncClient)
    client.post = AsyncMock(return_value=mock_response)
    client.aclose = AsyncMock()
    return client


class TestDependencyScanner:
    """Tests for DependencyScanner."""

    def test_scanner_name(self) -> None:
        scanner = DependencyScanner()
        assert scanner.scanner_name == DependencyScannerConfig.SCANNER_NAME

    def test_parse_dependencies(self) -> None:
        package_json = {
            "dependencies": {
                "react": "^18.2.0",
                "next": "^14.0.0",
            },
            "devDependencies": {
                "typescript": "^5.0.0",
            },
        }
        deps = DependencyScanner._parse_dependencies(package_json)
        assert "react" in deps
        assert "next" in deps
        assert "typescript" in deps
        assert deps["react"] == "^18.2.0"

    def test_clean_version(self) -> None:
        assert DependencyScanner._clean_version("^18.2.0") == "18.2.0"
        assert DependencyScanner._clean_version("~5.0.0") == "5.0.0"
        assert DependencyScanner._clean_version(">=1.0.0") == "1.0.0"
        assert DependencyScanner._clean_version("3.0.0") == "3.0.0"

    @pytest.mark.asyncio
    async def test_detects_vulnerable_package(self) -> None:
        client = _mock_client(VULNERABLE_OSV_RESPONSE)
        scanner = DependencyScanner(http_client=client)

        repo = _make_repo({
            "dependencies": {
                "lodash": "^4.17.15",
                "react": "^18.2.0",
            }
        })

        findings = await scanner.scan(repo)

        assert len(findings) >= 1
        vuln = findings[0]
        assert vuln.category == FindingCategory.DEPENDENCY_VULNERABILITY
        assert "lodash" in vuln.title
        assert vuln.confidence == DependencyScannerConfig.CONFIDENCE_KNOWN_CVE

    @pytest.mark.asyncio
    async def test_no_finding_for_safe_package(self) -> None:
        client = _mock_client(NO_VULNS_RESPONSE)
        scanner = DependencyScanner(http_client=client)

        repo = _make_repo({
            "dependencies": {
                "react": "^18.2.0",
                "next": "^14.0.0",
            }
        })

        findings = await scanner.scan(repo)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_handles_osv_error(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post = AsyncMock(side_effect=httpx.HTTPError("Connection refused"))
        client.aclose = AsyncMock()

        scanner = DependencyScanner(http_client=client)
        repo = _make_repo({
            "dependencies": {"lodash": "^4.17.15"}
        })

        # Should not raise, returns empty findings
        findings = await scanner.scan(repo)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_handles_empty_package_json(self) -> None:
        scanner = DependencyScanner()
        repo = _make_repo({})

        findings = await scanner.scan(repo)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_handles_no_package_json(self) -> None:
        scanner = DependencyScanner()
        repo = _make_repo(None)

        findings = await scanner.scan(repo)
        assert len(findings) == 0

    def test_cvss_to_severity_critical(self) -> None:
        assert _cvss_to_severity("9.8") == SeverityLevel.CRITICAL.value

    def test_cvss_to_severity_high(self) -> None:
        assert _cvss_to_severity("7.5") == SeverityLevel.HIGH.value

    def test_cvss_to_severity_medium(self) -> None:
        assert _cvss_to_severity("5.0") == SeverityLevel.MEDIUM.value

    def test_cvss_to_severity_low(self) -> None:
        assert _cvss_to_severity("2.0") == SeverityLevel.LOW.value

    def test_cvss_to_severity_vector_string(self) -> None:
        # CVSS vector strings should default to HIGH
        assert _cvss_to_severity("CVSS:3.1/AV:N/AC:L") == DependencyScannerConfig.DEFAULT_OSV_SEVERITY

    @pytest.mark.asyncio
    async def test_severity_mapping_from_osv(self) -> None:
        """Test that OSV severity is correctly mapped to SeverityLevel."""
        response = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "CVE-2023-0001",
                            "summary": "Critical vuln",
                            "severity": [{"score": "9.8"}],
                        }
                    ]
                }
            ]
        }
        client = _mock_client(response)
        scanner = DependencyScanner(http_client=client)

        repo = _make_repo({"dependencies": {"bad-pkg": "1.0.0"}})
        findings = await scanner.scan(repo)

        assert len(findings) == 1
        assert findings[0].severity == SeverityLevel.CRITICAL
