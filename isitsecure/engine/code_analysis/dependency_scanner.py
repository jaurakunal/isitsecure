"""Dependency vulnerability scanner.

Scans package.json dependencies against the OSV (Open Source Vulnerabilities)
database to identify packages with known CVEs.
"""

from __future__ import annotations

import json
import logging

import httpx

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import DependencyScannerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class _OSVSeverityMapper:
    """Maps OSV severity strings to internal SeverityLevel."""

    _MAPPING: dict[str, SeverityLevel] = {
        "CRITICAL": SeverityLevel.CRITICAL,
        "HIGH": SeverityLevel.HIGH,
        "MODERATE": SeverityLevel.MEDIUM,
        "MEDIUM": SeverityLevel.MEDIUM,
        "LOW": SeverityLevel.LOW,
    }
    DEFAULT = SeverityLevel.HIGH

    @classmethod
    def map(cls, osv_severity: str) -> SeverityLevel:
        """Map an OSV severity string to a SeverityLevel enum."""
        return cls._MAPPING.get(osv_severity.upper(), cls.DEFAULT)


class DependencyScanner:
    """Scans package.json dependencies for known vulnerabilities via OSV API.

    Implements CodeScannerProtocol.
    """

    def __init__(self, http_client: httpx.AsyncClient | None = None) -> None:
        self._external_client = http_client

    @property
    def scanner_name(self) -> str:
        return DependencyScannerConfig.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Scan repository dependencies for known vulnerabilities.

        For monorepos, scans each workspace's package.json in addition
        to the root package.json.  Deduplicates identical package@version
        pairs across workspaces.

        Args:
            repo: Repository snapshot with package_json populated.

        Returns:
            List of code findings for vulnerable dependencies.
        """
        # Collect dependencies from root + all workspaces (monorepo support)
        all_dependencies: dict[str, str] = {}
        package_sources: dict[str, str] = {}  # package -> source label

        # Root package.json
        if repo.package_json:
            root_deps = self._parse_dependencies(repo.package_json)
            for name, version in root_deps.items():
                all_dependencies[name] = version
                package_sources[name] = DependencyScannerConfig.PACKAGE_JSON_FILE

        # Workspace package.json files (monorepo)
        for ws in getattr(repo, "workspaces", []):
            if ws.package_json:
                ws_deps = self._parse_dependencies(ws.package_json)
                for name, version in ws_deps.items():
                    if name not in all_dependencies:
                        all_dependencies[name] = version
                        package_sources[name] = f"{ws.path}/package.json"

        if not all_dependencies:
            return []

        # Limit the number of packages to check
        packages = list(all_dependencies.items())[: DependencyScannerConfig.MAX_PACKAGES_TO_CHECK]

        findings: list[CodeFinding] = []
        client = self._external_client or httpx.AsyncClient(
            timeout=DependencyScannerConfig.HTTP_TIMEOUT_SECONDS
        )
        owns_client = self._external_client is None

        try:
            findings = await self._scan_packages(client, packages)

            # Update file_path to reflect which workspace the dep came from
            for finding in findings:
                # Extract package name from title
                for name, source in package_sources.items():
                    if name in finding.title:
                        finding.file_path = source
                        break

        except Exception as exc:
            logger.warning(
                DependencyScannerConfig.ERROR_OSV_QUERY_FAILED.format(
                    error=str(exc)
                )
            )
        finally:
            if owns_client:
                await client.aclose()

        logger.info(
            "DependencyScanner: checked %d packages across %d workspaces, %d findings",
            len(packages),
            len(getattr(repo, "workspaces", [])),
            len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_dependencies(package_json: dict) -> dict[str, str]:
        """Extract all dependencies with versions from package.json."""
        deps: dict[str, str] = {}
        for section in ("dependencies", "devDependencies"):
            section_deps = package_json.get(section, {})
            if isinstance(section_deps, dict):
                deps.update(section_deps)
        return deps

    @staticmethod
    def _clean_version(version: str) -> str:
        """Clean semver prefix (^, ~, >=, etc.) to get base version."""
        return version.lstrip("^~>=< ")

    # ------------------------------------------------------------------
    # OSV querying
    # ------------------------------------------------------------------

    async def _scan_packages(
        self,
        client: httpx.AsyncClient,
        packages: list[tuple[str, str]],
    ) -> list[CodeFinding]:
        """Query OSV API for each package and collect findings."""
        findings: list[CodeFinding] = []

        # Process in batches
        for batch_start in range(0, len(packages), DependencyScannerConfig.BATCH_SIZE):
            batch = packages[batch_start: batch_start + DependencyScannerConfig.BATCH_SIZE]
            batch_findings = await self._query_osv_batch(client, batch)
            findings.extend(batch_findings)

        return findings

    async def _query_osv_batch(
        self,
        client: httpx.AsyncClient,
        packages: list[tuple[str, str]],
    ) -> list[CodeFinding]:
        """Query OSV batch API for a batch of packages."""
        queries = []
        for name, raw_version in packages:
            version = self._clean_version(raw_version)
            queries.append({
                "package": {
                    "name": name,
                    "ecosystem": DependencyScannerConfig.ECOSYSTEM,
                },
                "version": version,
            })

        try:
            response = await client.post(
                DependencyScannerConfig.OSV_BATCH_URL,
                json={"queries": queries},
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning(
                DependencyScannerConfig.ERROR_OSV_QUERY_FAILED.format(
                    error=str(exc)
                )
            )
            return []

        return self._parse_osv_batch_response(
            response.json(), packages
        )

    def _parse_osv_batch_response(
        self,
        data: dict,
        packages: list[tuple[str, str]],
    ) -> list[CodeFinding]:
        """Parse OSV batch response and create findings."""
        findings: list[CodeFinding] = []
        results = data.get("results", [])

        for idx, result in enumerate(results):
            vulns = result.get("vulns", [])
            if not vulns or idx >= len(packages):
                continue

            name, raw_version = packages[idx]
            version = self._clean_version(raw_version)

            for vuln in vulns:
                finding = self._vuln_to_finding(name, version, vuln)
                if finding:
                    findings.append(finding)

        return findings

    def _vuln_to_finding(
        self,
        package: str,
        version: str,
        vuln: dict,
    ) -> CodeFinding | None:
        """Convert a single OSV vulnerability to a CodeFinding."""
        vuln_id = vuln.get("id", "unknown")
        summary = vuln.get("summary", vuln_id)
        severity_str = self._extract_severity(vuln)
        severity = _OSVSeverityMapper.map(severity_str)

        return CodeFinding(
            scanner_name=self.scanner_name,
            severity=severity,
            category=FindingCategory.DEPENDENCY_VULNERABILITY,
            title=DependencyScannerConfig.TITLE_KNOWN_CVE.format(
                package=package, version=version
            ),
            description=DependencyScannerConfig.DESC_KNOWN_CVE.format(
                package=package,
                version=version,
                summary=summary,
                severity=severity_str,
            ),
            file_path=DependencyScannerConfig.PACKAGE_JSON_FILE,
            confidence=DependencyScannerConfig.CONFIDENCE_KNOWN_CVE,
        )

    @staticmethod
    def _extract_severity(vuln: dict) -> str:
        """Extract severity string from OSV vulnerability data."""
        # OSV uses database_specific or severity array
        severity_list = vuln.get("severity", [])
        if severity_list:
            for s in severity_list:
                score = s.get("score", "")
                if score:
                    # CVSS score string; try to parse
                    return _cvss_to_severity(score)

        # Fallback: check database_specific
        db_specific = vuln.get("database_specific", {})
        return db_specific.get("severity", DependencyScannerConfig.DEFAULT_OSV_SEVERITY)


def _cvss_to_severity(cvss_vector: str) -> str:
    """Convert a CVSS vector or score to a severity string.

    Handles both numeric scores (e.g., "9.8") and CVSS vector strings.
    """
    try:
        score = float(cvss_vector)
    except ValueError:
        # It's a CVSS vector string, default to HIGH
        return DependencyScannerConfig.DEFAULT_OSV_SEVERITY

    if score >= DependencyScannerConfig.CVSS_CRITICAL_THRESHOLD:
        return SeverityLevel.CRITICAL.value
    if score >= DependencyScannerConfig.CVSS_HIGH_THRESHOLD:
        return SeverityLevel.HIGH.value
    if score >= DependencyScannerConfig.CVSS_MEDIUM_THRESHOLD:
        return SeverityLevel.MEDIUM.value
    return SeverityLevel.LOW.value
