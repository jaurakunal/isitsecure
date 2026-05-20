"""Scans Python dependencies for known vulnerabilities.

SRP: Scans requirements.txt / pyproject.toml for vulnerable packages.
OCP: Implements CodeScannerProtocol — added to scanner list without modifying others.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class PythonDependencyScanner:
    """Scans Python dependencies for known vulnerable patterns.

    Checks:
    - requirements.txt, requirements/*.txt
    - pyproject.toml [project.dependencies]
    - Unpinned dependencies (no version specifier)
    - Known vulnerable packages and version ranges
    """

    SCANNER_NAME = "python_dependency_scanner"

    # Known vulnerable Python packages (package → [(vulnerable_range, severity, description)])
    KNOWN_VULNERABILITIES: dict[str, list[tuple[str, SeverityLevel, str]]] = {
        "django": [
            ("<4.2.8", SeverityLevel.HIGH, "CVE-2023-46695: DoS via file uploads"),
            ("<3.2.23", SeverityLevel.CRITICAL, "CVE-2023-41164: DoS via URI validation"),
        ],
        "flask": [
            ("<2.3.2", SeverityLevel.HIGH, "CVE-2023-30861: Cookie handling vulnerability"),
        ],
        "fastapi": [
            ("<0.109.1", SeverityLevel.MEDIUM, "CVE-2024-24762: DoS via multipart form parsing"),
        ],
        "requests": [
            ("<2.31.0", SeverityLevel.MEDIUM, "CVE-2023-32681: Unintended leak of proxy credentials"),
        ],
        "cryptography": [
            ("<41.0.6", SeverityLevel.HIGH, "CVE-2023-49083: NULL pointer dereference"),
        ],
        "pyjwt": [
            ("<2.4.0", SeverityLevel.CRITICAL, "CVE-2022-29217: Algorithm confusion key confusion attack"),
        ],
        "sqlalchemy": [
            ("<1.4.49", SeverityLevel.MEDIUM, "SQL injection via textual SQL expressions"),
        ],
        "jinja2": [
            ("<3.1.3", SeverityLevel.MEDIUM, "CVE-2024-22195: XSS via xmlattr filter"),
        ],
        "werkzeug": [
            ("<3.0.1", SeverityLevel.HIGH, "CVE-2023-46136: DoS via multipart form data"),
        ],
        "pillow": [
            ("<10.0.1", SeverityLevel.HIGH, "CVE-2023-44271: DoS via crafted images"),
        ],
        "urllib3": [
            ("<2.0.7", SeverityLevel.MEDIUM, "CVE-2023-45803: Cookie leaking on redirect"),
        ],
        "paramiko": [
            ("<3.4.0", SeverityLevel.CRITICAL, "CVE-2023-48795: Terrapin SSH prefix truncation"),
        ],
        "pyyaml": [
            ("<6.0.1", SeverityLevel.CRITICAL, "Arbitrary code execution via yaml.load()"),
        ],
    }

    @property
    def scanner_name(self) -> str:
        return self.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Scan Python dependency files for vulnerabilities."""
        findings: list[CodeFinding] = []

        for file_path, content in repo.file_index.items():
            if self._is_requirements_file(file_path):
                findings.extend(self._scan_requirements(file_path, content))
            elif file_path.endswith("pyproject.toml"):
                findings.extend(self._scan_pyproject(file_path, content))

        logger.info("Python dependency scanner found %d issues", len(findings))
        return findings

    def _scan_requirements(self, file_path: str, content: str) -> list[CodeFinding]:
        """Scan a requirements.txt file."""
        findings: list[CodeFinding] = []

        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Parse: package==version, package>=version, package
            match = re.match(r"^([a-zA-Z0-9_-]+)\s*(?:([=<>!~]+)\s*([0-9.\w]+))?", line)
            if not match:
                continue

            package = self._normalize_package_name(match.group(1))
            version = match.group(3) or ""

            # Check for unpinned dependencies
            if not version:
                findings.append(CodeFinding(
                    scanner_name=self.SCANNER_NAME,
                    severity=SeverityLevel.LOW,
                    category=FindingCategory.DEPENDENCY_VULNERABILITY,
                    title=f"Unpinned Python dependency: {match.group(1)}",
                    description=(
                        f"The dependency '{match.group(1)}' has no version pinned. "
                        f"This means any version could be installed, including vulnerable ones."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=line,
                    confidence=0.6,
                    fix_suggestion="Pin the dependency to a specific version",
                ))
                continue

            # Check known vulnerabilities
            for pkg_name, vulns in self.KNOWN_VULNERABILITIES.items():
                if package == self._normalize_package_name(pkg_name):
                    for vuln_range, severity, description in vulns:
                        if self._is_vulnerable(version, vuln_range):
                            findings.append(CodeFinding(
                                scanner_name=self.SCANNER_NAME,
                                severity=severity,
                                category=FindingCategory.DEPENDENCY_VULNERABILITY,
                                title=f"Vulnerable dependency: {match.group(1)}=={version}",
                                description=f"{description}. Installed: {version}, vulnerable: {vuln_range}",
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=line,
                                confidence=0.85,
                                fix_suggestion=f"Upgrade {match.group(1)} to the latest version",
                            ))

        return findings

    def _scan_pyproject(self, file_path: str, content: str) -> list[CodeFinding]:
        """Scan pyproject.toml dependencies section."""
        findings: list[CodeFinding] = []

        # Simple extraction of dependencies from pyproject.toml
        in_deps = False
        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()

            if stripped in ("[project.dependencies]", "dependencies = ["):
                in_deps = True
                continue
            if in_deps and stripped.startswith("[") and not stripped.startswith('"'):
                in_deps = False
                continue

            if in_deps and stripped.startswith('"'):
                # Parse "package>=version"
                dep = stripped.strip('",').strip()
                match = re.match(r"^([a-zA-Z0-9_-]+)\s*(?:([=<>!~]+)\s*([0-9.\w]+))?", dep)
                if match:
                    package = match.group(1).lower()
                    version = match.group(3) or ""

                    normalized = self._normalize_package_name(package)
                    for pkg_name, vulns in self.KNOWN_VULNERABILITIES.items():
                        if normalized == self._normalize_package_name(pkg_name):
                            for vuln_range, severity, description in vulns:
                                if version and self._is_vulnerable(version, vuln_range):
                                    findings.append(CodeFinding(
                                        scanner_name=self.SCANNER_NAME,
                                        severity=severity,
                                        category=FindingCategory.DEPENDENCY_VULNERABILITY,
                                        title=f"Vulnerable dependency: {match.group(1)}=={version}",
                                        description=description,
                                        file_path=file_path,
                                        line_number=line_num,
                                        code_snippet=stripped,
                                        confidence=0.85,
                                        fix_suggestion=f"Upgrade {match.group(1)}",
                                    ))

        return findings

    @staticmethod
    def _normalize_package_name(name: str) -> str:
        """Normalize package name for comparison (lowercase, no dashes/underscores)."""
        return name.lower().replace("-", "").replace("_", "")

    @staticmethod
    def _is_requirements_file(file_path: str) -> bool:
        """Check if this is a Python requirements file."""
        name = Path(file_path).name.lower()
        return (
            name == "requirements.txt"
            or (name.startswith("requirements") and name.endswith(".txt"))
        )

    @staticmethod
    def _is_vulnerable(installed: str, vuln_range: str) -> bool:
        """Simple version comparison. Returns True if installed < threshold."""
        if not vuln_range.startswith("<"):
            return False
        threshold = vuln_range.lstrip("<").strip()
        try:
            inst_parts = [int(x) for x in installed.split(".")[:3]]
            thresh_parts = [int(x) for x in threshold.split(".")[:3]]
            # Pad to equal length
            while len(inst_parts) < 3:
                inst_parts.append(0)
            while len(thresh_parts) < 3:
                thresh_parts.append(0)
            return inst_parts < thresh_parts
        except (ValueError, IndexError):
            return False
