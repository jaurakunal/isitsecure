"""Scans Java/Kotlin dependencies for known vulnerabilities.

SRP: Scans pom.xml / build.gradle for vulnerable packages.
OCP: Implements CodeScannerProtocol — added to scanner list without modifying others.
"""

from __future__ import annotations

import logging
import re

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.code_analysis.shared_utils import is_version_vulnerable
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.shared.progress import emit

logger = logging.getLogger(__name__)


class JavaDependencyScanner:
    """Scans Java/Kotlin dependencies for known vulnerable patterns.

    Checks:
    - pom.xml (Maven)
    - build.gradle / build.gradle.kts (Gradle)
    - Known vulnerable libraries and version ranges
    """

    SCANNER_NAME = "java_dependency_scanner"

    # Known vulnerable Java packages: (group:artifact → [(version_range, severity, description)])
    KNOWN_VULNERABILITIES: dict[str, list[tuple[str, SeverityLevel, str]]] = {
        "org.apache.logging.log4j:log4j-core": [
            ("<2.17.1", SeverityLevel.CRITICAL, "CVE-2021-44228 (Log4Shell): Remote code execution via crafted log messages"),
        ],
        "org.apache.struts:struts2-core": [
            ("<2.5.33", SeverityLevel.CRITICAL, "CVE-2023-50164: Path traversal leading to RCE"),
            ("<2.3.37", SeverityLevel.CRITICAL, "CVE-2017-5638: RCE via Content-Type header (Equifax breach)"),
        ],
        "org.springframework:spring-webmvc": [
            ("<5.3.28", SeverityLevel.HIGH, "CVE-2023-34036: DoS via crafted requests"),
        ],
        "org.springframework.boot:spring-boot-starter": [
            ("<3.1.5", SeverityLevel.HIGH, "CVE-2023-34055: DoS via HTTP/2"),
        ],
        "org.springframework.security:spring-security-core": [
            ("<5.8.9", SeverityLevel.HIGH, "CVE-2023-34042: Authorization bypass"),
        ],
        "com.fasterxml.jackson.core:jackson-databind": [
            ("<2.15.3", SeverityLevel.HIGH, "CVE-2023-35116: DoS via crafted JSON"),
        ],
        "io.jsonwebtoken:jjwt": [
            ("<0.11.5", SeverityLevel.HIGH, "Algorithm confusion vulnerability"),
        ],
        "commons-io:commons-io": [
            ("<2.14.0", SeverityLevel.MEDIUM, "CVE-2024-47554: Path traversal"),
        ],
        "org.apache.commons:commons-text": [
            ("<1.10.0", SeverityLevel.CRITICAL, "CVE-2022-42889 (Text4Shell): RCE via string interpolation"),
        ],
        "com.google.guava:guava": [
            ("<32.0.0", SeverityLevel.MEDIUM, "CVE-2023-2976: Temp directory vulnerability"),
        ],
        "org.apache.tomcat.embed:tomcat-embed-core": [
            ("<10.1.16", SeverityLevel.HIGH, "CVE-2023-46589: Request smuggling"),
        ],
        "mysql:mysql-connector-java": [
            ("<8.0.33", SeverityLevel.HIGH, "CVE-2023-21971: Unauthorized access"),
        ],
    }

    @property
    def scanner_name(self) -> str:
        return self.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Scan Java dependency files for vulnerabilities."""
        findings: list[CodeFinding] = []

        for file_path, content in repo.file_index.items():
            name = file_path.rsplit("/", 1)[-1].lower()
            if name == "pom.xml":
                emit(f"deps: parsing {name}")
                findings.extend(self._scan_pom(file_path, content))
            elif name in ("build.gradle", "build.gradle.kts"):
                emit(f"deps: parsing {name}")
                findings.extend(self._scan_gradle(file_path, content))

        logger.info("Java dependency scanner found %d issues", len(findings))
        return findings

    def _scan_pom(self, file_path: str, content: str) -> list[CodeFinding]:
        """Scan Maven pom.xml for vulnerable dependencies."""
        findings: list[CodeFinding] = []

        # Match <dependency><groupId>X</groupId><artifactId>Y</artifactId><version>Z</version></dependency>
        dep_pattern = re.compile(
            r"<dependency>\s*"
            r"<groupId>([^<]+)</groupId>\s*"
            r"<artifactId>([^<]+)</artifactId>\s*"
            r"(?:<version>([^<]+)</version>)?",
            re.DOTALL,
        )

        for match in dep_pattern.finditer(content):
            group_id = match.group(1).strip()
            artifact_id = match.group(2).strip()
            version = (match.group(3) or "").strip()
            coord = f"{group_id}:{artifact_id}"
            line_num = content[:match.start()].count("\n") + 1

            if not version or version.startswith("$"):
                continue  # Property reference, can't resolve

            findings.extend(self._check_vulnerabilities(
                coord, version, file_path, line_num,
                f"{group_id}:{artifact_id}:{version}",
            ))

        return findings

    def _scan_gradle(self, file_path: str, content: str) -> list[CodeFinding]:
        """Scan Gradle build files for vulnerable dependencies."""
        findings: list[CodeFinding] = []

        # Match: implementation 'group:artifact:version' or implementation("group:artifact:version")
        dep_pattern = re.compile(
            r"""(?:implementation|api|compile|runtimeOnly|testImplementation)\s*[\('"]+([^:'"]+):([^:'"]+):([^'")\s]+)""",
        )

        for match in dep_pattern.finditer(content):
            group_id = match.group(1).strip()
            artifact_id = match.group(2).strip()
            version = match.group(3).strip()
            coord = f"{group_id}:{artifact_id}"
            line_num = content[:match.start()].count("\n") + 1

            findings.extend(self._check_vulnerabilities(
                coord, version, file_path, line_num,
                f"{group_id}:{artifact_id}:{version}",
            ))

        return findings

    def _check_vulnerabilities(
        self,
        coord: str,
        version: str,
        file_path: str,
        line_num: int,
        snippet: str,
    ) -> list[CodeFinding]:
        """Check a dependency coordinate against known vulnerabilities."""
        findings: list[CodeFinding] = []

        vulns = self.KNOWN_VULNERABILITIES.get(coord)
        if not vulns:
            return findings

        for vuln_range, severity, description in vulns:
            if is_version_vulnerable(version, vuln_range):
                findings.append(CodeFinding(
                    scanner_name=self.SCANNER_NAME,
                    severity=severity,
                    category=FindingCategory.DEPENDENCY_VULNERABILITY,
                    title=f"Vulnerable dependency: {coord}:{version}",
                    description=f"{description}. Installed: {version}, vulnerable: {vuln_range}",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet,
                    confidence=0.85,
                    fix_suggestion=f"Upgrade {coord} to the latest version",
                ))

        return findings

