"""Docker and Docker Compose security scanner.

SRP: This scanner is responsible ONLY for analyzing Dockerfile and
     docker-compose files for security misconfigurations.  It does not
     analyze application code or infrastructure-as-code.

OCP: Implements ``CodeScannerProtocol`` — added to the sast_scanners
     list without modifying the agent or factory.

DIP: Depends on ``RepoSnapshot`` and ``CodeScannerProtocol``
     (abstractions), never on concrete implementations.
"""

from __future__ import annotations

import logging
import re

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import DockerScannerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class DockerScanner:
    """Scans Dockerfile and docker-compose files for security issues.

    Dockerfile checks:
    1. Running as root (no USER directive)
    2. Using :latest or untagged base images
    3. Exposing sensitive ports (databases, SSH)
    4. Hardcoded secrets in ENV instructions
    5. ADD with remote URLs (supply chain risk)
    6. Missing HEALTHCHECK instruction

    Docker Compose checks:
    7. Default/weak passwords in environment
    8. Privileged mode containers
    9. Sensitive service ports exposed to host

    Implements ``CodeScannerProtocol``.
    """

    @property
    def scanner_name(self) -> str:
        return DockerScannerConfig.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Analyze Docker files for security issues."""
        findings: list[CodeFinding] = []

        dockerfiles = self._find_dockerfiles(repo)
        compose_files = self._find_compose_files(repo)

        if not dockerfiles and not compose_files:
            return findings

        for file_path, content in dockerfiles.items():
            try:
                findings.extend(self._scan_dockerfile(content, file_path))
            except Exception as e:
                logger.warning(
                    DockerScannerConfig.ERROR_ANALYSIS_FAILED.format(
                        file=file_path, error=e
                    )
                )

        for file_path, content in compose_files.items():
            try:
                findings.extend(self._scan_compose_file(content, file_path))
            except Exception as e:
                logger.warning(
                    DockerScannerConfig.ERROR_ANALYSIS_FAILED.format(
                        file=file_path, error=e
                    )
                )

        logger.info(
            "DockerScanner: %d Dockerfiles + %d compose files, %d findings",
            len(dockerfiles),
            len(compose_files),
            len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # File discovery
    # ------------------------------------------------------------------

    @staticmethod
    def _find_dockerfiles(repo: RepoSnapshot) -> dict[str, str]:
        """Find Dockerfiles in the file index."""
        return {
            path: content
            for path, content in repo.file_index.items()
            if any(
                path.endswith(name) or path.endswith(f"/{name}")
                for name in DockerScannerConfig.DOCKERFILE_NAMES
            )
        }

    @staticmethod
    def _find_compose_files(repo: RepoSnapshot) -> dict[str, str]:
        """Find Docker Compose files in the file index."""
        return {
            path: content
            for path, content in repo.file_index.items()
            if any(
                path.endswith(name) or path.endswith(f"/{name}")
                for name in DockerScannerConfig.COMPOSE_NAMES
            )
        }

    # ------------------------------------------------------------------
    # Dockerfile scanning
    # ------------------------------------------------------------------

    def _scan_dockerfile(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Run all Dockerfile checks."""
        findings: list[CodeFinding] = []

        # Skip .dev Dockerfiles for root user check (dev containers
        # commonly run as root for convenience)
        is_dev = ".dev" in file_path.lower() or "dev" in file_path.lower()

        # 1. Root user check (skip dev Dockerfiles)
        if not is_dev:
            findings.extend(self._check_root_user(content, file_path))

        # 2. Latest/untagged base image
        findings.extend(self._check_base_image_tags(content, file_path))

        # 3. Sensitive port exposure
        findings.extend(self._check_exposed_ports(content, file_path))

        # 4. Hardcoded secrets in ENV
        findings.extend(self._check_env_secrets(content, file_path))

        # 5. ADD with remote URL
        findings.extend(self._check_add_remote(content, file_path))

        # 6. Missing HEALTHCHECK (skip dev Dockerfiles)
        if not is_dev:
            findings.extend(self._check_healthcheck(content, file_path))

        return findings

    # ------------------------------------------------------------------
    # 1. Root user check
    # ------------------------------------------------------------------

    def _check_root_user(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check if Dockerfile runs as root."""
        if re.search(
            DockerScannerConfig.USER_DIRECTIVE_PATTERN, content, re.MULTILINE
        ):
            return []

        return [
            CodeFinding(
                scanner_name=self.scanner_name,
                severity=SeverityLevel.MEDIUM,
                category=FindingCategory.AUTH_WEAKNESS,
                title=DockerScannerConfig.TITLE_ROOT_USER,
                description=DockerScannerConfig.DESC_ROOT_USER.format(
                    file=file_path
                ),
                file_path=file_path,
                confidence=DockerScannerConfig.CONFIDENCE_ROOT_USER,
            )
        ]

    # ------------------------------------------------------------------
    # 2. Base image tag check
    # ------------------------------------------------------------------

    def _check_base_image_tags(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for :latest or untagged base images."""
        findings: list[CodeFinding] = []

        # Check for explicit :latest
        if re.search(
            DockerScannerConfig.LATEST_TAG_PATTERN, content, re.MULTILINE
        ):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.LOW,
                    category=FindingCategory.INFO_DISCLOSURE,
                    title=DockerScannerConfig.TITLE_LATEST_TAG,
                    description=DockerScannerConfig.DESC_LATEST_TAG.format(
                        file=file_path, image="(latest tag)"
                    ),
                    file_path=file_path,
                    confidence=DockerScannerConfig.CONFIDENCE_LATEST_TAG,
                )
            )

        # Check for untagged FROM (no version tag)
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped.upper().startswith("FROM "):
                continue

            # Extract image name (strip FROM and optional AS alias)
            parts = stripped.split()
            if len(parts) < 2:
                continue
            image = parts[1]

            # Skip scratch
            if image == "scratch":
                continue

            # Check if image has a version tag (name:tag format)
            # Handle registry URLs: docker.io/library/node has no tag
            # but registry.example.com:5000/app:v1 has a tag
            image_without_registry = image
            if "/" in image:
                # Registry may have port: registry.io:5000/app:tag
                # Split on last / to get image:tag part
                image_without_registry = image.rsplit("/", 1)[-1]

            if ":" not in image_without_registry:
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.LOW,
                        category=FindingCategory.INFO_DISCLOSURE,
                        title=DockerScannerConfig.TITLE_LATEST_TAG,
                        description=DockerScannerConfig.DESC_LATEST_TAG.format(
                            file=file_path, image=image
                        ),
                        file_path=file_path,
                        confidence=DockerScannerConfig.CONFIDENCE_LATEST_TAG,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # 3. Sensitive port exposure
    # ------------------------------------------------------------------

    def _check_exposed_ports(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for sensitive ports in EXPOSE directives."""
        findings: list[CodeFinding] = []

        for match in re.finditer(
            DockerScannerConfig.EXPOSE_PATTERN, content, re.MULTILINE
        ):
            port = int(match.group(1))
            if port in DockerScannerConfig.SENSITIVE_PORTS:
                service = DockerScannerConfig.SENSITIVE_PORTS[port]
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.MEDIUM,
                        category=FindingCategory.EXPOSED_API_ENDPOINT,
                        title=DockerScannerConfig.TITLE_SENSITIVE_PORT.format(
                            port=port, service=service
                        ),
                        description=DockerScannerConfig.DESC_SENSITIVE_PORT.format(
                            file=file_path, port=port, service=service
                        ),
                        file_path=file_path,
                        confidence=DockerScannerConfig.CONFIDENCE_SENSITIVE_PORT,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # 4. Hardcoded secrets in ENV
    # ------------------------------------------------------------------

    def _check_env_secrets(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for hardcoded secrets in ENV instructions."""
        findings: list[CodeFinding] = []

        for pattern, _ in DockerScannerConfig.ENV_SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.MULTILINE):
                value = match.group(1)
                # Skip variable references and empty values
                if value.startswith("$") or value.startswith("{") or not value:
                    continue
                # Skip common non-secret defaults
                if value.lower() in ("true", "false", "0", "1", "none", ""):
                    continue

                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.HIGH,
                        category=FindingCategory.EXPOSED_SECRETS,
                        title=DockerScannerConfig.TITLE_ENV_SECRET,
                        description=DockerScannerConfig.DESC_ENV_SECRET.format(
                            file=file_path
                        ),
                        file_path=file_path,
                        confidence=DockerScannerConfig.CONFIDENCE_ENV_SECRET,
                    )
                )
                # One finding per file is enough
                return findings

        return findings

    # ------------------------------------------------------------------
    # 5. ADD with remote URL
    # ------------------------------------------------------------------

    def _check_add_remote(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for ADD instructions with remote URLs."""
        if re.search(
            DockerScannerConfig.ADD_REMOTE_PATTERN, content, re.MULTILINE
        ):
            return [
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.MEDIUM,
                    category=FindingCategory.DEPENDENCY_VULNERABILITY,
                    title=DockerScannerConfig.TITLE_ADD_REMOTE,
                    description=DockerScannerConfig.DESC_ADD_REMOTE.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=DockerScannerConfig.CONFIDENCE_ADD_REMOTE,
                )
            ]
        return []

    # ------------------------------------------------------------------
    # 6. Missing HEALTHCHECK
    # ------------------------------------------------------------------

    def _check_healthcheck(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for missing HEALTHCHECK instruction."""
        if re.search(
            DockerScannerConfig.HEALTHCHECK_PATTERN, content, re.MULTILINE
        ):
            return []

        return [
            CodeFinding(
                scanner_name=self.scanner_name,
                severity=SeverityLevel.LOW,
                category=FindingCategory.INFO_DISCLOSURE,
                title=DockerScannerConfig.TITLE_NO_HEALTHCHECK,
                description=DockerScannerConfig.DESC_NO_HEALTHCHECK.format(
                    file=file_path
                ),
                file_path=file_path,
                confidence=DockerScannerConfig.CONFIDENCE_NO_HEALTHCHECK,
            )
        ]

    # ------------------------------------------------------------------
    # Docker Compose scanning
    # ------------------------------------------------------------------

    def _scan_compose_file(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Run all Docker Compose checks."""
        findings: list[CodeFinding] = []

        # 7. Default/weak passwords
        findings.extend(self._check_compose_passwords(content, file_path))

        # 8. Privileged mode
        findings.extend(self._check_privileged(content, file_path))

        # 9. Sensitive ports exposed to host
        findings.extend(self._check_compose_ports(content, file_path))

        return findings

    # ------------------------------------------------------------------
    # 7. Default/weak passwords
    # ------------------------------------------------------------------

    def _check_compose_passwords(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for default or weak passwords in compose environment."""
        findings: list[CodeFinding] = []

        for pattern in DockerScannerConfig.COMPOSE_DEFAULT_PASSWORD_PATTERNS:
            if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.MEDIUM,
                        category=FindingCategory.EXPOSED_SECRETS,
                        title=DockerScannerConfig.TITLE_DEFAULT_PASSWORD,
                        description=DockerScannerConfig.DESC_DEFAULT_PASSWORD.format(
                            file=file_path
                        ),
                        file_path=file_path,
                        confidence=DockerScannerConfig.CONFIDENCE_DEFAULT_PASSWORD,
                    )
                )
                # One finding per file
                return findings

        return findings

    # ------------------------------------------------------------------
    # 8. Privileged mode
    # ------------------------------------------------------------------

    def _check_privileged(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for privileged containers."""
        if re.search(DockerScannerConfig.PRIVILEGED_PATTERN, content):
            return [
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.CRITICAL,
                    category=FindingCategory.PRIVILEGE_ESCALATION,
                    title=DockerScannerConfig.TITLE_PRIVILEGED,
                    description=DockerScannerConfig.DESC_PRIVILEGED.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=DockerScannerConfig.CONFIDENCE_PRIVILEGED,
                )
            ]
        return []

    # ------------------------------------------------------------------
    # 9. Sensitive ports exposed to host
    # ------------------------------------------------------------------

    def _check_compose_ports(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for sensitive service ports exposed to the host."""
        findings: list[CodeFinding] = []
        seen_ports: set[int] = set()

        for match in re.finditer(
            DockerScannerConfig.COMPOSE_PORT_PATTERN, content, re.MULTILINE
        ):
            host_port = int(match.group(1))
            container_port = int(match.group(2))

            # Check if the container port is a sensitive service
            if (
                container_port in DockerScannerConfig.COMPOSE_SENSITIVE_PORTS
                and container_port not in seen_ports
            ):
                seen_ports.add(container_port)
                service = DockerScannerConfig.COMPOSE_SENSITIVE_PORTS[
                    container_port
                ]
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.LOW,
                        category=FindingCategory.EXPOSED_API_ENDPOINT,
                        title=DockerScannerConfig.TITLE_COMPOSE_PORT_EXPOSED.format(
                            service=service, port=container_port
                        ),
                        description=DockerScannerConfig.DESC_COMPOSE_PORT_EXPOSED.format(
                            file=file_path,
                            service=service,
                            port=container_port,
                        ),
                        file_path=file_path,
                        confidence=DockerScannerConfig.CONFIDENCE_COMPOSE_PORT_EXPOSED,
                    )
                )

        return findings
