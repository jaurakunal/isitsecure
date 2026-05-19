"""Tests for DockerScanner."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.docker_scanner import DockerScanner
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import DockerScannerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Content fixtures
# ---------------------------------------------------------------------------

DOCKERFILE_NO_USER = """\
FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm ci
CMD ["node", "server.js"]
"""

DOCKERFILE_WITH_USER = """\
FROM node:20-alpine
WORKDIR /app
COPY . .
RUN npm ci
USER node
CMD ["node", "server.js"]
"""

DOCKERFILE_DEV = """\
FROM node:20
WORKDIR /app
COPY . .
RUN npm install
CMD ["npm", "run", "dev"]
"""

DOCKERFILE_LATEST_TAG = """\
FROM node:latest
WORKDIR /app
COPY . .
CMD ["node", "server.js"]
"""

DOCKERFILE_PINNED_TAG = """\
FROM node:20-alpine
WORKDIR /app
COPY . .
USER node
CMD ["node", "server.js"]
"""

DOCKERFILE_SENSITIVE_PORT = """\
FROM node:20-alpine
WORKDIR /app
COPY . .
EXPOSE 5432
USER node
CMD ["node", "server.js"]
"""

DOCKERFILE_NORMAL_PORT = """\
FROM node:20-alpine
WORKDIR /app
COPY . .
EXPOSE 3000
USER node
CMD ["node", "server.js"]
"""

DOCKERFILE_WITH_HEALTHCHECK = """\
FROM node:20-alpine
WORKDIR /app
COPY . .
USER node
HEALTHCHECK CMD curl --fail http://localhost:3000/health || exit 1
CMD ["node", "server.js"]
"""

COMPOSE_DEFAULT_PASSWORD = """\
version: '3'
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"
"""

COMPOSE_PRIVILEGED = """\
version: '3'
services:
  app:
    build: .
    privileged: true
"""

COMPOSE_SENSITIVE_PORT = """\
version: '3'
services:
  db:
    image: postgres:15
    ports:
      - "5432:5432"
"""

COMPOSE_SAFE = """\
version: '3'
services:
  app:
    build: .
    ports:
      - "3000:3000"
"""

NO_DOCKER_CODE = """\
const express = require('express');
const app = express();
app.listen(3000);
"""


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_repo(
    file_index: dict[str, str] | None = None,
) -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="https://github.com/test/repo",
        branch="main",
        clone_path="/tmp/repo",
        file_index=file_index or {},
        route_map=[],
        package_json={},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestScannerName:
    def test_scanner_name(self) -> None:
        scanner = DockerScanner()
        assert scanner.scanner_name == DockerScannerConfig.SCANNER_NAME


class TestNoDockerFiles:
    @pytest.mark.asyncio
    async def test_empty_when_no_dockerfiles(self) -> None:
        """No Dockerfiles or compose files -> no findings."""
        repo = _make_repo(file_index={"src/app.ts": NO_DOCKER_CODE})
        scanner = DockerScanner()
        findings = await scanner.scan(repo)
        assert len(findings) == 0


class TestRunningAsRoot:
    @pytest.mark.asyncio
    async def test_flags_dockerfile_without_user(self) -> None:
        """Non-dev Dockerfile without USER directive -> MEDIUM finding."""
        repo = _make_repo(
            file_index={"Dockerfile": DOCKERFILE_NO_USER}
        )
        scanner = DockerScanner()
        findings = await scanner.scan(repo)

        root_findings = [
            f for f in findings
            if f.title == DockerScannerConfig.TITLE_ROOT_USER
        ]
        assert len(root_findings) == 1
        assert root_findings[0].severity == SeverityLevel.MEDIUM
        assert root_findings[0].category == FindingCategory.AUTH_WEAKNESS
        assert root_findings[0].confidence == DockerScannerConfig.CONFIDENCE_ROOT_USER


class TestNonRootUser:
    @pytest.mark.asyncio
    async def test_no_finding_when_user_directive_present(self) -> None:
        """Dockerfile with USER directive -> no root finding."""
        repo = _make_repo(
            file_index={"Dockerfile": DOCKERFILE_WITH_USER}
        )
        scanner = DockerScanner()
        findings = await scanner.scan(repo)

        root_findings = [
            f for f in findings
            if f.title == DockerScannerConfig.TITLE_ROOT_USER
        ]
        assert len(root_findings) == 0


class TestDevDockerfileSkipped:
    @pytest.mark.asyncio
    async def test_skips_root_check_for_dev_dockerfile(self) -> None:
        """Dockerfile.dev without USER -> no root finding (dev is exempt)."""
        repo = _make_repo(
            file_index={"Dockerfile.dev": DOCKERFILE_DEV}
        )
        scanner = DockerScanner()
        findings = await scanner.scan(repo)

        root_findings = [
            f for f in findings
            if f.title == DockerScannerConfig.TITLE_ROOT_USER
        ]
        assert len(root_findings) == 0


class TestLatestTag:
    @pytest.mark.asyncio
    async def test_flags_from_node_latest(self) -> None:
        """FROM node:latest -> LOW finding."""
        repo = _make_repo(
            file_index={"Dockerfile": DOCKERFILE_LATEST_TAG}
        )
        scanner = DockerScanner()
        findings = await scanner.scan(repo)

        tag_findings = [
            f for f in findings
            if f.title == DockerScannerConfig.TITLE_LATEST_TAG
        ]
        assert len(tag_findings) >= 1
        assert tag_findings[0].severity == SeverityLevel.LOW
        assert tag_findings[0].confidence == DockerScannerConfig.CONFIDENCE_LATEST_TAG


class TestPinnedTag:
    @pytest.mark.asyncio
    async def test_no_finding_for_pinned_tag(self) -> None:
        """FROM node:20-alpine -> no latest tag finding."""
        repo = _make_repo(
            file_index={"Dockerfile": DOCKERFILE_PINNED_TAG}
        )
        scanner = DockerScanner()
        findings = await scanner.scan(repo)

        tag_findings = [
            f for f in findings
            if f.title == DockerScannerConfig.TITLE_LATEST_TAG
        ]
        assert len(tag_findings) == 0


class TestSensitivePort:
    @pytest.mark.asyncio
    async def test_flags_expose_5432(self) -> None:
        """EXPOSE 5432 -> MEDIUM finding (PostgreSQL)."""
        repo = _make_repo(
            file_index={"Dockerfile": DOCKERFILE_SENSITIVE_PORT}
        )
        scanner = DockerScanner()
        findings = await scanner.scan(repo)

        port_findings = [
            f for f in findings
            if "5432" in f.title and "PostgreSQL" in f.title
        ]
        assert len(port_findings) == 1
        assert port_findings[0].severity == SeverityLevel.MEDIUM
        assert port_findings[0].confidence == DockerScannerConfig.CONFIDENCE_SENSITIVE_PORT

    @pytest.mark.asyncio
    async def test_no_finding_for_normal_port(self) -> None:
        """EXPOSE 3000 -> no finding (not a sensitive port)."""
        repo = _make_repo(
            file_index={"Dockerfile": DOCKERFILE_NORMAL_PORT}
        )
        scanner = DockerScanner()
        findings = await scanner.scan(repo)

        port_findings = [
            f for f in findings
            if "sensitive port" in f.title.lower()
        ]
        assert len(port_findings) == 0


class TestDefaultPassword:
    @pytest.mark.asyncio
    async def test_flags_postgres_password(self) -> None:
        """POSTGRES_PASSWORD: postgres in compose -> finding."""
        repo = _make_repo(
            file_index={"docker-compose.yml": COMPOSE_DEFAULT_PASSWORD}
        )
        scanner = DockerScanner()
        findings = await scanner.scan(repo)

        pw_findings = [
            f for f in findings
            if f.title == DockerScannerConfig.TITLE_DEFAULT_PASSWORD
        ]
        assert len(pw_findings) == 1
        assert pw_findings[0].severity == SeverityLevel.MEDIUM
        assert pw_findings[0].category == FindingCategory.EXPOSED_SECRETS
        assert pw_findings[0].confidence == DockerScannerConfig.CONFIDENCE_DEFAULT_PASSWORD


class TestPrivilegedMode:
    @pytest.mark.asyncio
    async def test_flags_privileged_true(self) -> None:
        """privileged: true in compose -> CRITICAL finding."""
        repo = _make_repo(
            file_index={"docker-compose.yml": COMPOSE_PRIVILEGED}
        )
        scanner = DockerScanner()
        findings = await scanner.scan(repo)

        priv_findings = [
            f for f in findings
            if f.title == DockerScannerConfig.TITLE_PRIVILEGED
        ]
        assert len(priv_findings) == 1
        assert priv_findings[0].severity == SeverityLevel.CRITICAL
        assert priv_findings[0].category == FindingCategory.PRIVILEGE_ESCALATION
        assert priv_findings[0].confidence == DockerScannerConfig.CONFIDENCE_PRIVILEGED


class TestComposePortExposed:
    @pytest.mark.asyncio
    async def test_flags_5432_port_mapping(self) -> None:
        """5432:5432 port mapping in compose -> LOW finding."""
        repo = _make_repo(
            file_index={"docker-compose.yml": COMPOSE_SENSITIVE_PORT}
        )
        scanner = DockerScanner()
        findings = await scanner.scan(repo)

        port_findings = [
            f for f in findings
            if "PostgreSQL" in f.title and "port" in f.title.lower()
        ]
        assert len(port_findings) == 1
        assert port_findings[0].severity == SeverityLevel.LOW
        assert port_findings[0].confidence == DockerScannerConfig.CONFIDENCE_COMPOSE_PORT_EXPOSED


class TestHealthcheckPresent:
    @pytest.mark.asyncio
    async def test_no_finding_when_healthcheck_exists(self) -> None:
        """Dockerfile with HEALTHCHECK -> no missing healthcheck finding."""
        repo = _make_repo(
            file_index={"Dockerfile": DOCKERFILE_WITH_HEALTHCHECK}
        )
        scanner = DockerScanner()
        findings = await scanner.scan(repo)

        hc_findings = [
            f for f in findings
            if f.title == DockerScannerConfig.TITLE_NO_HEALTHCHECK
        ]
        assert len(hc_findings) == 0

    @pytest.mark.asyncio
    async def test_flags_when_healthcheck_missing(self) -> None:
        """Non-dev Dockerfile without HEALTHCHECK -> LOW finding."""
        repo = _make_repo(
            file_index={"Dockerfile": DOCKERFILE_NO_USER}
        )
        scanner = DockerScanner()
        findings = await scanner.scan(repo)

        hc_findings = [
            f for f in findings
            if f.title == DockerScannerConfig.TITLE_NO_HEALTHCHECK
        ]
        assert len(hc_findings) == 1
        assert hc_findings[0].severity == SeverityLevel.LOW
        assert hc_findings[0].confidence == DockerScannerConfig.CONFIDENCE_NO_HEALTHCHECK
