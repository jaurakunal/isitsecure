"""Tests for ShellScriptScanner."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.shell_script_scanner import (
    ShellScriptScanner,
)
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import ShellScriptScannerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Content fixtures
# ---------------------------------------------------------------------------

SCRIPT_WITH_AWS_ACCOUNT_ID = """\
#!/bin/bash
set -e

ECR_REPO="123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app"
docker push $ECR_REPO
"""

SCRIPT_CURL_PIPE_BASH = """\
#!/bin/bash
set -e

curl https://example.com/install.sh | bash
"""

SCRIPT_CHMOD_777 = """\
#!/bin/bash
set -e

chmod 777 /tmp/data
"""

SCRIPT_EVAL_VARIABLE = """\
#!/bin/bash
set -e

CMD="ls -la"
eval $CMD
"""

SCRIPT_MISSING_SET_E = """\
#!/bin/bash

echo "deploying..."
docker build -t my-app .
docker push my-app
"""

SCRIPT_WITH_SET_E = """\
#!/bin/bash
set -euo pipefail

echo "deploying..."
docker build -t my-app .
docker push my-app
"""

SCRIPT_PLACEHOLDER_SKIP = """\
#!/bin/bash
set -e

export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_FROM_VAULT
export DB_URL=${DATABASE_URL}
"""

SCRIPT_CURL_INSECURE = """\
#!/bin/bash
set -e

curl -k https://internal.example.com/api/health
"""

SCRIPT_CLEAN = """\
#!/bin/bash
set -euo pipefail

echo "Building project..."
npm run build
npm run test
"""

NO_SHELL_CODE = """\
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
        scanner = ShellScriptScanner()
        assert scanner.scanner_name == ShellScriptScannerConfig.SCANNER_NAME


class TestNoShellFiles:
    @pytest.mark.asyncio
    async def test_empty_when_no_sh_files(self) -> None:
        """No .sh files -> no findings."""
        repo = _make_repo(file_index={"src/app.ts": NO_SHELL_CODE})
        scanner = ShellScriptScanner()
        findings = await scanner.scan(repo)
        assert len(findings) == 0


class TestHardcodedAWSAccountID:
    @pytest.mark.asyncio
    async def test_flags_12_digit_account_id_in_ecr_url(self) -> None:
        """12-digit AWS account ID in ECR URL -> LOW finding."""
        repo = _make_repo(
            file_index={"deploy/push.sh": SCRIPT_WITH_AWS_ACCOUNT_ID}
        )
        scanner = ShellScriptScanner()
        findings = await scanner.scan(repo)

        aws_findings = [
            f for f in findings
            if f.title == ShellScriptScannerConfig.TITLE_AWS_ACCOUNT_ID
        ]
        assert len(aws_findings) == 1
        assert aws_findings[0].severity == SeverityLevel.LOW
        assert aws_findings[0].category == FindingCategory.INFO_DISCLOSURE
        assert aws_findings[0].confidence == ShellScriptScannerConfig.CONFIDENCE_AWS_ACCOUNT_ID
        assert "123456789012" in aws_findings[0].description


class TestCurlPipeBash:
    @pytest.mark.asyncio
    async def test_flags_curl_piped_to_bash(self) -> None:
        """curl url | bash -> HIGH finding."""
        repo = _make_repo(
            file_index={"scripts/install.sh": SCRIPT_CURL_PIPE_BASH}
        )
        scanner = ShellScriptScanner()
        findings = await scanner.scan(repo)

        curl_findings = [
            f for f in findings
            if f.title == ShellScriptScannerConfig.TITLE_CURL_PIPE
        ]
        assert len(curl_findings) == 1
        assert curl_findings[0].severity == SeverityLevel.HIGH
        assert curl_findings[0].category == FindingCategory.DEPENDENCY_VULNERABILITY
        assert curl_findings[0].confidence == ShellScriptScannerConfig.CONFIDENCE_CURL_PIPE


class TestChmod777:
    @pytest.mark.asyncio
    async def test_flags_chmod_777(self) -> None:
        """chmod 777 -> MEDIUM finding."""
        repo = _make_repo(
            file_index={"scripts/setup.sh": SCRIPT_CHMOD_777}
        )
        scanner = ShellScriptScanner()
        findings = await scanner.scan(repo)

        chmod_findings = [
            f for f in findings
            if f.title == ShellScriptScannerConfig.TITLE_CHMOD_PERMISSIVE
        ]
        assert len(chmod_findings) == 1
        assert chmod_findings[0].severity == SeverityLevel.MEDIUM
        assert chmod_findings[0].category == FindingCategory.AUTH_WEAKNESS
        assert chmod_findings[0].confidence == ShellScriptScannerConfig.CONFIDENCE_CHMOD_PERMISSIVE


class TestEvalVariable:
    @pytest.mark.asyncio
    async def test_flags_eval_with_variable(self) -> None:
        """eval $var -> MEDIUM finding."""
        repo = _make_repo(
            file_index={"scripts/run.sh": SCRIPT_EVAL_VARIABLE}
        )
        scanner = ShellScriptScanner()
        findings = await scanner.scan(repo)

        eval_findings = [
            f for f in findings
            if f.title == ShellScriptScannerConfig.TITLE_EVAL_VARIABLE
        ]
        assert len(eval_findings) == 1
        assert eval_findings[0].severity == SeverityLevel.MEDIUM
        assert eval_findings[0].category == FindingCategory.INJECTION_RISK
        assert eval_findings[0].confidence == ShellScriptScannerConfig.CONFIDENCE_EVAL_VARIABLE


class TestMissingSetE:
    @pytest.mark.asyncio
    async def test_flags_scripts_without_set_e(self) -> None:
        """Script without set -e -> LOW finding."""
        repo = _make_repo(
            file_index={"scripts/deploy.sh": SCRIPT_MISSING_SET_E}
        )
        scanner = ShellScriptScanner()
        findings = await scanner.scan(repo)

        set_e_findings = [
            f for f in findings
            if f.title == ShellScriptScannerConfig.TITLE_NO_SET_E
        ]
        assert len(set_e_findings) == 1
        assert set_e_findings[0].severity == SeverityLevel.LOW
        assert set_e_findings[0].category == FindingCategory.INFO_DISCLOSURE
        assert set_e_findings[0].confidence == ShellScriptScannerConfig.CONFIDENCE_NO_SET_E


class TestSetEPresent:
    @pytest.mark.asyncio
    async def test_no_finding_when_set_e_exists(self) -> None:
        """Script with set -euo pipefail -> no missing set -e finding."""
        repo = _make_repo(
            file_index={"scripts/deploy.sh": SCRIPT_WITH_SET_E}
        )
        scanner = ShellScriptScanner()
        findings = await scanner.scan(repo)

        set_e_findings = [
            f for f in findings
            if f.title == ShellScriptScannerConfig.TITLE_NO_SET_E
        ]
        assert len(set_e_findings) == 0


class TestPlaceholderSkipped:
    @pytest.mark.asyncio
    async def test_skips_values_starting_with_dollar(self) -> None:
        """Values starting with $ or ${ should not be flagged as hardcoded secrets."""
        repo = _make_repo(
            file_index={"scripts/env.sh": SCRIPT_PLACEHOLDER_SKIP}
        )
        scanner = ShellScriptScanner()
        findings = await scanner.scan(repo)

        secret_findings = [
            f for f in findings
            if f.category == FindingCategory.EXPOSED_SECRETS
        ]
        assert len(secret_findings) == 0


class TestCurlInsecure:
    @pytest.mark.asyncio
    async def test_flags_curl_k(self) -> None:
        """curl -k -> MEDIUM finding."""
        repo = _make_repo(
            file_index={"scripts/check.sh": SCRIPT_CURL_INSECURE}
        )
        scanner = ShellScriptScanner()
        findings = await scanner.scan(repo)

        insecure_findings = [
            f for f in findings
            if f.title == ShellScriptScannerConfig.TITLE_CURL_INSECURE
        ]
        assert len(insecure_findings) == 1
        assert insecure_findings[0].severity == SeverityLevel.MEDIUM
        assert insecure_findings[0].category == FindingCategory.AUTH_WEAKNESS
        assert insecure_findings[0].confidence == ShellScriptScannerConfig.CONFIDENCE_CURL_INSECURE


class TestCleanScript:
    @pytest.mark.asyncio
    async def test_clean_script_minimal_findings(self) -> None:
        """Clean script with set -euo pipefail -> no security findings."""
        repo = _make_repo(
            file_index={"scripts/build.sh": SCRIPT_CLEAN}
        )
        scanner = ShellScriptScanner()
        findings = await scanner.scan(repo)

        # A clean script should have no findings at all
        assert len(findings) == 0
