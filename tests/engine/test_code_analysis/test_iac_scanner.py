"""Tests for IaCScanner."""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.iac_scanner import IaCScanner
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import IaCScannerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel


# ---------------------------------------------------------------------------
# Content fixtures
# ---------------------------------------------------------------------------

TF_OPEN_SG_SSH = """\
resource "aws_security_group" "allow_ssh" {
  name = "allow_ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

TF_OPEN_SG_HTTP = """\
resource "aws_security_group" "allow_http" {
  name = "allow_http"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

TF_OPEN_SG_HTTPS = """\
resource "aws_security_group" "allow_https" {
  name = "allow_https"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

TF_WILDCARD_IAM_ACTION = """\
resource "aws_iam_policy" "admin" {
  name = "admin-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      "Action": "*"
      "Resource": "arn:aws:s3:::my-bucket/*"
    }]
  })
}
"""

TF_SCOPED_IAM_ACTION = """\
resource "aws_iam_policy" "s3_read" {
  name = "s3-read-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      "Action": "s3:GetObject"
      "Resource": "arn:aws:s3:::my-bucket/*"
    }]
  })
}
"""

TF_HARDCODED_SECRET = """\
variable "stripe_key" {
  type    = string
  default = "sk_live_abc123def456ghi789jkl012mno"
}
"""

TF_RECOVERY_WINDOW_ZERO = """\
resource "aws_secretsmanager_secret" "my_secret" {
  name                    = "my-app-secret"
  recovery_window_in_days = 0
}
"""

TF_SHORT_LOG_RETENTION = """\
resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/my-app"
  retention_in_days = 7
}
"""

TF_ADEQUATE_LOG_RETENTION = """\
resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/my-app"
  retention_in_days = 90
}
"""

TF_ECS_PUBLIC_IP = """\
resource "aws_ecs_service" "app" {
  name            = "my-app"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn

  network_configuration {
    subnets          = var.public_subnets
    assign_public_ip = true
  }
}
"""

NO_TF_CODE = """\
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
        scanner = IaCScanner()
        assert scanner.scanner_name == IaCScannerConfig.SCANNER_NAME


class TestNoTfFiles:
    @pytest.mark.asyncio
    async def test_empty_when_no_tf_files(self) -> None:
        """No .tf files -> no findings."""
        repo = _make_repo(file_index={"src/app.ts": NO_TF_CODE})
        scanner = IaCScanner()
        findings = await scanner.scan(repo)
        assert len(findings) == 0


class TestOpenSecurityGroup:
    @pytest.mark.asyncio
    async def test_flags_ssh_open_to_world(self) -> None:
        """0.0.0.0/0 on port 22 (SSH) -> HIGH finding."""
        repo = _make_repo(
            file_index={"infra/main.tf": TF_OPEN_SG_SSH}
        )
        scanner = IaCScanner()
        findings = await scanner.scan(repo)

        sg_findings = [
            f for f in findings
            if "port 22" in f.title
        ]
        assert len(sg_findings) == 1
        assert sg_findings[0].severity == SeverityLevel.HIGH
        assert sg_findings[0].category == FindingCategory.EXPOSED_API_ENDPOINT
        assert sg_findings[0].confidence == IaCScannerConfig.CONFIDENCE_OPEN_SG


class TestAcceptablePublicPorts:
    @pytest.mark.asyncio
    async def test_does_not_flag_port_80(self) -> None:
        """Port 80 with 0.0.0.0/0 is acceptable -> no finding."""
        repo = _make_repo(
            file_index={"infra/main.tf": TF_OPEN_SG_HTTP}
        )
        scanner = IaCScanner()
        findings = await scanner.scan(repo)

        sg_findings = [
            f for f in findings
            if "Security group" in f.title
        ]
        assert len(sg_findings) == 0

    @pytest.mark.asyncio
    async def test_does_not_flag_port_443(self) -> None:
        """Port 443 with 0.0.0.0/0 is acceptable -> no finding."""
        repo = _make_repo(
            file_index={"infra/main.tf": TF_OPEN_SG_HTTPS}
        )
        scanner = IaCScanner()
        findings = await scanner.scan(repo)

        sg_findings = [
            f for f in findings
            if "Security group" in f.title
        ]
        assert len(sg_findings) == 0


class TestWildcardIAMAction:
    @pytest.mark.asyncio
    async def test_flags_action_star(self) -> None:
        """IAM policy with Action: '*' -> HIGH finding."""
        repo = _make_repo(
            file_index={"infra/iam.tf": TF_WILDCARD_IAM_ACTION}
        )
        scanner = IaCScanner()
        findings = await scanner.scan(repo)

        iam_findings = [
            f for f in findings
            if f.title == IaCScannerConfig.TITLE_WILDCARD_IAM_ACTION
        ]
        assert len(iam_findings) == 1
        assert iam_findings[0].severity == SeverityLevel.HIGH
        assert iam_findings[0].category == FindingCategory.PRIVILEGE_ESCALATION
        assert iam_findings[0].confidence == IaCScannerConfig.CONFIDENCE_WILDCARD_IAM


class TestScopedIAMAction:
    @pytest.mark.asyncio
    async def test_does_not_flag_specific_actions(self) -> None:
        """Scoped IAM action -> no wildcard finding."""
        repo = _make_repo(
            file_index={"infra/iam.tf": TF_SCOPED_IAM_ACTION}
        )
        scanner = IaCScanner()
        findings = await scanner.scan(repo)

        iam_findings = [
            f for f in findings
            if f.title == IaCScannerConfig.TITLE_WILDCARD_IAM_ACTION
        ]
        assert len(iam_findings) == 0


class TestHardcodedSecret:
    @pytest.mark.asyncio
    async def test_flags_sk_live_in_variable_default(self) -> None:
        """default = "sk_live_xxx" in tfvars -> CRITICAL finding."""
        repo = _make_repo(
            file_index={"infra/variables.tfvars": TF_HARDCODED_SECRET}
        )
        scanner = IaCScanner()
        findings = await scanner.scan(repo)

        secret_findings = [
            f for f in findings
            if f.category == FindingCategory.EXPOSED_SECRETS
        ]
        assert len(secret_findings) >= 1
        assert secret_findings[0].severity == SeverityLevel.CRITICAL
        assert secret_findings[0].confidence == IaCScannerConfig.CONFIDENCE_HARDCODED_SECRET


class TestRecoveryWindowZero:
    @pytest.mark.asyncio
    async def test_flags_recovery_window_zero(self) -> None:
        """recovery_window_in_days = 0 -> MEDIUM finding."""
        repo = _make_repo(
            file_index={"infra/secrets.tf": TF_RECOVERY_WINDOW_ZERO}
        )
        scanner = IaCScanner()
        findings = await scanner.scan(repo)

        recovery_findings = [
            f for f in findings
            if f.title == IaCScannerConfig.TITLE_RECOVERY_ZERO
        ]
        assert len(recovery_findings) == 1
        assert recovery_findings[0].severity == SeverityLevel.MEDIUM
        assert recovery_findings[0].confidence == IaCScannerConfig.CONFIDENCE_RECOVERY_ZERO


class TestShortLogRetention:
    @pytest.mark.asyncio
    async def test_flags_retention_7_days(self) -> None:
        """retention_in_days = 7 -> LOW finding."""
        repo = _make_repo(
            file_index={"infra/logs.tf": TF_SHORT_LOG_RETENTION}
        )
        scanner = IaCScanner()
        findings = await scanner.scan(repo)

        log_findings = [
            f for f in findings
            if "log retention" in f.title.lower()
        ]
        assert len(log_findings) == 1
        assert log_findings[0].severity == SeverityLevel.LOW
        assert log_findings[0].confidence == IaCScannerConfig.CONFIDENCE_SHORT_LOG_RETENTION

    @pytest.mark.asyncio
    async def test_no_finding_for_adequate_retention(self) -> None:
        """retention_in_days = 90 -> no finding."""
        repo = _make_repo(
            file_index={"infra/logs.tf": TF_ADEQUATE_LOG_RETENTION}
        )
        scanner = IaCScanner()
        findings = await scanner.scan(repo)

        log_findings = [
            f for f in findings
            if "log retention" in f.title.lower()
        ]
        assert len(log_findings) == 0


class TestECSPublicIP:
    @pytest.mark.asyncio
    async def test_flags_assign_public_ip_true(self) -> None:
        """assign_public_ip = true -> LOW finding."""
        repo = _make_repo(
            file_index={"infra/ecs.tf": TF_ECS_PUBLIC_IP}
        )
        scanner = IaCScanner()
        findings = await scanner.scan(repo)

        ecs_findings = [
            f for f in findings
            if f.title == IaCScannerConfig.TITLE_ECS_PUBLIC_IP
        ]
        assert len(ecs_findings) == 1
        assert ecs_findings[0].severity == SeverityLevel.LOW
        assert ecs_findings[0].category == FindingCategory.INFO_DISCLOSURE
        assert ecs_findings[0].confidence == IaCScannerConfig.CONFIDENCE_ECS_PUBLIC_IP
