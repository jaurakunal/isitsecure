"""CI/CD integration service for automated security scanning.

Handles:
1. Incoming webhooks from Vercel/Netlify deploys
2. GitHub commit status updates (pending -> success/failure)
3. GitHub check runs with detailed findings
4. Determining pass/fail based on severity threshold
"""

import logging
from datetime import UTC, datetime

import httpx
from pydantic import BaseModel, Field

from isitsecure.engine.constants import CICDConfig
from isitsecure.engine.enums import CICDProvider, WebhookEventType
from isitsecure.engine.models import DeepScanReport

logger = logging.getLogger(__name__)


class DeploymentWebhook(BaseModel):
    """Incoming webhook payload from a CI/CD provider."""

    provider: CICDProvider
    event_type: WebhookEventType
    deployment_url: str | None = None
    repo_url: str | None = None
    commit_sha: str | None = None
    branch: str = "main"
    project_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CICDIntegrationService:
    """Manages CI/CD integration for automated scan triggers."""

    # Severity ordering for threshold comparison
    SEVERITY_ORDER = ("low", "medium", "high", "critical")
    DEFAULT_SEVERITY_INDEX = 2  # "high"

    def __init__(self, github_token: str | None = None) -> None:
        self._github_token = github_token

    def should_fail_build(
        self,
        report: DeepScanReport,
        fail_on_severity: str = CICDConfig.FAIL_ON_SEVERITY_DEFAULT,
    ) -> bool:
        """Determine if the build should fail based on findings.

        Args:
            report: Scan results.
            fail_on_severity: Minimum severity that causes failure.
                "critical" = fail only on critical
                "high" = fail on high or critical
                "medium" = fail on medium, high, or critical
        """
        threshold_idx = (
            self.SEVERITY_ORDER.index(fail_on_severity)
            if fail_on_severity in self.SEVERITY_ORDER
            else self.DEFAULT_SEVERITY_INDEX
        )

        for finding in report.findings:
            finding_severity = finding.severity.value
            finding_idx = (
                self.SEVERITY_ORDER.index(finding_severity)
                if finding_severity in self.SEVERITY_ORDER
                else -1
            )
            if finding_idx >= threshold_idx:
                return True
        return False

    async def update_github_commit_status(
        self,
        owner: str,
        repo: str,
        sha: str,
        state: str,
        description: str,
        target_url: str | None = None,
    ) -> bool:
        """Update GitHub commit status via API.

        Args:
            owner: Repository owner.
            repo: Repository name.
            sha: Commit SHA to update status for.
            state: One of "pending", "success", "failure", "error".
            description: Short description of the status.
            target_url: URL to link from the status check.
        """
        if not self._github_token:
            return False

        url = (
            f"{CICDConfig.GITHUB_API_BASE}"
            f"{CICDConfig.GITHUB_COMMIT_STATUS_ENDPOINT.format(owner=owner, repo=repo, sha=sha)}"
        )

        async with httpx.AsyncClient(
            timeout=CICDConfig.HTTP_TIMEOUT_SECONDS,
        ) as client:
            try:
                resp = await client.post(
                    url,
                    json={
                        "state": state,
                        "description": description[
                            : CICDConfig.GITHUB_DESC_MAX_LENGTH
                        ],
                        "context": CICDConfig.STATUS_CONTEXT,
                        "target_url": target_url or "",
                    },
                    headers={
                        "Authorization": f"Bearer {self._github_token}",
                        "Accept": "application/vnd.github+json",
                    },
                )
                return resp.status_code in CICDConfig.SUCCESS_STATUS_CODES
            except Exception as exc:
                logger.error(
                    CICDConfig.ERROR_STATUS_UPDATE_FAILED.format(
                        error=str(exc),
                    ),
                )
                return False

    async def post_scan_status(
        self,
        report: DeepScanReport,
        owner: str,
        repo: str,
        sha: str,
        fail_on_severity: str = CICDConfig.FAIL_ON_SEVERITY_DEFAULT,
        report_url: str | None = None,
    ) -> bool:
        """Post scan results as a GitHub commit status."""
        should_fail = self.should_fail_build(report, fail_on_severity)

        if should_fail:
            state = "failure"
            description = CICDConfig.STATUS_FAILURE_DESC.format(
                critical=report.critical_count,
                high=report.high_count,
            )
        else:
            state = "success"
            from isitsecure.engine.reporting.report_generator import (
                ReportGenerator,
            )

            grade = ReportGenerator()._calculate_grade(report)
            description = CICDConfig.STATUS_SUCCESS_DESC.format(
                grade=grade,
                findings=len(report.findings),
            )

        return await self.update_github_commit_status(
            owner,
            repo,
            sha,
            state,
            description,
            report_url,
        )

    def parse_vercel_webhook(self, payload: dict) -> DeploymentWebhook:
        """Parse a Vercel deployment webhook payload."""
        git_source = payload.get("gitSource", {})
        return DeploymentWebhook(
            provider=CICDProvider.VERCEL,
            event_type=WebhookEventType.DEPLOYMENT,
            deployment_url=(
                payload.get("url")
                or payload.get("deployment", {}).get("url")
            ),
            repo_url=git_source.get("repoUrl"),
            commit_sha=git_source.get("sha"),
            branch=git_source.get("ref", "main"),
            project_id=payload.get("projectId"),
        )

    def parse_netlify_webhook(self, payload: dict) -> DeploymentWebhook:
        """Parse a Netlify deployment webhook payload."""
        return DeploymentWebhook(
            provider=CICDProvider.NETLIFY,
            event_type=WebhookEventType.DEPLOYMENT,
            deployment_url=(
                payload.get("ssl_url") or payload.get("url")
            ),
            repo_url=payload.get("build", {}).get("repo_url"),
            commit_sha=payload.get("commit_ref"),
            branch=payload.get("branch", "main"),
            project_id=payload.get("site_id"),
        )
