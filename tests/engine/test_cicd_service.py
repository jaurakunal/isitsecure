"""Tests for CI/CD integration service."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.constants import CICDConfig
from isitsecure.engine.enums import CICDProvider, WebhookEventType
from isitsecure.engine.integrations.cicd_service import (
    CICDIntegrationService,
    DeploymentWebhook,
)
from isitsecure.engine.models import DeepFinding, DeepScanReport, FindingSource
from isitsecure.engine.enums import FindingCategory, SeverityLevel


def _make_finding(severity: SeverityLevel) -> DeepFinding:
    """Helper to create a DeepFinding with a given severity."""
    return DeepFinding(
        source=FindingSource.DAST_URL,
        category=FindingCategory.AUTH_WEAKNESS,
        severity=severity,
        title="Test finding",
        description="Test description",
        confidence=0.9,
        scanner_name="test_scanner",
    )


def _make_report(findings: list[DeepFinding] | None = None) -> DeepScanReport:
    """Helper to create a DeepScanReport."""
    return DeepScanReport(
        target_url="https://example.com",
        findings=findings or [],
    )


class TestCICDIntegrationService:
    """Tests for CICDIntegrationService."""

    def test_should_fail_build_critical(self) -> None:
        """Critical finding should fail build with default threshold."""
        service = CICDIntegrationService()
        report = _make_report([_make_finding(SeverityLevel.CRITICAL)])
        assert service.should_fail_build(report) is True

    def test_should_fail_build_high(self) -> None:
        """High finding should fail build with default threshold (high)."""
        service = CICDIntegrationService()
        report = _make_report([_make_finding(SeverityLevel.HIGH)])
        assert service.should_fail_build(report) is True

    def test_should_not_fail_low(self) -> None:
        """Low finding should not fail build with default threshold."""
        service = CICDIntegrationService()
        report = _make_report([_make_finding(SeverityLevel.LOW)])
        assert service.should_fail_build(report) is False

    def test_should_not_fail_empty(self) -> None:
        """Empty report should not fail build."""
        service = CICDIntegrationService()
        report = _make_report([])
        assert service.should_fail_build(report) is False

    def test_should_fail_medium_with_medium_threshold(self) -> None:
        """Medium finding should fail when threshold is medium."""
        service = CICDIntegrationService()
        report = _make_report([_make_finding(SeverityLevel.MEDIUM)])
        assert service.should_fail_build(report, fail_on_severity="medium") is True

    def test_should_not_fail_medium_with_high_threshold(self) -> None:
        """Medium finding should not fail when threshold is high."""
        service = CICDIntegrationService()
        report = _make_report([_make_finding(SeverityLevel.MEDIUM)])
        assert service.should_fail_build(report, fail_on_severity="high") is False

    def test_should_fail_critical_only_threshold(self) -> None:
        """High finding should not fail when threshold is critical."""
        service = CICDIntegrationService()
        report = _make_report([_make_finding(SeverityLevel.HIGH)])
        assert service.should_fail_build(report, fail_on_severity="critical") is False

    @pytest.mark.asyncio
    async def test_update_github_status_success(self) -> None:
        """Successful GitHub status update returns True."""
        service = CICDIntegrationService(github_token="ghp_test_token")

        mock_response = httpx.Response(status_code=201, request=httpx.Request("POST", "https://test"))

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            result = await service.update_github_commit_status(
                owner="test-owner",
                repo="test-repo",
                sha="abc123",
                state="success",
                description="All good",
            )
        assert result is True

    @pytest.mark.asyncio
    async def test_update_github_status_no_token(self) -> None:
        """Missing GitHub token returns False without making request."""
        service = CICDIntegrationService(github_token=None)
        result = await service.update_github_commit_status(
            owner="test-owner",
            repo="test-repo",
            sha="abc123",
            state="success",
            description="All good",
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_update_github_status_http_error(self) -> None:
        """HTTP error is caught and returns False."""
        service = CICDIntegrationService(github_token="ghp_test_token")

        with patch(
            "httpx.AsyncClient.post",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            result = await service.update_github_commit_status(
                owner="test-owner",
                repo="test-repo",
                sha="abc123",
                state="pending",
                description=CICDConfig.STATUS_PENDING_DESC,
            )
        assert result is False

    @pytest.mark.asyncio
    async def test_post_scan_status_pass(self) -> None:
        """Passing scan posts success status."""
        service = CICDIntegrationService(github_token="ghp_test_token")
        report = _make_report([_make_finding(SeverityLevel.LOW)])

        mock_response = httpx.Response(status_code=201, request=httpx.Request("POST", "https://test"))

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            result = await service.post_scan_status(
                report=report,
                owner="owner",
                repo="repo",
                sha="abc123",
            )
        assert result is True

    @pytest.mark.asyncio
    async def test_post_scan_status_fail(self) -> None:
        """Failing scan posts failure status."""
        service = CICDIntegrationService(github_token="ghp_test_token")
        report = _make_report([_make_finding(SeverityLevel.CRITICAL)])

        mock_response = httpx.Response(status_code=201, request=httpx.Request("POST", "https://test"))

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response) as mock_post:
            result = await service.post_scan_status(
                report=report,
                owner="owner",
                repo="repo",
                sha="abc123",
            )
        assert result is True
        # Verify it posted failure state
        call_kwargs = mock_post.call_args
        posted_json = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert posted_json["state"] == "failure"

    def test_parse_vercel_webhook(self) -> None:
        """Vercel webhook payload is parsed correctly."""
        service = CICDIntegrationService()
        payload = {
            "url": "https://my-app-abc123.vercel.app",
            "projectId": "prj_abc",
            "gitSource": {
                "repoUrl": "https://github.com/owner/repo",
                "sha": "deadbeef",
                "ref": "feature-branch",
            },
        }
        webhook = service.parse_vercel_webhook(payload)

        assert webhook.provider == CICDProvider.VERCEL
        assert webhook.event_type == WebhookEventType.DEPLOYMENT
        assert webhook.deployment_url == "https://my-app-abc123.vercel.app"
        assert webhook.commit_sha == "deadbeef"
        assert webhook.branch == "feature-branch"
        assert webhook.project_id == "prj_abc"

    def test_parse_netlify_webhook(self) -> None:
        """Netlify webhook payload is parsed correctly."""
        service = CICDIntegrationService()
        payload = {
            "ssl_url": "https://my-app.netlify.app",
            "site_id": "site_abc",
            "commit_ref": "cafebabe",
            "branch": "main",
            "build": {
                "repo_url": "https://github.com/owner/repo",
            },
        }
        webhook = service.parse_netlify_webhook(payload)

        assert webhook.provider == CICDProvider.NETLIFY
        assert webhook.event_type == WebhookEventType.DEPLOYMENT
        assert webhook.deployment_url == "https://my-app.netlify.app"
        assert webhook.commit_sha == "cafebabe"
        assert webhook.branch == "main"
        assert webhook.project_id == "site_abc"

    def test_parse_vercel_webhook_fallback_url(self) -> None:
        """Vercel webhook falls back to deployment.url if url is missing."""
        service = CICDIntegrationService()
        payload = {
            "deployment": {"url": "https://fallback.vercel.app"},
            "gitSource": {},
        }
        webhook = service.parse_vercel_webhook(payload)
        assert webhook.deployment_url == "https://fallback.vercel.app"

    def test_parse_netlify_webhook_fallback_url(self) -> None:
        """Netlify webhook falls back to url if ssl_url is missing."""
        service = CICDIntegrationService()
        payload = {
            "url": "http://my-app.netlify.app",
            "build": {},
        }
        webhook = service.parse_netlify_webhook(payload)
        assert webhook.deployment_url == "http://my-app.netlify.app"


class TestDeploymentWebhook:
    """Tests for the DeploymentWebhook model."""

    def test_model_creation(self) -> None:
        """DeploymentWebhook can be created with required fields."""
        webhook = DeploymentWebhook(
            provider=CICDProvider.GITHUB_ACTIONS,
            event_type=WebhookEventType.PUSH,
            commit_sha="abc123",
        )
        assert webhook.provider == CICDProvider.GITHUB_ACTIONS
        assert webhook.event_type == WebhookEventType.PUSH
        assert webhook.commit_sha == "abc123"

    def test_default_branch(self) -> None:
        """Default branch is 'main'."""
        webhook = DeploymentWebhook(
            provider=CICDProvider.VERCEL,
            event_type=WebhookEventType.DEPLOYMENT,
        )
        assert webhook.branch == "main"

    def test_timestamp_auto_set(self) -> None:
        """Timestamp is automatically set."""
        webhook = DeploymentWebhook(
            provider=CICDProvider.NETLIFY,
            event_type=WebhookEventType.MANUAL,
        )
        assert webhook.timestamp is not None

    def test_optional_fields_none(self) -> None:
        """Optional fields default to None."""
        webhook = DeploymentWebhook(
            provider=CICDProvider.VERCEL,
            event_type=WebhookEventType.DEPLOYMENT,
        )
        assert webhook.deployment_url is None
        assert webhook.repo_url is None
        assert webhook.commit_sha is None
        assert webhook.project_id is None
