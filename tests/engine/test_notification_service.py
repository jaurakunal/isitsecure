"""Tests for notification service."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.constants import NotificationConfig
from isitsecure.engine.integrations.notification_service import (
    NotificationSettings,
    ScanNotifier,
)
from isitsecure.engine.models import DeepFinding, DeepScanReport, FindingSource
from isitsecure.engine.enums import FindingCategory, SeverityLevel


def _make_finding(
    severity: SeverityLevel = SeverityLevel.CRITICAL,
    title: str = "Test finding",
    description: str = "Test description",
) -> DeepFinding:
    """Helper to create a DeepFinding."""
    return DeepFinding(
        source=FindingSource.DAST_URL,
        category=FindingCategory.AUTH_WEAKNESS,
        severity=severity,
        title=title,
        description=description,
        confidence=0.9,
        scanner_name="test_scanner",
    )


def _make_report(findings: list[DeepFinding] | None = None) -> DeepScanReport:
    """Helper to create a DeepScanReport."""
    return DeepScanReport(
        target_url="https://example.com",
        scan_mode="full",
        scan_duration_seconds=42.5,
        findings=findings or [],
    )


class TestScanNotifier:
    """Tests for ScanNotifier."""

    @pytest.mark.asyncio
    async def test_notify_webhook(self) -> None:
        """Webhook notification sends correct payload."""
        notifier = ScanNotifier()
        report = _make_report([_make_finding(SeverityLevel.HIGH)])
        settings = NotificationSettings(
            webhook_url="https://hooks.example.com/scan",
        )

        mock_response = httpx.Response(
            status_code=200,
            request=httpx.Request("POST", "https://hooks.example.com/scan"),
        )

        with patch(
            "httpx.AsyncClient.post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ) as mock_post:
            results = await notifier.notify_scan_complete(
                report=report,
                settings=settings,
                grade="B",
                report_url="https://app.example.com/reports/123",
            )

        assert results["webhook"] is True
        call_kwargs = mock_post.call_args
        posted_json = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert posted_json[NotificationConfig.WEBHOOK_EVENT_KEY] == NotificationConfig.EVENT_SCAN_COMPLETE
        assert posted_json[NotificationConfig.WEBHOOK_REPORT_KEY]["grade"] == "B"

    @pytest.mark.asyncio
    async def test_notify_slack(self) -> None:
        """Slack notification sends formatted message."""
        notifier = ScanNotifier()
        report = _make_report([_make_finding(SeverityLevel.CRITICAL)])
        settings = NotificationSettings(
            slack_webhook_url="https://hooks.slack.com/services/T/B/X",
        )

        mock_response = httpx.Response(
            status_code=200,
            request=httpx.Request("POST", "https://hooks.slack.com/services/T/B/X"),
        )

        with patch(
            "httpx.AsyncClient.post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ) as mock_post:
            results = await notifier.notify_scan_complete(
                report=report,
                settings=settings,
                grade="D",
            )

        assert results["slack"] is True
        call_kwargs = mock_post.call_args
        posted_json = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert "text" in posted_json
        assert "example.com" in posted_json["text"]

    @pytest.mark.asyncio
    async def test_notify_critical_finding(self) -> None:
        """Critical finding triggers immediate Slack + webhook notification."""
        notifier = ScanNotifier()
        finding = _make_finding(
            severity=SeverityLevel.CRITICAL,
            title="SQL Injection in /api/users",
            description="Unparameterized query allows SQL injection",
        )
        settings = NotificationSettings(
            slack_webhook_url="https://hooks.slack.com/services/T/B/X",
            webhook_url="https://hooks.example.com/scan",
            email_on_critical=True,
        )

        mock_response = httpx.Response(
            status_code=200,
            request=httpx.Request("POST", "https://test"),
        )

        with patch(
            "httpx.AsyncClient.post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            results = await notifier.notify_critical_finding(
                finding=finding,
                target="https://example.com",
                settings=settings,
            )

        assert results.get("slack") is True
        assert results.get("webhook") is True

    @pytest.mark.asyncio
    async def test_webhook_failure_handled(self) -> None:
        """Webhook connection error is caught and returns False."""
        notifier = ScanNotifier()
        report = _make_report()
        settings = NotificationSettings(
            webhook_url="https://hooks.example.com/scan",
        )

        with patch(
            "httpx.AsyncClient.post",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            results = await notifier.notify_scan_complete(
                report=report,
                settings=settings,
                grade="A",
            )

        assert results["webhook"] is False

    @pytest.mark.asyncio
    async def test_slack_failure_handled(self) -> None:
        """Slack connection error is caught and returns False."""
        notifier = ScanNotifier()
        report = _make_report()
        settings = NotificationSettings(
            slack_webhook_url="https://hooks.slack.com/services/T/B/X",
        )

        with patch(
            "httpx.AsyncClient.post",
            new_callable=AsyncMock,
            side_effect=httpx.TimeoutException("Timeout"),
        ):
            results = await notifier.notify_scan_complete(
                report=report,
                settings=settings,
                grade="A",
            )

        assert results["slack"] is False

    @pytest.mark.asyncio
    async def test_no_notifications_if_not_configured(self) -> None:
        """No notifications sent when no channels are configured."""
        notifier = ScanNotifier()
        report = _make_report([_make_finding()])
        settings = NotificationSettings()  # No webhook_url or slack_webhook_url

        results = await notifier.notify_scan_complete(
            report=report,
            settings=settings,
            grade="F",
        )

        assert results == {}

    def test_notification_settings_defaults(self) -> None:
        """NotificationSettings has correct defaults."""
        settings = NotificationSettings()
        assert settings.webhook_url is None
        assert settings.slack_webhook_url is None
        assert settings.email_on_complete is True
        assert settings.email_on_critical is True
        assert settings.email_recipients == []

    @pytest.mark.asyncio
    async def test_webhook_non_success_status(self) -> None:
        """Webhook returning 4xx/5xx is treated as failure."""
        notifier = ScanNotifier()
        report = _make_report()
        settings = NotificationSettings(
            webhook_url="https://hooks.example.com/scan",
        )

        mock_response = httpx.Response(
            status_code=500,
            request=httpx.Request("POST", "https://hooks.example.com/scan"),
        )

        with patch(
            "httpx.AsyncClient.post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ):
            results = await notifier.notify_scan_complete(
                report=report,
                settings=settings,
                grade="A",
            )

        assert results["webhook"] is False

    @pytest.mark.asyncio
    async def test_critical_finding_no_slack_if_email_on_critical_false(self) -> None:
        """Critical finding skips Slack when email_on_critical is False."""
        notifier = ScanNotifier()
        finding = _make_finding(severity=SeverityLevel.CRITICAL)
        settings = NotificationSettings(
            slack_webhook_url="https://hooks.slack.com/services/T/B/X",
            email_on_critical=False,
        )

        results = await notifier.notify_critical_finding(
            finding=finding,
            target="https://example.com",
            settings=settings,
        )

        # Slack should NOT be in results because email_on_critical is False
        assert "slack" not in results

    @pytest.mark.asyncio
    async def test_scan_complete_uses_repo_url_fallback(self) -> None:
        """Target falls back to repo_url when target_url is None."""
        notifier = ScanNotifier()
        report = DeepScanReport(repo_url="https://github.com/owner/repo")
        settings = NotificationSettings(
            webhook_url="https://hooks.example.com/scan",
        )

        mock_response = httpx.Response(
            status_code=200,
            request=httpx.Request("POST", "https://test"),
        )

        with patch(
            "httpx.AsyncClient.post",
            new_callable=AsyncMock,
            return_value=mock_response,
        ) as mock_post:
            await notifier.notify_scan_complete(
                report=report,
                settings=settings,
                grade="A",
            )

        call_kwargs = mock_post.call_args
        posted_json = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert posted_json[NotificationConfig.WEBHOOK_REPORT_KEY]["target"] == "https://github.com/owner/repo"
