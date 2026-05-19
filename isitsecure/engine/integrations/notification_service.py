"""Notification service for scan events.

Sends notifications when:
1. Scan completes (email, webhook, Slack)
2. Critical finding discovered (immediate alert)
"""

import logging

import httpx
from pydantic import BaseModel, Field

from isitsecure.engine.constants import NotificationConfig
from isitsecure.engine.models import DeepFinding, DeepScanReport

logger = logging.getLogger(__name__)


class NotificationSettings(BaseModel):
    """Per-project notification configuration."""

    webhook_url: str | None = None
    email_on_complete: bool = True
    email_on_critical: bool = True
    slack_webhook_url: str | None = None
    email_recipients: list[str] = Field(default_factory=list)


class ScanNotifier:
    """Sends notifications for scan events."""

    async def notify_scan_complete(
        self,
        report: DeepScanReport,
        settings: NotificationSettings,
        grade: str = "",
        report_url: str | None = None,
    ) -> dict[str, bool]:
        """Send scan-complete notifications.

        Returns:
            Dict mapping channel name to success/failure boolean.
        """
        results: dict[str, bool] = {}
        target = report.target_url or report.repo_url or "unknown"

        if settings.webhook_url:
            results["webhook"] = await self._post_webhook(
                settings.webhook_url,
                event=NotificationConfig.EVENT_SCAN_COMPLETE,
                data={
                    "target": target,
                    "grade": grade,
                    "total_findings": len(report.findings),
                    "critical": report.critical_count,
                    "high": report.high_count,
                    "report_url": report_url,
                    "scan_mode": report.scan_mode,
                    "duration_seconds": report.scan_duration_seconds,
                },
            )

        if settings.slack_webhook_url:
            text = NotificationConfig.SLACK_COMPLETE_TEXT.format(
                target=target,
                grade=grade,
                total=len(report.findings),
                critical=report.critical_count,
                high=report.high_count,
                report_url=report_url or "",
            )
            results["slack"] = await self._post_slack(
                settings.slack_webhook_url,
                text,
            )

        return results

    async def notify_critical_finding(
        self,
        finding: DeepFinding,
        target: str,
        settings: NotificationSettings,
    ) -> dict[str, bool]:
        """Send immediate notification for critical findings."""
        results: dict[str, bool] = {}

        if settings.slack_webhook_url and settings.email_on_critical:
            text = NotificationConfig.SLACK_CRITICAL_TEXT.format(
                target=target,
                title=finding.title,
                description=finding.description[
                    : NotificationConfig.DESCRIPTION_PREVIEW_LENGTH
                ],
            )
            results["slack"] = await self._post_slack(
                settings.slack_webhook_url,
                text,
            )

        if settings.webhook_url:
            results["webhook"] = await self._post_webhook(
                settings.webhook_url,
                event=NotificationConfig.EVENT_CRITICAL_FINDING,
                data={
                    "target": target,
                    "finding": {
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "category": finding.category.value,
                        "description": finding.description,
                    },
                },
            )

        return results

    async def _post_webhook(
        self,
        url: str,
        event: str,
        data: dict,
    ) -> bool:
        """POST to a webhook URL."""
        try:
            async with httpx.AsyncClient(
                timeout=NotificationConfig.HTTP_TIMEOUT_SECONDS,
            ) as client:
                resp = await client.post(
                    url,
                    json={
                        NotificationConfig.WEBHOOK_EVENT_KEY: event,
                        NotificationConfig.WEBHOOK_REPORT_KEY: data,
                    },
                )
                return resp.status_code < NotificationConfig.MAX_SUCCESS_STATUS_CODE
        except Exception as exc:
            logger.error(
                NotificationConfig.ERROR_WEBHOOK_FAILED.format(
                    error=str(exc),
                ),
            )
            return False

    async def _post_slack(self, webhook_url: str, text: str) -> bool:
        """POST to a Slack webhook."""
        try:
            async with httpx.AsyncClient(
                timeout=NotificationConfig.HTTP_TIMEOUT_SECONDS,
            ) as client:
                resp = await client.post(
                    webhook_url,
                    json={"text": text},
                )
                return resp.status_code == 200
        except Exception as exc:
            logger.error(
                NotificationConfig.ERROR_SLACK_FAILED.format(
                    error=str(exc),
                ),
            )
            return False
