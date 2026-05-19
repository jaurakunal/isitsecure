"""File upload vulnerability scanner.

Tests file upload endpoints for:
1. Unrestricted file type acceptance -- dangerous extensions like .html, .svg
2. Path traversal via filenames -- ../../../etc/passwd style names
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from isitsecure.engine.constants import DeepScanConfig, FileUploadConfig
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot

logger = logging.getLogger(__name__)


class FileUploadScanner:
    """Tests file upload endpoints for vulnerabilities.

    Detects upload endpoints from path indicators, then tests for
    dangerous file type acceptance and path traversal.
    """

    HTTP_STATUS_OK_LOWER = 200
    HTTP_STATUS_OK_UPPER = 300
    SAFE_FILE_CONTENT = b"test"
    FORM_FIELD_NAME = "file"

    @property
    def scanner_name(self) -> str:
        """Unique name identifying this scanner."""
        return FileUploadConfig.SCANNER_NAME

    @property
    def scan_categories(self) -> list[FindingCategory]:
        """Finding categories this scanner can detect."""
        return [FindingCategory.INJECTION_RISK]

    async def scan(
        self,
        endpoints: list[DiscoveredEndpoint],
        snapshot: CodebaseSnapshot | None = None,
    ) -> list[DeepFinding]:
        """Run file upload vulnerability tests on discovered endpoints.

        Args:
            endpoints: Endpoints discovered during the discovery phase.
            snapshot: Optional codebase snapshot (unused by this scanner).

        Returns:
            List of unified findings from this scanner.
        """
        findings: list[DeepFinding] = []

        upload_endpoints = self._detect_upload_endpoints(endpoints)
        if not upload_endpoints:
            logger.info("FileUploadScanner: no upload endpoints detected")
            return findings

        async with RateLimitedClient(
            max_concurrent=FileUploadConfig.MAX_CONCURRENT,
            delay_seconds=FileUploadConfig.PROBE_DELAY,
            timeout_seconds=FileUploadConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            for endpoint in upload_endpoints:
                ep_findings = await self._test_endpoint(client, endpoint)
                findings.extend(ep_findings)

        logger.info("FileUploadScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Endpoint detection
    # ------------------------------------------------------------------

    def _detect_upload_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """Filter endpoints that look like file upload endpoints."""
        upload_eps: list[DiscoveredEndpoint] = []
        for ep in endpoints:
            parsed = urlparse(ep.url)
            path_lower = parsed.path.lower()
            if any(
                indicator in path_lower
                for indicator in FileUploadConfig.UPLOAD_PATH_INDICATORS
            ):
                upload_eps.append(ep)
        return upload_eps

    # ------------------------------------------------------------------
    # Per-endpoint testing
    # ------------------------------------------------------------------

    async def _test_endpoint(
        self,
        client: RateLimitedClient,
        endpoint: DiscoveredEndpoint,
    ) -> list[DeepFinding]:
        """Run all file upload tests on a single endpoint."""
        findings: list[DeepFinding] = []

        type_findings = await self._test_dangerous_types(client, endpoint.url)
        findings.extend(type_findings)

        traversal_findings = await self._test_path_traversal(client, endpoint.url)
        findings.extend(traversal_findings)

        return findings

    # ------------------------------------------------------------------
    # Dangerous file type test
    # ------------------------------------------------------------------

    async def _test_dangerous_types(
        self, client: RateLimitedClient, url: str
    ) -> list[DeepFinding]:
        """Test if the upload endpoint accepts dangerous file types."""
        findings: list[DeepFinding] = []

        for ext, content_type, payload in FileUploadConfig.DANGEROUS_EXTENSIONS:
            finding = await self._upload_file(
                client, url, f"test{ext}", content_type, payload.encode()
            )
            if finding:
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.INJECTION_RISK,
                        severity=SeverityLevel.HIGH,
                        title=FileUploadConfig.TITLE_UNRESTRICTED_TYPE,
                        description=FileUploadConfig.DESC_UNRESTRICTED_TYPE.format(
                            url=url, ext=ext, content_type=content_type
                        ),
                        technical_detail=(
                            f"Uploaded test{ext} with content-type {content_type}\n"
                            f"Server returned 2xx, indicating the file was accepted"
                        ),
                        evidence=f"POST {url} with test{ext} -> accepted",
                        confidence=FileUploadConfig.CONFIDENCE_UNRESTRICTED,
                        scanner_name=self.scanner_name,
                        endpoint_url=url,
                        http_method="POST",
                        request_payload=f"filename=test{ext}",
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Path traversal test
    # ------------------------------------------------------------------

    async def _test_path_traversal(
        self, client: RateLimitedClient, url: str
    ) -> list[DeepFinding]:
        """Test if the upload endpoint is vulnerable to path traversal."""
        findings: list[DeepFinding] = []

        for traversal_filename in FileUploadConfig.PATH_TRAVERSAL_FILENAMES:
            result = await self._upload_file(
                client, url, traversal_filename, "text/plain", self.SAFE_FILE_CONTENT
            )
            if result:
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.INJECTION_RISK,
                        severity=SeverityLevel.CRITICAL,
                        title=FileUploadConfig.TITLE_PATH_TRAVERSAL,
                        description=FileUploadConfig.DESC_PATH_TRAVERSAL.format(
                            url=url, filename=traversal_filename
                        ),
                        technical_detail=(
                            f"Uploaded file with name '{traversal_filename}'\n"
                            f"Server returned 2xx, suggesting the name was accepted"
                        ),
                        evidence=(
                            f"POST {url} with filename='{traversal_filename}' "
                            f"-> accepted"
                        ),
                        confidence=FileUploadConfig.CONFIDENCE_PATH_TRAVERSAL,
                        scanner_name=self.scanner_name,
                        endpoint_url=url,
                        http_method="POST",
                        request_payload=f"filename={traversal_filename}",
                    )
                )
                # One traversal finding per endpoint is enough
                break

        return findings

    # ------------------------------------------------------------------
    # Upload helper
    # ------------------------------------------------------------------

    async def _upload_file(
        self,
        client: RateLimitedClient,
        url: str,
        filename: str,
        content_type: str,
        content: bytes,
    ) -> bool:
        """Attempt to upload a file and return True if the server accepted it."""
        try:
            files = {
                self.FORM_FIELD_NAME: (filename, content, content_type),
            }
            response = await client.post(url, files=files)

            return (
                self.HTTP_STATUS_OK_LOWER
                <= response.status_code
                < self.HTTP_STATUS_OK_UPPER
            )

        except Exception as exc:
            logger.debug(
                FileUploadConfig.ERROR_UPLOAD_SCAN_FAILED.format(
                    endpoint=url, error=str(exc)
                )
            )
            return False
