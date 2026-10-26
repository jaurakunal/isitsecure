"""File upload vulnerability scanner.

Tests file upload endpoints for:
1. Unrestricted file type acceptance -- dangerous extensions like .html, .svg
2. Path traversal via filenames -- ../../../etc/passwd style names
"""

from __future__ import annotations

import json
import logging
import re
from urllib.parse import urljoin, urlparse

import httpx

from isitsecure.engine.constants import DeepScanConfig, FileUploadConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import CodebaseSnapshot
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.shared.auth_aware import AuthAwareScanner
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.shared.time_budget import TimeBudget

logger = logging.getLogger(__name__)


class FileUploadScanner(AuthAwareScanner):
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
            extra_headers=self.auth_headers,
        ) as client:
            # Stop cooperatively before the runner's hard timeout cancels us
            # (which discards every finding so far).
            budget = TimeBudget()
            for endpoint in upload_endpoints:
                if budget.expired():
                    logger.info("FileUploadScanner: time budget reached, stopping early")
                    break
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
                client, url, f"test{ext}", content_type, payload.encode(),
                payload_marker=payload,
            )
            if finding:
                unverified = finding == self.NO_STORAGE_EVIDENCE
                findings.append(
                    DeepFinding(
                        source=FindingSource.DAST_URL,
                        category=FindingCategory.INJECTION_RISK,
                        severity=(
                            SeverityLevel.MEDIUM if unverified else SeverityLevel.HIGH
                        ),
                        title=FileUploadConfig.TITLE_UNRESTRICTED_TYPE,
                        description=FileUploadConfig.DESC_UNRESTRICTED_TYPE.format(
                            url=url, ext=ext, content_type=content_type
                        ),
                        technical_detail=(
                            f"Uploaded test{ext} with content-type {content_type}\n"
                            "Server returned 2xx with a non-failure body, but evidence "
                            "of storage was not found (the response does not name or "
                            "link the file)"
                            if unverified
                            else f"Server returned 2xx with a success body that "
                            f"references the stored file ({finding})"
                        ),
                        evidence=(
                            f"POST {url} with test{ext} -> 2xx; evidence of storage "
                            f"was not found"
                            if unverified
                            else f"POST {url} with test{ext} -> accepted ({finding})"
                        ),
                        confidence=(
                            min(0.4, FileUploadConfig.CONFIDENCE_UNRESTRICTED)
                            if unverified
                            else FileUploadConfig.CONFIDENCE_UNRESTRICTED
                        ),
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
                client, url, traversal_filename, "text/plain", self.SAFE_FILE_CONTENT,
                require_raw_name=True,
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
                            f"Server returned 2xx and echoed the unsanitised name "
                            f"({result})"
                        ),
                        evidence=(
                            f"POST {url} with filename='{traversal_filename}' "
                            f"-> accepted ({result})"
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

    _FAILURE_TEXT_RE = re.compile(
        r"\b(invalid|not allowed|disallowed|forbidden|rejected|denied|error|"
        r"fail(?:ed|ure)?|unsupported|unauthori[sz]ed)\b",
        re.IGNORECASE,
    )
    # Sentinel: 2xx, non-failure body, but nothing shows the file was stored.
    NO_STORAGE_EVIDENCE = "no evidence of storage"
    _UNSAFE_FOLLOWUP_RE = re.compile(
        r"logout|signout|delete|remove|destroy|reset", re.IGNORECASE
    )
    _FAILURE_STATUS_VALUES = frozenset({"error", "fail", "failed", "failure", "false"})

    @classmethod
    def _body_signals_failure(cls, text: str) -> bool:
        """True when a 2xx body is really an application-level rejection."""
        try:
            data = json.loads(text)
        except ValueError:
            return bool(cls._FAILURE_TEXT_RE.search(text[:2000]))
        if not isinstance(data, dict):
            return False
        for key in ("success", "ok", "uploaded"):
            if data.get(key) is False:
                return True
        status = data.get("status")
        if isinstance(status, str) and status.lower() in cls._FAILURE_STATUS_VALUES:
            return True
        if isinstance(status, bool) and not status:
            return True
        return bool(data.get("error") or data.get("errors"))

    @staticmethod
    def _json_strings(text: str) -> list[str]:
        """All string values (recursively) in a JSON body; [] if not JSON."""
        try:
            data = json.loads(text)
        except ValueError:
            return []
        out: list[str] = []
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, str):
                out.append(node)
            elif isinstance(node, dict):
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
        return out

    async def _stored_evidence(
        self,
        client: RateLimitedClient,
        url: str,
        response: httpx.Response,
        filename: str,
        payload_marker: str | None,
        require_raw_name: bool,
    ) -> str | None:
        """Evidence (beyond a bare 2xx) that the upload was actually stored.

        Rule: the 2xx body must not be a failure shape, AND either
        (a) a same-host URL/path the response points at (JSON value or
        Location header) is fetched and serves back the uploaded payload, or
        (b) the response echoes the uploaded filename (for traversal tests:
        the *unsanitised* name, so a server that stores the basename is not
        flagged).
        """
        text = response.text
        if self._body_signals_failure(text):
            return None
        strings = self._json_strings(text)
        haystacks = [text, *strings]

        if require_raw_name:
            raw = filename
            escaped = filename.replace("\\", "\\\\")
            if any(raw in h or escaped in h for h in haystacks):
                return "response echoes the unsanitised filename"
            return None

        basename = filename.rsplit("/", 1)[-1]
        ext = "." + basename.rsplit(".", 1)[-1].lower() if "." in basename else ""
        if payload_marker:
            candidates = [loc for loc in [response.headers.get("location", "")] if loc]
            candidates += [
                v for v in strings
                if basename in v or v.startswith(("/", "http://", "https://"))
            ]
            host = urlparse(url).netloc
            for cand in candidates[:5]:
                target = urljoin(url, cand)
                parsed = urlparse(target)
                if parsed.netloc != host:
                    continue
                if parsed.query or self._UNSAFE_FOLLOWUP_RE.search(parsed.path):
                    continue  # never GET state-changing / session-ending URLs
                try:
                    follow = await client.get(target)
                    if (
                        isinstance(follow.status_code, int)
                        and self.HTTP_STATUS_OK_LOWER <= follow.status_code < self.HTTP_STATUS_OK_UPPER
                        and payload_marker in follow.text
                    ):
                        return f"follow-up GET {target} serves the uploaded file"
                except Exception as exc:  # noqa: BLE001 - evidence is best-effort
                    logger.debug("FileUploadScanner follow-up failed: %s", exc)
            for cand in candidates[:5]:
                parsed = urlparse(urljoin(url, cand))
                if (
                    ext
                    and parsed.netloc == host
                    and parsed.path.lower().endswith(ext)
                    and parsed.path.lower() != urlparse(url).path.lower()
                ):
                    # The server points at a same-host file of the uploaded
                    # type: storage evidence even if a GET is not verbatim
                    # (e.g. the script executes instead of being served).
                    return f"response points at stored file URL {parsed.path}"
        if any(basename in h for h in haystacks):
            return "response references the stored file name"
        if payload_marker and not self._looks_like_html(response):
            return self.NO_STORAGE_EVIDENCE
        return None

    @staticmethod
    def _looks_like_html(response: httpx.Response) -> bool:
        """An HTML reply to an upload POST is an app shell or error page, not an API answer."""
        ctype = response.headers.get("content-type", "").lower()
        return "text/html" in ctype or response.text.lstrip()[:1] == "<"

    async def _upload_file(
        self,
        client: RateLimitedClient,
        url: str,
        filename: str,
        content_type: str,
        content: bytes,
        payload_marker: str | None = None,
        require_raw_name: bool = False,
    ) -> str | None:
        """Upload a file; return a short evidence string if it was really stored.

        A bare 2xx is NOT acceptance (many endpoints answer 200 with an error
        body or sanitise the name): see ``_stored_evidence`` for the rule.
        """
        try:
            files = {
                self.FORM_FIELD_NAME: (filename, content, content_type),
            }
            response = await client.post(url, files=files)

            if not (
                self.HTTP_STATUS_OK_LOWER
                <= response.status_code
                < self.HTTP_STATUS_OK_UPPER
            ):
                return None
            return await self._stored_evidence(
                client, url, response, filename, payload_marker, require_raw_name,
            )

        except Exception as exc:
            logger.debug(
                FileUploadConfig.ERROR_UPLOAD_SCAN_FAILED.format(
                    endpoint=url, error=str(exc)
                )
            )
            return None
