"""Ownership verification service.

Verifies that the customer controls the target before scanning:
1. DNS TXT: Customer adds TXT record to their domain
2. Meta tag: Customer adds <meta name="deepscan-verify"> to HTML
3. File: Customer uploads /.well-known/deepscan-verify.txt
4. GitHub: Customer provides GitHub token with repo read access
5. Manual: Admin manually authorizes (consultant mode)
"""

from __future__ import annotations

import logging
import re
import secrets
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlparse

import httpx

from isitsecure.engine.constants import OwnershipVerificationConfig
from isitsecure.engine.enums import (
    VerificationMethod,
    VerificationStatus,
)
from isitsecure.engine.verification.models import (
    VerificationResult,
    VerificationToken,
)

logger = logging.getLogger(__name__)


class DNSResolverProtocol(Protocol):
    """Protocol for DNS resolution (enables test injection)."""

    async def resolve_txt(self, domain: str) -> list[str]:
        """Resolve TXT records for a domain."""
        ...


class HttpClientProtocol(Protocol):
    """Protocol for HTTP requests (enables test injection)."""

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 10.0
    ) -> "HttpResponse":
        """Perform an HTTP GET request."""
        ...


class HttpResponse(Protocol):
    """Protocol for HTTP response."""

    @property
    def status_code(self) -> int: ...

    @property
    def text(self) -> str: ...


class _DefaultDNSResolver:
    """Default DNS resolver using aiodns (or fallback)."""

    async def resolve_txt(self, domain: str) -> list[str]:
        """Resolve TXT records using asyncio DNS."""
        import asyncio

        try:
            import aiodns  # type: ignore[import-untyped]

            resolver = aiodns.DNSResolver()
            records = await resolver.query(domain, "TXT")
            return [r.text for r in records]
        except ImportError:
            # Fallback: use subprocess for dig
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "TXT", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            raw = stdout.decode().strip()
            if not raw:
                return []
            return [line.strip('"') for line in raw.splitlines()]


class _DefaultHttpClient:
    """Default HTTP client using httpx."""

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None, timeout: float = 10.0
    ) -> httpx.Response:
        """Perform an HTTP GET request."""
        async with httpx.AsyncClient() as client:
            return await client.get(url, headers=headers, timeout=timeout)


class OwnershipVerifier:
    """Verifies customer owns the target URL or repo."""

    def __init__(
        self,
        dns_resolver: DNSResolverProtocol | None = None,
        http_client: HttpClientProtocol | None = None,
    ) -> None:
        self._dns_resolver = dns_resolver or _DefaultDNSResolver()
        self._http_client = http_client or _DefaultHttpClient()

    def generate_token(
        self,
        target_url: str | None = None,
        repo_url: str | None = None,
        method: VerificationMethod = VerificationMethod.META_TAG,
    ) -> VerificationToken:
        """Generate a verification token for the customer to install."""
        token = secrets.token_hex(OwnershipVerificationConfig.TOKEN_LENGTH)
        return VerificationToken(
            token=token,
            target_url=target_url,
            repo_url=repo_url,
            method=method,
        )

    async def verify(self, token: VerificationToken) -> VerificationResult:
        """Verify ownership using the specified method."""
        method = token.method

        if method == VerificationMethod.MANUAL:
            return self._verify_manual(token)
        elif method == VerificationMethod.DNS_TXT:
            return await self._verify_dns(token)
        elif method == VerificationMethod.META_TAG:
            return await self._verify_meta_tag(token)
        elif method == VerificationMethod.FILE:
            return await self._verify_file(token)
        elif method == VerificationMethod.GITHUB:
            return await self._verify_github(token)

        return VerificationResult(
            method=method,
            status=VerificationStatus.FAILED,
            error=OwnershipVerificationConfig.ERROR_VERIFICATION_FAILED.format(
                method=method.value, error="Unknown verification method"
            ),
        )

    def _verify_manual(self, token: VerificationToken) -> VerificationResult:
        """Manual verification (admin mode)."""
        logger.info(OwnershipVerificationConfig.MSG_VERIFICATION_SKIPPED)
        return VerificationResult(
            method=VerificationMethod.MANUAL,
            status=VerificationStatus.VERIFIED,
            verified_at=datetime.now(UTC),
            target_url=token.target_url,
            repo_url=token.repo_url,
            token=token.token,
            confidence=OwnershipVerificationConfig.CONFIDENCE_MANUAL,
        )

    async def _verify_dns(self, token: VerificationToken) -> VerificationResult:
        """Verify via DNS TXT record."""
        if not token.target_url:
            return self._failed_result(
                VerificationMethod.DNS_TXT,
                "No target URL provided for DNS verification",
            )

        domain = urlparse(token.target_url).hostname
        if not domain:
            return self._failed_result(
                VerificationMethod.DNS_TXT,
                f"Could not extract domain from {token.target_url}",
            )

        lookup_domain = OwnershipVerificationConfig.DNS_TXT_RECORD_NAME.format(
            domain=domain
        )
        expected_value = (
            OwnershipVerificationConfig.DNS_TXT_VALUE_PREFIX + token.token
        )

        try:
            records = await self._dns_resolver.resolve_txt(lookup_domain)
        except Exception as exc:
            error = OwnershipVerificationConfig.ERROR_DNS_LOOKUP_FAILED.format(
                domain=lookup_domain, error=str(exc)
            )
            logger.warning(error)
            return self._failed_result(VerificationMethod.DNS_TXT, error)

        for record in records:
            if expected_value in record:
                logger.info(
                    OwnershipVerificationConfig.MSG_VERIFIED.format(
                        method=VerificationMethod.DNS_TXT.value
                    )
                )
                return VerificationResult(
                    method=VerificationMethod.DNS_TXT,
                    status=VerificationStatus.VERIFIED,
                    verified_at=datetime.now(UTC),
                    target_url=token.target_url,
                    token=token.token,
                    confidence=OwnershipVerificationConfig.CONFIDENCE_DNS,
                )

        return self._failed_result(
            VerificationMethod.DNS_TXT,
            OwnershipVerificationConfig.ERROR_TOKEN_MISMATCH.format(
                expected=expected_value,
                found="; ".join(records) if records else "(no records)",
            ),
        )

    async def _verify_meta_tag(self, token: VerificationToken) -> VerificationResult:
        """Verify via HTML meta tag."""
        if not token.target_url:
            return self._failed_result(
                VerificationMethod.META_TAG,
                "No target URL provided for meta tag verification",
            )

        try:
            response = await self._http_client.get(
                token.target_url,
                timeout=OwnershipVerificationConfig.HTTP_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            return self._failed_result(
                VerificationMethod.META_TAG,
                OwnershipVerificationConfig.ERROR_VERIFICATION_FAILED.format(
                    method=VerificationMethod.META_TAG.value, error=str(exc)
                ),
            )

        match = re.search(
            OwnershipVerificationConfig.META_TAG_PATTERN, response.text
        )
        if not match:
            return self._failed_result(
                VerificationMethod.META_TAG,
                OwnershipVerificationConfig.ERROR_META_NOT_FOUND,
            )

        found_token = match.group(1)
        if found_token != token.token:
            return self._failed_result(
                VerificationMethod.META_TAG,
                OwnershipVerificationConfig.ERROR_TOKEN_MISMATCH.format(
                    expected=token.token, found=found_token
                ),
            )

        logger.info(
            OwnershipVerificationConfig.MSG_VERIFIED.format(
                method=VerificationMethod.META_TAG.value
            )
        )
        return VerificationResult(
            method=VerificationMethod.META_TAG,
            status=VerificationStatus.VERIFIED,
            verified_at=datetime.now(UTC),
            target_url=token.target_url,
            token=token.token,
            confidence=OwnershipVerificationConfig.CONFIDENCE_META,
        )

    async def _verify_file(self, token: VerificationToken) -> VerificationResult:
        """Verify via well-known file."""
        if not token.target_url:
            return self._failed_result(
                VerificationMethod.FILE,
                "No target URL provided for file verification",
            )

        parsed = urlparse(token.target_url)
        file_url = (
            f"{parsed.scheme}://{parsed.netloc}"
            f"{OwnershipVerificationConfig.VERIFICATION_FILE_PATH}"
        )

        try:
            response = await self._http_client.get(
                file_url,
                timeout=OwnershipVerificationConfig.HTTP_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            return self._failed_result(
                VerificationMethod.FILE,
                OwnershipVerificationConfig.ERROR_VERIFICATION_FAILED.format(
                    method=VerificationMethod.FILE.value, error=str(exc)
                ),
            )

        if response.status_code != 200:
            return self._failed_result(
                VerificationMethod.FILE,
                OwnershipVerificationConfig.ERROR_FILE_NOT_FOUND.format(
                    url=file_url
                ),
            )

        if token.token not in response.text:
            return self._failed_result(
                VerificationMethod.FILE,
                OwnershipVerificationConfig.ERROR_TOKEN_MISMATCH.format(
                    expected=token.token, found=response.text[:100]
                ),
            )

        logger.info(
            OwnershipVerificationConfig.MSG_VERIFIED.format(
                method=VerificationMethod.FILE.value
            )
        )
        return VerificationResult(
            method=VerificationMethod.FILE,
            status=VerificationStatus.VERIFIED,
            verified_at=datetime.now(UTC),
            target_url=token.target_url,
            token=token.token,
            confidence=OwnershipVerificationConfig.CONFIDENCE_FILE,
        )

    async def _verify_github(self, token: VerificationToken) -> VerificationResult:
        """Verify GitHub repo access via token."""
        if not token.repo_url:
            return self._failed_result(
                VerificationMethod.GITHUB,
                "No repo URL provided for GitHub verification",
            )

        # Extract owner/repo from GitHub URL
        owner_repo = self._extract_github_owner_repo(token.repo_url)
        if not owner_repo:
            return self._failed_result(
                VerificationMethod.GITHUB,
                f"Could not extract owner/repo from {token.repo_url}",
            )

        github_api_url = f"https://api.github.com/repos/{owner_repo}"
        headers = {
            "Authorization": f"Bearer {token.token}",
            "Accept": "application/vnd.github.v3+json",
        }

        try:
            response = await self._http_client.get(
                github_api_url,
                headers=headers,
                timeout=OwnershipVerificationConfig.HTTP_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            return self._failed_result(
                VerificationMethod.GITHUB,
                OwnershipVerificationConfig.ERROR_VERIFICATION_FAILED.format(
                    method=VerificationMethod.GITHUB.value, error=str(exc)
                ),
            )

        if response.status_code != 200:
            return self._failed_result(
                VerificationMethod.GITHUB,
                OwnershipVerificationConfig.ERROR_GITHUB_ACCESS_DENIED.format(
                    repo=owner_repo
                ),
            )

        logger.info(
            OwnershipVerificationConfig.MSG_VERIFIED.format(
                method=VerificationMethod.GITHUB.value
            )
        )
        return VerificationResult(
            method=VerificationMethod.GITHUB,
            status=VerificationStatus.VERIFIED,
            verified_at=datetime.now(UTC),
            repo_url=token.repo_url,
            token=token.token,
            confidence=OwnershipVerificationConfig.CONFIDENCE_GITHUB,
        )

    @staticmethod
    def _extract_github_owner_repo(repo_url: str) -> str | None:
        """Extract 'owner/repo' from a GitHub URL."""
        parsed = urlparse(repo_url)
        path = parsed.path.strip("/")
        if path.endswith(".git"):
            path = path[:-4]
        parts = path.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return None

    @staticmethod
    def _failed_result(
        method: VerificationMethod, error: str
    ) -> VerificationResult:
        """Create a failed verification result."""
        return VerificationResult(
            method=method,
            status=VerificationStatus.FAILED,
            error=error,
        )
