"""Tests for ownership verification and scan configuration."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import pytest

from isitsecure.engine.constants import (
    OwnershipVerificationConfig,
    ScanConfigDefaults,
)
from isitsecure.engine.enums import (
    ScanMode,
    VerificationMethod,
    VerificationStatus,
)
from isitsecure.engine.scan_config import ScanConfiguration
from isitsecure.engine.verification.models import (
    VerificationResult,
    VerificationToken,
)
from isitsecure.engine.verification.ownership_verifier import (
    OwnershipVerifier,
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


@dataclass
class FakeHttpResponse:
    """Fake HTTP response for testing."""

    status_code: int
    text: str


class FakeHttpClient:
    """Fake HTTP client that returns pre-configured responses."""

    def __init__(
        self,
        responses: dict[str, FakeHttpResponse] | None = None,
        error: Exception | None = None,
    ) -> None:
        self._responses = responses or {}
        self._error = error

    async def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> FakeHttpResponse:
        if self._error:
            raise self._error
        if url in self._responses:
            return self._responses[url]
        return FakeHttpResponse(status_code=404, text="Not Found")


class FakeDNSResolver:
    """Fake DNS resolver for testing."""

    def __init__(
        self,
        records: dict[str, list[str]] | None = None,
        error: Exception | None = None,
    ) -> None:
        self._records = records or {}
        self._error = error

    async def resolve_txt(self, domain: str) -> list[str]:
        if self._error:
            raise self._error
        return self._records.get(domain, [])


# ---------------------------------------------------------------------------
# TestOwnershipVerifier
# ---------------------------------------------------------------------------


class TestOwnershipVerifier:
    """Tests for the OwnershipVerifier service."""

    def test_generate_token(self) -> None:
        """generate_token returns a VerificationToken with correct fields."""
        verifier = OwnershipVerifier()
        token = verifier.generate_token(
            target_url="https://example.com",
            method=VerificationMethod.META_TAG,
        )
        assert isinstance(token, VerificationToken)
        assert token.target_url == "https://example.com"
        assert token.method == VerificationMethod.META_TAG
        assert token.token  # non-empty

    def test_generate_token_length(self) -> None:
        """Token hex string has the expected length (2 chars per byte)."""
        verifier = OwnershipVerifier()
        token = verifier.generate_token()
        expected_hex_len = OwnershipVerificationConfig.TOKEN_LENGTH * 2
        assert len(token.token) == expected_hex_len

    def test_verify_manual(self) -> None:
        """Manual verification always succeeds immediately."""
        verifier = OwnershipVerifier()
        token = VerificationToken(
            token="abc123",
            target_url="https://example.com",
            method=VerificationMethod.MANUAL,
        )
        # _verify_manual is sync, but verify() is async — test sync helper
        result = verifier._verify_manual(token)
        assert result.status == VerificationStatus.VERIFIED
        assert result.confidence == OwnershipVerificationConfig.CONFIDENCE_MANUAL
        assert result.verified_at is not None

    @pytest.mark.asyncio
    async def test_verify_meta_tag_success(self) -> None:
        """Mock HTTP response with matching meta tag results in verified."""
        token_value = "abc123def456"
        html = (
            '<html><head><meta name="deepscan-verify" '
            f'content="{token_value}"></head></html>'
        )
        http_client = FakeHttpClient(
            responses={
                "https://example.com": FakeHttpResponse(
                    status_code=200, text=html
                )
            }
        )
        verifier = OwnershipVerifier(http_client=http_client)
        token = VerificationToken(
            token=token_value,
            target_url="https://example.com",
            method=VerificationMethod.META_TAG,
        )
        result = await verifier.verify(token)
        assert result.status == VerificationStatus.VERIFIED
        assert result.confidence == OwnershipVerificationConfig.CONFIDENCE_META

    @pytest.mark.asyncio
    async def test_verify_meta_tag_mismatch(self) -> None:
        """Meta tag with wrong token results in failed."""
        html = (
            '<html><head><meta name="deepscan-verify" '
            'content="wrong_token"></head></html>'
        )
        http_client = FakeHttpClient(
            responses={
                "https://example.com": FakeHttpResponse(
                    status_code=200, text=html
                )
            }
        )
        verifier = OwnershipVerifier(http_client=http_client)
        token = VerificationToken(
            token="correct_token",
            target_url="https://example.com",
            method=VerificationMethod.META_TAG,
        )
        result = await verifier.verify(token)
        assert result.status == VerificationStatus.FAILED
        assert result.error is not None
        assert "mismatch" in result.error.lower()

    @pytest.mark.asyncio
    async def test_verify_meta_tag_missing(self) -> None:
        """No meta tag in HTML results in failed."""
        html = "<html><head><title>No verify</title></head></html>"
        http_client = FakeHttpClient(
            responses={
                "https://example.com": FakeHttpResponse(
                    status_code=200, text=html
                )
            }
        )
        verifier = OwnershipVerifier(http_client=http_client)
        token = VerificationToken(
            token="sometoken",
            target_url="https://example.com",
            method=VerificationMethod.META_TAG,
        )
        result = await verifier.verify(token)
        assert result.status == VerificationStatus.FAILED
        assert OwnershipVerificationConfig.ERROR_META_NOT_FOUND in (
            result.error or ""
        )

    @pytest.mark.asyncio
    async def test_verify_file_success(self) -> None:
        """File contains token results in verified."""
        token_value = "file_verify_token_123"
        http_client = FakeHttpClient(
            responses={
                "https://example.com/.well-known/deepscan-verify.txt": FakeHttpResponse(
                    status_code=200, text=token_value
                )
            }
        )
        verifier = OwnershipVerifier(http_client=http_client)
        token = VerificationToken(
            token=token_value,
            target_url="https://example.com",
            method=VerificationMethod.FILE,
        )
        result = await verifier.verify(token)
        assert result.status == VerificationStatus.VERIFIED
        assert result.confidence == OwnershipVerificationConfig.CONFIDENCE_FILE

    @pytest.mark.asyncio
    async def test_verify_file_not_found(self) -> None:
        """404 response results in failed."""
        http_client = FakeHttpClient()  # Default returns 404
        verifier = OwnershipVerifier(http_client=http_client)
        token = VerificationToken(
            token="some_token",
            target_url="https://example.com",
            method=VerificationMethod.FILE,
        )
        result = await verifier.verify(token)
        assert result.status == VerificationStatus.FAILED
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_verify_github_success(self) -> None:
        """GitHub API returns 200 results in verified."""
        http_client = FakeHttpClient(
            responses={
                "https://api.github.com/repos/owner/repo": FakeHttpResponse(
                    status_code=200,
                    text='{"full_name": "owner/repo"}',
                )
            }
        )
        verifier = OwnershipVerifier(http_client=http_client)
        token = VerificationToken(
            token="ghp_fake_token",
            repo_url="https://github.com/owner/repo",
            method=VerificationMethod.GITHUB,
        )
        result = await verifier.verify(token)
        assert result.status == VerificationStatus.VERIFIED
        assert result.confidence == OwnershipVerificationConfig.CONFIDENCE_GITHUB

    @pytest.mark.asyncio
    async def test_verify_github_denied(self) -> None:
        """GitHub API returns 404 results in failed."""
        http_client = FakeHttpClient(
            responses={
                "https://api.github.com/repos/owner/repo": FakeHttpResponse(
                    status_code=404, text="Not Found"
                )
            }
        )
        verifier = OwnershipVerifier(http_client=http_client)
        token = VerificationToken(
            token="ghp_bad_token",
            repo_url="https://github.com/owner/repo",
            method=VerificationMethod.GITHUB,
        )
        result = await verifier.verify(token)
        assert result.status == VerificationStatus.FAILED
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_verify_dns_success(self) -> None:
        """DNS TXT record with correct value results in verified."""
        token_value = "dns_token_abc"
        expected_record = (
            OwnershipVerificationConfig.DNS_TXT_VALUE_PREFIX + token_value
        )
        dns_resolver = FakeDNSResolver(
            records={
                "_deepscan.example.com": [expected_record],
            }
        )
        verifier = OwnershipVerifier(dns_resolver=dns_resolver)
        token = VerificationToken(
            token=token_value,
            target_url="https://example.com",
            method=VerificationMethod.DNS_TXT,
        )
        result = await verifier.verify(token)
        assert result.status == VerificationStatus.VERIFIED
        assert result.confidence == OwnershipVerificationConfig.CONFIDENCE_DNS

    @pytest.mark.asyncio
    async def test_verify_dns_no_records(self) -> None:
        """No DNS records results in failed."""
        dns_resolver = FakeDNSResolver(records={})
        verifier = OwnershipVerifier(dns_resolver=dns_resolver)
        token = VerificationToken(
            token="some_token",
            target_url="https://example.com",
            method=VerificationMethod.DNS_TXT,
        )
        result = await verifier.verify(token)
        assert result.status == VerificationStatus.FAILED

    @pytest.mark.asyncio
    async def test_verify_dns_error(self) -> None:
        """DNS resolution error results in failed."""
        dns_resolver = FakeDNSResolver(error=OSError("DNS timeout"))
        verifier = OwnershipVerifier(dns_resolver=dns_resolver)
        token = VerificationToken(
            token="some_token",
            target_url="https://example.com",
            method=VerificationMethod.DNS_TXT,
        )
        result = await verifier.verify(token)
        assert result.status == VerificationStatus.FAILED
        assert "DNS" in (result.error or "")

    @pytest.mark.asyncio
    async def test_verify_http_error(self) -> None:
        """HTTP error during meta tag check results in failed."""
        http_client = FakeHttpClient(error=httpx.ConnectError("Connection refused"))
        verifier = OwnershipVerifier(http_client=http_client)
        token = VerificationToken(
            token="some_token",
            target_url="https://example.com",
            method=VerificationMethod.META_TAG,
        )
        result = await verifier.verify(token)
        assert result.status == VerificationStatus.FAILED

    def test_verification_result_model(self) -> None:
        """VerificationResult model initializes with correct defaults."""
        result = VerificationResult(
            method=VerificationMethod.META_TAG,
            status=VerificationStatus.PENDING,
        )
        assert result.confidence == 0.0
        assert result.error is None
        assert result.verified_at is None

    def test_verification_token_model(self) -> None:
        """VerificationToken model stores fields correctly."""
        token = VerificationToken(
            token="test_token",
            target_url="https://example.com",
            repo_url="https://github.com/owner/repo",
            method=VerificationMethod.FILE,
        )
        assert token.token == "test_token"
        assert token.target_url == "https://example.com"
        assert token.repo_url == "https://github.com/owner/repo"
        assert token.method == VerificationMethod.FILE
        assert isinstance(token.created_at, datetime)

    def test_extract_github_owner_repo(self) -> None:
        """_extract_github_owner_repo parses various GitHub URL formats."""
        extract = OwnershipVerifier._extract_github_owner_repo
        assert extract("https://github.com/owner/repo") == "owner/repo"
        assert extract("https://github.com/owner/repo.git") == "owner/repo"
        assert extract("https://github.com/owner/repo/") == "owner/repo"
        assert extract("https://github.com/a") is None


# We need httpx for the error type in test_verify_http_error
import httpx  # noqa: E402


# ---------------------------------------------------------------------------
# TestScanConfiguration
# ---------------------------------------------------------------------------


class TestScanConfiguration:
    """Tests for the ScanConfiguration model."""

    def test_default_values(self) -> None:
        """Default config has expected values from ScanConfigDefaults."""
        config = ScanConfiguration()
        assert config.scan_mode == ScanMode.URL_ONLY
        assert config.max_crawl_depth == ScanConfigDefaults.MAX_CRAWL_DEPTH
        assert config.max_endpoints_to_test == ScanConfigDefaults.MAX_ENDPOINTS_TO_TEST
        assert (
            config.max_files_for_llm_review
            == ScanConfigDefaults.MAX_FILES_FOR_LLM_REVIEW
        )
        assert config.llm_token_budget == ScanConfigDefaults.LLM_TOKEN_BUDGET
        assert config.exclude_paths == []
        assert config.exclude_tables == []
        assert config.include_only_paths == []

    def test_should_scan_path_no_excludes(self) -> None:
        """With no excludes, all paths should be scanned."""
        config = ScanConfiguration()
        assert config.should_scan_path("/api/users") is True
        assert config.should_scan_path("/admin/settings") is True

    def test_should_scan_path_excluded(self) -> None:
        """Excluded paths are not scanned."""
        config = ScanConfiguration(exclude_paths=["/admin", "/internal"])
        assert config.should_scan_path("/admin/settings") is False
        assert config.should_scan_path("/internal/debug") is False
        assert config.should_scan_path("/api/users") is True

    def test_should_scan_path_include_only(self) -> None:
        """When include_only_paths is set, only those paths are scanned."""
        config = ScanConfiguration(include_only_paths=["/api"])
        assert config.should_scan_path("/api/users") is True
        assert config.should_scan_path("/admin/settings") is False

    def test_should_scan_path_include_only_overrides_exclude(self) -> None:
        """include_only_paths takes precedence over exclude_paths."""
        config = ScanConfiguration(
            include_only_paths=["/api"],
            exclude_paths=["/api/internal"],
        )
        # include_only_paths is checked first, excludes are ignored
        assert config.should_scan_path("/api/internal") is True

    def test_should_scan_table(self) -> None:
        """Tables not in exclude list should be scanned."""
        config = ScanConfiguration()
        assert config.should_scan_table("users") is True
        assert config.should_scan_table("profiles") is True

    def test_should_scan_table_excluded(self) -> None:
        """Excluded tables are not scanned."""
        config = ScanConfiguration(exclude_tables=["migrations", "schema_info"])
        assert config.should_scan_table("migrations") is False
        assert config.should_scan_table("schema_info") is False
        assert config.should_scan_table("users") is True

    def test_scanner_toggles(self) -> None:
        """Scanner toggles can be individually disabled."""
        config = ScanConfiguration(
            enable_active_xss=False,
            enable_llm_review=False,
        )
        assert config.enable_active_xss is False
        assert config.enable_llm_review is False
        assert config.enable_csrf is True  # default True

    def test_serialization(self) -> None:
        """ScanConfiguration round-trips through dict serialization."""
        config = ScanConfiguration(
            scan_mode=ScanMode.FULL,
            exclude_paths=["/admin"],
            max_crawl_depth=5,
            enable_csrf=False,
        )
        data = config.model_dump()
        restored = ScanConfiguration(**data)
        assert restored.scan_mode == ScanMode.FULL
        assert restored.exclude_paths == ["/admin"]
        assert restored.max_crawl_depth == 5
        assert restored.enable_csrf is False
