"""Tests for the live Supabase RLS deep scanner."""

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import RLSDeepScanConfig
from isitsecure.engine.enums import AuthProvider
from isitsecure.engine.models import FindingSource
from isitsecure.engine.scanners.rls_deep_scanner import (
    RLSDeepScanner,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel

SUPABASE_URL = "https://test-project.supabase.co"
ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"


def _make_session(user_id: str = "user-a-id", token: str = "token-a") -> AuthSession:
    """Create a test AuthSession."""
    return AuthSession(
        user_id=user_id,
        access_token=token,
        provider=AuthProvider.SUPABASE,
    )


def _make_response(
    status_code: int = 200,
    body: str = "[]",
) -> httpx.Response:
    """Create a mock httpx.Response."""
    return httpx.Response(
        status_code=status_code,
        text=body,
        request=httpx.Request("GET", "https://test.com"),
    )


class TestRLSDeepScannerProtocolCompliance:
    """Protocol compliance tests for RLSDeepScanner.

    Note: RLSDeepScanner has a non-standard scan() signature
    (requires supabase_url, anon_key, tables), so it does not implement
    DASTScannerProtocol. We verify it has scanner_name and scan.
    """

    def test_has_scanner_name(self) -> None:
        scanner = RLSDeepScanner()
        assert isinstance(scanner.scanner_name, str)
        assert len(scanner.scanner_name) > 0

    def test_has_scan_method(self) -> None:
        scanner = RLSDeepScanner()
        assert hasattr(scanner, "scan")
        assert callable(scanner.scan)


class TestRLSDeepScanner:
    """Tests for RLSDeepScanner."""

    def test_scanner_name(self) -> None:
        scanner = RLSDeepScanner()
        assert scanner.scanner_name == RLSDeepScanConfig.SCANNER_NAME

    @pytest.mark.asyncio
    async def test_detects_anon_read_access(self) -> None:
        """Table returning data with anon key should produce HIGH finding."""
        scanner = RLSDeepScanner()
        mock_client = AsyncMock()
        # GET returns data, POST returns 401 (no write)
        mock_client.get = AsyncMock(
            return_value=_make_response(200, '[{"id": "abc-123"}]')
        )
        mock_client.post = AsyncMock(
            return_value=_make_response(401, '{"message": "unauthorized"}')
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(mock_client):
            findings = await scanner.scan(
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
                tables=["profiles"],
            )

        anon_read = [
            f for f in findings
            if "readable with anon key" in f.title
        ]
        assert len(anon_read) == 1
        assert anon_read[0].severity == SeverityLevel.HIGH
        assert anon_read[0].source == FindingSource.DAST_AUTHENTICATED
        assert anon_read[0].category == FindingCategory.RLS_MISCONFIGURATION

    @pytest.mark.asyncio
    async def test_no_finding_anon_read_blocked(self) -> None:
        """Table returning 401 with anon key should produce no finding."""
        scanner = RLSDeepScanner()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(
            return_value=_make_response(401, '{"message": "unauthorized"}')
        )
        mock_client.post = AsyncMock(
            return_value=_make_response(401, '{"message": "unauthorized"}')
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(mock_client):
            findings = await scanner.scan(
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
                tables=["profiles"],
            )

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_no_finding_anon_read_empty(self) -> None:
        """Table returning empty array [] should produce no finding."""
        scanner = RLSDeepScanner()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=_make_response(200, "[]"))
        mock_client.post = AsyncMock(return_value=_make_response(401))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(mock_client):
            findings = await scanner.scan(
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
                tables=["profiles"],
            )

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_detects_anon_write_access(self) -> None:
        """Table accepting POST with anon key should produce CRITICAL finding."""
        scanner = RLSDeepScanner()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=_make_response(200, "[]"))
        mock_client.post = AsyncMock(return_value=_make_response(201, ""))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(mock_client):
            findings = await scanner.scan(
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
                tables=["profiles"],
            )

        write_findings = [
            f for f in findings if "writable with anon key" in f.title
        ]
        assert len(write_findings) == 1
        assert write_findings[0].severity == SeverityLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_detects_cross_user_data_leak(self) -> None:
        """User B sees User A's row IDs should produce CRITICAL IDOR finding."""
        scanner = RLSDeepScanner()
        session_a = _make_session("user-a", "token-a")
        session_b = _make_session("user-b", "token-b")

        call_count = 0

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            headers = kwargs.get("headers", {})
            # Anon GET (no auth header from extra kwargs)
            if not headers:
                return _make_response(200, "[]")
            auth = headers.get("Authorization", "") if isinstance(headers, dict) else ""
            # Both users see the same row
            return _make_response(200, '[{"id": "shared-id-123"}]')

        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=_make_response(401))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(mock_client):
            findings = await scanner.scan(
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
                tables=["user_data"],
                user_a_session=session_a,
                user_b_session=session_b,
            )

        cross_user = [
            f for f in findings if "leaks data across users" in f.title
        ]
        assert len(cross_user) == 1
        assert cross_user[0].severity == SeverityLevel.CRITICAL
        assert cross_user[0].category == FindingCategory.IDOR

    @pytest.mark.asyncio
    async def test_no_cross_user_leak_when_filtered(self) -> None:
        """User B sees different rows than A should produce no cross-user finding."""
        scanner = RLSDeepScanner()
        session_a = _make_session("user-a", "token-a")
        session_b = _make_session("user-b", "token-b")

        async def mock_get(url: str, **kwargs: object) -> httpx.Response:
            headers = kwargs.get("headers", {})
            if not headers:
                return _make_response(200, "[]")
            auth = headers.get("Authorization", "") if isinstance(headers, dict) else ""
            if "token-a" in str(auth):
                return _make_response(200, '[{"id": "a-only-id"}]')
            return _make_response(200, '[{"id": "b-only-id"}]')

        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.post = AsyncMock(return_value=_make_response(401))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(mock_client):
            findings = await scanner.scan(
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
                tables=["user_data"],
                user_a_session=session_a,
                user_b_session=session_b,
            )

        cross_user = [
            f for f in findings if "leaks data across users" in f.title
        ]
        assert len(cross_user) == 0

    @pytest.mark.asyncio
    async def test_detects_rpc_no_auth(self) -> None:
        """RPC function returning 200 without auth should produce finding."""
        scanner = RLSDeepScanner()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=_make_response(200, "[]"))
        mock_client.post = AsyncMock(
            side_effect=lambda url, **kw: (
                _make_response(200, '{"result": "ok"}')
                if "/rpc/" in url
                else _make_response(401)
            )
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(mock_client):
            findings = await scanner.scan(
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
                tables=[],
                rpc_functions=["get_secret_data"],
            )

        rpc_findings = [
            f for f in findings if "RPC function" in f.title
        ]
        assert len(rpc_findings) == 1
        assert rpc_findings[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_rpc_blocked_without_auth(self) -> None:
        """RPC returning 401 should produce no finding."""
        scanner = RLSDeepScanner()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=_make_response(200, "[]"))
        mock_client.post = AsyncMock(return_value=_make_response(401))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(mock_client):
            findings = await scanner.scan(
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
                tables=[],
                rpc_functions=["get_secret_data"],
            )

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_respects_max_tables(self) -> None:
        """Should not test more than MAX_TABLES_TO_TEST."""
        scanner = RLSDeepScanner()
        tables = [f"table_{i}" for i in range(50)]

        get_call_count = 0

        async def counting_get(url: str, **kwargs: object) -> httpx.Response:
            nonlocal get_call_count
            get_call_count += 1
            return _make_response(200, "[]")

        mock_client = AsyncMock()
        mock_client.get = counting_get
        mock_client.post = AsyncMock(return_value=_make_response(401))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(mock_client):
            await scanner.scan(
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
                tables=tables,
            )

        # Each table gets 1 GET (anon read) + 1 POST (anon write)
        # Max tables = 25, so max GET calls = 25
        assert get_call_count <= RLSDeepScanConfig.MAX_TABLES_TO_TEST

    @pytest.mark.asyncio
    async def test_error_does_not_stop_scan(self) -> None:
        """A failure on one table should not prevent scanning others."""
        scanner = RLSDeepScanner()

        call_count = 0

        async def error_then_ok(url: str, **kwargs: object) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if "bad_table" in url:
                raise httpx.ConnectError("Connection refused")
            return _make_response(200, '[{"id": "1"}]')

        mock_client = AsyncMock()
        mock_client.get = error_then_ok
        mock_client.post = AsyncMock(return_value=_make_response(401))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(mock_client):
            findings = await scanner.scan(
                supabase_url=SUPABASE_URL,
                anon_key=ANON_KEY,
                tables=["bad_table", "good_table"],
            )

        # good_table should still produce a finding
        good_findings = [f for f in findings if "good_table" in f.title]
        assert len(good_findings) >= 1


class TestRLSDeepScannerRefinements:
    """Sensitive-column read escalation + constraint-inferred anon writes."""

    @pytest.mark.asyncio
    async def test_sensitive_column_escalates_read_to_critical(self) -> None:
        """A readable table exposing an email column is CRITICAL, not HIGH."""
        scanner = RLSDeepScanner()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(
            return_value=_make_response(200, '[{"id": 1, "email": "a@b.com"}]')
        )
        mock_client.post = AsyncMock(return_value=_make_response(401))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(mock_client):
            findings = await scanner.scan(
                supabase_url=SUPABASE_URL, anon_key=ANON_KEY, tables=["leads"]
            )

        read = [f for f in findings if "anon key" in f.title and "writable" not in f.title]
        assert len(read) == 1
        assert read[0].severity == SeverityLevel.CRITICAL
        assert "sensitive" in read[0].title.lower()
        assert "email" in read[0].description
        # The row VALUES must never appear in the report — only column names.
        assert "a@b.com" not in read[0].response_preview

    @pytest.mark.asyncio
    async def test_non_sensitive_read_stays_high(self) -> None:
        """A readable table with no sensitive columns remains HIGH."""
        scanner = RLSDeepScanner()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(
            return_value=_make_response(200, '[{"id": 1, "slug": "x"}]')
        )
        mock_client.post = AsyncMock(return_value=_make_response(401))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(mock_client):
            findings = await scanner.scan(
                supabase_url=SUPABASE_URL, anon_key=ANON_KEY, tables=["pages"]
            )
        read = [f for f in findings if "readable with anon key" in f.title]
        assert len(read) == 1
        assert read[0].severity == SeverityLevel.HIGH

    @pytest.mark.asyncio
    async def test_anon_write_inferred_from_constraint_error(self) -> None:
        """A 400 not-null (code 23502) INSERT means the row cleared RLS."""
        scanner = RLSDeepScanner()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=_make_response(200, "[]"))
        mock_client.post = AsyncMock(return_value=_make_response(
            400,
            '{"code":"23502","message":"null value in column \\"email\\" '
            'violates not-null constraint"}',
        ))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(mock_client):
            findings = await scanner.scan(
                supabase_url=SUPABASE_URL, anon_key=ANON_KEY, tables=["leads"]
            )
        write = [f for f in findings if "writable with anon key" in f.title]
        assert len(write) == 1
        assert write[0].severity == SeverityLevel.CRITICAL
        assert write[0].confidence == RLSDeepScanConfig.CONFIDENCE_ANON_WRITE_INFERRED

    @pytest.mark.asyncio
    async def test_anon_write_blocked_by_rls_no_finding(self) -> None:
        """A 400/403 with the RLS-denial code (42501) is NOT a write finding."""
        scanner = RLSDeepScanner()
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=_make_response(200, "[]"))
        mock_client.post = AsyncMock(return_value=_make_response(
            403,
            '{"code":"42501","message":"new row violates row-level security '
            'policy for table \\"leads\\""}',
        ))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with _patch_client(mock_client):
            findings = await scanner.scan(
                supabase_url=SUPABASE_URL, anon_key=ANON_KEY, tables=["leads"]
            )
        assert [f for f in findings if "writable" in f.title] == []

    def test_write_passed_rls_helper(self) -> None:
        f = RLSDeepScanner._write_passed_rls
        assert f('{"code":"23502","message":"not-null"}') is True     # constraint
        assert f('{"code":"23505","message":"duplicate"}') is True    # unique
        assert f('{"code":"42501","message":"denied"}') is False      # RLS block
        assert f('{"message":"new row violates row-level security"}') is False
        assert f("not json") is False                                  # ambiguous

    def test_sensitive_columns_helper(self) -> None:
        f = RLSDeepScanner._sensitive_columns
        assert f(["id", "email", "created_at"]) == ["email"]
        assert f(["user_email", "phone"]) == ["user_email", "phone"]
        assert f(["id", "slug", "title"]) == []


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _patch_client(mock_client: AsyncMock):
    """Patch RateLimitedClient to return the mock."""
    from unittest.mock import patch

    return patch(
        "isitsecure.engine.scanners.rls_deep_scanner.RateLimitedClient",
        return_value=mock_client,
    )
