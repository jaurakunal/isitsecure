"""Tests for SessionScanner."""

from __future__ import annotations

import base64
import json
import time
from unittest.mock import MagicMock

import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import SessionScanConfig
from isitsecure.engine.enums import AuthProvider
from isitsecure.engine.models import (
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.scanners.session_scanner import SessionScanner
from isitsecure.engine.scanners.protocols import DASTScannerProtocol
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.ingestion.snapshot import (
    CodebaseSnapshot,
    HTTPHeadersData,
    PageAsset,
)
from isitsecure.engine.enums import AssetType


# --- Helpers ---


def _encode_jwt_part(data: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(data).encode()
    ).rstrip(b"=").decode()


def _make_jwt(payload: dict | None = None) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    if payload is None:
        payload = {"sub": "user123", "exp": int(time.time()) + 3600}
    return f"{_encode_jwt_part(header)}.{_encode_jwt_part(payload)}.fakesig"


def _make_snapshot(
    js_content: str = "",
    cookies: list[dict] | None = None,
) -> CodebaseSnapshot:
    assets = []
    if js_content:
        assets.append(
            PageAsset(
                url="https://example.com/app.js",
                asset_type=AssetType.JAVASCRIPT,
                content=js_content,
                size_bytes=len(js_content),
                is_external=False,
            )
        )
    return CodebaseSnapshot(
        url="https://example.com",
        html_content="<html></html>",
        assets=assets,
        headers=HTTPHeadersData(
            raw_headers={},
            status_code=200,
            cookies=cookies or [],
        ),
    )


def _make_auth_session(token: str | None = None) -> AuthSession:
    return AuthSession(
        user_id="user-123",
        access_token=token or _make_jwt(),
        provider=AuthProvider.SUPABASE,
    )


class TestSessionScannerProtocolCompliance:
    """Protocol compliance tests for SessionScanner."""

    def test_implements_dast_protocol(self) -> None:
        """SessionScanner should implement DASTScannerProtocol."""
        scanner = SessionScanner()
        assert isinstance(scanner, DASTScannerProtocol)

    def test_has_scanner_name(self) -> None:
        scanner = SessionScanner()
        assert isinstance(scanner.scanner_name, str)
        assert len(scanner.scanner_name) > 0

    def test_has_scan_method(self) -> None:
        scanner = SessionScanner()
        assert hasattr(scanner, "scan")
        assert callable(scanner.scan)


class TestSessionScanner:
    """Tests for the SessionScanner."""

    def setup_method(self) -> None:
        self.scanner = SessionScanner()

    # --- Basic Properties ---

    def test_scanner_name(self) -> None:
        assert self.scanner.scanner_name == SessionScanConfig.SCANNER_NAME

    def test_scan_categories(self) -> None:
        assert FindingCategory.AUTH_WEAKNESS in self.scanner.scan_categories

    # --- localStorage Token Detection ---

    def test_detects_localstorage_token(self) -> None:
        """JS with localStorage.setItem('token') -> finding."""
        js = """
        function login(response) {
            localStorage.setItem('token', response.access_token);
            redirect('/dashboard');
        }
        """
        snapshot = _make_snapshot(js_content=js)

        findings = self.scanner._check_localstorage_usage(snapshot)

        assert len(findings) == 1
        assert findings[0].title == SessionScanConfig.TITLE_TOKEN_IN_LOCALSTORAGE
        assert findings[0].severity == SeverityLevel.HIGH
        assert findings[0].confidence == SessionScanConfig.CONFIDENCE_INSECURE_STORAGE

    def test_detects_localstorage_bracket_access(self) -> None:
        """JS with localStorage['jwt'] -> finding."""
        js = """
        localStorage['jwt'] = data.token;
        """
        snapshot = _make_snapshot(js_content=js)

        findings = self.scanner._check_localstorage_usage(snapshot)

        assert len(findings) == 1

    def test_no_finding_clean_js(self) -> None:
        """JS without localStorage token storage -> no finding."""
        js = """
        function fetchData() {
            const data = await fetch('/api/data');
            return data.json();
        }
        localStorage.setItem('theme', 'dark');
        """
        snapshot = _make_snapshot(js_content=js)

        findings = self.scanner._check_localstorage_usage(snapshot)

        assert len(findings) == 0

    def test_no_finding_empty_js(self) -> None:
        """No JS content -> no finding."""
        snapshot = _make_snapshot(js_content="")

        findings = self.scanner._check_localstorage_usage(snapshot)

        assert len(findings) == 0

    # --- Cookie Flag Analysis ---

    def test_detects_missing_httponly(self) -> None:
        """Auth cookie without HttpOnly flag -> finding."""
        cookies = [{"name": "access_token", "httponly": False, "secure": True}]
        snapshot = _make_snapshot(cookies=cookies)

        findings = self.scanner._check_cookie_flags(snapshot)

        httponly_findings = [
            f for f in findings if f.title == SessionScanConfig.TITLE_MISSING_HTTPONLY
        ]
        assert len(httponly_findings) == 1
        assert httponly_findings[0].severity == SeverityLevel.HIGH
        assert "access_token" in httponly_findings[0].description

    def test_detects_missing_secure(self) -> None:
        """Auth cookie without Secure flag -> finding."""
        cookies = [{"name": "session", "httponly": True, "secure": False}]
        snapshot = _make_snapshot(cookies=cookies)

        findings = self.scanner._check_cookie_flags(snapshot)

        secure_findings = [
            f for f in findings if f.title == SessionScanConfig.TITLE_MISSING_SECURE
        ]
        assert len(secure_findings) == 1
        assert secure_findings[0].severity == SeverityLevel.MEDIUM
        assert "session" in secure_findings[0].description

    def test_no_finding_secure_cookies(self) -> None:
        """Auth cookie with both HttpOnly and Secure -> no finding."""
        cookies = [{"name": "access_token", "httponly": True, "secure": True}]
        snapshot = _make_snapshot(cookies=cookies)

        findings = self.scanner._check_cookie_flags(snapshot)

        assert len(findings) == 0

    def test_skips_non_auth_cookies(self) -> None:
        """Non-auth cookies (e.g., theme) should not be checked."""
        cookies = [{"name": "theme", "httponly": False, "secure": False}]
        snapshot = _make_snapshot(cookies=cookies)

        findings = self.scanner._check_cookie_flags(snapshot)

        assert len(findings) == 0

    def test_detects_both_missing_flags(self) -> None:
        """Auth cookie missing both flags -> 2 findings."""
        cookies = [{"name": "jwt", "httponly": False, "secure": False}]
        snapshot = _make_snapshot(cookies=cookies)

        findings = self.scanner._check_cookie_flags(snapshot)

        assert len(findings) == 2

    # --- Token Expiry Analysis ---

    def test_detects_long_expiry(self) -> None:
        """Token expiring in 30 days -> finding."""
        thirty_days_from_now = int(time.time()) + (30 * 24 * 3600)
        token = _make_jwt(payload={"sub": "user123", "exp": thirty_days_from_now})
        scanner = SessionScanner(auth_session=_make_auth_session(token))

        finding = scanner._check_token_expiry(token)

        assert finding is not None
        assert finding.title == SessionScanConfig.TITLE_LONG_EXPIRY
        assert finding.severity == SeverityLevel.MEDIUM
        assert finding.confidence == SessionScanConfig.CONFIDENCE_LONG_EXPIRY

    def test_no_finding_short_expiry(self) -> None:
        """Token expiring in 1 hour -> no finding."""
        one_hour_from_now = int(time.time()) + 3600
        token = _make_jwt(payload={"sub": "user123", "exp": one_hour_from_now})
        scanner = SessionScanner(auth_session=_make_auth_session(token))

        finding = scanner._check_token_expiry(token)

        assert finding is None

    def test_no_finding_expired_token(self) -> None:
        """Already-expired token -> no finding (expired is fine)."""
        past = int(time.time()) - 3600
        token = _make_jwt(payload={"sub": "user123", "exp": past})
        scanner = SessionScanner(auth_session=_make_auth_session(token))

        finding = scanner._check_token_expiry(token)

        assert finding is None

    def test_no_finding_missing_exp(self) -> None:
        """Token without exp -> None (JWTScanner handles this)."""
        token = _make_jwt(payload={"sub": "user123"})
        scanner = SessionScanner(auth_session=_make_auth_session(token))

        finding = scanner._check_token_expiry(token)

        assert finding is None

    # --- Full Scan Integration ---

    @pytest.mark.asyncio
    async def test_full_scan_with_snapshot_and_auth(self) -> None:
        """Full scan combining JS, cookies, and JWT checks."""
        js = "localStorage.setItem('token', data.jwt);"
        cookies = [{"name": "session", "httponly": False, "secure": False}]
        snapshot = _make_snapshot(js_content=js, cookies=cookies)

        thirty_days = int(time.time()) + (30 * 24 * 3600)
        token = _make_jwt(payload={"sub": "user123", "exp": thirty_days})
        session = _make_auth_session(token)

        scanner = SessionScanner(auth_session=session)
        findings = await scanner.scan(endpoints=[], snapshot=snapshot)

        # Should have: localStorage (1) + httponly (1) + secure (1) + long expiry (1)
        assert len(findings) >= 3

    @pytest.mark.asyncio
    async def test_empty_scan(self) -> None:
        """No snapshot, no auth -> 0 findings."""
        findings = await self.scanner.scan(endpoints=[], snapshot=None)
        assert findings == []
