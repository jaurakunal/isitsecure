"""Comprehensive tests for auth providers in the Deep Security Scan Agent."""

import base64
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from isitsecure.engine.auth.browser_auth import BrowserAuthProvider
from isitsecure.engine.auth.protocols import (
    AuthCredentials,
    AuthProviderProtocol,
    AuthSession,
)
from isitsecure.engine.auth.supabase_auth import SupabaseAuthProvider
from isitsecure.engine.auth.token_auth import TokenAuthProvider
from isitsecure.engine.constants import (
    BrowserAuthConfig,
    SupabaseAuthConfig,
    TokenAuthConfig,
)
from isitsecure.engine.enums import AuthProvider


def _make_jwt(payload: dict) -> str:
    """Build a fake JWT (header.payload.signature) for testing."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    signature = "fakesignature"
    return f"{header}.{body}.{signature}"


# ---------------------------------------------------------------------------
# SupabaseAuthProvider
# ---------------------------------------------------------------------------


class TestSupabaseAuthProvider:
    """Tests for SupabaseAuthProvider."""

    SUPABASE_URL = "https://test-project.supabase.co"
    ANON_KEY = "test-anon-key-1234"

    def _make_provider(self) -> SupabaseAuthProvider:
        return SupabaseAuthProvider(
            supabase_url=self.SUPABASE_URL,
            anon_key=self.ANON_KEY,
        )

    def _make_credentials(
        self,
        email: str = "user@example.com",
        password: str = "password123",
    ) -> AuthCredentials:
        return AuthCredentials(
            provider=AuthProvider.SUPABASE,
            email=email,
            password=password,
        )

    def test_implements_protocol(self):
        """Verify SupabaseAuthProvider satisfies AuthProviderProtocol."""
        provider = self._make_provider()
        assert isinstance(provider, AuthProviderProtocol)

    def test_provider_type(self):
        """Should return AuthProvider.SUPABASE."""
        provider = self._make_provider()
        assert provider.provider_type == AuthProvider.SUPABASE

    def test_constructor_validates_url(self):
        """Should raise ValueError if supabase_url is empty."""
        with pytest.raises(ValueError, match=SupabaseAuthConfig.ERROR_MISSING_SUPABASE_URL):
            SupabaseAuthProvider(supabase_url="", anon_key=self.ANON_KEY)

    def test_constructor_validates_anon_key(self):
        """Should raise ValueError if anon_key is empty."""
        with pytest.raises(ValueError, match=SupabaseAuthConfig.ERROR_MISSING_ANON_KEY):
            SupabaseAuthProvider(supabase_url=self.SUPABASE_URL, anon_key="")

    @pytest.mark.asyncio
    async def test_authenticate_success(self):
        """Mock successful Supabase auth response."""
        provider = self._make_provider()
        credentials = self._make_credentials()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "expires_in": 3600,
            "user": {
                "id": "user-uuid-123",
                "email": "user@example.com",
                "user_metadata": {"name": "Test User"},
            },
        }

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            session = await provider.authenticate(credentials)

        assert session.user_id == "user-uuid-123"
        assert session.access_token == "new-access-token"
        assert session.refresh_token == "new-refresh-token"
        assert session.user_email == "user@example.com"
        assert session.provider == AuthProvider.SUPABASE
        assert session.user_metadata == {"name": "Test User"}

    @pytest.mark.asyncio
    async def test_authenticate_invalid_credentials(self):
        """Should raise ValueError on 400 response."""
        provider = self._make_provider()
        credentials = self._make_credentials()

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Invalid login credentials"

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            with pytest.raises(ValueError, match="Authentication failed"):
                await provider.authenticate(credentials)

    @pytest.mark.asyncio
    async def test_authenticate_missing_email(self):
        """Should raise ValueError if email is missing."""
        provider = self._make_provider()
        credentials = AuthCredentials(
            provider=AuthProvider.SUPABASE,
            password="password123",
        )
        with pytest.raises(ValueError, match=SupabaseAuthConfig.ERROR_MISSING_CREDENTIALS):
            await provider.authenticate(credentials)

    @pytest.mark.asyncio
    async def test_authenticate_missing_password(self):
        """Should raise ValueError if password is missing."""
        provider = self._make_provider()
        credentials = AuthCredentials(
            provider=AuthProvider.SUPABASE,
            email="user@example.com",
        )
        with pytest.raises(ValueError, match=SupabaseAuthConfig.ERROR_MISSING_CREDENTIALS):
            await provider.authenticate(credentials)

    @pytest.mark.asyncio
    async def test_refresh_success(self):
        """Mock successful token refresh."""
        provider = self._make_provider()
        old_session = AuthSession(
            user_id="user-uuid-123",
            access_token="old-access-token",
            refresh_token="old-refresh-token",
            headers={},
            provider=AuthProvider.SUPABASE,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "refreshed-access-token",
            "refresh_token": "refreshed-refresh-token",
            "user": {
                "id": "user-uuid-123",
                "email": "user@example.com",
                "user_metadata": {},
            },
        }

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            new_session = await provider.refresh(old_session)

        assert new_session.access_token == "refreshed-access-token"
        assert new_session.refresh_token == "refreshed-refresh-token"
        assert new_session.provider == AuthProvider.SUPABASE

    @pytest.mark.asyncio
    async def test_refresh_missing_refresh_token(self):
        """Should raise ValueError if refresh_token is missing."""
        provider = self._make_provider()
        session = AuthSession(
            user_id="user-uuid-123",
            access_token="token",
            headers={},
            provider=AuthProvider.SUPABASE,
        )
        with pytest.raises(ValueError, match=SupabaseAuthConfig.ERROR_MISSING_REFRESH_TOKEN):
            await provider.refresh(session)

    @pytest.mark.asyncio
    async def test_refresh_expired_token(self):
        """Should raise ValueError on failed refresh."""
        provider = self._make_provider()
        session = AuthSession(
            user_id="user-uuid-123",
            access_token="token",
            refresh_token="bad-refresh",
            headers={},
            provider=AuthProvider.SUPABASE,
        )

        mock_response = MagicMock()
        mock_response.status_code = 401

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            with pytest.raises(ValueError, match=SupabaseAuthConfig.ERROR_TOKEN_EXPIRED):
                await provider.refresh(session)

    def test_headers_include_apikey_and_bearer(self):
        """AuthSession headers should include both apikey and Authorization."""
        provider = self._make_provider()
        headers = provider._build_session_headers("test-token")
        assert headers[SupabaseAuthConfig.HEADER_APIKEY] == self.ANON_KEY
        assert headers[SupabaseAuthConfig.HEADER_AUTHORIZATION] == "Bearer test-token"
        assert headers[SupabaseAuthConfig.HEADER_CONTENT_TYPE] == SupabaseAuthConfig.CONTENT_TYPE_JSON


# ---------------------------------------------------------------------------
# TokenAuthProvider
# ---------------------------------------------------------------------------


class TestTokenAuthProvider:
    """Tests for TokenAuthProvider."""

    def _make_provider(self) -> TokenAuthProvider:
        return TokenAuthProvider()

    def test_implements_protocol(self):
        """Verify TokenAuthProvider satisfies AuthProviderProtocol."""
        provider = self._make_provider()
        assert isinstance(provider, AuthProviderProtocol)

    def test_provider_type(self):
        """Should return AuthProvider.TOKEN."""
        provider = self._make_provider()
        assert provider.provider_type == AuthProvider.TOKEN

    @pytest.mark.asyncio
    async def test_authenticate_decodes_jwt(self):
        """Should decode JWT payload to extract user_id and email."""
        provider = self._make_provider()
        token = _make_jwt({
            "sub": "user-id-456",
            "email": "jwt@example.com",
            "exp": 1893456000,
        })
        credentials = AuthCredentials(
            provider=AuthProvider.TOKEN,
            access_token=token,
        )

        session = await provider.authenticate(credentials)

        assert session.user_id == "user-id-456"
        assert session.user_email == "jwt@example.com"
        assert session.access_token == token
        assert session.provider == AuthProvider.TOKEN
        assert session.expires_at is not None
        assert TokenAuthConfig.HEADER_AUTHORIZATION in session.headers

    @pytest.mark.asyncio
    async def test_authenticate_missing_token(self):
        """Should raise ValueError when no token is provided."""
        provider = self._make_provider()
        credentials = AuthCredentials(provider=AuthProvider.TOKEN)

        with pytest.raises(ValueError, match=TokenAuthConfig.ERROR_MISSING_TOKEN):
            await provider.authenticate(credentials)

    @pytest.mark.asyncio
    async def test_authenticate_invalid_jwt_format(self):
        """Should raise ValueError for malformed JWT."""
        provider = self._make_provider()
        credentials = AuthCredentials(
            provider=AuthProvider.TOKEN,
            access_token="not-a-valid-jwt",
        )

        with pytest.raises(ValueError, match="Failed to decode JWT"):
            await provider.authenticate(credentials)

    @pytest.mark.asyncio
    async def test_authenticate_jwt_without_sub(self):
        """Should fallback to 'unknown' user_id if 'sub' missing."""
        provider = self._make_provider()
        token = _make_jwt({"email": "test@example.com"})
        credentials = AuthCredentials(
            provider=AuthProvider.TOKEN,
            access_token=token,
        )

        session = await provider.authenticate(credentials)
        assert session.user_id == "unknown"

    @pytest.mark.asyncio
    async def test_refresh_raises(self):
        """Token auth doesn't support refresh."""
        provider = self._make_provider()
        session = AuthSession(
            user_id="user-id",
            access_token="token",
            headers={},
            provider=AuthProvider.TOKEN,
        )

        with pytest.raises(NotImplementedError, match=TokenAuthConfig.ERROR_REFRESH_NOT_SUPPORTED):
            await provider.refresh(session)


# ---------------------------------------------------------------------------
# BrowserAuthProvider
# ---------------------------------------------------------------------------


class TestBrowserAuthProvider:
    """Tests for BrowserAuthProvider."""

    def _make_provider(self) -> BrowserAuthProvider:
        return BrowserAuthProvider()

    def test_implements_protocol(self):
        """Verify BrowserAuthProvider satisfies AuthProviderProtocol."""
        provider = self._make_provider()
        assert isinstance(provider, AuthProviderProtocol)

    def test_provider_type(self):
        """Should return AuthProvider.BROWSER."""
        provider = self._make_provider()
        assert provider.provider_type == AuthProvider.BROWSER

    @pytest.mark.asyncio
    async def test_authenticate_missing_login_url(self):
        """Should raise ValueError if login_url is missing."""
        provider = self._make_provider()
        credentials = AuthCredentials(
            provider=AuthProvider.BROWSER,
            email="user@example.com",
            password="password",
        )

        with pytest.raises(ValueError, match=BrowserAuthConfig.ERROR_MISSING_LOGIN_URL):
            await provider.authenticate(credentials)

    @pytest.mark.asyncio
    async def test_authenticate_missing_credentials(self):
        """Should raise ValueError if email or password is missing."""
        provider = self._make_provider()
        credentials = AuthCredentials(
            provider=AuthProvider.BROWSER,
            login_url="https://app.example.com/login",
        )

        with pytest.raises(ValueError, match=BrowserAuthConfig.ERROR_MISSING_CREDENTIALS):
            await provider.authenticate(credentials)

    @pytest.mark.asyncio
    async def test_authenticate_extracts_tokens(self):
        """Mock Playwright page with localStorage token."""
        provider = self._make_provider()
        credentials = AuthCredentials(
            provider=AuthProvider.BROWSER,
            email="user@example.com",
            password="password123",
            login_url="https://app.example.com/login",
        )

        # Build mock Playwright objects
        mock_page = AsyncMock()
        mock_page.goto = AsyncMock()
        mock_page.wait_for_load_state = AsyncMock()

        # query_selector returns elements for email, password, submit
        email_input = AsyncMock()
        password_input = AsyncMock()
        submit_button = AsyncMock()

        async def mock_query_selector(selector):
            if "email" in selector:
                return email_input
            if "password" in selector:
                return password_input
            if "submit" in selector:
                return submit_button
            return None

        mock_page.query_selector = AsyncMock(side_effect=mock_query_selector)

        # localStorage returns a token for "access_token"
        async def mock_evaluate(script):
            if "localStorage.getItem('access_token')" in script:
                return "found-browser-token"
            if "Object.keys" in script:
                return []
            return None

        mock_page.evaluate = AsyncMock(side_effect=mock_evaluate)

        mock_context = AsyncMock()
        mock_context.new_page = AsyncMock(return_value=mock_page)
        mock_context.cookies = AsyncMock(return_value=[
            {"name": "session", "value": "sess-123"},
        ])

        mock_browser = AsyncMock()
        mock_browser.new_context = AsyncMock(return_value=mock_context)
        mock_browser.close = AsyncMock()

        mock_playwright = AsyncMock()
        mock_playwright.chromium.launch = AsyncMock(return_value=mock_browser)

        mock_pw_context = AsyncMock()
        mock_pw_context.__aenter__ = AsyncMock(return_value=mock_playwright)
        mock_pw_context.__aexit__ = AsyncMock(return_value=None)

        mock_pw_module = MagicMock()
        mock_pw_module.async_playwright = MagicMock(return_value=mock_pw_context)

        with patch.dict(
            "sys.modules",
            {"playwright.async_api": mock_pw_module},
        ):
            session = await provider.authenticate(credentials)

        assert session.access_token == "found-browser-token"
        assert session.provider == AuthProvider.BROWSER
        assert "Authorization" in session.headers

    @pytest.mark.asyncio
    async def test_refresh_raises(self):
        """Browser auth doesn't support refresh."""
        provider = self._make_provider()
        session = AuthSession(
            user_id="user-id",
            access_token="token",
            headers={},
            provider=AuthProvider.BROWSER,
        )

        with pytest.raises(
            NotImplementedError,
            match=BrowserAuthConfig.ERROR_REFRESH_NOT_SUPPORTED,
        ):
            await provider.refresh(session)

    def test_clean_token_strips_quotes(self):
        """Should strip surrounding quotes from token strings (now in shared helper)."""
        from isitsecure.engine.auth.browser_login_helper import _clean_token
        assert _clean_token('"quoted-token"') == "quoted-token"
        assert _clean_token("'single-quoted'") == "single-quoted"
        assert _clean_token("plain-token") == "plain-token"

    def test_extract_token_from_json(self):
        """Should extract access_token from JSON string (now in shared helper)."""
        from isitsecure.engine.auth.browser_login_helper import extract_token_from_json
        raw = json.dumps({"access_token": "json-token", "other": "data"})
        assert extract_token_from_json(raw) == "json-token"

    def test_extract_token_from_json_invalid(self):
        """Should return None for invalid JSON (now in shared helper)."""
        from isitsecure.engine.auth.browser_login_helper import extract_token_from_json
        assert extract_token_from_json("not-json") is None


# ---------------------------------------------------------------------------
# AuthCredentials and AuthSession model tests
# ---------------------------------------------------------------------------


class TestAuthModels:
    """Tests for Pydantic auth models."""

    def test_auth_credentials_minimal(self):
        """Should create with only provider."""
        creds = AuthCredentials(provider=AuthProvider.TOKEN)
        assert creds.provider == AuthProvider.TOKEN
        assert creds.email is None
        assert creds.cookies is None

    def test_auth_session_defaults(self):
        """Should use default_factory for mutable fields."""
        session = AuthSession(
            user_id="uid",
            access_token="tok",
            provider=AuthProvider.SUPABASE,
        )
        assert session.headers == {}
        assert session.user_metadata == {}
        assert session.refresh_token is None
        assert session.expires_at is None

    def test_auth_session_mutable_defaults_are_independent(self):
        """Two sessions should not share mutable default dicts."""
        s1 = AuthSession(
            user_id="u1", access_token="t1", provider=AuthProvider.TOKEN
        )
        s2 = AuthSession(
            user_id="u2", access_token="t2", provider=AuthProvider.TOKEN
        )
        s1.headers["key"] = "value"
        assert "key" not in s2.headers
