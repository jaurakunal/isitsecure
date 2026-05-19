"""Supabase authentication provider for the Deep Security Scan Agent."""

from datetime import datetime, timedelta, timezone

import httpx

from isitsecure.engine.constants import SupabaseAuthConfig
from isitsecure.engine.enums import AuthProvider

from .protocols import AuthCredentials, AuthSession


class SupabaseAuthProvider:
    """Authenticates via Supabase Auth API using email/password.

    Uses the anon key (discovered from JS bundles) + user credentials
    to obtain a JWT via /auth/v1/token?grant_type=password.
    """

    def __init__(self, supabase_url: str, anon_key: str) -> None:
        if not supabase_url:
            raise ValueError(SupabaseAuthConfig.ERROR_MISSING_SUPABASE_URL)
        if not anon_key:
            raise ValueError(SupabaseAuthConfig.ERROR_MISSING_ANON_KEY)
        self._supabase_url = supabase_url.rstrip("/")
        self._anon_key = anon_key

    @property
    def provider_type(self) -> AuthProvider:
        return AuthProvider.SUPABASE

    def _build_api_headers(self) -> dict[str, str]:
        """Build standard headers for Supabase API calls."""
        return {
            SupabaseAuthConfig.HEADER_APIKEY: self._anon_key,
            SupabaseAuthConfig.HEADER_CONTENT_TYPE: SupabaseAuthConfig.CONTENT_TYPE_JSON,
        }

    def _build_session_headers(self, access_token: str) -> dict[str, str]:
        """Build headers for authenticated requests."""
        return {
            SupabaseAuthConfig.HEADER_AUTHORIZATION: (
                f"{SupabaseAuthConfig.BEARER_PREFIX}{access_token}"
            ),
            SupabaseAuthConfig.HEADER_APIKEY: self._anon_key,
            SupabaseAuthConfig.HEADER_CONTENT_TYPE: SupabaseAuthConfig.CONTENT_TYPE_JSON,
        }

    async def authenticate(self, credentials: AuthCredentials) -> AuthSession:
        """Authenticate with Supabase using email and password."""
        if not credentials.email or not credentials.password:
            raise ValueError(SupabaseAuthConfig.ERROR_MISSING_CREDENTIALS)

        url = f"{self._supabase_url}{SupabaseAuthConfig.AUTH_TOKEN_ENDPOINT}"
        payload = {
            "email": credentials.email,
            "password": credentials.password,
        }

        async with httpx.AsyncClient(
            timeout=SupabaseAuthConfig.HTTP_TIMEOUT_SECONDS
        ) as client:
            response = await client.post(
                url,
                json=payload,
                headers=self._build_api_headers(),
            )

        if response.status_code != 200:
            error_detail = response.text
            raise ValueError(
                SupabaseAuthConfig.ERROR_AUTH_FAILED.format(error=error_detail)
            )

        data = response.json()
        access_token = data["access_token"]
        user = data.get("user", {})
        expires_in = data.get("expires_in")

        expires_at = None
        if expires_in:
            expires_at = datetime.now(tz=timezone.utc).replace(
                microsecond=0
            ) + timedelta(seconds=expires_in)

        return AuthSession(
            user_id=user.get("id", ""),
            access_token=access_token,
            refresh_token=data.get("refresh_token"),
            headers=self._build_session_headers(access_token),
            expires_at=expires_at,
            user_email=user.get("email"),
            user_metadata=user.get("user_metadata", {}),
            provider=AuthProvider.SUPABASE,
        )

    async def refresh(self, session: AuthSession) -> AuthSession:
        """Refresh an expired Supabase session."""
        if not session.refresh_token:
            raise ValueError(SupabaseAuthConfig.ERROR_MISSING_REFRESH_TOKEN)

        url = f"{self._supabase_url}{SupabaseAuthConfig.AUTH_REFRESH_ENDPOINT}"
        payload = {"refresh_token": session.refresh_token}

        async with httpx.AsyncClient(
            timeout=SupabaseAuthConfig.HTTP_TIMEOUT_SECONDS
        ) as client:
            response = await client.post(
                url,
                json=payload,
                headers=self._build_api_headers(),
            )

        if response.status_code != 200:
            raise ValueError(
                SupabaseAuthConfig.ERROR_TOKEN_EXPIRED
            )

        data = response.json()
        access_token = data["access_token"]
        user = data.get("user", {})

        return AuthSession(
            user_id=user.get("id", session.user_id),
            access_token=access_token,
            refresh_token=data.get("refresh_token"),
            headers=self._build_session_headers(access_token),
            expires_at=session.expires_at,
            user_email=user.get("email", session.user_email),
            user_metadata=user.get("user_metadata", session.user_metadata),
            provider=AuthProvider.SUPABASE,
        )
