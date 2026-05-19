"""Protocols and models for authentication in the Deep Security Scan Agent."""

from datetime import datetime
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from isitsecure.engine.enums import AuthProvider


class AuthCredentials(BaseModel):
    """Credentials provided by the customer for authentication."""

    provider: AuthProvider
    email: str | None = None
    password: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    cookies: dict[str, str] | None = None
    login_url: str | None = None


class AuthSession(BaseModel):
    """Authenticated session returned by a provider."""

    user_id: str
    access_token: str
    refresh_token: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    expires_at: datetime | None = None
    user_email: str | None = None
    user_metadata: dict = Field(default_factory=dict)
    provider: AuthProvider


@runtime_checkable
class AuthProviderProtocol(Protocol):
    """Protocol that all auth providers must satisfy."""

    @property
    def provider_type(self) -> AuthProvider: ...

    async def authenticate(self, credentials: AuthCredentials) -> AuthSession: ...

    async def refresh(self, session: AuthSession) -> AuthSession: ...
