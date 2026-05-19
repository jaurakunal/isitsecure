"""Models for ownership verification tokens and results."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from isitsecure.engine.enums import (
    VerificationMethod,
    VerificationStatus,
)


class VerificationToken(BaseModel):
    """A verification token issued to a customer."""

    token: str
    target_url: str | None = None
    repo_url: str | None = None
    method: VerificationMethod
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None


class VerificationResult(BaseModel):
    """Result of an ownership verification check."""

    method: VerificationMethod
    status: VerificationStatus
    verified_at: datetime | None = None
    target_url: str | None = None
    repo_url: str | None = None
    token: str = ""
    error: str | None = None
    confidence: float = 0.0
