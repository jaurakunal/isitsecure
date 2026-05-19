"""Token-based authentication provider for the Deep Security Scan Agent."""

import base64
import json
from datetime import datetime, timezone

from isitsecure.engine.constants import TokenAuthConfig
from isitsecure.engine.enums import AuthProvider

from .protocols import AuthCredentials, AuthSession


class TokenAuthProvider:
    """Uses a pre-existing JWT token provided directly by the customer."""

    @property
    def provider_type(self) -> AuthProvider:
        return AuthProvider.TOKEN

    def _decode_jwt_payload(self, token: str) -> dict:
        """Decode the JWT payload without signature verification."""
        parts = token.split(".")
        if len(parts) != TokenAuthConfig.JWT_PARTS_COUNT:
            raise ValueError(
                TokenAuthConfig.ERROR_INVALID_JWT.format(
                    error="Token does not have 3 parts"
                )
            )

        payload_b64 = parts[TokenAuthConfig.JWT_PAYLOAD_INDEX]
        # Add padding if needed for base64 decoding
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        try:
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            return json.loads(payload_bytes)
        except (ValueError, json.JSONDecodeError) as exc:
            raise ValueError(
                TokenAuthConfig.ERROR_INVALID_JWT.format(error=str(exc))
            ) from exc

    async def authenticate(self, credentials: AuthCredentials) -> AuthSession:
        """Authenticate using the provided JWT token."""
        if not credentials.access_token:
            raise ValueError(TokenAuthConfig.ERROR_MISSING_TOKEN)

        token = credentials.access_token
        payload = self._decode_jwt_payload(token)

        user_id = payload.get(
            TokenAuthConfig.JWT_CLAIM_SUB,
            payload.get(
                TokenAuthConfig.JWT_CLAIM_USER_ID,
                TokenAuthConfig.DEFAULT_USER_ID,
            ),
        )
        email = payload.get(TokenAuthConfig.JWT_CLAIM_EMAIL)

        expires_at = None
        exp = payload.get(TokenAuthConfig.JWT_CLAIM_EXP)
        if exp:
            expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)

        return AuthSession(
            user_id=str(user_id),
            access_token=token,
            headers={
                TokenAuthConfig.HEADER_AUTHORIZATION: (
                    f"{TokenAuthConfig.BEARER_PREFIX}{token}"
                ),
            },
            expires_at=expires_at,
            user_email=email,
            user_metadata=payload,
            provider=AuthProvider.TOKEN,
        )

    async def refresh(self, session: AuthSession) -> AuthSession:
        """Token auth does not support refresh."""
        raise NotImplementedError(TokenAuthConfig.ERROR_REFRESH_NOT_SUPPORTED)
