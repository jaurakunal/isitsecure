"""Generic REST login provider.

Authenticates against an arbitrary JSON REST API by POSTing credentials to a
login endpoint and extracting a bearer token from the response — the piece
that lets cross-user IDOR testing work on APIs that aren't Supabase and have
no browser frontend to drive. All heuristics are generic (common login paths,
common credential/token field names, JWT shape) — no app-specific strings.
"""

from __future__ import annotations

import base64
import binascii
import json
import re

import httpx

from isitsecure.engine.constants import RestLoginConfig
from isitsecure.engine.enums import AuthProvider

from .protocols import AuthCredentials, AuthSession


class RestLoginAuthProvider:
    """Logs into a REST API with email/username + password → AuthSession."""

    def __init__(self, base_url: str, login_paths: tuple[str, ...] | None = None) -> None:
        self._base = base_url.rstrip("/")
        self._login_paths = login_paths or RestLoginConfig.LOGIN_PROBE_PATHS

    @property
    def provider_type(self) -> AuthProvider:
        return AuthProvider.TOKEN

    async def authenticate(self, credentials: AuthCredentials) -> AuthSession:
        identifier = credentials.email or ""
        if credentials.login_url:
            candidates = [credentials.login_url]
        else:
            candidates = [f"{self._base}{p}" for p in self._login_paths]

        last_error = "no endpoint responded with a token"
        async with httpx.AsyncClient(
            timeout=RestLoginConfig.HTTP_TIMEOUT_SECONDS, follow_redirects=True,
        ) as client:
            for url in candidates:
                for id_key in RestLoginConfig.IDENTIFIER_KEYS:
                    payload = {id_key: identifier, "password": credentials.password}
                    try:
                        resp = await client.post(url, json=payload)
                    except httpx.HTTPError as exc:
                        last_error = str(exc)
                        continue
                    if resp.status_code >= 400:
                        last_error = f"{url} -> HTTP {resp.status_code}"
                        continue
                    token = self._extract_token(resp)
                    if token:
                        # Prefer the cookies the app actually set on login
                        # (the real session cookie, correct name and value).
                        real_cookie = "; ".join(
                            f"{c.name}={c.value}" for c in client.cookies.jar
                        )
                        return self._build_session(token, identifier, real_cookie)
                    last_error = f"{url} -> no token in response"

        raise ValueError(RestLoginConfig.ERROR_LOGIN_FAILED.format(
            count=len(candidates), error=last_error))

    # ------------------------------------------------------------------

    def _extract_token(self, resp: httpx.Response) -> str | None:
        """Pull a bearer token from the login response."""
        try:
            data = resp.json()
        except (ValueError, json.JSONDecodeError):
            data = None
        if isinstance(data, dict):
            for key in RestLoginConfig.TOKEN_RESPONSE_KEYS:
                value = self._find_key(data, key)
                if isinstance(value, str) and value:
                    return value
        # Fallback: any JWT-shaped string in the body.
        match = re.search(RestLoginConfig.JWT_REGEX, resp.text)
        return match.group(0) if match else None

    @staticmethod
    def _find_key(obj: object, key: str) -> object | None:
        """Depth-first search for `key` in a nested dict/list."""
        if isinstance(obj, dict):
            if key in obj:
                return obj[key]
            for v in obj.values():
                found = RestLoginAuthProvider._find_key(v, key)
                if found is not None:
                    return found
        elif isinstance(obj, list):
            for item in obj:
                found = RestLoginAuthProvider._find_key(item, key)
                if found is not None:
                    return found
        return None

    def _build_session(
        self, token: str, identifier: str, real_cookie: str = "",
    ) -> AuthSession:
        user_id = self._jwt_subject(token) or identifier or "user"
        headers = {"Authorization": f"Bearer {token}"}
        # Server-rendered endpoints (profile forms, upload handlers) often
        # authenticate by cookie, not the Authorization header. Prefer the real
        # cookie the app set on login -- correct name and value, general to any
        # app. Only when the login response sets no cookie (e.g. an SPA whose
        # login API returns the JWT in the body and sets the auth cookie
        # client-side, like Juice Shop) fall back to mirroring the token into
        # the common JWT-cookie names. Unknown cookies are harmlessly ignored.
        if real_cookie:
            headers["Cookie"] = real_cookie
        else:
            headers["Cookie"] = f"token={token}; access_token={token}"
        return AuthSession(
            user_id=str(user_id),
            access_token=token,
            headers=headers,
            user_email=identifier if "@" in identifier else None,
            provider=AuthProvider.TOKEN,
        )

    @staticmethod
    def _jwt_subject(token: str) -> str | None:
        """Best-effort: read `sub`/`user_id` from a JWT without verifying it."""
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        try:
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        except (ValueError, binascii.Error, json.JSONDecodeError):
            return None
        return payload.get(RestLoginConfig.JWT_CLAIM_SUB) or payload.get(
            RestLoginConfig.JWT_CLAIM_USER_ID)

    async def refresh(self, session: AuthSession) -> AuthSession:
        return session  # stateless bearer tokens; re-authenticate if expired
