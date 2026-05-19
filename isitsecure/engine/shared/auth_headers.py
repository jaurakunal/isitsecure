"""Shared auth header building utilities.

Used by BodyParamFuzzer, RaceConditionScanner, PrivilegeEscalationScanner,
and any other scanner that needs to replay requests with auth tokens.
"""

from __future__ import annotations

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import SharedPatterns
from isitsecure.engine.models import InterceptedRequest


def build_auth_headers(session: AuthSession) -> dict[str, str]:
    """Build Authorization headers from a session."""
    return {
        SharedPatterns.HEADER_AUTHORIZATION: (
            f"{SharedPatterns.BEARER_PREFIX}{session.access_token}"
        ),
        SharedPatterns.HEADER_CONTENT_TYPE: SharedPatterns.CONTENT_TYPE_JSON,
    }


def build_replay_headers(
    session: AuthSession,
    intercepted: InterceptedRequest | None = None,
) -> dict[str, str]:
    """Build headers for replaying an intercepted request.

    Includes the auth token and carries over the apikey header
    from the original request if present.
    """
    headers = build_auth_headers(session)
    if intercepted and intercepted.request_headers.get(SharedPatterns.HEADER_APIKEY):
        headers[SharedPatterns.HEADER_APIKEY] = (
            intercepted.request_headers[SharedPatterns.HEADER_APIKEY]
        )
    return headers
