"""Auth-aware DAST scanner mixin (#115).

DAST HTTP scanners that probe endpoints inherit this so the authenticated scan
path can hand them the session's auth (bearer token and/or session cookie). The
orchestrator sets ``_auth_headers`` on every scanner exposing it after an
authenticated crawl; each scanner passes ``self.auth_headers`` as
``extra_headers`` to its ``RateLimitedClient`` so probes reach protected
endpoints instead of being redirected to login.

``_auth_headers`` is a class-level default so ``hasattr(scanner, "_auth_headers")``
is always true (the orchestrator's propagation guard); the orchestrator assigns a
fresh per-instance dict, so the shared default is only ever read, never mutated.
"""

from __future__ import annotations


class AuthAwareScanner:
    """Mixin giving a DAST scanner an injectable auth-headers slot."""

    _auth_headers: dict[str, str] = {}

    @property
    def auth_headers(self) -> dict[str, str] | None:
        """Auth headers for the scanner's HTTP client, or None when unauthenticated."""
        return self._auth_headers or None
