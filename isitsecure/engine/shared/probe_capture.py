"""Shared helper for building DAST probe capture entries.

Provides utility functions to record HTTP request/response pairs during
DAST scanning for inclusion in findings and reports.
"""

from __future__ import annotations

import re
import shlex
from datetime import datetime, timezone

from isitsecure.engine.constants import ProbeCaptureConfig
from isitsecure.engine.models import DASTProbeCaptureEntry


def build_probe_capture(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str,
    response_status: int,
    response_headers: dict[str, str],
    response_body: str,
    elapsed_ms: float,
    scanner_name: str,
) -> DASTProbeCaptureEntry:
    """Build a capture entry from request/response data.

    Args:
        method: HTTP method (GET, POST, etc.).
        url: Full request URL.
        headers: Request headers (will be sanitized).
        body: Request body content.
        response_status: HTTP response status code.
        response_headers: Response headers (will be sanitized).
        response_body: Response body content (will be truncated).
        elapsed_ms: Response time in milliseconds.
        scanner_name: Name of the scanner that produced this capture.

    Returns:
        A fully populated DASTProbeCaptureEntry.
    """
    sanitized_req_headers = sanitize_headers(headers)
    sanitized_resp_headers = sanitize_headers(response_headers)
    truncated_req_body = redact_body(body)[: ProbeCaptureConfig.MAX_REQUEST_BODY_CAPTURE]
    truncated_resp_body = redact_body(response_body)[: ProbeCaptureConfig.MAX_RESPONSE_BODY_CAPTURE]

    return DASTProbeCaptureEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        scanner_name=scanner_name,
        request_method=method,
        request_url=url,
        request_headers=sanitized_req_headers,
        request_body=truncated_req_body,
        response_status=response_status,
        response_headers=sanitized_resp_headers,
        response_body=truncated_resp_body,
        response_time_ms=elapsed_ms,
        curl_command=build_curl_command(method, url, sanitized_req_headers, truncated_req_body),
    )


def build_curl_command(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str,
) -> str:
    """Generate a curl command for replaying the request.

    Args:
        method: HTTP method.
        url: Full request URL.
        headers: Request headers (should already be sanitized).
        body: Request body.

    Returns:
        A shell-safe curl command string.
    """
    parts = ["curl", "-X", method]

    for header_name, header_value in headers.items():
        parts.extend(["-H", f"{header_name}: {header_value}"])

    if body:
        parts.extend(["-d", body])

    parts.append(url)

    return " ".join(shlex.quote(p) for p in parts)


_SENSITIVE_HEADER_NAMES = frozenset({
    "set-cookie", "cookie", "authorization", "proxy-authorization",
    "x-auth-token", "x-api-key", "apikey", "x-csrf-token",
})
_SENSITIVE_HEADER_SUBSTRINGS = ("token", "secret", "key", "session")
_SENSITIVE_FIELD = (
    r"(?:access_?token|refresh_?token|id_?token|token|password|passwd|secret|"
    r"client_?secret|api_?key|apikey|authorization|session|session_?id|bearer)"
)
# "field": "value"  (JSON, tolerant of truncated bodies)
_JSON_FIELD_RE = re.compile(
    r'("' + _SENSITIVE_FIELD + r'"\s*:\s*)"(?:[^"\\]|\\.)*"', re.IGNORECASE
)
# field=value / field: value (form bodies, plain text, python-repr dicts)
_KV_FIELD_RE = re.compile(
    r"(['\"]?\b" + _SENSITIVE_FIELD + r"['\"]?\s*[=:]\s*)(['\"]?)[^&\s'\",;}]+",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
REDACTED = "[REDACTED]"


def _is_sensitive_header(name: str) -> bool:
    lowered = name.lower()
    return lowered in _SENSITIVE_HEADER_NAMES or any(
        part in lowered for part in _SENSITIVE_HEADER_SUBSTRINGS
    )


def mask_token(value: str) -> str:
    """Mask a token to at most an 8-char prefix plus its length."""
    return f"{value[:8]}...[len={len(value)}]"


def mask_jwts(text: str) -> str:
    """Replace every JWT-looking string in ``text`` with a masked form."""
    return _JWT_RE.sub(lambda m: mask_token(m.group(0)), text)


def redact_body(body: str) -> str:
    """Redact secrets (token/password JSON fields, bearer values, JWTs) in a body.

    The rest of the body is preserved so evidence stays useful.
    """
    if not body:
        return body
    body = _JSON_FIELD_RE.sub(lambda m: f'{m.group(1)}"{REDACTED}"', body)
    body = _KV_FIELD_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", body)
    body = _BEARER_RE.sub(lambda m: f"{m.group(1)}{REDACTED}", body)
    return _JWT_RE.sub(REDACTED, body)


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact sensitive header values, keeping header names.

    Cookies, auth headers, API keys, CSRF tokens and any header whose name
    contains token/secret/key/session get their value replaced entirely
    with ``ProbeCaptureConfig.REDACT_PLACEHOLDER``.
    """
    sanitized: dict[str, str] = {}
    for name, value in headers.items():
        if _is_sensitive_header(name):
            value = ProbeCaptureConfig.REDACT_PLACEHOLDER
        sanitized[name] = value
    return sanitized
