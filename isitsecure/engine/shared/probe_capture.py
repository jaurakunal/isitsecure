"""Shared helper for building DAST probe capture entries.

Provides utility functions to record HTTP request/response pairs during
DAST scanning for inclusion in findings and reports.
"""

from __future__ import annotations

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
    truncated_req_body = body[: ProbeCaptureConfig.MAX_REQUEST_BODY_CAPTURE]
    truncated_resp_body = response_body[: ProbeCaptureConfig.MAX_RESPONSE_BODY_CAPTURE]

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


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact sensitive header values (auth tokens, API keys).

    Headers whose names match any entry in
    ``ProbeCaptureConfig.SENSITIVE_HEADERS`` will have their values
    truncated after ``ProbeCaptureConfig.REDACT_AFTER_CHARS`` characters
    and replaced with the redact placeholder.

    Args:
        headers: Raw header dict.

    Returns:
        A new dict with sensitive values redacted.
    """
    sanitized: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in ProbeCaptureConfig.SENSITIVE_HEADERS:
            if len(value) > ProbeCaptureConfig.REDACT_AFTER_CHARS:
                value = value[: ProbeCaptureConfig.REDACT_AFTER_CHARS] + ProbeCaptureConfig.REDACT_PLACEHOLDER
        sanitized[name] = value
    return sanitized
