"""Response-evidence helpers for the SAST-guided DAST runner.

A guided probe is only a finding when the *response body* shows the weakness.
A bare 2xx is not evidence: single-page apps answer every path and method with
the same HTML shell, and APIs answer an ignored parameter with a normal 200.

SRP: this module only inspects responses; it never sends requests.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from isitsecure.engine.constants import InjectionConfig

_ERROR_ONLY_KEYS = frozenset({
    "error", "errors", "message", "detail", "details", "status", "code", "msg",
})

_SQL_ERROR_RE = re.compile(
    "|".join(InjectionConfig.SQL_ERROR_PATTERNS), re.IGNORECASE,
)

_CATCH_ALL_LENGTH_TOLERANCE = 0.02


def is_html(response: httpx.Response) -> bool:
    """True when the response is an HTML document (content-type or body)."""
    ctype = response.headers.get("content-type", "").lower()
    if "html" in ctype:
        return True
    head = response.text[:200].lstrip().lower()
    return head.startswith("<!doctype html") or head.startswith("<html")


def json_body(response: httpx.Response) -> Any:
    """Parsed JSON body, or None when the body is not JSON."""
    try:
        return json.loads(response.text)
    except (ValueError, TypeError):
        return None


def has_data(parsed: Any) -> bool:
    """True when parsed JSON carries records, not an empty/error envelope."""
    if isinstance(parsed, list):
        return len(parsed) > 0
    if isinstance(parsed, dict):
        return bool(parsed) and not set(parsed) <= _ERROR_ONLY_KEYS
    return False


def sql_error(response: httpx.Response) -> str | None:
    """The SQL error signature found in the body, if any."""
    match = _SQL_ERROR_RE.search(response.text[:5000])
    return match.group(0) if match else None


def reflects_unescaped(response: httpx.Response, payload: str) -> bool:
    """True when a non-JSON response echoes the payload unescaped."""
    ctype = response.headers.get("content-type", "").lower()
    if "json" in ctype or "text/plain" in ctype:
        return False
    return payload in response.text


def same_page(a: httpx.Response, b: httpx.Response) -> bool:
    """True when two responses are the same page (catch-all shell detection)."""
    if a.status_code != b.status_code:
        return False
    if a.text == b.text:
        return True
    if is_html(a) and is_html(b):
        la, lb = len(a.text), len(b.text)
        return abs(la - lb) <= max(la, lb) * _CATCH_ALL_LENGTH_TOLERANCE
    return False


def echoes_field(parsed: Any, sent: dict) -> bool:
    """True when the response JSON contains a sent key with the sent value."""
    if isinstance(parsed, dict):
        for key, value in parsed.items():
            if key in sent and sent[key] == value:
                return True
            if echoes_field(value, sent):
                return True
    elif isinstance(parsed, list):
        return any(echoes_field(item, sent) for item in parsed)
    return False
