"""Response-shape helpers for DAST verdicts.

Live apps (single-page apps especially) answer every path and method with a
catch-all ``200`` HTML shell. A bare 2xx or a generic marker word in the body
is therefore never evidence on its own. These helpers let scanners tell a
real API answer from a shell or from a ``200 {"success": false}`` rejection.
"""

from __future__ import annotations

import json
from typing import Any

_HTML_PREFIXES = ("<!doctype html", "<html", "<head", "<body")
_FAILURE_FLAGS = ("success", "ok", "status")
_FAILURE_STATUS_WORDS = frozenset({"error", "fail", "failed", "failure", "denied"})
_ERROR_KEYS = ("error", "errors", "err")


def is_html_document(text: str) -> bool:
    """True when the body is an HTML document (SPA shell / error page)."""
    head = text.lstrip()[:200].lower()
    return head.startswith(_HTML_PREFIXES)


def parse_json_body(text: str) -> Any | None:
    """Parse a JSON body, returning ``None`` when it is not valid JSON."""
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def json_signals_failure(data: Any) -> bool:
    """True for ``{"success": false}`` / ``{"error": ...}`` style rejections."""
    if not isinstance(data, dict):
        return False
    for key in _FAILURE_FLAGS:
        value = data.get(key)
        if value is False:
            return True
        if (
            key == "status"
            and isinstance(value, str)
            and value.lower() in _FAILURE_STATUS_WORDS
        ):
            return True
    return any(data.get(key) for key in _ERROR_KEYS)
