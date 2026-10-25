"""Shared helper for building DAST probe capture entries.

Provides utility functions to record HTTP request/response pairs during
DAST scanning for inclusion in findings and reports.
"""

from __future__ import annotations

import json
import re
import shlex
from datetime import datetime, timezone
from urllib.parse import unquote_plus, urlsplit, urlunsplit

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
    safe_url = redact_url(url)
    sanitized_req_headers = sanitize_headers(headers)
    sanitized_resp_headers = sanitize_headers(response_headers)
    truncated_req_body = redact_body(body)[: ProbeCaptureConfig.MAX_REQUEST_BODY_CAPTURE]
    truncated_resp_body = redact_body(response_body)[: ProbeCaptureConfig.MAX_RESPONSE_BODY_CAPTURE]

    return DASTProbeCaptureEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        scanner_name=scanner_name,
        request_method=method,
        request_url=safe_url,
        request_headers=sanitized_req_headers,
        request_body=truncated_req_body,
        response_status=response_status,
        response_headers=sanitized_resp_headers,
        response_body=truncated_resp_body,
        response_time_ms=elapsed_ms,
        curl_command=build_curl_command(method, safe_url, sanitized_req_headers, truncated_req_body),
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
    url = redact_url(url)
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
# Headers whose value is a URL (or contains one): scrub secrets in its query.
_URL_HEADER_NAMES = frozenset({"location", "content-location", "referer", "refresh", "link"})

# A key is secret when its normalised form (case-folded, "-", "_" and spaces
# removed) contains one of these words: ``newPassword``, ``api-key``,
# ``user_password`` and ``X-Auth-Token`` all match.
_SECRET_WORDS = (
    "token", "secret", "password", "passwd", "pwd", "passphrase", "apikey",
    "privatekey", "authorization", "credential", "session", "cookie",
    "bearer", "jwt", "signature",
)
_KEY_STRIP_RE = re.compile(r"[-_\s]")
REDACTED = "[REDACTED]"
_MAX_KEY_LEN = 64
_MAX_JSON_DEPTH = 200

# key candidate in free text / truncated JSON: [quote]key[quote] (=|:) value
_KEY_RE = re.compile(
    r"(?<![\w.-])([\"']?)([A-Za-z0-9_.\-]{1,%d})([\"']?)[ \t]*([=:])[ \t]*" % _MAX_KEY_LEN
)
_STRING_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|[\[\]{}]', re.DOTALL)
_BEARER_RE = re.compile(r"(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
# userinfo of a URL embedded in text: scheme://user:pass@host
_USERINFO_RE = re.compile(r"(\b[a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s@?#]+@")
_BARE_STOP_PLAIN = frozenset("&\r\n")
_BARE_STOP_JSON = frozenset("&\r\n,}]")


def is_secret_key(name: str) -> bool:
    """True when a field/parameter/header name looks like it carries a secret."""
    normalised = _KEY_STRIP_RE.sub("", str(name)).casefold()
    return any(word in normalised for word in _SECRET_WORDS)


def _is_sensitive_header(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered in _SENSITIVE_HEADER_NAMES
        or any(part in lowered for part in _SENSITIVE_HEADER_SUBSTRINGS)
        or is_secret_key(name)
    )


def mask_token(value: str) -> str:
    """Mask a token to at most an 8-char prefix plus its length."""
    return f"{value[:8]}...[len={len(value)}]"


def mask_jwts(text: str) -> str:
    """Replace every JWT-looking string in ``text`` with a masked form."""
    return _JWT_RE.sub(lambda m: mask_token(m.group(0)), text)


def _bracket_end(text: str, start: int) -> int:
    """Index just past the bracket group opening at ``start`` (or len(text) if unclosed)."""
    depth = 0
    for m in _STRING_TOKEN_RE.finditer(text, start):
        tok = m.group(0)
        if tok == "{" or tok == "[":
            depth += 1
        elif tok == "}" or tok == "]":
            depth -= 1
            if depth == 0:
                return m.end()
    return len(text)


def _value_end(text: str, start: int, json_style: bool) -> tuple[int, str]:
    """Return (end index, quote char or "") of the value starting at ``start``."""
    n = len(text)
    if start >= n:
        return start, ""
    ch = text[start]
    if ch in "\"'":
        i = start + 1
        while i < n:
            nxt = text.find(ch, i)
            if nxt == -1:
                return n, ch
            k = nxt - 1  # an odd run of backslashes escapes the quote
            while k >= i and text[k] == "\\":
                k -= 1
            if (nxt - 1 - k) % 2 == 0:
                return nxt + 1, ch
            i = nxt + 1
        return n, ch
    if ch in "{[":
        return _bracket_end(text, start), ""
    stop = _BARE_STOP_JSON if json_style else _BARE_STOP_PLAIN
    i = start
    while i < n and text[i] not in stop:
        i += 1
    return i, ""


def _redact_pairs(text: str) -> str:
    """Redact the whole value after every secret-looking ``key=`` / ``key:``."""
    out: list[str] = []
    pos = 0
    last = 0
    n = len(text)
    while pos < n:
        m = _KEY_RE.search(text, pos)
        if m is None:
            break
        if not is_secret_key(m.group(2)):
            pos = m.end()
            continue
        json_style = bool(m.group(1)) and m.group(4) == ":"
        end, quote = _value_end(text, m.end(), json_style)
        if end == m.end() and not quote:
            pos = m.end()  # empty value, nothing to hide
            continue
        out.append(text[last:m.end()])
        out.append(f"{quote}{REDACTED}{quote}" if quote else REDACTED)
        last = pos = end
    out.append(text[last:])
    return "".join(out)


def redact_text(text: str) -> str:
    """Redact secrets in free text: key=value pairs, bearer values, JWTs, URL userinfo."""
    if not text:
        return text
    text = _USERINFO_RE.sub(lambda m: f"{m.group(1)}{REDACTED}@", text)
    text = _redact_pairs(text)
    text = _BEARER_RE.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    return _JWT_RE.sub(REDACTED, text)


def _redact_json_value(node, depth: int = 0):
    if depth > _MAX_JSON_DEPTH:
        return REDACTED
    if isinstance(node, dict):
        return {
            k: (REDACTED if is_secret_key(k) else _redact_json_value(v, depth + 1))
            for k, v in node.items()
        }
    if isinstance(node, list):
        return [_redact_json_value(v, depth + 1) for v in node]
    if isinstance(node, str):
        if node.lstrip()[:1] in ("{", "["):  # JSON embedded in a string value
            try:
                inner = json.loads(node)
            except (ValueError, RecursionError):
                inner = None
            if isinstance(inner, (dict, list)):
                return json.dumps(_redact_json_value(inner, depth + 1), ensure_ascii=False)
        return redact_text(node)
    return node


def redact_body(body: str) -> str:
    """Redact secrets in a request/response body.

    Valid JSON is parsed and every value under a secret-looking key (any
    type, recursively) is replaced. Anything else (form bodies, text,
    truncated JSON) goes through a linear key/value scanner. The rest of the
    body is preserved so evidence stays useful.
    """
    if not body:
        return body
    if body.lstrip()[:1] in ("{", "["):
        try:
            parsed = json.loads(body)
        except (ValueError, RecursionError):
            parsed = None
        if isinstance(parsed, (dict, list)):
            return json.dumps(_redact_json_value(parsed), ensure_ascii=False)
    return redact_text(body)


def redact_url(url: str) -> str:
    """Redact userinfo and secret query/fragment values in a URL."""
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return redact_text(url)
    netloc = parts.netloc
    if "@" in netloc:
        netloc = f"REDACTED@{netloc.rsplit('@', 1)[1]}"

    def _scrub(component: str) -> str:
        if not component:
            return component
        pieces = []
        for piece in component.split("&"):
            key, sep, _value = piece.partition("=")
            if sep and is_secret_key(unquote_plus(key)):
                piece = f"{key}={REDACTED}"
            pieces.append(piece)
        return "&".join(pieces)

    cleaned = urlunsplit(
        parts._replace(netloc=netloc, query=_scrub(parts.query), fragment=_scrub(parts.fragment))
    )
    return _JWT_RE.sub(REDACTED, cleaned)


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
        elif name.lower() in _URL_HEADER_NAMES:
            value = redact_text(redact_url(value))
        sanitized[name] = value
    return sanitized
