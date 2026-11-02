"""Neutralise untrusted finding text before it lands in a PR or a commit.

Finding titles and file paths come from scanned repository content and LLM
output, so they are attacker-influenced. Rendered into a pull-request body they
could ``@mention`` arbitrary people, embed tracking images, auto-link to
attacker URLs, break out of code spans, cross-reference issues, spoof text with
bidi overrides, or carry a secret value the scanner just found. These helpers
flatten, redact, escape and bound that text.
"""

from __future__ import annotations

import re

# Zero-width space: breaks `@user` mentions, `#123`/`GH-123` references and
# URL autolinking without changing how the text reads.
_ZWSP = "​"

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{12,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"),
)
_BEARER = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=\-]{8,}")
_ASSIGNED_SECRET = re.compile(
    r"(?i)\b([\w-]*(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key"
    r"|access[_-]?key)[\w-]*\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
# scheme://user:pass@host for ANY scheme (postgres://, mongodb+srv://, https://...).
# Greedy up to the last '@' before the path, so passwords containing '@' go too.
_URL_CREDENTIALS = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*://)[^/\s:@]+:[^/\s]*@")

_CONTROL = re.compile(r"[\x00-\x1f\x7f  ]+")
# Bidi embeddings/overrides/isolates and marks: can visually reorder or spoof text.
_BIDI = re.compile(r"[؜‎‏‪-‮⁦-⁩]")
_MD_SPECIALS = re.compile(r"([\\`*_{}\[\]<>()!|~&])")
_AUTOLINK_SCHEME = re.compile(r"(?i)\b(https?|ftp)://")
_AUTOLINK_WWW = re.compile(r"(?i)\bwww\.")
_GH_REF = re.compile(r"(?i)\bGH-(?=\d)")


def redact_secrets(text: str) -> str:
    """Replace secret-looking values with ``[REDACTED]``."""
    out = str(text)
    out = _URL_CREDENTIALS.sub(lambda m: m.group(1) + "[REDACTED]@", out)
    for pat in _SECRET_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    out = _BEARER.sub(lambda m: m.group(1) + "[REDACTED]", out)
    return _ASSIGNED_SECRET.sub(lambda m: m.group(1) + "[REDACTED]", out)


def _truncate(text: str, max_len: int) -> str:
    return text if len(text) <= max_len else text[: max_len - 1].rstrip() + "…"


def inline(text: str, max_len: int = 100) -> str:
    """Single-line, redacted, bounded plain text (commit subjects, PR titles)."""
    flat = _CONTROL.sub(" ", _BIDI.sub("", redact_secrets(text)))
    return _truncate(" ".join(flat.split()), max_len)


def md_text(text: str, max_len: int = 200) -> str:
    """:func:`inline` plus markdown/mention/reference/autolink neutralisation."""
    safe = _MD_SPECIALS.sub(r"\\\1", inline(text, max_len))
    safe = safe.replace("@", "@" + _ZWSP)
    safe = _AUTOLINK_SCHEME.sub(lambda m: m.group(1) + ":" + _ZWSP + "//", safe)
    safe = _AUTOLINK_WWW.sub("www" + _ZWSP + ".", safe)
    safe = _GH_REF.sub("GH-" + _ZWSP, safe)
    return re.sub(r"#(?=\d)", "#" + _ZWSP, safe)


def md_code(text: str, max_len: int = 200) -> str:
    """Body of an inline code span: no backticks, newlines or mentions."""
    return inline(text, max_len).replace("`", "'")
