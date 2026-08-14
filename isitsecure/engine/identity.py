"""Stable, cross-scan finding identity (#38 trust & false-positive epic).

The per-scan ``DeepFinding.id`` is a random ``uuid4`` — it cannot match a finding
across two separate scans. Suppression (#51) and baseline mode (#52) both need a
signature that is the SAME every time the same underlying issue is found, so a
user can say "ignore this one" once and have it stick.

The fingerprint is derived only from stable, deterministic content — never from
the random id or from LLM-enriched, non-deterministic fields (priority, theme,
remediation). It is deliberately line-agnostic for SAST (edits above a finding
don't change it) and host/query-agnostic for DAST (the same endpoint on
localhost vs. prod, with different query values, keeps one identity).
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from isitsecure.engine.models import DeepFinding

# Length of the hex digest exposed to users. 16 hex chars = 64 bits — plenty to
# avoid collisions across a single project's findings while staying short enough
# to paste into a `.isitsecureignore` line.
_FINGERPRINT_LEN = 16
_SEP = "\x1f"  # unit separator — cannot appear in the hashed fields

# Some finding titles interpolate the full target URL (host:port + query). That
# would make the fingerprint environment-dependent, so before hashing we replace
# any embedded URL with just its path — matching how the DAST locus is built.
_URL_IN_TEXT = re.compile(r"https?://\S+")


def _normalize_title(title: str) -> str:
    """Neutralise environment-specific data embedded in a title (full URLs →
    path) so the same issue fingerprints identically across hosts/queries."""
    return _URL_IN_TEXT.sub(lambda m: urlparse(m.group(0)).path or "/", title or "")


def compute_fingerprint(
    *,
    scanner_name: str,
    category: object,
    title: str,
    file_path: str | None = None,
    endpoint_url: str | None = None,
    http_method: str | None = None,
) -> str:
    """Compute a stable fingerprint from a finding's identifying content.

    Locus is the source file (SAST) or the ``METHOD /path`` (DAST) — host, port
    and query string are dropped so the identity survives environment changes.
    """
    cat = category.value if hasattr(category, "value") else str(category)
    if file_path:
        locus = file_path.replace("\\", "/")
    elif endpoint_url:
        path = urlparse(endpoint_url).path or "/"
        locus = f"{(http_method or 'GET').upper()} {path}"
    else:
        locus = ""
    raw = _SEP.join([scanner_name or "", cat, locus, _normalize_title(title)])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:_FINGERPRINT_LEN]


def finding_fingerprint(finding: DeepFinding) -> str:
    """Stable fingerprint for a ``DeepFinding`` (SAST or DAST)."""
    return compute_fingerprint(
        scanner_name=finding.scanner_name,
        category=finding.category,
        title=finding.title,
        file_path=finding.code_location.file_path if finding.code_location else None,
        endpoint_url=finding.endpoint_url,
        http_method=finding.http_method,
    )
