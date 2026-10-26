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

Two findings that share scanner, category, title and file (or METHOD /path)
used to collide, so suppressing or baselining one hid every other instance and
a newly introduced second instance looked "already known". The fingerprint now
also carries a *discriminator*: the flagged source line (SAST) or the injected
parameter name (DAST). A finding with no discriminator keeps exactly the
original value, and :func:`legacy_fingerprint` always gives the pre-discriminator
value, so entries already in a ``.isitsecureignore`` or a baseline keep matching
(see :func:`matches_any`).
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


# The marker the code-context extractor puts on the flagged line:
# "253 >>>   });"  (other lines are "252 |   ...").
_FLAGGED_LINE = re.compile(r"^\s*\d+\s*>>>\s?(.*)$", re.MULTILINE)
# Scanners record an injected parameter as "name=payload".
_PAYLOAD_PARAM = re.compile(r"^([A-Za-z_][\w.\-\[\]$]{0,63})=")
_DISCRIMINATOR_MAX = 200


def _squash(text: str) -> str:
    return " ".join(text.split())[:_DISCRIMINATOR_MAX]


def _discriminator(finding: DeepFinding) -> str:
    """What tells two same-titled findings in one file / on one path apart.

    SAST: the flagged source line (line NUMBER is deliberately excluded, so
    edits above the finding do not change it). DAST: the injected parameter
    name. Empty when the finding gives nothing to tell it apart by.
    """
    loc = finding.code_location
    if loc and loc.file_path:
        snippet = loc.code_snippet or ""
        match = _FLAGGED_LINE.search(snippet)
        return _squash(match.group(1) if match else snippet)
    if finding.request_payload:
        match = _PAYLOAD_PARAM.match(finding.request_payload)
        if match:
            return f"param:{match.group(1)}"
    return ""


def compute_fingerprint(
    *,
    scanner_name: str,
    category: object,
    title: str,
    file_path: str | None = None,
    endpoint_url: str | None = None,
    http_method: str | None = None,
    discriminator: str = "",
) -> str:
    """Compute a stable fingerprint from a finding's identifying content.

    Locus is the source file (SAST) or the ``METHOD /path`` (DAST) — host, port
    and query string are dropped so the identity survives environment changes.
    ``discriminator`` (see ``_discriminator``) separates same-titled findings at
    one locus; empty keeps the original, pre-discriminator value.
    """
    cat = category.value if hasattr(category, "value") else str(category)
    if file_path:
        locus = file_path.replace("\\", "/")
    elif endpoint_url:
        path = urlparse(endpoint_url).path or "/"
        locus = f"{(http_method or 'GET').upper()} {path}"
    else:
        locus = ""
    parts = [scanner_name or "", cat, locus, _normalize_title(title)]
    if discriminator:
        parts.append(discriminator)
    raw = _SEP.join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:_FINGERPRINT_LEN]


def legacy_fingerprint(finding: DeepFinding) -> str:
    """The pre-discriminator fingerprint, as recorded in older ignore files and
    baselines. Equal to :func:`finding_fingerprint` when there is no
    discriminator."""
    return compute_fingerprint(
        scanner_name=finding.scanner_name,
        category=finding.category,
        title=finding.title,
        file_path=finding.code_location.file_path if finding.code_location else None,
        endpoint_url=finding.endpoint_url,
        http_method=finding.http_method,
    )


def finding_fingerprint(finding: DeepFinding) -> str:
    """Stable fingerprint for a ``DeepFinding`` (SAST or DAST)."""
    return compute_fingerprint(
        scanner_name=finding.scanner_name,
        category=finding.category,
        title=finding.title,
        file_path=finding.code_location.file_path if finding.code_location else None,
        endpoint_url=finding.endpoint_url,
        http_method=finding.http_method,
        discriminator=_discriminator(finding),
    )


def matches_any(finding: DeepFinding, fingerprints: set[str]) -> bool:
    """True when the finding's current OR legacy fingerprint is in the set.

    Used for every lookup against a user's ``.isitsecureignore`` / baseline so
    entries written before the discriminator existed keep matching.
    """
    return (
        finding_fingerprint(finding) in fingerprints
        or legacy_fingerprint(finding) in fingerprints
    )
