"""Shared helpers for turning LLM replies into findings.

Used by the LLM code reviewer, the semantic rule verifier and the business
logic scanner so reply parsing and skip bookkeeping live in one place.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from isitsecure.engine.enums import SeverityLevel
from isitsecure.engine.shared.progress import emit

_logger = logging.getLogger(__name__)


def extract_json_array(response: str) -> list | None:
    """Return the first valid JSON array found in an LLM reply, else None.

    Tolerates code fences and prose (including bracketed prose such as
    "Found [2 issues]:") before the array by trying ``raw_decode`` from each
    ``[`` rather than a greedy ``\\[.*\\]`` match.
    """
    text = (response or "").strip()
    decoder = json.JSONDecoder()
    pos = text.find("[")
    while pos != -1:
        try:
            value, _ = decoder.raw_decode(text, pos)
        except ValueError:
            value = None
        if isinstance(value, list):
            return value
        pos = text.find("[", pos + 1)
    return None


def coerce_severity(raw: object, severity_map: dict) -> SeverityLevel:
    """Map a model-supplied severity to a level, defaulting to MEDIUM."""
    if isinstance(raw, str):
        return severity_map.get(raw.strip().upper(), SeverityLevel.MEDIUM)
    return SeverityLevel.MEDIUM


def coerce_line_number(raw: object) -> int | None:
    """Return an int line number or None (never raises)."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.strip().isdigit():
        return int(raw.strip())
    return None


@dataclass(frozen=True)
class FindingFields:
    """The fields every reviewer reads from one model-supplied finding."""

    severity: SeverityLevel
    title: str
    description: str
    line_number: int | None


def parse_finding_fields(
    item: dict, severity_map: dict, fallback_title: str
) -> FindingFields:
    """Read severity, title, description and line number from a reply item."""
    return FindingFields(
        severity=coerce_severity(item.get("severity"), severity_map),
        title=str(item.get("title") or fallback_title),
        description=str(item.get("description") or ""),
        line_number=coerce_line_number(item.get("line_number")),
    )


def record_skip(
    skips: list[tuple[str, str]], prefix: str, name: str, reason: str
) -> None:
    """Record an incomplete review: append to ``skips``, log, emit progress.

    ``prefix`` is the message lead-in, e.g. "LLM review incomplete for".
    """
    skips.append((name, reason))
    _logger.warning("%s %s: %s", prefix, name, reason)
    emit(f"{prefix} {name}: {reason}")
