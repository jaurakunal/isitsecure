"""Conclusive vs inconclusive verdicts for DAST oracles (#276).

A scanner that cannot tell must say so. An HTTP failure is never "safe" and never
"vulnerable"; a status-code change or an echoed input is never proof. A proof is a
response BODY that differs from a control response for a reason other than the
input being reflected back.

- ``Verdict`` is the tiny immutable result: PROVEN, NOT_PROVEN or INCONCLUSIVE
  plus the evidence sentence behind it.
- ``unreachable_reason`` / ``rejection_reason`` say why a single reply cannot be
  evidence (transport failure, status 0, 5xx, missing endpoint, SPA shell,
  validation rejection).
- ``judge_difference`` is the control-vs-treatment oracle. It is the shared oracle
  that upcoming scanner PRs (differential injection oracles, #277) build on; the
  rate-limit and business-logic scanners use the other helpers today.
- ``evidence_gap`` is the pre-check before a judge weighs a set of replies.
- ``absolutize`` makes a URL sendable, or ``None`` when it cannot be.
"""

from __future__ import annotations

import html
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, NamedTuple
from urllib.parse import quote, quote_plus, urljoin, urlparse

from isitsecure.engine.shared.response_shape import (
    is_html_document,
    json_signals_failure,
    parse_json_body,
)

_STATUS_TRANSPORT_FAILURE = 0
_SERVER_ERROR_FLOOR = 500
_MISSING_ENDPOINT_STATUSES = frozenset({404, 405, 410})
_VALIDATION_REJECTION_STATUSES = frozenset({400, 415, 422})
_DENIAL_STATUSES = frozenset({401, 403})
_SHELL_METHODS = frozenset({"GET", "HEAD"})
_DEFAULT_PORTS = {"http": 80, "https": 443}

# A probe input shorter than this is not stripped from bodies: "1" would collapse
# distinct bodies such as "12" and "21" into the same text.
_MIN_STRIP_LENGTH = 4
# Bodies are compared on at most this many characters (plus their length), so a
# multi-megabyte reply cannot make the oracle slow.
_MAX_COMPARE_CHARS = 200_000

_ERROR_KEYS = ("error", "errors", "err")
# Sibling keys that mean the body carries real data next to an ``errors`` array
# (a GraphQL partial response is a 200 with both).
_DATA_KEYS = ("data", "result", "results", "items", "user", "users", "id", "payload")


class Outcome(Enum):
    """What an oracle could establish."""

    PROVEN = "proven"
    NOT_PROVEN = "not_proven"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Verdict:
    """Immutable oracle result: the outcome and the evidence behind it."""

    outcome: Outcome
    evidence: str = ""

    @property
    def conclusive(self) -> bool:
        """True when the oracle could tell (proven or ruled out)."""
        return self.outcome is not Outcome.INCONCLUSIVE

    @property
    def vulnerable(self) -> bool:
        """True only for a proof; INCONCLUSIVE is never vulnerable."""
        return self.outcome is Outcome.PROVEN

    @classmethod
    def proven(cls, evidence: str) -> Verdict:
        return cls(Outcome.PROVEN, evidence)

    @classmethod
    def not_proven(cls, evidence: str) -> Verdict:
        return cls(Outcome.NOT_PROVEN, evidence)

    @classmethod
    def inconclusive(cls, evidence: str) -> Verdict:
        return cls(Outcome.INCONCLUSIVE, evidence)


class Reply(NamedTuple):
    """The part of an HTTP response an oracle reasons about.

    Status 0 stands for "no response" (timeout, connection error)."""

    status: int
    body: str = ""
    method: str = "GET"


def _origin(url: str) -> tuple[str, str, int | None] | None:
    """(scheme, host, port) of an absolute http(s) URL, else None."""
    try:
        parts = urlparse(url)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        if scheme not in _DEFAULT_PORTS or not host:
            return None
        return scheme, host, parts.port or _DEFAULT_PORTS[scheme]
    except ValueError:
        return None


def absolutize(url: str, base: str = "") -> str | None:
    """Absolute http(s) URL for ``url`` (resolved against ``base``), else None.

    A relative URL with no base cannot be sent; callers treat None as
    "could not test", never as a response. With a ``base`` the result must keep
    the base's scheme, host and port: ``//evil.example/x`` would otherwise switch
    host, so it (and any cross-origin absolute URL) yields None."""
    if not isinstance(url, str) or not url.strip():
        return None
    resolved = urljoin(base, url.strip()) if base else url.strip()
    origin = _origin(resolved)
    if origin is None:
        return None
    if base and origin != _origin(base):
        return None
    return resolved


def unreachable_reason(reply: Reply, *, server_error: bool = True) -> str | None:
    """Why this reply says nothing about the endpoint's behavior, else None.

    ``server_error=False`` lets a 5xx through as a usable reply, for callers where
    an unhandled server error on hostile input is itself a signal."""
    if reply.status <= _STATUS_TRANSPORT_FAILURE:
        return "no response (transport failure, status 0)"
    if server_error and reply.status >= _SERVER_ERROR_FLOOR:
        return f"server error (HTTP {reply.status})"
    if reply.status in _MISSING_ENDPOINT_STATUSES:
        return f"no such endpoint for this method (HTTP {reply.status})"
    if (
        reply.method.upper() in _SHELL_METHODS
        and 200 <= reply.status < 300
        and is_html_document(reply.body)
    ):
        return "HTML page / SPA shell, not an API answer"
    return None


def rejection_reason(reply: Reply) -> str | None:
    """Why the request was refused before reaching the logic under test, else None."""
    if reply.status in _VALIDATION_REJECTION_STATUSES:
        return f"rejected by request validation (HTTP {reply.status})"
    return None


def body_signals_failure(text: str) -> bool:
    """True for ``{"success": false}`` or a pure ``{"error": ...}`` body.

    Stricter than ``json_signals_failure``: an ``error``/``errors`` key next to real
    data (a GraphQL partial response) is not a failure, so a leak that arrives with
    an errors array still reaches the judge. An explicit ``success``/``ok`` false or
    failure ``status`` word is always a failure."""
    data = parse_json_body(text)
    if not isinstance(data, dict) or not json_signals_failure(data):
        return False
    without_errors = {k: v for k, v in data.items() if k not in _ERROR_KEYS}
    if json_signals_failure(without_errors):
        return True
    return not any(data.get(k) not in (None, "", [], {}) for k in _DATA_KEYS)


def _probe_forms(probe_input: str | None) -> list[str]:
    """The probe as it can appear in a body: raw, JSON-escaped, URL- and HTML-encoded."""
    if not probe_input or len(probe_input) < _MIN_STRIP_LENGTH:
        return []
    forms = {
        probe_input,
        json.dumps(probe_input)[1:-1],
        quote(probe_input, safe=""),
        quote_plus(probe_input),
        html.escape(probe_input),
    }
    return sorted((f for f in forms if f), key=len, reverse=True)


def _strip_pattern(probe_input: str | None) -> re.Pattern[str] | None:
    """Regex matching each probe form, anchored at word boundaries where it has them."""
    forms = _probe_forms(probe_input)
    if not forms:
        return None
    parts = []
    for form in forms:
        head = r"(?<!\w)" if form[0].isalnum() else ""
        tail = r"(?!\w)" if form[-1].isalnum() else ""
        parts.append(f"{head}{re.escape(form)}{tail}")
    return re.compile("|".join(parts))


def _canonical(body: str, pattern: re.Pattern[str] | None) -> str:
    """Comparable form of a body: parsed JSON re-serialized (key order and
    whitespace insensitive) or trimmed text, bounded in size, probe input removed."""
    text = body or ""
    if len(text) > _MAX_COMPARE_CHARS:
        text = text[:_MAX_COMPARE_CHARS] + f"#{len(body)}"
    else:
        parsed: Any = parse_json_body(text)
        if parsed is not None:
            text = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    text = text.strip()
    return pattern.sub("", text) if pattern else text


def judge_difference(
    treatment: Reply,
    control: Reply,
    *,
    probe_input: str | None = None,
    control_repeat: Reply | None = None,
) -> Verdict:
    """Control-vs-treatment oracle: PROVEN only for a distinct, real response body.

    Never a verdict from a status code or from the probe input reflected back
    (``probe_input``, in raw, JSON-escaped, URL- and HTML-encoded form, is stripped
    from both bodies before comparing; inputs shorter than ``_MIN_STRIP_LENGTH`` are
    left alone). JSON bodies compare by parsed value, not by key order or spacing.
    Pass a second fetch of the control as ``control_repeat`` so a body that changes
    on its own (timestamps, nonces) is INCONCLUSIVE instead of a false proof.
    """
    for label, reply in (("treatment", treatment), ("control", control)):
        reason = unreachable_reason(reply)
        if reason:
            return Verdict.inconclusive(f"{label}: {reason}")
    reason = rejection_reason(treatment)
    if reason:
        return Verdict.inconclusive(f"treatment: {reason}")

    if treatment.status in _DENIAL_STATUSES:
        return Verdict.not_proven(f"treatment denied (HTTP {treatment.status})")
    if is_html_document(treatment.body):
        return Verdict.not_proven("treatment is an HTML page, not an API answer")
    pattern = _strip_pattern(probe_input)
    treated = _canonical(treatment.body, pattern)
    if not treated:
        return Verdict.not_proven("treatment returned an empty body")
    if body_signals_failure(treatment.body):
        return Verdict.not_proven("treatment body signals failure")

    controlled = _canonical(control.body, pattern)
    if control_repeat is not None:
        again = unreachable_reason(control_repeat)
        if again:
            return Verdict.inconclusive(f"control repeat: {again}")
        if _canonical(control_repeat.body, pattern) != controlled:
            return Verdict.inconclusive("control body is dynamic, cannot compare")
    if treated == controlled:
        return Verdict.not_proven("treatment body identical to control")
    return Verdict.proven(
        f"treatment body ({len(treated)} chars) differs from control "
        f"({len(controlled)} chars)"
    )


def evidence_gap(replies: Sequence[Reply]) -> Verdict | None:
    """Verdict when no reply gives a judge anything to weigh, else None.

    INCONCLUSIVE when nothing usable came back (transport failures, status 0,
    missing endpoints, HTML pages, validation rejections); NOT_PROVEN when usable
    replies exist but all are denials or ``{"success": false}`` style failures. An
    empty 2xx is not a gap: a state-changing call (DELETE, PATCH) legitimately
    succeeds with no body. A 5xx is not a gap either: an unhandled server error on
    hostile input can itself be the finding, so it always reaches the judge. None
    means a judge may proceed."""
    if not replies:
        return Verdict.inconclusive("no requests were made")
    reasons = [
        unreachable_reason(r, server_error=False) or rejection_reason(r)
        for r in replies
    ]
    usable = [r for r, why in zip(replies, reasons, strict=True) if why is None]
    if not usable:
        distinct = sorted({why for why in reasons if why})
        return Verdict.inconclusive("; ".join(distinct))
    if all(
        r.status in _DENIAL_STATUSES
        or (r.status < _SERVER_ERROR_FLOOR and body_signals_failure(r.body))
        for r in usable
    ):
        return Verdict.not_proven("every usable reply was a denial or a failure")
    return None
