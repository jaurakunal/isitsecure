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
- ``judge_difference`` is the control-vs-treatment oracle.
- ``evidence_gap`` is the pre-check before a judge weighs a set of replies.
- ``absolutize`` makes a URL sendable, or ``None`` when it cannot be.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple
from urllib.parse import urljoin, urlparse

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


def absolutize(url: str, base: str = "") -> str | None:
    """Absolute http(s) URL for ``url`` (resolved against ``base``), else None.

    A relative URL with no base cannot be sent; callers treat None as
    "could not test", never as a response."""
    if not isinstance(url, str) or not url.strip():
        return None
    resolved = urljoin(base, url.strip()) if base else url.strip()
    parts = urlparse(resolved)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    return resolved


def unreachable_reason(reply: Reply) -> str | None:
    """Why this reply says nothing about the endpoint's behavior, else None."""
    if reply.status <= _STATUS_TRANSPORT_FAILURE:
        return "no response (transport failure, status 0)"
    if reply.status >= _SERVER_ERROR_FLOOR:
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


def _normalized(body: str, probe_input: str | None) -> str:
    """Body with the probe's own input removed, so a reflection compares equal."""
    text = body or ""
    if probe_input:
        text = text.replace(probe_input, "")
    return text.strip()


def judge_difference(
    treatment: Reply,
    control: Reply,
    *,
    probe_input: str | None = None,
    control_repeat: Reply | None = None,
) -> Verdict:
    """Control-vs-treatment oracle: PROVEN only for a distinct, real response body.

    Never a verdict from a status code or from the probe input reflected back
    (``probe_input`` is stripped from both bodies before comparing). Pass a second
    fetch of the control as ``control_repeat`` so a body that changes on its own
    (timestamps, nonces) is INCONCLUSIVE instead of a false proof.
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
    treated = _normalized(treatment.body, probe_input)
    if not treated:
        return Verdict.not_proven("treatment returned an empty body")
    if json_signals_failure(parse_json_body(treated)):
        return Verdict.not_proven("treatment body signals failure")

    controlled = _normalized(control.body, probe_input)
    if control_repeat is not None:
        again = unreachable_reason(control_repeat)
        if again:
            return Verdict.inconclusive(f"control repeat: {again}")
        if _normalized(control_repeat.body, probe_input) != controlled:
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
    server errors, missing endpoints, HTML pages, validation rejections);
    NOT_PROVEN when usable replies exist but all are denials or
    ``{"success": false}`` style failures. An empty 2xx is not a gap: a
    state-changing call (DELETE, PATCH) legitimately succeeds with no body. None
    means a judge may proceed."""
    if not replies:
        return Verdict.inconclusive("no requests were made")
    reasons = [
        unreachable_reason(r) or rejection_reason(r) for r in replies
    ]
    usable = [r for r, why in zip(replies, reasons, strict=True) if why is None]
    if not usable:
        distinct = sorted({why for why in reasons if why})
        return Verdict.inconclusive("; ".join(distinct))
    if all(
        r.status in _DENIAL_STATUSES
        or json_signals_failure(parse_json_body(r.body))
        for r in usable
    ):
        return Verdict.not_proven("every usable reply was a denial or a failure")
    return None
