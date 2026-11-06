"""Request contracts: what the server says a request MUST look like, learned from its own
validation rejections.

A pentester reads a 422. When an endpoint answers "field X is required" or "X must match
'password'", the next request carries that. Anything else is rejected by request validation
before the application sees it, and a probe that never reaches the application proves nothing
about it. Without this, a scanner against a strict API sends every payload into the same
rejection and reports "no injection found": a silent miss that reads as "safe".

This module is pure Python and does no I/O. Scanners own the HTTP client and hand it a ``send``
callback, so the rate limiter and request budgets they already use stay in charge:

- ``parse_validation`` reads a 400/422 body (FastAPI/pydantic, Django/DRF, Rails, Laravel,
  express-validator, Zod, Spring, ASP.NET, Joi, WordPress, RFC 6749) into ``FieldRule``s:
  required / literal / enum / pattern;
- ``ContractLedger`` keeps one ``RequestContract`` per ``(METHOD, path template)`` and the
  per-field probe outcomes;
- ``probe_with_repair`` sends one probe, and when the answer is an ACTIONABLE rejection repairs
  the sibling fields (or switches the body encoding on a 415) and retries a bounded number of
  times;
- ``contract_blocked_finding`` turns the endpoints whose probes never reached the sink into an
  informational "not tested" finding, so a rejected request is never reported as "safe".

A rejection counts only when it is ACTIONABLE: it names a field we did not send, sent empty, or
sent with a value the rule does not accept. A 400 "invalid username or password" names a field
we sent an acceptable value for: that is the application's verdict, not a contract.

Generic: every framework's validation error is parsed by shape or by phrase. No
application-specific knowledge.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import DeepFinding, FindingSource

VALIDATION_STATUSES = frozenset({400, 422})
# A rejection of the body's ENCODING rather than a field: 415, or a 400 whose text says so. The
# contract it discloses is "send the other encoding" (an endpoint that refuses a form wants JSON,
# and vice versa); the server rarely names the one it wants.
ENCODING_STATUSES = frozenset({415})
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_FORM = "application/x-www-form-urlencoded"
# Hard bounds so learning a contract can never turn into a request storm: retries per probe, and
# retries per endpoint across the whole scan (once spent, probes are sent once and not repaired).
MAX_RETRIES_PER_PROBE = 2
MAX_RETRIES_PER_ENDPOINT = 6

TITLE_CONTRACT_BLOCKED = "Injection probes blocked by request validation (not tested)"
DESC_CONTRACT_BLOCKED = (
    "{method} {url} rejected the probes sent to {params} with a validation error (HTTP "
    "400/415/422) even after the request was repaired to match the contract the server "
    "disclosed. The payloads never reached the application, so this endpoint was NOT tested "
    "for those fields; the absence of a finding here is not evidence that they are safe. "
    "Contract learned: {contract}. Re-run with a request that satisfies the contract."
)
CONFIDENCE_CONTRACT_BLOCKED = 0.9
_MAX_BLOCKED_PARAMS_LISTED = 8

_RX_ENCODING = re.compile(
    r"unsupported (?:content|media)[ -]?type|content[ -]?type (?:is )?(?:not supported|not "
    r"allowed|must be|should be|invalid|unsupported)|invalid content[ -]?type|"
    r"(?:expected|requires?|must be|should be) (?:a |an )?(?:json|application/json)\b|"
    r"body must be json|request body (?:is )?not (?:valid )?json|failed to decode json",
    re.IGNORECASE)
_MAX_RULES_RENDERED = 8
_MAX_MESSAGE = 120
_LOC_CONTAINERS = frozenset({"body", "query", "path", "header", "cookie", "form", "params"})
_FIELD_NAME_RE = re.compile(r"^[A-Za-z_][\w.\-\[\]]{0,63}$")
_REGEX_META = set(".*+?[](){}|\\")
# RFC 6749 §4.3 / §5.2: a token endpoint that rejects the grant names the one field at fault.
_OAUTH_GRANT_TYPES = ("password", "client_credentials", "authorization_code", "refresh_token")
# Top-level keys of an error body that are never field names (the flat Django/DRF fallback).
_NOT_FIELD_KEYS = frozenset({"message", "error", "errors", "status", "code", "title", "type",
                             "msg", "detail", "details", "issues", "validation", "path",
                             "timestamp", "trace", "data", "non_field_errors"})
# Marks every value the engine invents so rows a repaired write leaves behind are identifiable.
PROBE_MARKER = "isitsecure-probe"
_FILLER_CANDIDATES = (PROBE_MARKER, "1", f"{PROBE_MARKER}@example.com", "2024-01-01", "true",
                      "a", "0")
# Methods that cannot change server state: only these may be repaired and retried freely.
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# -- message classifiers (a field's message → the rule it implies) -----------------------------
_RX_REQUIRED = re.compile(
    r"\b(?:required|mandatory|missing|can'?t be blank|cannot be blank|must not be (?:blank|null|"
    r"empty)|should not be empty|is not present|null value|none is not an allowed value)\b",
    re.IGNORECASE)
_RX_QUOTED_VALUES = re.compile(r"""['"`]([^'"`]{1,64})['"`]""")
_RX_VALUE_LIST = re.compile(
    r"(?:should be|must be one of|must be in|permitted|allowed values?|valid (?:choices|"
    r"options|values)|one of|is not one of)\s*[:\-]?\s*(.+)", re.IGNORECASE)
_RX_PATTERN = re.compile(
    r"""(?:match(?:es)? (?:the )?(?:pattern|regex|regexp|format)|does not match regex|"""
    r"""string does not match regex)\s*[:\-]?\s*['"`]?(?P<p>[^'"`]+?)['"`]?\s*$""",
    re.IGNORECASE)
_RX_ENUMISH = re.compile(
    r"is not a valid (?:choice|enumeration member|option)|invalid enum|invalid_enum|"
    r"not included in the list|is not one of", re.IGNORECASE)


@dataclass
class FieldRule:
    """One thing the server said about one field: ``required`` (send it), ``literal`` (send
    exactly this), ``enum`` (one of these), ``pattern`` (match this; ``values`` holds the regex
    and, when it is a plain literal, the literal it reduces to), ``invalid`` (rejected, no
    actionable shape: recorded for the report only)."""

    name: str
    kind: str
    values: tuple[str, ...] = ()
    message: str = ""

    @property
    def pinned(self) -> bool:
        """Whether the server fixes this field to a closed set: a payload there is rejected
        before any sink, so probing it is wasted budget."""
        return self.kind in ("literal", "enum") or (self.kind == "pattern" and len(self.values) > 1)

    def accepts(self, value: Any) -> bool:
        text = "" if value is None else str(value)
        if self.kind == "required":
            return text != ""
        if self.kind in ("literal", "enum"):
            return text in self.values
        if self.kind == "pattern" and self.values:
            try:
                return re.search(self.values[0], text) is not None
            except re.error:
                return True
        return True

    def preferred(self) -> str | None:
        """A value the rule accepts, when one can be derived."""
        if self.kind in ("literal", "enum") and self.values:
            return self.values[0]
        if self.kind == "pattern":
            if len(self.values) > 1:
                return self.values[1]
            for candidate in _FILLER_CANDIDATES:
                if self.accepts(candidate):
                    return candidate
        return None

    def describe(self) -> str:
        if self.kind == "required":
            return f"{self.name} required"
        if self.kind == "literal" or (self.kind == "pattern" and len(self.values) > 1):
            return f"{self.name} must be {self.preferred()!r}"
        if self.kind == "enum":
            return f"{self.name} must be one of {', '.join(repr(v) for v in self.values[:6])}"
        if self.kind == "pattern" and self.values:
            return f"{self.name} must match pattern {self.values[0]!r}"
        if self.message:
            return f"{self.name} rejected ({self.message[:60]})"
        return f"{self.name} rejected"

    def merge(self, other: FieldRule) -> FieldRule:
        """The more specific of two rules for the same field (a literal beats required)."""
        rank = {"invalid": 0, "required": 1, "pattern": 2, "enum": 3, "literal": 4}
        if rank.get(other.kind, 0) > rank.get(self.kind, 0):
            return other
        if other.kind == self.kind == "enum":
            merged = tuple(dict.fromkeys(self.values + other.values))
            return FieldRule(self.name, "enum", merged, self.message or other.message)
        return self


@dataclass
class RequestContract:
    """The rules learned for one ``(METHOD, path template)``."""

    method: str
    path: str
    rules: dict[str, FieldRule] = field(default_factory=dict)
    rejections: int = 0
    last_message: str = ""
    encoding: str = ""          # "json" | "form" when the server rejected the other encoding

    def note(self, rules: list[FieldRule], message: str = "") -> None:
        for rule in rules:
            current = self.rules.get(rule.name)
            self.rules[rule.name] = current.merge(rule) if current else rule
        self.rejections += 1
        if message:
            self.last_message = message[:_MAX_MESSAGE]

    def actionable(self, sent: dict[str, Any]) -> list[FieldRule]:
        """The rules the request ``sent`` violates: the ones a repair would change."""
        out: list[FieldRule] = []
        for rule in self.rules.values():
            if rule.kind == "invalid":
                continue
            if rule.name not in sent and rule.kind != "required" and rule.preferred() is None:
                continue
            if not rule.accepts(sent.get(rule.name)):
                out.append(rule)
        return out

    def repair(self, fields: dict[str, Any], filler: Callable[[str], Any] | None = None,
               *, keep: str | None = None) -> dict[str, Any]:
        """``fields`` with every violated rule satisfied: a missing required field is filled
        (``filler(name)``), a pinned field is set to a value the server accepts. ``keep`` names
        a field left untouched (the one a probe is testing). Never removes a field."""
        out = dict(fields)
        for rule in self.rules.values():
            if rule.name == keep or rule.kind == "invalid":
                continue
            if rule.accepts(out.get(rule.name)):
                continue
            value = rule.preferred()
            if value is None and rule.kind == "required":
                value = filler(rule.name) if filler else PROBE_MARKER
            if value is not None:
                out[rule.name] = value
        return out

    def pinned_fields(self) -> set[str]:
        return {r.name for r in self.rules.values() if r.pinned}

    def describe(self) -> str:
        rules = sorted(self.rules.values(), key=lambda r: (r.kind == "invalid", r.name))
        parts = [r.describe() for r in rules[:_MAX_RULES_RENDERED]]
        if self.encoding:
            parts.insert(0, "body must be " + ("JSON" if self.encoding == "json"
                                               else "form-encoded"))
        body = "; ".join(parts) or "(no field named)"
        extra = len(rules) - _MAX_RULES_RENDERED
        more = f" (+{extra} more)" if extra > 0 else ""
        return f"{self.method} {self.path}: {body}{more}"


@dataclass
class BlockedEndpoint:
    """An endpoint whose probes for ``params`` only ever met a validation rejection."""

    method: str
    url: str
    params: list[str]
    contract: str


class ContractLedger:
    """Every request contract the target has disclosed, keyed by ``(METHOD, path template)``,
    plus how each probed field fared (so a rejection is reported, not read as "safe")."""

    def __init__(self) -> None:
        self.contracts: dict[tuple[str, str], RequestContract] = {}
        self.total_rejections = 0
        self._retries: dict[tuple[str, str], int] = {}
        # key -> param -> [probes sent, probes rejected]; _urls keeps one real URL per key.
        self._stats: dict[tuple[str, str], dict[str, list[int]]] = {}
        self._urls: dict[tuple[str, str], str] = {}

    # -- observations --------------------------------------------------------------------------
    def observe(self, method: str, url: str, status: int | None, body_text: str, *,
                sent_body: str = "", content_type: str = "",
                extra_required: tuple[str, ...] | list[str] = ()) -> RequestContract | None:
        """Read one target response. Returns the contract when the response was an ACTIONABLE
        validation rejection (it named a field the request did not satisfy); ``None`` when the
        response is an answer (any other status, or a complaint about a field we already sent
        acceptably: the application's verdict, not the contract's)."""
        if status in ENCODING_STATUSES or (
                status in VALIDATION_STATUSES and _RX_ENCODING.search(body_text or "")):
            key = self.key(method, url)
            contract = self.contracts.setdefault(key, RequestContract(key[0], key[1]))
            contract.encoding = "form" if "json" in (content_type or "").lower() else "json"
            contract.rejections += 1
            contract.last_message = _first_message(body_text)
            self.total_rejections += 1
            return contract
        if status not in VALIDATION_STATUSES:
            return None
        rules = parse_validation(body_text)
        for name in extra_required:
            if _FIELD_NAME_RE.match(name or "") and name not in {r.name for r in rules}:
                rules.append(FieldRule(name, "required"))
        if not rules:
            return None
        key = self.key(method, url)
        contract = self.contracts.get(key) or RequestContract(key[0], key[1])
        probe = RequestContract(key[0], key[1], dict(contract.rules))
        probe.note(rules)
        sent = parse_sent_fields(sent_body, content_type)
        if not probe.actionable(sent):
            return None
        contract.note(rules, _first_message(body_text))
        self.contracts[key] = contract
        self.total_rejections += 1
        return contract

    def record_probe(self, method: str, url: str, param: str, *, blocked: bool) -> None:
        """Count one probe of ``param`` and whether it only met a validation rejection."""
        key = self.key(method, url)
        self._urls.setdefault(key, url)
        stat = self._stats.setdefault(key, {}).setdefault(param, [0, 0])
        stat[0] += 1
        stat[1] += 1 if blocked else 0

    def take_retry(self, method: str, url: str) -> bool:
        """Spend one repair retry on this endpoint; ``False`` once its budget is gone."""
        key = self.key(method, url)
        if self._retries.get(key, 0) >= MAX_RETRIES_PER_ENDPOINT:
            return False
        self._retries[key] = self._retries.get(key, 0) + 1
        return True

    # -- reads ---------------------------------------------------------------------------------
    def get(self, method: str, url: str) -> RequestContract | None:
        return self.contracts.get(self.key(method, url))

    def encoding(self, method: str, url: str) -> str:
        """The body encoding the endpoint demands (``"json"`` / ``"form"``), or ``""``."""
        contract = self.get(method, url)
        return contract.encoding if contract else ""

    def rejections(self, method: str, url: str) -> int:
        contract = self.get(method, url)
        return contract.rejections if contract else 0

    def pinned(self, method: str, url: str) -> set[str]:
        """Fields the endpoint fixes to a closed set (a payload there dies in validation)."""
        contract = self.get(method, url)
        return contract.pinned_fields() if contract else set()

    def blocked(self) -> list[BlockedEndpoint]:
        """Endpoints with at least one field whose every probe was rejected by validation."""
        out: list[BlockedEndpoint] = []
        for key, params in self._stats.items():
            names = [p for p, (sent, rejected) in params.items() if sent and rejected == sent]
            if names:
                contract = self.contracts.get(key)
                out.append(BlockedEndpoint(
                    key[0], self._urls.get(key, key[1]), names,
                    contract.describe() if contract else f"{key[0]} {key[1]}: (no field named)"))
        return out

    def lines(self) -> list[str]:
        """One line per learned contract, most-rejected first."""
        ordered = sorted(self.contracts.values(), key=lambda c: -c.rejections)
        return [f"{c.describe()} (rejected {c.rejections} request(s))" for c in ordered]

    @staticmethod
    def key(method: str, url: str) -> tuple[str, str]:
        return (method or "GET").upper(), _template(urlparse(url).path if "://" in url else url)


# -- probing -------------------------------------------------------------------------------------
@dataclass
class ProbeResult:
    """One probe's outcome: the last response, what was finally sent, and whether the response
    is still a validation rejection (the payload never reached the application)."""

    response: Any
    fields: dict[str, Any]
    blocked: bool
    requests: int = 1


def encode_body(fields: dict[str, Any], encoding: str = "") -> tuple[str, str]:
    """``(content, content_type)`` for ``fields``: JSON unless the endpoint demanded a form."""
    if encoding == "form":
        flat = {k: v if isinstance(v, str) else json.dumps(v, default=str)
                for k, v in fields.items()}
        return urlencode(flat), CONTENT_TYPE_FORM
    return json.dumps(fields, default=str), CONTENT_TYPE_JSON


# send(content, content_type) -> an object with .status_code and .text (an httpx.Response).
Send = Callable[[str, str], Awaitable[Any]]


async def probe_with_repair(
    send: Send, ledger: ContractLedger, method: str, url: str, fields: dict[str, Any], *,
    param: str | None = None, keep: str | None = None,
    filler: Callable[[str], Any] | None = None,
    max_retries: int = MAX_RETRIES_PER_PROBE, track: bool = True,
    repair_writes: bool = False,
) -> ProbeResult:
    """Send one probe; if the server answers with an actionable validation rejection, learn the
    contract, repair the sibling fields (``keep`` is left untouched: it carries the payload) or
    switch the body encoding, and send again, at most ``max_retries`` times and only while the
    endpoint's retry budget lasts. A contract already learned repairs the first send for free.

    ``blocked`` is True when the final response is still a rejection: the payload never reached
    the sink. With ``track`` the outcome is recorded against ``param`` for the blocked report;
    pass ``track=False`` for probes where a rejection is the expected, tested behaviour (type
    confusion) rather than a coverage gap.

    Repair invents field values, so for a state-changing method it is opt-in
    (``repair_writes``): a scanner whose own policy already sends writes passes True; otherwise
    the probe is sent once as given, never retried with invented values, and a rejection is
    still learned and reported as blocked. Invented free-text values carry ``PROBE_MARKER``."""
    keep = keep if keep is not None else param
    may_repair = repair_writes or method.upper() in SAFE_METHODS
    contract = ledger.get(method, url)
    encoding = contract.encoding if contract else ""
    if contract and may_repair:
        fields = contract.repair(fields, filler, keep=keep)
    requests = 0
    while True:
        content, ctype = encode_body(fields, encoding)
        response = await send(content, ctype)
        requests += 1
        contract = ledger.observe(method, url, response.status_code, response.text,
                                  sent_body=content, content_type=ctype)
        if contract is None:
            blocked = False
            break
        blocked = True
        if requests > max_retries or not may_repair:
            break
        repaired = contract.repair(fields, filler, keep=keep)
        new_encoding = contract.encoding or encoding
        if (repaired == fields and new_encoding == encoding) \
                or not ledger.take_retry(method, url):
            break
        fields, encoding = repaired, new_encoding
    if track and param is not None:
        ledger.record_probe(method, url, param, blocked=blocked)
    return ProbeResult(response, fields, blocked, requests)


def contract_blocked_finding(
    entry: BlockedEndpoint, *, scanner_name: str, category: FindingCategory,
    source: FindingSource,
) -> DeepFinding:
    """The informational "could not test" finding for an endpoint the validation layer shielded.
    INFO on purpose: it is a coverage statement, not a vulnerability."""
    listed = entry.params[:_MAX_BLOCKED_PARAMS_LISTED]
    more = len(entry.params) - len(listed)
    names = ", ".join(f"'{p}'" for p in listed) + (f" (+{more} more)" if more > 0 else "")
    return DeepFinding(
        source=source,
        category=category,
        severity=SeverityLevel.INFO,
        title=TITLE_CONTRACT_BLOCKED,
        description=DESC_CONTRACT_BLOCKED.format(
            method=entry.method, url=entry.url, params=names, contract=entry.contract),
        technical_detail=f"Contract-blocked fields: {names}\n{entry.contract}",
        evidence=f"{entry.method} {entry.url}: validation rejected every probe for {names}",
        confidence=CONFIDENCE_CONTRACT_BLOCKED,
        scanner_name=scanner_name,
        endpoint_url=entry.url,
        http_method=entry.method,
    )


# -- parsing -------------------------------------------------------------------------------------
def parse_validation(body_text: str) -> list[FieldRule]:
    """Field rules named by a validation-error body, by structure first and by phrase second.
    Never raises; an unrecognised body yields ``[]``."""
    text = body_text or ""
    rules: list[FieldRule] = []
    data: Any = None
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, dict):
        rules.extend(_rules_from_structured(data))
    if not rules:
        rules.extend(_rules_from_text(text))
    merged: dict[str, FieldRule] = {}
    for rule in rules:
        if not _FIELD_NAME_RE.match(rule.name):
            continue
        merged[rule.name] = merged[rule.name].merge(rule) if rule.name in merged else rule
    return list(merged.values())


def _rules_from_structured(data: dict) -> list[FieldRule]:
    out: list[FieldRule] = []
    # FastAPI / pydantic: {"detail": [{"loc": [...], "msg": "...", "type": "..."}]}
    detail = data.get("detail")
    if isinstance(detail, list):
        for item in detail:
            if not isinstance(item, dict):
                continue
            name = _name_from_loc(item.get("loc"))
            if name:
                out.append(_classify(name, str(item.get("msg") or ""), str(item.get("type") or ""),
                                     item))
    # Zod: {"issues": [{"code": "...", "path": [...], "message": "...", "expected"/"options": ...}]}
    issues = data.get("issues")
    if isinstance(issues, list):
        for item in issues:
            if not isinstance(item, dict):
                continue
            name = _name_from_loc(item.get("path"))
            if name:
                out.append(_classify(name, str(item.get("message") or ""),
                                     str(item.get("code") or ""), item))
    # Rails / Laravel / ASP.NET / DRF-ish: {"errors": {"field": ["msg", ...]}}
    # express-validator / Spring: {"errors": [{"param"|"path"|"field": "x", "msg": "..."}]}
    errors = data.get("errors")
    if isinstance(errors, dict):
        out.extend(_rules_from_field_map(errors))
    elif isinstance(errors, list):
        for item in errors:
            if not isinstance(item, dict):
                continue
            name = item.get("field") or item.get("param") or item.get("path") or item.get("name")
            if isinstance(name, list):
                name = _name_from_loc(name)
            msg = item.get("msg") or item.get("message") or item.get("defaultMessage") or ""
            if isinstance(name, str) and name:
                out.append(_classify(name.split(".")[-1], str(msg), str(item.get("code") or ""),
                                     item))
    # Joi / celebrate: {"validation": {"body": {"keys": ["x"], "message": "..."}}}
    validation = data.get("validation")
    if isinstance(validation, dict):
        for container in validation.values():
            if isinstance(container, dict):
                msg = str(container.get("message") or "")
                for key in container.get("keys") or []:
                    if isinstance(key, str):
                        out.append(_classify(key, msg, ""))
    # WordPress REST: {"code": "rest_missing_callback_param", "message": "Missing parameter(s): x",
    # "data": {"status": 400, "params": ["x"]}} / rest_invalid_param with "params": {"x": "why"}
    wp = data.get("data")
    if isinstance(wp, dict) and "params" in wp:
        params = wp.get("params")
        code = str(data.get("code") or "")
        if isinstance(params, list):
            out.extend(FieldRule(str(n), "required", (), code)
                       for n in params if isinstance(n, str))
        elif isinstance(params, dict):
            for name, msg in params.items():
                if isinstance(name, str):
                    out.append(_classify(name, str(msg), "missing" if "missing" in code else ""))
    # RFC 6749 token endpoint: {"error": "unsupported_grant_type" | "invalid_request", ...}
    error = data.get("error")
    if isinstance(error, str):
        desc = str(data.get("error_description") or "")
        if error == "unsupported_grant_type":
            out.append(FieldRule("grant_type", "enum", _OAUTH_GRANT_TYPES, desc or error))
        elif error == "invalid_request" and desc:
            out.extend(_rules_from_text(desc))
    # Django / DRF flat: {"field": ["This field is required."]} — only when nothing else matched
    if not out:
        flat = {k: v for k, v in data.items()
                if isinstance(k, str) and isinstance(v, list) and _FIELD_NAME_RE.match(k)
                and k not in _NOT_FIELD_KEYS}
        out.extend(_rules_from_field_map(flat))
    return out


def _rules_from_field_map(errors: dict) -> list[FieldRule]:
    out: list[FieldRule] = []
    for name, msgs in errors.items():
        if not isinstance(name, str):
            continue
        if isinstance(msgs, str):
            msgs = [msgs]
        if isinstance(msgs, dict):            # nested {"field": {"message": "..."}}
            msgs = [str(msgs.get("message") or msgs.get("msg") or "")]
        if not isinstance(msgs, list):
            continue
        for msg in msgs:
            if isinstance(msg, dict):
                msg = msg.get("message") or msg.get("msg") or ""
            out.append(_classify(name.split(".")[-1], str(msg), ""))
    return out


def _rules_from_text(text: str) -> list[FieldRule]:
    """Phrase-level: ``'x' is required`` / ``the x field is required`` / ``missing x`` /
    ``x must be one of ...`` — bounded, field-name validated."""
    out: list[FieldRule] = []
    for m in re.finditer(r"""['"]([A-Za-z_][\w.\-]*)['"]\s+(?:is\s+)?(?:a\s+)?required""", text,
                         re.IGNORECASE):
        out.append(FieldRule(m.group(1), "required", (), m.group(0)))
    for m in re.finditer(r"""\b(?:the\s+)?['"]?([A-Za-z_][\w.\-]*)['"]?\s+field\s+is\s+required""",
                         text, re.IGNORECASE):
        out.append(FieldRule(m.group(1), "required", (), m.group(0)))
    for m in re.finditer(r"""\bmissing\s+(?:required\s+)?(?:field|parameter|param)[:\s]+['"]?"""
                         r"""([A-Za-z_][\w.\-]*)""", text, re.IGNORECASE):
        out.append(FieldRule(m.group(1), "required", (), m.group(0)))
    for m in re.finditer(r"""\b([A-Za-z_][\w.\-]*)\s+must be one of\s*[:\-]?\s*([^.;\n]+)""", text,
                         re.IGNORECASE):
        values = _values_from(m.group(2))
        if values:
            out.append(FieldRule(m.group(1), "enum", values, m.group(0)))
    return out


def _classify(name: str, msg: str, type_: str, item: dict | None = None) -> FieldRule:
    """A field's message (and the framework's type code, when present) → its rule."""
    low_type = type_.lower()
    item = item or {}
    # Explicit expected / options carried by the error item (Zod, some pydantic shapes).
    expected = item.get("expected")
    options = item.get("options") or item.get("permitted") or item.get("allowed")
    phrase_required = bool(_RX_REQUIRED.search(msg)) and not _RX_PATTERN.search(msg) \
        and not _RX_VALUE_LIST.search(msg)
    if ("missing" in low_type or low_type in ("required", "value_error.missing")
            or (low_type == "invalid_type" and "undefined" in msg.lower()) or phrase_required):
        return FieldRule(name, "required", (), msg)
    if isinstance(expected, str) and "literal" in low_type:
        return FieldRule(name, "literal", (expected,), msg)
    if isinstance(options, list) and options:
        return FieldRule(name, "enum", tuple(str(o) for o in options), msg)
    if "pattern" in low_type or "regex" in low_type or _RX_PATTERN.search(msg):
        m = _RX_PATTERN.search(msg)
        pattern = (m.group("p") if m else "").strip()
        if pattern and _valid_regex(pattern):
            literal = _literal_from_pattern(pattern)
            return FieldRule(name, "pattern", (pattern, literal) if literal else (pattern,), msg)
        return FieldRule(name, "invalid", (), msg)
    # A closed set is pinned only from an explicit listing ("one of 'a', 'b'", "should be 'a'")
    # or a framework literal/enum code. "'x' is not a valid choice" quotes the value WE sent,
    # not the allowed set, and "expected string" names a type: neither pins the field.
    if "literal" in low_type or "enum" in low_type or _RX_VALUE_LIST.search(msg):
        values = _values_from(msg, allow_bare=bool(_RX_EXPLICIT_SET.search(msg)))
        if len(values) == 1 and ("literal" in low_type or "should be" in msg.lower()):
            return FieldRule(name, "literal", values, msg)
        if values:
            return FieldRule(name, "enum", values, msg)
        return FieldRule(name, "invalid", (), msg)
    return FieldRule(name, "invalid", (), msg)


_RX_EXPLICIT_SET = re.compile(
    r"one of|valid (?:choices|options|values)|allowed|permitted", re.IGNORECASE)


def _valid_regex(pattern: str) -> bool:
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


def _values_from(text: str, allow_bare: bool = True) -> tuple[str, ...]:
    """The quoted values a message lists (``'a', 'b' or 'c'``); unquoted comma lists as a
    fallback when every item is a bare token and the message names an explicit set."""
    m = _RX_VALUE_LIST.search(text)
    tail = m.group(1) if m else text
    quoted = tuple(dict.fromkeys(_RX_QUOTED_VALUES.findall(tail)))
    if quoted:
        return quoted
    bare = [t.strip().rstrip(".;:") for t in re.split(r",|\bor\b|\|", tail) if t.strip()]
    if allow_bare and bare and all(re.fullmatch(r"[\w.\-]{1,40}", t) for t in bare):
        return tuple(dict.fromkeys(bare))
    return ()


def _literal_from_pattern(pattern: str) -> str | None:
    """A regex that is really a literal (``password``, ``^password$``) reduced to it."""
    core = re.sub(r"^\^|^\\A|\$$|\\[Zz]$", "", pattern.strip())
    core = re.sub(r"^\^|\$$", "", core)
    if core and not (set(core) & _REGEX_META):
        return core
    return None


def _name_from_loc(loc: Any) -> str | None:
    if isinstance(loc, (list, tuple)) and loc:
        for segment in reversed(loc):
            if isinstance(segment, str) and segment.lower() not in _LOC_CONTAINERS:
                return segment
        return None
    if isinstance(loc, str) and loc:
        return loc.split(".")[-1]
    return None


def _first_message(body_text: str) -> str:
    try:
        data = json.loads(body_text or "")
    except (ValueError, TypeError):
        return (body_text or "").strip()[:_MAX_MESSAGE]
    if isinstance(data, dict):
        detail = data.get("detail")
        if isinstance(detail, list) and detail and isinstance(detail[0], dict):
            return str(detail[0].get("msg") or "")[:_MAX_MESSAGE]
        if isinstance(detail, str):
            return detail[:_MAX_MESSAGE]
        for key in ("message", "error_description", "error"):
            if isinstance(data.get(key), str):
                return str(data[key])[:_MAX_MESSAGE]
    return ""


def parse_sent_fields(body: str, content_type: str = "") -> dict[str, Any]:
    """The fields a request body carried (form or JSON object); ``{}`` for anything else."""
    text = body or ""
    if not text:
        return {}
    ctype = (content_type or "").lower()
    if "json" in ctype or text.lstrip().startswith("{"):
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            data = None
        if isinstance(data, dict):
            return {str(k): v for k, v in data.items()}
    try:
        return dict(parse_qsl(text, keep_blank_values=True))
    except ValueError:
        return {}


_RX_ID_SEGMENT = re.compile(r"^(?:\d+|[0-9a-f]{16,}|[0-9a-f-]{32,})$", re.IGNORECASE)


def _template(path: str) -> str:
    parts = [("{id}" if _RX_ID_SEGMENT.match(p) else p) for p in (path or "/").split("/")]
    return "/".join(parts) or "/"
