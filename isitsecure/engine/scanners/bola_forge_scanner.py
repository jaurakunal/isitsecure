"""Forged-ownership BOLA scanner: the owner identity is in the request BODY, not the URL.

Many create endpoints carry the owner/author/account id in the body (``POST /api/Feedbacks
{"UserId": 1, ...}``). If the server persists that field verbatim instead of deriving the owner
from the session, an authenticated user can create objects attributed to someone else -- a
cross-user write that URL-id swapping (the IDOR scanner) can never reach.

Method (control vs treatment, every proof comes from a fresh READ, never from a write response):

1. Locate OUR identity field by VALUE: the key in a body we sent whose value equals one of our
   own ids (session user id, email, JWT claims). No field-name vocabulary.
2. CONTROL: replay the body unchanged with a unique ``isitsecure-probe`` marker in a free-text
   field, re-read the collection, and require the marker record to come back attributed to US.
   This proves the read endpoint can show our records and that the field is the persisted owner.
3. TREATMENT: resend with the identity field forged to a victim and a second marker, re-read,
   and require the marker record to be attributed to the VICTIM. A write-response echo
   (reflection) is never accepted, and a pre-existing victim record cannot match (no marker).

Two modes, with different strength (see ``docs/scanners/bola-forge-scanner.md``):

- TWO identities: forge to user B's id. Strongest when B's own (owner-scoped) listing shows the
  record while the control record was NOT visible to B -- the server attributed it to B.
- ONE identity: forge to a synthetic, same-shaped, non-existent id (never a real third party).
  Proves only that the server persists a client-chosen owner value; reported MEDIUM.

Safety: strictly opt-in (``probe_writes``); only POSTs that CREATE records carrying the probe
marker; never updates or deletes anything; bounded and non-looping. Conservative about WHAT it
writes: dangerous paths (payment, email, auth, ...) and payment-looking bodies are skipped, a
verified read endpoint must exist BEFORE the first write, and nothing (writes, reads or
credentials) ever leaves the scan target's origin. When unsure the outcome is INCONCLUSIVE, no
write is sent and nothing is reported.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import secrets
import time
import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

import httpx

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import DeepScanConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import DeepFinding, FindingSource, InterceptedRequest
from isitsecure.engine.shared.auth_headers import build_replay_headers
from isitsecure.engine.shared.probe_capture import build_probe_capture
from isitsecure.engine.shared.progress import emit
from isitsecure.engine.shared.rate_limited_client import RateLimitedClient
from isitsecure.engine.shared.time_budget import TimeBudget

logger = logging.getLogger(__name__)


class BolaForgeConfig:
    """Constants for the forged-ownership BOLA scanner (kept local to this module)."""

    SCANNER_NAME = "bola_forge_scanner"

    # Hard bounds. Per endpoint the probe sends at most: pre-write read verification (up to
    # MAX_READ_URLS GETs) + control write (1) + control read (1) + control read as B (1) +
    # treatment write (1) + treatment reads as A and B (2) = MAX_READ_URLS + 6 requests, of
    # which only 2 are writes. It never loops or retries.
    MAX_ENDPOINTS = 5
    MAX_READ_URLS = 3
    MAX_CONCURRENT = 1
    PROBE_DELAY_SECONDS = 0.3
    HTTP_TIMEOUT_SECONDS = 10

    WRITE_METHOD = "POST"          # creation only: updating a pre-existing record is never done
    SUCCESS_CODES = (200, 201)
    MARKER_PREFIX = "isitsecure-probe"
    # JWT claims that are not a per-user identity (time, issuer, audience, role, ... can equal
    # an unrelated body value by chance). ``sub`` is covered through the session user id.
    NON_IDENTITY_CLAIMS = frozenset({
        "exp", "iat", "nbf", "auth_time", "jti", "sub", "iss", "aud", "azp", "role", "roles",
        "scope", "scp", "typ", "alg", "nonce", "sid", "amr", "acr",
    })
    SESSION_CLAIM_PREFIX = "session."   # the session's own user id / email: the strongest match

    # A create whose path has one of these tokens (whole path segment, or a token inside a
    # hyphen/underscore/camelCase/dot-delimited segment) charges, sends, authenticates or
    # consumes something, so it is never replayed. ``order(s)`` is skipped on purpose: a normal
    # resource in some apps, a purchase in others, and a wrong guess spends money.
    DANGEROUS_PATH_TOKENS = frozenset({
        "checkout", "pay", "payment", "payments", "charge", "purchase", "refund", "send",
        "email", "emails", "mail", "sms", "notify", "notification", "notifications", "invite",
        "invites", "subscribe", "webhook", "webhooks", "transfer", "withdraw", "delete",
        "remove", "reset", "password", "login", "logout", "signin", "signup", "register",
        "token", "otp", "verify", "auth", "oauth", "session", "2fa", "mfa", "order", "orders",
    })
    # A body carrying any of these keys (token-wise), or amount together with currency, is a
    # payment and is never replayed.
    PAYMENT_BODY_TOKENS = frozenset({
        "card", "cardnumber", "cvv", "cvc", "iban", "expiry", "routing", "swift",
    })
    PAYMENT_AMOUNT_PAIR = ("amount", "currency")
    # Keys whose value must never carry the probe marker.
    SECRET_KEY_TOKENS = frozenset({
        "password", "passwd", "pwd", "secret", "token", "key", "auth", "credential",
        "credentials", "otp", "pin", "card", "cvv", "cvc", "iban", "ssn", "hash", "signature",
        "url", "uri", "link", "email", "mail", "phone",
    })
    SECRET_VALUE_RE = re.compile(r"^[A-Za-z0-9+/=_.\-]{20,}$")
    MAX_RESPONSE_DEPTH = 8
    EVIDENCE_LENGTH = 400
    # A listing that is not owner-scoped cannot prove attribution by visibility, so the forged
    # value alone must be unlikely to equal an unrelated field by chance: short numeric ids
    # (1, 2, ...) are not, long numeric / opaque ids are.
    MIN_OPAQUE_ID_LENGTH = 8
    MIN_NUMERIC_ID_LENGTH = 9

    CONFIDENCE_SCOPED = 0.92
    CONFIDENCE_FIELD_VALUE = 0.80
    CONFIDENCE_SYNTHETIC = 0.60

    TITLE_TWO = "Forged-ownership BOLA — '{field}' in {method} '{path}' is client-controlled"
    TITLE_ONE = (
        "Client-controlled owner field — '{field}' in {method} '{path}' persisted as sent"
    )
    DESC_TWO = (
        "{method} '{path}' takes the record owner from the request body field '{field}' "
        "instead of the authenticated session. A record created as one user with '{field}' "
        "set to another user's id was persisted attributed to that other user ({proof}). Any "
        "authenticated user can therefore create objects in another user's name. Derive the "
        "owner from the session and ignore or reject a body-supplied owner."
    )
    DESC_ONE = (
        "{method} '{path}' persisted a client-chosen value for the owner field '{field}' "
        "(a synthetic id that belongs to nobody) and returned it on a fresh read, so the "
        "server trusts the body over the session. With a second account this is a cross-user "
        "write (forged authorship); with one account it proves the field is client-controlled "
        "but not that another real user can be impersonated. Derive the owner from the session."
    )
    PROOF_SCOPED = (
        "the forged record appeared in the victim's own listing, which did not show the "
        "attacker's control record"
    )
    PROOF_FIELD = "a fresh read returned the marked record with the victim's id in the field"

    UUID_RE = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE,
    )
    EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    SYNTHETIC_EMAIL_DOMAIN = "example.invalid"


class ForgeStatus(StrEnum):
    """Outcome of one endpoint probe. Only PROVEN becomes a finding."""

    PROVEN = "proven"
    NOT_VULNERABLE = "not_vulnerable"
    INCONCLUSIVE = "inconclusive"


@dataclass
class ForgeOutcome:
    """Small internal result (could adopt the shared ``Verdict`` type once it lands)."""

    status: ForgeStatus
    reason: str = ""
    field: str = ""
    synthetic: bool = False
    proof: str = ""
    confidence: float = 0.0
    evidence: str = ""
    payload: str = ""
    capture: Any = None


@dataclass
class _IdentityField:
    """A body key whose value is one of OUR ids, and the value to forge it to."""

    key: str
    own: str
    victim: str
    strong: bool = False     # matched the session user id/email (not just some other claim)


def _tokens(text: str) -> list[str]:
    """Lower-case word tokens of a path or key: camelCase, snake_case, kebab-case, dots, slashes."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(text))
    return [t for t in re.split(r"[^a-z0-9]+", spaced.lower()) if t]


def is_dangerous_create(url: str, body: dict) -> bool:
    """Whether replaying this create could charge, send, authenticate or consume something."""
    cfg = BolaForgeConfig
    if cfg.DANGEROUS_PATH_TOKENS & set(_tokens(urlparse(url).path)):
        return True
    keys = {t for key, _ in _iter_pairs(body) if isinstance(key, str) for t in _tokens(key)}
    return bool(cfg.PAYMENT_BODY_TOKENS & keys) or set(cfg.PAYMENT_AMOUNT_PAIR) <= keys


def origin_of(url: str) -> tuple[str, str, int] | None:
    """(scheme, host, port) of ``url`` with default ports normalised, or None if unparseable."""
    try:
        parts = urlparse(url)
        host, scheme = (parts.hostname or "").lower(), parts.scheme.lower()
        port = parts.port or {"http": 80, "https": 443}.get(scheme, 0)
    except ValueError:
        return None
    return (scheme, host, port) if host and scheme in ("http", "https") else None


def _decode_jwt_payload(token: str) -> dict:
    """Unverified JWT payload (we only READ our own token's claims); {} when not a JWT."""
    parts = (token or "").split(".")
    if len(parts) != 3:
        return {}
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, TypeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _flatten(obj: Any, prefix: str = "") -> dict[str, str]:
    """Scalar leaves of a nested dict as ``{"a.b": "value"}`` (bools and empties dropped)."""
    out: dict[str, str] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            out.update(_flatten(value, f"{prefix}.{key}" if prefix else str(key)))
    elif isinstance(obj, (str, int)) and not isinstance(obj, bool) and str(obj) != "":
        out[prefix] = str(obj)
    return out


def identity_claims(session: AuthSession | None) -> dict[str, str]:
    """Every id-like value a session carries, keyed by claim name (JWT claims + session ids)."""
    if session is None:
        return {}
    claims = {
        name: value
        for name, value in _flatten(_decode_jwt_payload(session.access_token)).items()
        if name.split(".")[-1] not in BolaForgeConfig.NON_IDENTITY_CLAIMS
    }
    if session.user_id:
        claims[f"{BolaForgeConfig.SESSION_CLAIM_PREFIX}user_id"] = str(session.user_id)
    if session.user_email:
        claims[f"{BolaForgeConfig.SESSION_CLAIM_PREFIX}user_email"] = str(session.user_email)
    return claims


def _iter_pairs(obj: Any, depth: int = 0):
    """Yield (key, value) for every mapping in ``obj``, recursing into dicts and lists."""
    if depth > BolaForgeConfig.MAX_RESPONSE_DEPTH:
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield key, value
            yield from _iter_pairs(value, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_pairs(item, depth + 1)


def _iter_records(obj: Any, depth: int = 0):
    """Every dict in a listing (bare list, enveloped, or single record)."""
    if depth > BolaForgeConfig.MAX_RESPONSE_DEPTH:
        return
    if isinstance(obj, list):
        for item in obj:
            yield from _iter_records(item, depth + 1)
    elif isinstance(obj, dict):
        for value in obj.values():
            if isinstance(value, (dict, list)):
                yield from _iter_records(value, depth + 1)
        yield obj


def _set_key_everywhere(obj: Any, key: str, value: str) -> Any:
    """Deep copy of ``obj`` with every occurrence of ``key`` set to ``value``."""
    if isinstance(obj, dict):
        return {
            k: value if k == key else _set_key_everywhere(v, key, value)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_set_key_everywhere(item, key, value) for item in obj]
    return obj


def _find_identity_fields(
    body: dict, own: dict[str, str], victim: dict[str, str],
) -> list[_IdentityField]:
    """Body keys whose value IS one of our ids, paired with the value to forge them to.

    A match on the session user id/email is "strong" and may be a small number (``UserId: 7``).
    A match on any other claim must be distinctive (opaque/long id or email), so ``rating: 1``
    cannot be mistaken for an identity through a JWT claim. ``victim`` maps the same claim names
    to the other identity's values; a blank ``victim`` means none distinct exists (the caller
    then only goes on for strong fields, in synthetic mode). Strong fields are listed first.
    """
    prefix = BolaForgeConfig.SESSION_CLAIM_PREFIX
    by_value: dict[str, str] = {}
    for name in sorted(own, key=lambda n: not n.startswith(prefix)):   # session ids win ties
        by_value.setdefault(own[name].lower(), name)
    found: list[_IdentityField] = []
    for key, value in _iter_pairs(body):
        if (
            not isinstance(key, str) or isinstance(value, (dict, list, bool, float))
            or value in (None, "") or any(f.key == key for f in found)
        ):
            continue
        claim = by_value.get(str(value).lower())
        if claim is None:
            continue
        strong = claim.startswith(prefix)
        if not strong and not (
            _is_distinctive(str(value)) or BolaForgeConfig.EMAIL_RE.match(str(value))
        ):
            continue
        other = victim.get(claim, "")
        same = other.lower() == str(value).lower()
        found.append(_IdentityField(key, str(value), "" if same else other, strong))
    return sorted(found, key=lambda f: not f.strong)


def _ambiguous(fields: list[_IdentityField]) -> bool:
    """Several keys share one short value (``{"rating": 1, "UserId": 1}``): can't tell which."""
    values = [f.own.lower() for f in fields if not _is_distinctive(f.own)]
    return len(values) != len(set(values))


def _safe_free_text_key(key: str, value: Any) -> bool:
    """Whether ``value`` under ``key`` can carry the probe marker without breaking a secret/URL."""
    cfg = BolaForgeConfig
    text = value.strip()
    return bool(
        text and not (cfg.SECRET_KEY_TOKENS & set(_tokens(key)))
        and "://" not in text and not cfg.EMAIL_RE.match(text)
        and not cfg.SECRET_VALUE_RE.match(text)
    )


def _mark_free_text(body: dict, exclude: set[str], marker: str) -> dict | None:
    """``body`` with ``marker`` appended to its best top-level free-text field, or None.

    Candidates are non-identity string fields that are not secret-, URL- or email-like; one that
    already contains a space (real prose) is preferred, then the longest.
    """
    best, best_rank = "", (-1, -1)
    for key, value in body.items():
        if key in exclude or not isinstance(value, str) or not _safe_free_text_key(key, value):
            continue
        rank = (int(" " in value.strip()), len(value))
        if rank > best_rank:
            best, best_rank = key, rank
    if not best:
        return None
    return {**body, best: f"{body[best]} {marker}".strip()}


def _record_with_marker(listing: Any, marker: str) -> dict | None:
    """The record in ``listing`` carrying ``marker`` (most specific first), else None."""
    for record in _iter_records(listing):
        if marker.lower() in json.dumps(record, default=str).lower():
            return record
    return None


def _has_value(record: dict, key: str, value: str) -> bool:
    """Whether ``record`` carries ``key`` (case-insensitive) set to ``value``, at any depth."""
    return any(
        isinstance(k, str) and k.lower() == key.lower()
        and not isinstance(v, (dict, list)) and str(v).lower() == value.lower()
        for k, v in _iter_pairs(record)
    )


def _is_distinctive(value: str) -> bool:
    """Whether ``value`` is unlikely to equal an unrelated field by chance."""
    if value.isdigit():
        return len(value) >= BolaForgeConfig.MIN_NUMERIC_ID_LENGTH
    return len(value) >= BolaForgeConfig.MIN_OPAQUE_ID_LENGTH


def _synthetic_like(value: str) -> str | None:
    """A random, same-shaped id that belongs to nobody; None when the shape is unsafe to fake.

    Numeric ids are refused: any number we pick could be a real user's id.
    """
    cfg = BolaForgeConfig
    if value.isdigit() or len(value) < cfg.MIN_OPAQUE_ID_LENGTH:
        return None
    if cfg.UUID_RE.match(value):
        return str(uuid.uuid4())
    if cfg.EMAIL_RE.match(value):
        return f"{cfg.MARKER_PREFIX}-{secrets.token_hex(4)}@{cfg.SYNTHETIC_EMAIL_DOMAIN}"
    return secrets.token_hex(max(len(value) // 2, 4))[: len(value)]


def _inconclusive(reason: str) -> ForgeOutcome:
    return ForgeOutcome(ForgeStatus.INCONCLUSIVE, reason=reason)


def _json(response: httpx.Response) -> Any:
    try:
        return json.loads(response.text)
    except (ValueError, TypeError):
        return None


def _ok(response: httpx.Response) -> bool:
    return 200 <= response.status_code < 300


class BolaForgeScanner:
    """Proves BOLA through a body-supplied owner field by forging it and re-reading."""

    def __init__(self, probe_writes: bool = False) -> None:
        self._probe_writes = probe_writes
        self._origin: tuple[str, str, int] | None = None   # the only origin we may talk to
        # Per-endpoint outcomes of the last scan (incl. INCONCLUSIVE, which is never a finding).
        self.outcomes: dict[str, ForgeOutcome] = {}

    @property
    def scanner_name(self) -> str:
        return BolaForgeConfig.SCANNER_NAME

    async def scan(
        self,
        intercepted_requests: list[InterceptedRequest],
        session_a: AuthSession | None,
        session_b: AuthSession | None = None,
        target_url: str | None = None,
    ) -> list[DeepFinding]:
        """Forge the body owner on captured creates; ``session_b`` enables the strong mode.

        ``target_url`` is the scan target: requests (and our credentials) go to its origin only.
        """
        self.outcomes = {}
        if not self._probe_writes:
            return []                                   # mutates data: explicit opt-in only
        self._origin = origin_of(target_url or "")
        own = identity_claims(session_a)
        if self._origin is None or not own:
            return []
        victim = identity_claims(session_b) if session_b else {}

        candidates = self._candidates(intercepted_requests, self._origin)
        findings: list[DeepFinding] = []
        budget = TimeBudget()
        async with RateLimitedClient(
            max_concurrent=BolaForgeConfig.MAX_CONCURRENT,
            delay_seconds=BolaForgeConfig.PROBE_DELAY_SECONDS,
            timeout_seconds=BolaForgeConfig.HTTP_TIMEOUT_SECONDS,
            user_agent=DeepScanConfig.USER_AGENT,
        ) as client:
            for req in candidates:
                if budget.expired():
                    logger.info("BolaForgeScanner: time budget reached, stopping early")
                    break
                emit(f"bola-forge: POST {req.url}")
                try:
                    outcome = await self._probe(
                        client, req, intercepted_requests, session_a, session_b, own, victim,
                    )
                except Exception as exc:                # one bad endpoint must not stop the rest
                    logger.debug("BolaForgeScanner: %s failed: %s", req.url, exc)
                    continue
                self.outcomes[req.url] = outcome
                if outcome.status is ForgeStatus.PROVEN:
                    findings.append(self._finding(req, outcome))
        logger.info("BolaForgeScanner: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Candidate selection
    # ------------------------------------------------------------------

    @staticmethod
    def _candidates(
        captured: list[InterceptedRequest], origin: tuple[str, str, int],
    ) -> list[InterceptedRequest]:
        """Successful, on-origin, non-dangerous JSON-object POST creates, one per path, bounded."""
        seen: set[str] = set()
        picked: list[InterceptedRequest] = []
        for req in captured:
            path = urlparse(req.url).path
            if (
                req.method.upper() != BolaForgeConfig.WRITE_METHOD
                or req.response_status not in BolaForgeConfig.SUCCESS_CODES
                or path in seen or origin_of(req.url) != origin
            ):
                continue
            try:
                body = json.loads(req.request_body)
            except (ValueError, TypeError):
                continue
            if isinstance(body, dict) and body and not is_dangerous_create(req.url, body):
                seen.add(path)
                picked.append(req)
        return picked[: BolaForgeConfig.MAX_ENDPOINTS]

    def _read_candidates(
        self, req: InterceptedRequest, captured: list[InterceptedRequest],
    ) -> list[str]:
        """On-origin URLs that may list the created collection: captured GETs, then the path."""
        path = urlparse(req.url).path
        urls = [
            c.url for c in captured
            if c.method.upper() == "GET" and urlparse(c.url).path == path
            and 200 <= c.response_status < 300
        ]
        urls.append(req.url.split("?", 1)[0])
        return [
            u for u in dict.fromkeys(urls) if origin_of(u) == self._origin
        ][: BolaForgeConfig.MAX_READ_URLS]

    async def _verified_read_url(self, client, req, captured, session, field) -> str | None:
        """A read URL proven BEFORE any write: 200 JSON that already holds a record of ours."""
        for url in self._read_candidates(req, captured):
            response = await self._send(client, "GET", url, session)
            if not _ok(response):
                continue
            if any(
                _has_value(record, field.key, field.own)
                for record in _iter_records(_json(response))
            ):
                return url
        return None

    # ------------------------------------------------------------------
    # The probe
    # ------------------------------------------------------------------

    @staticmethod
    def _headers(session: AuthSession, req: InterceptedRequest | None = None) -> dict[str, str]:
        return {**build_replay_headers(session, req), **session.headers}

    async def _send(self, client, method, url, session, req=None, body=None):
        if origin_of(url) != self._origin:      # never attach our credentials elsewhere
            raise ValueError(f"refusing to send to {url}: outside the scan target's origin")
        return await client.request(
            method=method, url=url, headers=self._headers(session, req),
            content=body,
        )

    async def _read(self, client, url, session, marker) -> dict | None:
        """The record carrying ``marker`` in a fresh read of ``url``, or None."""
        response = await self._send(client, "GET", url, session)
        return _record_with_marker(_json(response), marker) if _ok(response) else None

    async def _probe(
        self, client, req, captured, session_a, session_b, own, victim,
    ) -> ForgeOutcome:
        cfg = BolaForgeConfig
        body = json.loads(req.request_body)
        fields = _find_identity_fields(body, own, victim)
        if not fields:
            return _inconclusive("no body field carries our own identity")
        if _ambiguous(fields):
            return _inconclusive("several body fields share our short id: owner field unclear")
        two_identity = session_b is not None and all(f.victim for f in fields)
        if not two_identity:
            if not all(f.strong for f in fields):
                return _inconclusive("field matches only a non-session claim with no victim")
            fakes = [_synthetic_like(f.own) for f in fields]
            if any(fake is None for fake in fakes):
                return _inconclusive(
                    "one identity and the id shape cannot be faked safely (numeric/short)"
                )
            for f, fake in zip(fields, fakes, strict=True):
                f.victim = fake
        id_keys = {f.key for f in fields}
        tag = secrets.token_hex(4)
        control_marker = f"{cfg.MARKER_PREFIX}-ctl-{tag}"
        forge_marker = f"{cfg.MARKER_PREFIX}-frg-{tag}"
        control_body = _mark_free_text(body, id_keys, control_marker)
        if control_body is None:
            return _inconclusive("no free-text field to carry the probe marker")
        primary = fields[0]

        # A usable read endpoint must exist BEFORE anything is written.
        read_url = await self._verified_read_url(client, req, captured, session_a, primary)
        if read_url is None:
            return _inconclusive("no verified read endpoint (nothing was written)")

        # CONTROL: unchanged identity. The read endpoint must show our new record, owned by us.
        control = await self._send(
            client, "POST", req.url, session_a, req, json.dumps(control_body),
        )
        if not _ok(control):
            return _inconclusive("control write rejected")
        control_record = await self._read(client, read_url, session_a, control_marker)
        if control_record is None:
            return _inconclusive("no read endpoint shows the records we create")
        if not _has_value(control_record, primary.key, primary.own):
            return _inconclusive("control record is not attributed to us in the field")
        control_visible_to_b = False
        if two_identity:
            seen = await self._read(client, read_url, session_b, control_marker)
            control_visible_to_b = seen is not None

        # TREATMENT: forge the identity fields to the victim.
        forged = body
        for f in fields:
            forged = _set_key_everywhere(forged, f.key, f.victim)
        forged = _mark_free_text(forged, id_keys, forge_marker)
        payload = json.dumps(forged)
        started = time.perf_counter()
        treatment = await self._send(client, "POST", req.url, session_a, req, payload)
        elapsed_ms = (time.perf_counter() - started) * 1000
        if not _ok(treatment):
            return ForgeOutcome(ForgeStatus.NOT_VULNERABLE, reason="forged write rejected")
        record_a = await self._read(client, read_url, session_a, forge_marker)
        record_b = None
        if two_identity:
            record_b = await self._read(client, read_url, session_b, forge_marker)

        capture = build_probe_capture(
            "POST", req.url, self._headers(session_a, req), payload, treatment.status_code,
            dict(treatment.headers), treatment.text, elapsed_ms, cfg.SCANNER_NAME,
        )

        def attributed(record: dict | None) -> bool:
            """Marked record carries the forged owner in every identity field it exposes."""
            return record is not None and _has_value(record, primary.key, primary.victim) and all(
                _has_value(record, f.key, f.victim) for f in fields
                if any(isinstance(k, str) and k.lower() == f.key.lower()
                       for k, _ in _iter_pairs(record))
            )

        proven = ForgeOutcome(
            ForgeStatus.PROVEN, field=primary.key, synthetic=not two_identity,
            payload=payload, capture=capture,
        )
        if not (attributed(record_a) or attributed(record_b)):
            # Missing, or persisted under the real owner (a response echo proves nothing).
            return ForgeOutcome(ForgeStatus.NOT_VULNERABLE, reason="owner not honoured on re-read")
        proven.evidence = json.dumps(record_b or record_a, default=str)[: cfg.EVIDENCE_LENGTH]
        if not two_identity:
            proven.proof, proven.confidence = cfg.PROOF_FIELD, cfg.CONFIDENCE_SYNTHETIC
            return proven
        if attributed(record_b) and not control_visible_to_b:
            proven.proof, proven.confidence = cfg.PROOF_SCOPED, cfg.CONFIDENCE_SCOPED
            return proven
        if all(_is_distinctive(f.victim) for f in fields):
            proven.proof, proven.confidence = cfg.PROOF_FIELD, cfg.CONFIDENCE_FIELD_VALUE
            return proven
        return _inconclusive(
            "listing is not owner-scoped and the id is short/numeric: attribution by value "
            "alone could be an unrelated field"
        )

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def _finding(self, req: InterceptedRequest, outcome: ForgeOutcome) -> DeepFinding:
        cfg = BolaForgeConfig
        path = urlparse(req.url).path
        title = (cfg.TITLE_ONE if outcome.synthetic else cfg.TITLE_TWO).format(
            field=outcome.field, method=cfg.WRITE_METHOD, path=path,
        )
        description = (cfg.DESC_ONE if outcome.synthetic else cfg.DESC_TWO).format(
            field=outcome.field, method=cfg.WRITE_METHOD, path=path, proof=outcome.proof,
        )
        return DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.IDOR,
            severity=SeverityLevel.MEDIUM if outcome.synthetic else SeverityLevel.HIGH,
            title=title,
            description=description,
            technical_detail=(
                f"Control write kept our identity and read back attributed to us; forged "
                f"write set '{outcome.field}' to another identity and a fresh read returned "
                f"the marked record attributed to it ({outcome.proof})."
            ),
            evidence=outcome.evidence,
            confidence=outcome.confidence,
            scanner_name=self.scanner_name,
            endpoint_url=req.url,
            http_method=cfg.WRITE_METHOD,
            request_payload=outcome.payload,
            probe_captures=[outcome.capture] if outcome.capture else [],
        )
