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
marker; never updates or deletes anything; bounded and non-looping. When unsure the outcome is
INCONCLUSIVE and nothing is reported.
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
from urllib.parse import quote, urljoin, urlparse

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

    # Hard bounds. Per endpoint the probe sends at most: control write (1) + control reads (up
    # to MAX_READ_URLS) + control read as B (1) + treatment write (1) + treatment reads as A and
    # B (2) = MAX_READ_URLS + 5 requests. It never loops or retries.
    MAX_ENDPOINTS = 5
    MAX_READ_URLS = 3
    MAX_CONCURRENT = 1
    PROBE_DELAY_SECONDS = 0.3
    HTTP_TIMEOUT_SECONDS = 10

    WRITE_METHOD = "POST"          # creation only: updating a pre-existing record is never done
    SUCCESS_CODES = (200, 201)
    MARKER_PREFIX = "isitsecure-probe"
    # JWT time claims are not identities (a body number can equal ``iat`` by chance).
    NON_IDENTITY_CLAIMS = frozenset({"exp", "iat", "nbf", "auth_time"})
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


def identity_claims(session: AuthSession) -> dict[str, str]:
    """Every id-like value a session carries, keyed by claim name (JWT claims + session ids)."""
    claims = {
        name: value
        for name, value in _flatten(_decode_jwt_payload(session.access_token)).items()
        if name.split(".")[-1] not in BolaForgeConfig.NON_IDENTITY_CLAIMS
    }
    if session.user_id:
        claims["session.user_id"] = str(session.user_id)
    if session.user_email:
        claims["session.user_email"] = str(session.user_email)
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

    ``victim`` maps the same claim names to the other identity's values; an empty/absent claim
    leaves ``victim`` blank (the caller then falls back to synthetic mode).
    """
    by_value: dict[str, str] = {}
    for name, value in own.items():
        by_value.setdefault(value.lower(), name)
    found: list[_IdentityField] = []
    for key, value in _iter_pairs(body):
        if (
            not isinstance(key, str) or isinstance(value, (dict, list, bool))
            or value in (None, "") or any(f.key == key for f in found)
        ):
            continue
        claim = by_value.get(str(value).lower())
        if claim is None:
            continue
        other = victim.get(claim, "")
        same = other.lower() == str(value).lower()
        found.append(_IdentityField(key, str(value), "" if same else other))
    return found


def _mark_free_text(body: dict, exclude: set[str], marker: str) -> dict | None:
    """``body`` with ``marker`` appended to its longest top-level free-text field, or None."""
    best, best_len = "", -1
    for key, value in body.items():
        if key not in exclude and isinstance(value, str) and len(value) > best_len:
            best, best_len = key, len(value)
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
        # Per-endpoint outcomes of the last scan (incl. INCONCLUSIVE, which is never a finding).
        self.outcomes: dict[str, ForgeOutcome] = {}

    @property
    def scanner_name(self) -> str:
        return BolaForgeConfig.SCANNER_NAME

    async def scan(
        self,
        intercepted_requests: list[InterceptedRequest],
        session_a: AuthSession,
        session_b: AuthSession | None = None,
    ) -> list[DeepFinding]:
        """Forge the body owner on captured creates; ``session_b`` enables the strong mode."""
        self.outcomes = {}
        if not self._probe_writes:
            return []                                   # mutates data: explicit opt-in only
        own = identity_claims(session_a)
        if not own:
            return []
        victim = identity_claims(session_b) if session_b else {}

        candidates = self._candidates(intercepted_requests)
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
    def _candidates(captured: list[InterceptedRequest]) -> list[InterceptedRequest]:
        """Successful JSON-object POST creates we captured, one per path, bounded."""
        seen: set[str] = set()
        picked: list[InterceptedRequest] = []
        for req in captured:
            path = urlparse(req.url).path
            if (
                req.method.upper() != BolaForgeConfig.WRITE_METHOD
                or req.response_status not in BolaForgeConfig.SUCCESS_CODES
                or path in seen
            ):
                continue
            try:
                body = json.loads(req.request_body)
            except (ValueError, TypeError):
                continue
            if isinstance(body, dict) and body:
                seen.add(path)
                picked.append(req)
        return picked[: BolaForgeConfig.MAX_ENDPOINTS]

    @staticmethod
    def _read_urls(
        req: InterceptedRequest,
        captured: list[InterceptedRequest],
        control: httpx.Response,
    ) -> list[str]:
        """Where the created collection can be read back, most promising first."""
        path = urlparse(req.url).path
        urls = [
            c.url for c in captured
            if c.method.upper() == "GET" and urlparse(c.url).path == path
            and 200 <= c.response_status < 300
        ]
        base = req.url.split("?", 1)[0]
        urls.append(base)
        location = control.headers.get("location")
        if location:
            urls.append(urljoin(base, location))
        for key, value in _iter_pairs(_json(control)):
            if isinstance(key, str) and key.lower() in ("id", "_id", "uuid") \
                    and isinstance(value, (str, int)) and not isinstance(value, bool):
                urls.append(base.rstrip("/") + "/" + quote(str(value), safe=""))
                break
        return list(dict.fromkeys(urls))[: BolaForgeConfig.MAX_READ_URLS]

    # ------------------------------------------------------------------
    # The probe
    # ------------------------------------------------------------------

    @staticmethod
    def _headers(session: AuthSession, req: InterceptedRequest | None = None) -> dict[str, str]:
        return {**build_replay_headers(session, req), **session.headers}

    async def _send(self, client, method, url, session, req=None, body=None):
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
        two_identity = session_b is not None and all(f.victim for f in fields)
        if not two_identity:
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

        # CONTROL: unchanged identity. The read endpoint must show our record, owned by us.
        control = await self._send(
            client, "POST", req.url, session_a, req, json.dumps(control_body),
        )
        if not _ok(control):
            return _inconclusive("control write rejected")
        read_url, control_record = None, None
        for url in self._read_urls(req, captured, control):
            record = await self._read(client, url, session_a, control_marker)
            if record is not None:
                read_url, control_record = url, record
                break
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
            return record is not None and _has_value(record, primary.key, primary.victim)

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
