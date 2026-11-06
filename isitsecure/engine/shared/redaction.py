"""Shared evidence redaction (#282).

Evidence (response samples, request payloads, captured headers, code snippets) is
stored in the report and exported to JSON/HTML/SARIF/Markdown, so it must not
become a data leak. Masks are *shape-preserving*: a reader can still see WHAT was
exposed (``a***@example.com``, ``***-**-****``, ``eyJ…[redacted JWT, 3 segments]``,
``sk_live_[redacted token]``) without seeing the value.

This is regex-based, best-effort redaction -- NOT a DLP guarantee. A secret in a
shape none of the rules know can pass through, and masking is lossy by design.

This module layers PII and token masks on top of the key/header based secret
redaction in :mod:`isitsecure.engine.shared.probe_capture` (reused, not forked):

- :func:`redact_text` / :func:`redact_sample` -- free text or a bounded body preview.
- :func:`redact_code` -- a SAST code snippet (secrets only; line structure and the
  ``>>>`` flagged-line marker are kept).
- :func:`redact_headers` -- credential header *values* (names are kept).
- :func:`redact_finding` / :func:`redact_report` -- export boundary: a copy with every
  evidence-bearing field redacted. The copy carries the RAW finding's fingerprints.
- :func:`scrub_value` -- model-free dict walker, the fail-closed fallback when a
  report does not parse.

Rules (each has a test):

- Masked: emails, SSNs, phone and card numbers (grouped shapes), JWTs, PEM private-key
  blocks (one rule for the whole block), AWS access key ids (``AKIA...``) and 40-char
  secret keys, provider-prefixed keys (prefix kept: ``sk_live_``, ``sk_test_``,
  ``ghp_``, ``xoxb-``, ``AIza``, ``AKIA``), long hex strings and long mixed
  letter/digit runs, digit runs of 12+, values under credential-looking keys.
- Not masked: hyphenated UUIDs, ISO timestamps, epoch seconds/milliseconds, version
  strings, digit runs under 12 (ids, ports, counts), digit runs under an ``id``-ish
  key (``orderId``, ``user_id``) at any length, plain words and identifiers without
  digits, hex hashes that follow a label (``commit``, ``sha``, ``revision``,
  ``build``, ``hash``, ``checksum``), token *metadata* keys (``token_type``,
  ``tokenCount``, ``max_tokens`` ...), and ``true``/``false``/``null`` under any key.
  Consequence: an ungrouped 9-11 digit phone number is not masked.

Every regex is linear-time and input is capped at ``MAX_INPUT_CHARS``, so a
pathological string cannot stall a scan.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import TYPE_CHECKING, Any

from isitsecure.engine.shared.probe_capture import (
    REDACTED,
    is_secret_key,
    redact_body,
    redact_url,
    sanitize_headers,
)
from isitsecure.engine.shared.probe_capture import redact_text as redact_secret_pairs

if TYPE_CHECKING:
    from isitsecure.engine.models import DeepFinding, DeepScanReport

MAX_INPUT_CHARS = 200_000
DEFAULT_SAMPLE_LIMIT = 300
_TRUNCATED_MARK = "…[truncated]"
_TOKEN_MASK = "[redacted token]"  # noqa: S105
_MAX_SCRUB_DEPTH = 100

_TOKEN_MIN_LEN = 24
_HEX_MIN_LEN = 32
_MIXED_CASE_MIN_ENTROPY = 3.0
_SINGLE_CASE_MIN_ENTROPY = 4.0
_DIGITS_MIN_LEN = 12

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(?:\.[A-Za-z0-9_-]*)?")
_EMAIL_RE = re.compile(r"(?<![\w.+-])([\w.+-]+)@([\w-]+(?:\.[\w-]+)+)")
_SSN_RE = re.compile(r"(?<![\d-])\d{3}[- ]\d{2}[- ]\d{4}(?![\d-])")
_CARD_RE = re.compile(r"(?<![\d-])(?:\d{4}[ -]){3}\d{4}(?![\d-])")
# NANP-style (optional +1) and +country-code international numbers. Grouping is
# required so a date (2024-01-15) or a plain id never matches.
_PHONE_RE = re.compile(
    r"(?<![\w.+-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?![\d-])"
    r"|(?<![\w.+-])\+\d{1,3}(?:[ .-]?\d{2,4}){2,4}(?![\d-])"
)
_DIGITS_RE = re.compile(rf"(?<![\w.-])\d{{{_DIGITS_MIN_LEN},}}(?![\w-])")
# ``orderId: 123456789012`` / ``"user_id"=...``: an identifier, not personal data.
_ID_KEY_BEFORE_RE = re.compile(
    r"""(?i)(?:^|[^a-z0-9])(?:[a-z0-9_]*id)["']?\s*[:=]\s*["']?$"""
)
_PROVIDER_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_])((?:sk|rk|pk)_(?:live|test)_|gh[pousr]_|github_pat_|xox[bapors]-|AIza)"
    r"[A-Za-z0-9_\-]{8,}"
)
_AWS_KEY_ID_RE = re.compile(r"(?<![A-Z0-9])(AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")
# 40-char base64-ish AWS secret access key; may contain ``/`` so it must be matched
# before the path-aware token rule would split it.
_AWS_SECRET_RE = re.compile(r"(?<![A-Za-z0-9/+_-])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+_-])")
_PEM_HEADER_RE = re.compile(r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----")
_TOKEN_RUN_RE = re.compile(rf"[A-Za-z0-9_\-+/]{{{_TOKEN_MIN_LEN},}}")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_HASH_LABEL_BEFORE_RE = re.compile(
    r"(?i)(?:commit|sha\d*|revision|rev|build|hash|checksum|digest|etag|md5)\W{0,4}$"
)
_DIGIT_RE = re.compile(r"\d")
_CONTEXT_WINDOW = 48


def _mask_digits(text: str) -> str:
    """Every digit becomes ``*``; separators and length are kept (the shape survives)."""
    return _DIGIT_RE.sub("*", text)


def _mask_jwt(match: re.Match) -> str:
    segments = match.group().count(".") + 1
    return f"eyJ…[redacted JWT, {segments} segments]"


def _mask_email(match: re.Match) -> str:
    return f"{match.group(1)[0]}***@{match.group(2)}"


def _before(match: re.Match) -> str:
    return match.string[max(0, match.start() - _CONTEXT_WINDOW):match.start()]


def _mask_long_digits(match: re.Match) -> str:
    digits = match.group()
    if len(digits) in (10, 13) and digits[0] == "1":  # epoch seconds / milliseconds
        return digits
    if _ID_KEY_BEFORE_RE.search(_before(match)):
        return digits
    return _mask_digits(digits)


def _mask_pem(text: str) -> str:
    """One rule for a whole ``-----BEGIN ... PRIVATE KEY-----`` block (an unterminated
    block is masked to the end of the text). Linear: each header is looked up once."""
    out: list[str] = []
    pos = 0
    while True:
        m = _PEM_HEADER_RE.search(text, pos)
        if m is None:
            break
        footer = m.group().replace("BEGIN", "END")
        end = text.find(footer, m.end())
        out.append(text[pos:m.start()])
        out.append(f"{m.group()}[redacted]{footer if end != -1 else ''}")
        if end == -1:
            return "".join(out)
        pos = end + len(footer)
    out.append(text[pos:])
    return "".join(out)


def _entropy(token: str) -> float:
    counts = Counter(token)
    n = len(token)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _is_secret_like(run: str, labelled_hash: bool = False) -> bool:
    """A long hex string (unless it is a labelled commit/hash), or a long run mixing
    letters and digits with high entropy. UUIDs, words and identifiers are not."""
    if len(run) < _TOKEN_MIN_LEN or _UUID_RE.match(run):
        return False
    if len(run) >= _HEX_MIN_LEN and _HEX_RE.match(run):
        return not labelled_hash
    has_digit = any(c.isdigit() for c in run)
    has_alpha = any(c.isalpha() for c in run)
    if not (has_digit and has_alpha):
        return False
    mixed_case = any(c.islower() for c in run) and any(c.isupper() for c in run)
    if mixed_case:
        return _entropy(run) >= _MIXED_CASE_MIN_ENTROPY
    # One letter case + digits: identifiers (``snake_case_v2_handler``) look like this.
    return "_" not in run and "-" not in run and _entropy(run) >= _SINGLE_CASE_MIN_ENTROPY


def _mask_token_run(match: re.Match) -> str:
    run = match.group()
    labelled = bool(_HASH_LABEL_BEFORE_RE.search(_before(match)))
    if "/" in run:
        # Path-shaped (``/api/v2/users/<token>``): judge each segment on its own
        # so the path stays readable and only a key-looking segment is masked.
        segs = run.split("/")
        if sum(1 for s in segs if 0 < len(s) < _TOKEN_MIN_LEN) >= 2:
            return "/".join(_TOKEN_MASK if _is_secret_like(s, labelled) else s for s in segs)
    return _TOKEN_MASK if _is_secret_like(run, labelled) else run


def _mask_aws_secret(match: re.Match) -> str:
    run = match.group()
    base64ish = "/" in run[1:] or "+" in run
    if (run[0] == "/" or not base64ish or not any(c.isdigit() for c in run)
            or not any(c.islower() for c in run) or not any(c.isupper() for c in run)):
        return run
    return _TOKEN_MASK


def _mask_provider_secrets(text: str) -> str:
    """Known-format keys keep their prefix so the finding stays identifiable."""
    text = _PROVIDER_KEY_RE.sub(lambda m: f"{m.group(1)}{_TOKEN_MASK}", text)
    return _AWS_KEY_ID_RE.sub(lambda m: f"{m.group(1)}{_TOKEN_MASK}", text)


def _mask_tokens(text: str) -> str:
    text = _AWS_SECRET_RE.sub(_mask_aws_secret, text)
    return _TOKEN_RUN_RE.sub(_mask_token_run, text)


def _mask_pii(text: str) -> str:
    text = _EMAIL_RE.sub(_mask_email, text)
    text = _SSN_RE.sub(lambda m: _mask_digits(m.group()), text)
    text = _CARD_RE.sub(lambda m: _mask_digits(m.group()), text)
    text = _PHONE_RE.sub(lambda m: _mask_digits(m.group()), text)
    return text


def _cap(text: str) -> str:
    if len(text) > MAX_INPUT_CHARS:
        return text[:MAX_INPUT_CHARS] + _TRUNCATED_MARK
    return text


def redact_text(text: str | None) -> str:
    """Mask secrets and PII in free text or a body, keeping its structure.

    Order matters: PEM blocks and JWTs first (so their informative placeholders
    survive), then provider-prefixed keys, then the key-aware secret redaction (nested
    JSON, ``key=value``, Bearer values) from ``probe_capture``, then the shape-based
    PII, token and digit masks. Idempotent."""
    if not text:
        return text or ""
    text = _mask_provider_secrets(_JWT_RE.sub(_mask_jwt, _mask_pem(_cap(text))))
    text = _mask_tokens(_mask_pii(redact_body(text)))
    return _DIGITS_RE.sub(_mask_long_digits, text)


def redact_code(snippet: str | None) -> str:
    """Mask secrets in a source snippet. Only credentials are masked (no PII or digit
    rules: code is full of numbers and fixture emails), and line structure is kept,
    including the ``NNN >>>`` marker the fingerprint discriminator relies on."""
    if not snippet:
        return snippet or ""
    text = _mask_provider_secrets(_JWT_RE.sub(_mask_jwt, _mask_pem(_cap(snippet))))
    return _mask_tokens(redact_secret_pairs(text))


def redact_sample(text: str | None, *, limit: int = DEFAULT_SAMPLE_LIMIT) -> str:
    """A bounded preview. Masking runs on the full text BEFORE the cut, so a
    secret straddling ``limit`` cannot leak a raw prefix."""
    return redact_text(text)[:limit]


def redact_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Credential header values (Authorization, Cookie, Set-Cookie, X-API-Key, ...)
    are replaced; names are kept. Other values get the PII/token masks."""
    cleaned = sanitize_headers(dict(headers or {}))
    return {k: redact_text(v) if isinstance(v, str) else v for k, v in cleaned.items()}


def _redact_url_text(url: str | None) -> str:
    return redact_text(redact_url(url)) if url else (url or "")


_HEADER_MAP_KEYS = frozenset({"headers", "request_headers", "response_headers"})


def scrub_value(node: Any, _depth: int = 0) -> Any:
    """Model-free redaction of any JSON-like structure: every string value goes through
    :func:`redact_text`, scalar values under credential-looking keys are replaced, and
    header mappings are masked by header name. Used as the fail-closed fallback when a
    report does not validate -- the raw dict must never be returned."""
    if _depth > _MAX_SCRUB_DEPTH:
        return REDACTED
    if isinstance(node, dict):
        out: dict = {}
        for key, value in node.items():
            if str(key).lower() in _HEADER_MAP_KEYS and isinstance(value, dict):
                out[key] = redact_headers({str(k): v for k, v in value.items()})
            elif is_secret_key(key) and not (
                value is None or isinstance(value, (bool, dict, list))
            ):
                out[key] = REDACTED
            else:
                out[key] = scrub_value(value, _depth + 1)
        return out
    if isinstance(node, (list, tuple)):
        return [scrub_value(v, _depth + 1) for v in node]
    if isinstance(node, str):
        return redact_text(node)
    return node


# Finding fields that can carry response data, payloads or echoed credentials.
_FINDING_TEXT_FIELDS = (
    "title", "description", "technical_detail", "evidence", "request_payload",
    "response_preview", "baseline_response_preview", "remediation_guidance",
)


def redact_finding(finding: DeepFinding) -> DeepFinding:
    """A copy of ``finding`` safe to export: evidence-bearing text fields, the URL,
    the code snippet, probe captures and the evidence pair are redacted. The original
    is untouched, and the copy is pinned to the ORIGINAL's fingerprints (the SAST
    fingerprint hashes the flagged snippet line, which masking may change)."""
    update: dict = {}
    for name in _FINDING_TEXT_FIELDS:
        value = getattr(finding, name, None)
        if value:
            update[name] = redact_text(value)
    if finding.endpoint_url:
        update["endpoint_url"] = _redact_url_text(finding.endpoint_url)
    if finding.code_location and finding.code_location.code_snippet:
        update["code_location"] = finding.code_location.model_copy(
            update={"code_snippet": redact_code(finding.code_location.code_snippet)}
        )
    if finding.probe_captures:
        update["probe_captures"] = [
            c.model_copy(update={
                "request_url": _redact_url_text(c.request_url),
                "request_headers": redact_headers(c.request_headers),
                "response_headers": redact_headers(c.response_headers),
                "request_body": redact_text(c.request_body),
                "response_body": redact_text(c.response_body),
                "curl_command": redact_text(c.curl_command),
            })
            for c in finding.probe_captures
        ]
    pair = getattr(finding, "evidence_pair", None)
    if pair is not None:
        update["evidence_pair"] = pair.model_copy(update={
            "baseline": _redact_excerpt(pair.baseline),
            "proof": _redact_excerpt(pair.proof),
            "note": redact_text(pair.note),
        })
    redacted = finding.model_copy(update=update)
    from isitsecure.engine.identity import finding_fingerprint, legacy_fingerprint

    redacted.pin_fingerprints(finding_fingerprint(finding), legacy_fingerprint(finding))
    return redacted


def _redact_excerpt(excerpt):
    return excerpt.model_copy(update={
        "url": _redact_url_text(excerpt.url),
        "request_payload": redact_text(excerpt.request_payload),
        "body_excerpt": redact_sample(excerpt.body_excerpt),
    })


def _redact_endpoint(endpoint):
    return endpoint.model_copy(update={"url": _redact_url_text(endpoint.url)})


def redact_report(report: DeepScanReport) -> DeepScanReport:
    """A copy of ``report`` with every finding redacted, for any export format."""
    return report.model_copy(update={
        "findings": [redact_finding(f) for f in report.findings],
        "scanner_errors": [redact_text(e) for e in report.scanner_errors],
        "ingestion_errors": [redact_text(e) for e in report.ingestion_errors],
        "discovered_endpoints": [_redact_endpoint(e) for e in report.discovered_endpoints],
        "idor_results": [
            r.model_copy(update={"endpoint": _redact_endpoint(r.endpoint), "probes": [
                p.model_copy(update={
                    "original_url": _redact_url_text(p.original_url),
                    "probed_url": _redact_url_text(p.probed_url),
                    "original_body_preview": redact_text(p.original_body_preview),
                    "probed_body_preview": redact_text(p.probed_body_preview),
                })
                for p in r.probes
            ]})
            for r in report.idor_results
        ],
    })
