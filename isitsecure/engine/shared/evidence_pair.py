"""Build the redacted baseline-vs-proof pair attached to DAST findings (#282).

A scanner that already holds a control response and the response that proved the
finding calls :func:`build_evidence_pair` and sets ``DeepFinding.evidence_pair``.
Both sides are redacted here, so a scanner cannot forget to.

    finding.evidence_pair = build_evidence_pair(
        method="GET", url=endpoint.url,
        baseline_payload="id=1", baseline_status=200, baseline_body=control.text,
        proof_payload="id=1'", proof_status=500, proof_body=response.text,
    )
"""

from __future__ import annotations

from isitsecure.engine.models import EvidenceExcerpt, EvidencePair
from isitsecure.engine.shared.probe_capture import redact_url
from isitsecure.engine.shared.redaction import DEFAULT_SAMPLE_LIMIT, redact_sample, redact_text


def _excerpt(label: str, method: str, url: str, payload: str,
             status: int | None, body: str, limit: int) -> EvidenceExcerpt:
    return EvidenceExcerpt(
        label=label,
        method=method,
        url=redact_url(url),
        request_payload=redact_text(payload),
        status=status,
        body_length=len(body),
        body_excerpt=redact_sample(body, limit=limit),
    )


def _auto_note(baseline: EvidenceExcerpt, proof: EvidenceExcerpt) -> str:
    return (
        f"baseline: HTTP {baseline.status or '?'}, {baseline.body_length} bytes; "
        f"proof: HTTP {proof.status or '?'}, {proof.body_length} bytes"
    )


def build_evidence_pair(
    *,
    method: str,
    url: str,
    baseline_payload: str,
    baseline_body: str,
    proof_payload: str,
    proof_body: str,
    baseline_status: int | None = None,
    proof_status: int | None = None,
    note: str = "",
    limit: int = DEFAULT_SAMPLE_LIMIT,
) -> EvidencePair | None:
    """Return a redacted pair, or ``None`` when there is no control to compare
    against (an empty baseline body and no status means the control never ran)."""
    if not baseline_body and baseline_status is None:
        return None
    baseline = _excerpt(
        "baseline", method, url, baseline_payload, baseline_status, baseline_body, limit)
    proof = _excerpt("proof", method, url, proof_payload, proof_status, proof_body, limit)
    return EvidencePair(baseline=baseline, proof=proof, note=note or _auto_note(baseline, proof))
