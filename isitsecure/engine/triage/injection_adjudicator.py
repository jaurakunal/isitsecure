"""LLM injection-finding adjudicator (#5).

The active DAST injection scanner uses heuristics (response-size deltas, error
strings) to flag SQL/NoSQL/command/template/XXE injection. Those heuristics
misfire on benign behaviour — a redirect that renders the app shell, pagination,
timestamps — producing false positives (issue #5).

This adjudicator is a verification-layer pass that runs *before* triage. For each
borderline DAST injection finding it hands the LLM the payload plus the BASELINE
(safe-value) and INJECTED responses and asks: is the difference genuinely caused
by injection, or normal application behaviour? Findings judged benign are
dropped.

Guarantees:
- It only ever REMOVES a candidate; it never creates or mutates findings, and
  only DAST injection findings in the adjudicated set — the deterministic
  Semgrep taint (SAST) findings are never touched.
- It fails OPEN on any LLM or parse error (a failed/malformed response keeps
  every finding in the batch), and the prompt instructs the model to resolve
  genuine uncertainty to "genuine". Note this is a precision filter that runs
  only with an API key: a confident-but-wrong ``benign`` verdict can still drop
  a true positive, so it trades a little recall for fewer false positives — it
  is not a hard guarantee that a real finding is never dropped.
- It is a strict no-op when no LLM client is configured, so the deterministic
  ``--llm none`` benchmark floor is unaffected.
"""

from __future__ import annotations

import json
import logging
import re

from isitsecure.engine.constants import InjectionAdjudicatorConfig as Cfg
from isitsecure.engine.enums import FindingCategory
from isitsecure.engine.models import DeepFinding
from isitsecure.llm.protocol import LLMClientProtocol

logger = logging.getLogger(__name__)


class InjectionAdjudicator:
    """LLM-powered genuine-vs-benign filter for DAST injection findings.

    Depends on ``LLMClientProtocol`` (DIP), mirroring ``SemanticRuleVerifier``.
    """

    def __init__(self, llm_client: LLMClientProtocol) -> None:
        self._llm = llm_client

    @property
    def scanner_name(self) -> str:
        return Cfg.SCANNER_NAME

    async def adjudicate(self, findings: list[DeepFinding]) -> list[DeepFinding]:
        """Return ``findings`` with LLM-confirmed benign injection FPs removed.

        Non-candidate findings (non-injection, SAST, or not in the adjudicated
        set) pass through untouched.
        """
        candidates = [f for f in findings if self._is_candidate(f)]
        if not candidates:
            return findings

        emitted = Cfg.MSG_ADJUDICATING.format(count=len(candidates))
        logger.info(emitted)

        benign_ids: set[str] = set()
        for start in range(0, len(candidates), Cfg.BATCH_SIZE):
            batch = candidates[start:start + Cfg.BATCH_SIZE]
            benign_ids |= await self._adjudicate_batch(batch)

        if not benign_ids:
            return findings

        logger.info(Cfg.LOG_DROPPED, len(benign_ids), len(candidates))
        return [f for f in findings if f.id not in benign_ids]

    # ------------------------------------------------------------------
    # Candidate selection
    # ------------------------------------------------------------------

    @staticmethod
    def _is_candidate(finding: DeepFinding) -> bool:
        """A DAST injection finding whose title is in the adjudicated set.

        DAST findings carry ``endpoint_url``; SAST (deterministic taint) findings
        carry ``code_location`` instead and are never touched.
        """
        if finding.category != FindingCategory.INJECTION_RISK:
            return False
        if not finding.endpoint_url:
            return False
        return any(s.lower() in finding.title.lower()
                   for s in Cfg.ADJUDICATED_TITLE_SUBSTRINGS)

    # ------------------------------------------------------------------
    # LLM adjudication
    # ------------------------------------------------------------------

    async def _adjudicate_batch(self, batch: list[DeepFinding]) -> set[str]:
        """Return the ids in ``batch`` the LLM judged benign. Fail-open: any
        error returns an empty set (every finding kept)."""
        user_prompt = self._build_user_prompt(batch)
        try:
            response = await self._llm.generate_with_system(
                system_prompt=Cfg.SYSTEM_PROMPT,
                user_prompt=user_prompt,
                max_tokens=Cfg.MAX_TOKENS,
            )
        except Exception as exc:  # noqa: BLE001 — fail open on any LLM error
            logger.warning(Cfg.ERROR_LLM_FAILED.format(error=str(exc)))
            return set()

        return self._parse_benign_ids(response, {f.id for f in batch})

    def _build_user_prompt(self, batch: list[DeepFinding]) -> str:
        parts = [Cfg.USER_PROMPT_HEADER.format(count=len(batch))]
        for f in batch:
            injected = self._fence(f.response_preview or f.evidence or "")
            baseline = self._fence(f.baseline_response_preview or "")
            parts.append(Cfg.FINDING_TEMPLATE.format(
                id=f.id,
                title=f.title,
                method=f.http_method or "GET",
                url=f.endpoint_url or "",
                payload=f.request_payload or "",
                detail=f.technical_detail or "",
                open=Cfg.EVIDENCE_OPEN,
                close=Cfg.EVIDENCE_CLOSE,
                baseline_len=len(baseline),
                baseline=baseline or "(not captured)",
                injected_len=len(injected),
                injected=injected or "(not captured)",
            ))
        return "".join(parts)

    @staticmethod
    def _fence(body: str) -> str:
        """Truncate an untrusted response body and neutralise any attempt to
        spoof the evidence delimiters (prompt-injection defence)."""
        cleaned = body[:Cfg.MAX_EVIDENCE_CHARS]
        return (cleaned.replace(Cfg.EVIDENCE_OPEN, "[open]")
                .replace(Cfg.EVIDENCE_CLOSE, "[close]"))

    def _parse_benign_ids(self, response: str, batch_ids: set[str]) -> set[str]:
        """Extract ids the LLM marked benign. Only ids that were in the batch
        count; anything unparseable keeps all (returns empty set)."""
        match = re.search(r"\[.*\]", response, re.DOTALL)
        if not match:
            return set()
        try:
            items = json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            return set()
        if not isinstance(items, list):
            return set()

        benign: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            fid = item.get("id")
            verdict = str(item.get("verdict", "")).strip().lower()
            if fid in batch_ids and verdict == "benign":
                benign.add(fid)
        return benign
