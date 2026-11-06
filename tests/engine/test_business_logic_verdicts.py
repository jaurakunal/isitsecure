"""Business-logic scanner: deterministic evidence gate before the judge (#276)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.enums import AuthProvider
from isitsecure.engine.scanners.llm_business_logic_scanner import (
    LLMBusinessLogicScanner,
)

PLAN = json.dumps({
    "attack_plans": [{
        "title": "IDOR in deal update",
        "severity": "HIGH",
        "description": "d",
        "success_criteria": "200",
        "steps": [{"method": "PATCH", "url": "/api/deals/123", "user": "regular_user",
                   "body": {"t": 1}}],
    }]
})
CONFIRM = json.dumps({"confirmed": True, "confidence": 0.9, "evidence": "e",
                      "severity": "HIGH"})


def _session() -> AuthSession:
    return AuthSession(
        user_id="u", access_token="t", provider=AuthProvider.SUPABASE  # noqa: S106
    )


async def _run(request_impl):
    llm = AsyncMock()
    llm.generate_with_system.side_effect = [PLAN, CONFIRM]
    scanner = LLMBusinessLogicScanner(llm_client=llm)
    with patch("httpx.AsyncClient") as MockClient:
        client = AsyncMock()
        client.request = AsyncMock(side_effect=request_impl)
        MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
        MockClient.return_value.__aexit__ = AsyncMock(return_value=False)
        findings = await scanner.scan(
            repo_files={"src/server/routers/deal.ts": "code"},
            endpoints=[],
            admin_session=_session(),
            regular_session=_session(),
            target_url="https://x.com",
        )
    return findings, scanner, llm


def _resp(status, text):
    return httpx.Response(status, text=text, request=httpx.Request("PATCH", "https://x.com"))


@pytest.mark.asyncio
async def test_transport_failure_never_reaches_judge_and_is_surfaced():
    async def boom(*a, **k):
        raise httpx.ConnectError("refused")

    findings, scanner, llm = await _run(boom)
    assert findings == []
    assert llm.generate_with_system.await_count == 1  # plan only, judge not asked
    assert any("inconclusive" in r for _, r in scanner.skipped_steps)
    assert any("no response" in r for _, r in scanner.skipped_steps)


@pytest.mark.asyncio
async def test_validation_rejection_is_inconclusive_not_judged():
    findings, scanner, llm = await _run(lambda *a, **k: _resp(422, '{"detail":"bad"}'))
    assert findings == []
    assert llm.generate_with_system.await_count == 1
    assert any("validation" in r for _, r in scanner.skipped_steps)


@pytest.mark.asyncio
async def test_denial_only_is_not_proven_and_not_judged():
    findings, scanner, llm = await _run(lambda *a, **k: _resp(403, '{"error":"no"}'))
    assert findings == []
    assert llm.generate_with_system.await_count == 1
    assert scanner.skipped_steps == []  # a conclusive "not vulnerable", not a skip


@pytest.mark.asyncio
async def test_success_false_body_is_not_judged():
    findings, _, llm = await _run(lambda *a, **k: _resp(200, '{"success": false}'))
    assert findings == []
    assert llm.generate_with_system.await_count == 1


@pytest.mark.asyncio
async def test_real_answer_still_reaches_judge_and_reports():
    """Recall guard: a well-supported confirmation is still reported."""
    findings, _, llm = await _run(lambda *a, **k: _resp(200, '{"title":"hacked"}'))
    assert len(findings) == 1
    assert llm.generate_with_system.await_count == 2
