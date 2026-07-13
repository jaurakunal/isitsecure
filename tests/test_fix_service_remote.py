"""Server-side run_fix_all routing to the remote PR flow (mocked)."""

from __future__ import annotations

import pytest

from isitsecure.server import fix_service


def _report(repo_url):
    return {
        "repo_url": repo_url,
        "findings": [
            {
                "source": "sast_code",
                "category": "injection_risk",
                "severity": "critical",
                "title": "SQL injection",
                "description": "d",
                "scanner_name": "s",
                "confidence": 0.9,
                "code_location": {"file_path": "src/db.ts", "line_number": 3,
                                  "code_snippet": "bad()"},
            }
        ],
    }


@pytest.mark.asyncio
async def test_remote_github_routes_to_pr_flow(monkeypatch):
    events = []

    async def emit(e):
        events.append(e)

    # Stub the LLM key + client so we never call a real provider.
    monkeypatch.setattr(fix_service, "load_api_key", lambda p: "key")
    monkeypatch.setattr(
        "isitsecure.llm.adapters.create_llm_client",
        lambda provider, key: object(),
    )

    captured = {}

    class FakeFlow:
        def __init__(self, generator):
            captured["generator"] = generator

        async def run(self, *, repo_url, findings, github_token, strategy, max_prs, emit):
            captured.update(
                repo_url=repo_url, token=github_token, strategy=strategy, max_prs=max_prs,
                n=len(findings),
            )

            class R:
                def to_dict(self_inner):
                    return {"mode": "pull_requests", "pull_requests": [], "fixed_count": 1}

            return R()

    monkeypatch.setattr(fix_service, "PRFlow", FakeFlow)

    result = await fix_service.run_fix_all(
        report=_report("https://github.com/octo/app"),
        llm_provider="anthropic",
        emit=emit,
        github_token="TESTTOKEN",
        pr_strategy="per-category",
        max_prs=5,
    )
    assert result["mode"] == "pull_requests"
    assert captured["repo_url"] == "https://github.com/octo/app"
    assert captured["token"] == "TESTTOKEN"
    assert captured["max_prs"] == 5
    assert captured["n"] == 1


@pytest.mark.asyncio
async def test_no_token_does_not_route_to_pr_flow(monkeypatch):
    """Without a token, a remote repo falls back to plan mode (no PR flow)."""
    monkeypatch.setattr(fix_service, "load_api_key", lambda p: "key")
    monkeypatch.setattr(
        "isitsecure.llm.adapters.create_llm_client",
        lambda provider, key: _StubLLM(),
    )

    called = {"pr": False}

    class NeverFlow:
        def __init__(self, *a, **k):
            called["pr"] = True

    monkeypatch.setattr(fix_service, "PRFlow", NeverFlow)

    async def emit(e):
        pass

    result = await fix_service.run_fix_all(
        report=_report("https://github.com/octo/app"),
        llm_provider="anthropic",
        emit=emit,
        github_token=None,
    )
    # Remote URL with no local checkout + no token → plan mode.
    assert result["mode"] == "plan"
    assert called["pr"] is False


@pytest.mark.asyncio
async def test_non_github_remote_falls_back_to_plan(monkeypatch):
    monkeypatch.setattr(fix_service, "load_api_key", lambda p: "key")
    monkeypatch.setattr(
        "isitsecure.llm.adapters.create_llm_client",
        lambda provider, key: _StubLLM(),
    )

    class NeverFlow:
        def __init__(self, *a, **k):
            raise AssertionError("PRFlow must not run for non-GitHub hosts")

    monkeypatch.setattr(fix_service, "PRFlow", NeverFlow)

    msgs = []

    async def emit(e):
        msgs.append(e.get("message", ""))

    result = await fix_service.run_fix_all(
        report=_report("https://gitlab.com/octo/app"),
        llm_provider="anthropic",
        emit=emit,
        github_token="TESTTOKEN",
    )
    assert result["mode"] == "plan"
    assert any("not GitHub" in m for m in msgs)


class _StubLLM:
    async def generate_with_system(self, **kwargs):
        # Return a trivial fenced block so plan-mode generation succeeds.
        return "```ts\nfixed\n```"
