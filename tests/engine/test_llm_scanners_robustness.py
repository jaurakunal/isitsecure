"""Scope safety and parse robustness for the LLM scanners."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx
import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.code_analysis.llm_code_reviewer import (
    LLMCodeReviewer,
    extract_json_array,
)
from isitsecure.engine.code_analysis.protocols import RepoSnapshot, RouteEntry
from isitsecure.engine.code_analysis.semantic_rule_verifier import (
    SemanticRuleVerifier,
)
from isitsecure.engine.constants import LLMCodeReviewConfig
from isitsecure.engine.enums import (
    AuthProvider,
    ReviewTriggerType,
    SeverityLevel,
)
from isitsecure.engine.scanners.llm_business_logic_scanner import (
    LLMBusinessLogicScanner,
)

TARGET = "http://127.0.0.1:9001"


def _sess(token: str) -> AuthSession:
    return AuthSession(
        user_id="u", access_token=token, provider=list(AuthProvider)[0]
    )


def _scanner(plans):
    llm = AsyncMock()
    llm.generate_with_system.side_effect = [
        json.dumps({"attack_plans": plans}),
        *[json.dumps({"confirmed": True, "severity": "HIGH", "evidence": "x"})] * 5,
    ]
    return LLMBusinessLogicScanner(llm)


@pytest.fixture
def serve(monkeypatch):
    """Route every httpx.AsyncClient through a MockTransport; return seen list."""
    real = httpx.AsyncClient
    seen: list[httpx.Request] = []

    def install(handler):
        def wrapped(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return handler(req)

        def factory(*a, **kw):
            kw["transport"] = httpx.MockTransport(wrapped)
            return real(*a, **kw)

        monkeypatch.setattr(httpx, "AsyncClient", factory)
        return seen

    return install


async def _run(scanner):
    return await scanner.scan(
        {"app/orders/route.py": "x=1"}, [],
        _sess("ADMIN-SECRET"), _sess("USER"), TARGET,
    )


class TestBusinessLogicScope:
    async def test_out_of_scope_url_never_requested(self, serve):
        seen = serve(lambda r: httpx.Response(200))
        sc = _scanner([{"title": "p", "steps": [{
            "method": "GET", "url": "http://127.0.0.1:9002/admin",
            "user": "admin_user"}]}])
        assert await _run(sc) == []
        assert seen == []
        assert len(sc.skipped_steps) == 1

    @pytest.mark.parametrize("url", [
        "http://evil.example/x", "//evil.example/x", "https://127.0.0.1:9001/x",
        "http://127.0.0.1/x", "ftp://127.0.0.1:9001/x",
    ])
    async def test_scheme_host_port_mismatch_refused(self, serve, url):
        seen = serve(lambda r: httpx.Response(200))
        sc = _scanner([{"title": "p", "steps": [{"method": "GET", "url": url}]}])
        await _run(sc)
        assert seen == []
        assert sc.skipped_steps

    async def test_relative_url_resolves_and_gets_token(self, serve):
        seen = serve(lambda r: httpx.Response(200))
        sc = _scanner([{"title": "p", "steps": [{
            "method": "GET", "url": "/api/x", "user": "admin_user"}]}])
        findings = await _run(sc)
        assert len(findings) == 1
        assert str(seen[0].url) == f"{TARGET}/api/x"
        assert seen[0].headers["authorization"] == "Bearer ADMIN-SECRET"

    async def test_redirect_off_origin_not_followed(self, serve):
        def handler(req):
            if req.url.port == 9001:
                return httpx.Response(
                    302, headers={"location": "http://127.0.0.1:9002/steal"}
                )
            return httpx.Response(200)

        seen = serve(handler)
        sc = _scanner([{"title": "p", "steps": [{
            "method": "GET", "url": "/r", "user": "admin_user"}]}])
        await _run(sc)
        assert [r.url.port for r in seen] == [9001]
        assert any("redirect" in r for _, r in sc.skipped_steps)

    async def test_same_origin_redirect_followed(self, serve):
        def handler(req):
            if req.url.path == "/r":
                return httpx.Response(302, headers={"location": "/final"})
            return httpx.Response(200, text="ok")

        seen = serve(handler)
        sc = _scanner([{"title": "p", "steps": [{"method": "GET", "url": "/r"}]}])
        await _run(sc)
        assert [r.url.path for r in seen] == ["/r", "/final"]

    async def test_malformed_step_does_not_discard_findings(self, serve):
        serve(lambda r: httpx.Response(200))
        sc = _scanner([
            {"title": "good", "steps": [{"method": "GET", "url": "/ok"}]},
            {"title": "bad", "steps": ["not-a-dict"]},
            {"title": "worse", "steps": [{"method": 5, "url": 7, "user": []}]},
        ])
        findings = await _run(sc)
        assert [f.title for f in findings] == ["good"]

    async def test_first_step_not_dict_still_yields_finding(self, serve):
        serve(lambda r: httpx.Response(200))
        sc = _scanner([{"title": "mixed", "steps": [
            "x", {"method": "GET", "url": "/ok"}]}])
        assert len(await _run(sc)) == 1


class TestExtractJsonArray:
    def test_bracketed_prose_before_array(self):
        assert extract_json_array('Found [2 issues]:\n[{"a": 1}]') == [{"a": 1}]

    def test_code_fence(self):
        assert extract_json_array('```json\n[{"a": 1}]\n```') == [{"a": 1}]

    def test_none_when_absent(self):
        assert extract_json_array("I cannot help with that") is None

    def test_empty_array_is_valid(self):
        assert extract_json_array("[]") == []


def _repo(**kw):
    return RepoSnapshot(repo_url="r", branch="b", clone_path="/tmp/x", **kw)


def _reviewer():
    return LLMCodeReviewer(AsyncMock())


class TestReviewerParsing:
    def test_null_severity_keeps_other_items(self):
        reply = json.dumps([
            {"title": "A", "severity": None, "description": "d", "line_number": "7"},
            {"title": "B", "severity": "HIGH", "description": "d", "line_number": 2},
            {"title": "C"},
        ])
        out = _reviewer()._parse_llm_findings(reply, "f.py", "a\nb\nc")
        assert [f.title for f in out] == ["A", "B", "C"]
        assert out[0].severity == SeverityLevel.MEDIUM
        assert out[1].severity == SeverityLevel.HIGH

    def test_bracketed_prose(self):
        reply = 'Found [2 issues]:\n[{"title": "A", "severity": "LOW"}]'
        assert len(_reviewer()._parse_llm_findings(reply, "f.py")) == 1

    def test_unparseable_recorded(self):
        r = _reviewer()
        assert r._parse_llm_findings("sorry, can't", "f.py") == []
        assert r.skipped_files and r.skipped_files[0][0] == "f.py"

    async def test_llm_error_recorded_with_route(self):
        llm = AsyncMock()
        llm.generate_with_system.side_effect = IndexError("refusal")
        r = LLMCodeReviewer(llm)
        route = RouteEntry(file_path="a/route.ts", route_pattern="/a",
                           http_methods=["GET"], content="x")
        assert await r._review_route(
            route, _repo(), ReviewTriggerType.CROSS_SCANNER_FLAGGED
        ) == []
        assert r.skipped_files[0][0] == "a/route.ts"
        assert "refusal" in r.skipped_files[0][1]

    async def test_oversize_route_recorded_in_scan(self):
        big = RouteEntry(
            file_path="big/route.ts", route_pattern="/big", http_methods=["GET"],
            content="x" * (LLMCodeReviewConfig.MAX_FILE_SIZE_CHARS + 1),
        )
        r = LLMCodeReviewer(AsyncMock())
        await r.scan(_repo(route_map=[big]))
        assert any(n == "big/route.ts" for n, _ in r.skipped_files)


class TestSemanticVerifierParsing:
    def test_null_severity_and_prose(self):
        v = SemanticRuleVerifier(AsyncMock())
        reply = (
            'Notes [x]:\n```json\n[{"title":"A","severity":null},'
            '{"title":"B","severity":"low","line_number":"x"}]\n```'
        )
        out = v._parse_llm_findings(reply, "m.sql", "")
        assert [f.title for f in out] == ["A", "B"]
        assert out[0].severity == SeverityLevel.MEDIUM
        assert out[1].severity == SeverityLevel.LOW
        assert out[1].line_number is None

    async def test_error_and_garbage_recorded(self):
        llm = AsyncMock()
        llm.generate_with_system.side_effect = [RuntimeError("429"), "no json"]
        v = SemanticRuleVerifier(llm)
        assert await v._send_to_llm("s", "u", "a.sql", "") == []
        assert await v._send_to_llm("s", "u", "b.sql", "") == []
        assert [n for n, _ in v.skipped_files] == ["a.sql", "b.sql"]
