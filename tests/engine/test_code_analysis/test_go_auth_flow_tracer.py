"""Go strategy in the LSP auth-flow tracer.

Verifies per-route auth verdicts for Go: router/group middleware, inline
identity+refusal, and — the reason gopls is here — a handler whose auth is a
cross-file helper resolved by go-to-definition. A fake LSP client stands in for
gopls so the tests are deterministic.
"""

from __future__ import annotations

import pytest

from isitsecure.engine.code_analysis.lsp.auth_flow_tracer import AuthFlowTracer
from isitsecure.engine.code_analysis.protocols import RouteEntry


class _FakeRepo:
    clone_path = "/repo"
    file_index: dict = {}


class _FakeLSP:
    """Resolves one symbol name to a canned definition body."""
    def __init__(self, defs: dict[str, str]):
        self._defs = defs
        self.last_error = None

    async def get_definition(self, file_path, line, character):
        # The tracer follows _trace_definition_body which calls get_definition;
        # we short-circuit by returning a location the tracer then reads. To
        # keep it simple we monkeypatch _trace_definition_body instead.
        return None


def _tracer(defs=None):
    t = AuthFlowTracer(_FakeLSP(defs or {}), _FakeRepo())
    return t


def _route(pattern, methods, body="", auth=False, content=""):
    return RouteEntry(
        file_path="h.go", http_methods=methods, route_pattern=pattern,
        has_auth_check=auth, content=content or body, handler_source=body,
    )


@pytest.mark.asyncio
async def test_group_middleware_route_is_verified():
    t = _tracer()
    r = _route("/api/me", ["GET"], body="func me(){}", auth=True)
    res = await t._verify_go_route(r, r.content, "/repo/h.go")
    assert res.has_verified_auth is True
    assert res.middleware_chain == ["Use"]


@pytest.mark.asyncio
async def test_inline_identity_and_refusal_is_verified():
    body = ('func h(w http.ResponseWriter, r *http.Request){ '
            'if r.Header.Get("Authorization")=="" { '
            'http.Error(w,"no",http.StatusUnauthorized); return }; w.Write(x) }')
    t = _tracer()
    r = _route("/x", ["GET"], body=body, auth=False)
    res = await t._verify_go_route(r, r.content, "/repo/h.go")
    assert res.has_verified_auth is True
    assert res.trace_depth == 0


@pytest.mark.asyncio
async def test_unprotected_handler_is_not_verified():
    body = 'func h(w http.ResponseWriter, r *http.Request){ w.Write(x) }'
    t = _tracer()
    r = _route("/open", ["GET"], body=body, auth=False)
    res = await t._verify_go_route(r, r.content, "/repo/h.go")
    assert res.has_verified_auth is False


@pytest.mark.asyncio
async def test_cross_file_helper_resolved_via_lsp(monkeypatch):
    """The handler's only auth is a cross-file helper; go-to-definition returns
    a body with an auth terminal → verified (the gopls refinement)."""
    handler = 'func secret(w, r){ if !mustAuth(w,r) { return }; w.Write(x) }'
    content = handler + "\n// mustAuth lives in another file"
    helper_body = ('func mustAuth(w, r) bool { '
                   'if r.Header.Get("Authorization")=="" { return false }; return true }')

    t = _tracer()

    async def _fake_def(abs_path, line, char, depth=0, seen=frozenset()):
        return helper_body
    monkeypatch.setattr(t, "_trace_definition_body", _fake_def)

    r = _route("/secret", ["ANY"], body=handler, content=content, auth=False)
    res = await t._verify_go_route(r, r.content, "/repo/h.go")
    assert res.has_verified_auth is True
    assert res.middleware_chain == ["mustAuth"]
    assert res.trace_depth == 1


@pytest.mark.asyncio
async def test_helper_without_terminal_does_not_verify(monkeypatch):
    """A helper whose body has no auth terminal must NOT vouch for auth."""
    handler = 'func h(w, r){ doAuthThing(r); w.Write(x) }'
    t = _tracer()

    async def _fake_def(abs_path, line, char, depth=0, seen=frozenset()):
        return "func doAuthThing(r) { log.Println(\"hi\") }"  # no terminal
    monkeypatch.setattr(t, "_trace_definition_body", _fake_def)

    r = _route("/x", ["GET"], body=handler, content=handler, auth=False)
    res = await t._verify_go_route(r, r.content, "/repo/h.go")
    assert res.has_verified_auth is False


def test_go_auth_helper_calls_are_auth_named_only():
    t = _tracer()
    body = "requireAuth(r); validateSession(x); render(y); computeTotal(z)"
    names = t._go_auth_helper_calls(body)
    assert "requireAuth" in names
    assert "validateSession" in names
    assert "render" not in names
    assert "computeTotal" not in names
