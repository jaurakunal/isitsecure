"""F2: MCP fix keeps CRLF/encoding and never writes; verify fails cleanly."""

from __future__ import annotations

from collections import OrderedDict

import pytest

from isitsecure import mcp_server
from isitsecure.engine.models import DeepScanReport
from tests._f2_support import StubLLM, make_finding


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch):
    monkeypatch.setattr(mcp_server, "_SCAN_CACHE", OrderedDict())


async def test_mcp_fix_tool_keeps_crlf_and_writes_nothing(tmp_path, monkeypatch):
    (tmp_path / "db.js").write_bytes(b"var q = BAD;\r\nvar r = 1;\r\n")
    f = make_finding("db.js")
    sid = mcp_server._cache_report(DeepScanReport(findings=[f]), repo_path=str(tmp_path))
    llm = StubLLM()
    monkeypatch.setattr(mcp_server, "_maybe_llm_client", lambda: llm)
    server = mcp_server.build_server()
    _, res = await server.call_tool("fix", {"scan_id": sid, "finding_id": f.id})
    # The host gets the file exactly as on disk (CRLF intact) and no LLM is called.
    assert res["file_content"] == "var q = BAD;\r\nvar r = 1;\r\n"
    assert res["applied"] is False
    assert llm.calls == 0
    assert (tmp_path / "db.js").read_bytes() == b"var q = BAD;\r\nvar r = 1;\r\n"


async def test_mcp_fix_tool_refuses_latin1_without_calling_the_llm(tmp_path, monkeypatch):
    raw = b"var s = 'caf\xe9'; BAD\n"
    (tmp_path / "l.js").write_bytes(raw)
    f = make_finding("l.js")
    sid = mcp_server._cache_report(DeepScanReport(findings=[f]), repo_path=str(tmp_path))
    llm = StubLLM()
    monkeypatch.setattr(mcp_server, "_maybe_llm_client", lambda: llm)
    server = mcp_server.build_server()
    with pytest.raises(Exception) as exc:
        await server.call_tool("fix", {"scan_id": sid, "finding_id": f.id})
    assert "UTF-8" in str(exc.value) and llm.calls == 0
    assert (tmp_path / "l.js").read_bytes() == raw


async def test_mcp_verify_malformed_report_is_a_clear_tool_error(tmp_path, monkeypatch):
    sid = mcp_server._cache_report(DeepScanReport(findings=[make_finding("a.py")]),
                                   repo_path=str(tmp_path))

    async def fake_rescan(path, mode):
        return DeepScanReport(findings=[])

    def broken(*a, **k):
        raise KeyError("severity")

    monkeypatch.setattr(mcp_server, "_run_scan_silent", fake_rescan)
    monkeypatch.setattr(mcp_server, "_verify_result", broken)
    server = mcp_server.build_server()
    with pytest.raises(Exception) as exc:
        await server.call_tool("verify", {"scan_id": sid})
    assert "malformed" in str(exc.value) and "Traceback" not in str(exc.value)
