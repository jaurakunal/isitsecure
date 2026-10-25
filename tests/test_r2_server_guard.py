"""R5: strict Host parsing, same-origin Origin rule, scan eviction and key clearing."""

import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from isitsecure.server import app as srv


@pytest.fixture
def client(monkeypatch):
    for env in (srv.ALLOWED_HOSTS_ENV, srv.BIND_HOST_ENV, "ISITSECURE_ALLOWED_ORIGINS"):
        monkeypatch.delenv(env, raising=False)
    srv.app.state.allowed_hosts = None
    yield TestClient(srv.app, base_url="http://localhost:3000")
    srv.app.state.allowed_hosts = None
    srv._scans.clear()


@pytest.mark.parametrize("host", [
    "evil.com:80@localhost", "localhost#@evil.com", "localhost?x", "localhost/x",
    "localhost\\x", "local host", "", "localhost:", "localhost:0",
    "localhost:65536", "localhost:abc", "localhost:-1", "user@localhost",
    "[::1", "::1",
])
def test_malformed_host_rejected_421(client, host):
    assert client.get("/api/health", headers={"Host": host}).status_code == 421


@pytest.mark.parametrize("host", ["localhost\t", "local\x01host", " ", "localhost\r\nX: y", "l\u00f6calhost"])
def test_split_host_rejects_whitespace_and_control(host):
    assert srv._split_host(host) is None


def test_split_host_accepts_valid_forms():
    assert srv._split_host("LocalHost:3000") == ("localhost", "3000")
    assert srv._split_host("[::1]:8080") == ("::1", "8080")
    assert srv._split_host("127.0.0.1") == ("127.0.0.1", "")


def test_duplicate_host_headers_rejected(client):
    r = client.get("/api/health", headers=[("Host", "localhost"), ("Host", "localhost")])
    assert r.status_code == 421
    r = client.get("/api/health", headers=[("Host", "evil.com"), ("Host", "localhost")])
    assert r.status_code == 421


def _post(client, origin):
    return client.post("/api/fix-all", json={"scan_id": "nope"},
                       headers={"Origin": origin}).status_code


@pytest.mark.parametrize("origin", [
    "http://[", "null", "http://localhost:4000", "http://127.0.0.1:3000",
    "https://localhost", "https://localhost:4000", "ftp://localhost:3000",
    "http://localhost:3000/x", "http://u@localhost:3000", "http://localhost:3000#f",
    "localhost:3000", "",
])
def test_origin_must_be_same_origin(client, origin):
    assert _post(client, origin) == 403


def test_same_origin_passes(client):
    assert _post(client, "http://localhost:3000") == 404  # reached the route
    assert _post(client, "HTTP://LOCALHOST:3000") == 404


def test_allowed_origins_env(client, monkeypatch):
    monkeypatch.setenv("ISITSECURE_ALLOWED_ORIGINS", "http://localhost:4000, https://ui.test")
    assert _post(client, "http://localhost:4000") == 404
    assert _post(client, "https://ui.test") == 404
    assert _post(client, "http://localhost:4001") == 403


def test_websocket_foreign_origin_rejected(client):
    for origin in ("http://evil.com", "http://localhost:4000", "null", "http://["):
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws", headers={"Origin": origin}):
                pass


def _scan(status, **kw):
    return {"status": status, "report": None, "events": [], **kw}


def test_finished_scans_evicted_beyond_bound():
    srv._scans.clear()
    for i in range(srv.MAX_RETAINED_SCANS + 20):
        srv._scans[f"s{i}"] = _scan("complete", report={"findings": []})
    srv._scans["running"] = _scan("running")
    srv._evict_scans()
    assert "running" in srv._scans
    finished = [k for k, v in srv._scans.items() if v["status"] != "running"]
    assert len(finished) == srv.MAX_RETAINED_SCANS
    assert "s0" not in srv._scans and f"s{srv.MAX_RETAINED_SCANS + 19}" in srv._scans
    srv._scans.clear()


def test_retained_scan_report_still_served(client):
    srv._scans["keep"] = _scan("complete", report={"findings": []}, llm_provider="none")
    assert client.get("/api/scan/keep/report").status_code == 200


async def test_key_cleared_when_scan_fails(monkeypatch):
    class Agent:
        async def scan(self, **kw):
            if False:
                yield None

    monkeypatch.setattr("isitsecure.engine.factory.create_deep_security_scan_agent",
                        lambda **kw: Agent())
    srv._scans["f1"] = _scan("pending", api_key="sk-secret", error=None)
    await srv._run_scan_background(
        "f1", srv.ScanRequest(target_url="http://x", llm_provider="none"))
    assert srv._scans["f1"]["status"] == "failed"
    assert srv._scans["f1"].get("api_key") is None
    srv._scans.clear()


def test_key_cleared_after_fix_all_finishes(client, monkeypatch):
    async def fake_job(job_id, report, provider, severities, **kw):
        pass

    monkeypatch.setattr(srv, "_run_fix_all_job", fake_job)
    srv._scans["k"] = _scan("complete", report={"findings": [{}]},
                            llm_provider="anthropic", api_key="sk-x")
    assert client.post("/api/fix-all", json={"scan_id": "k"}).status_code == 200
    for _ in range(50):
        if srv._scans["k"].get("api_key") is None:
            break
        time.sleep(0.05)
    assert srv._scans["k"].get("api_key") is None


def test_key_dropped_when_no_findings_to_fix():
    scan = _scan("complete", report={"findings": []}, api_key="sk-x")
    srv._settle_scan_key(scan)
    assert scan.get("api_key") is None
    scan = _scan("complete", report={"findings": [{}]}, api_key="sk-x")
    srv._settle_scan_key(scan)
    assert scan["api_key"] == "sk-x"
