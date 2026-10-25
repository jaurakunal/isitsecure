"""Host/Origin allow-list and scan-failure handling for the web server."""

import pytest
from fastapi.testclient import TestClient

from isitsecure.server import app as srv


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv(srv.ALLOWED_HOSTS_ENV, raising=False)
    monkeypatch.delenv(srv.BIND_HOST_ENV, raising=False)
    srv.app.state.allowed_hosts = None
    yield TestClient(srv.app, base_url="http://localhost:3000")
    srv.app.state.allowed_hosts = None
    srv._scans.clear()


@pytest.mark.parametrize("host", [
    "localhost", "localhost:3000", "127.0.0.1:8080", "[::1]:3000", "LOCALHOST",
])
def test_loopback_hosts_allowed(client, host):
    assert client.get("/api/health", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize("host", [
    "attacker.example:3000", "evil.com", "localhost.evil.com", "127.0.0.1.evil.com",
])
def test_foreign_host_gets_421_everywhere(client, host):
    for path in ("/api/health", "/", "/api/scan/x/report"):
        assert client.get(path, headers={"Host": host}).status_code == 421


def test_env_extends_allow_list(client, monkeypatch):
    monkeypatch.setenv(srv.ALLOWED_HOSTS_ENV, "scan.internal, other.test")
    assert client.get("/api/health", headers={"Host": "scan.internal:443"}).status_code == 200
    assert client.get("/api/health", headers={"Host": "evil.com"}).status_code == 421


def test_bind_host_allowed_but_wildcard_is_not(client, monkeypatch):
    monkeypatch.setenv(srv.BIND_HOST_ENV, "10.1.2.3")
    assert client.get("/api/health", headers={"Host": "10.1.2.3:3000"}).status_code == 200
    monkeypatch.setenv(srv.BIND_HOST_ENV, "0.0.0.0")
    assert client.get("/api/health", headers={"Host": "0.0.0.0:3000"}).status_code == 421


def test_app_state_override(client):
    srv.app.state.allowed_hosts = ["only.test"]
    assert client.get("/api/health", headers={"Host": "only.test"}).status_code == 200
    assert client.get("/api/health", headers={"Host": "localhost"}).status_code == 421


def test_foreign_origin_blocked_on_state_changing(client):
    for origin in ("http://evil.com", "null"):
        r = client.post("/api/fix-all", json={"scan_id": "nope"},
                        headers={"Origin": origin})
        assert r.status_code == 403


def test_loopback_origin_and_no_origin_pass(client):
    for headers in ({"Origin": "http://localhost:3000"}, {}):
        r = client.post("/api/fix-all", json={"scan_id": "nope"}, headers=headers)
        assert r.status_code == 404  # reached the route


def test_foreign_origin_on_get_not_blocked(client):
    assert client.get("/api/health", headers={"Origin": "http://evil.com"}).status_code == 200


def test_failed_scan_reports_failure_not_202(client):
    srv._scans["abc"] = {"status": "failed", "report": None, "events": [],
                         "error": "boom", "llm_provider": "none"}
    for path in ("/api/scan/abc/report", "/api/scan/abc/report.html"):
        r = client.get(path)
        assert r.status_code == 500 and "boom" in r.json()["detail"]
    srv._scans["run"] = {"status": "running", "report": None, "events": []}
    assert client.get("/api/scan/run/report").status_code == 202


async def test_scan_without_report_marked_failed(monkeypatch):
    class Agent:
        async def scan(self, **kw):
            if False:
                yield None

    monkeypatch.setattr("isitsecure.engine.factory.create_deep_security_scan_agent",
                        lambda **kw: Agent())
    srv._scans["s1"] = {"status": "pending", "report": None, "events": [], "error": None}
    await srv._run_scan_background(
        "s1", srv.ScanRequest(target_url="http://x", llm_provider="none"))
    assert srv._scans["s1"]["status"] == "failed"
    assert srv._scans["s1"]["error"]
    srv._scans.clear()


def test_fix_all_uses_key_from_scan_request(client, monkeypatch):
    captured = {}

    async def fake_job(job_id, report, provider, severities, **kw):
        captured.update(kw)

    monkeypatch.setattr(srv, "_run_fix_all_job", fake_job)
    srv._scans["k1"] = {"status": "complete", "report": {"findings": []},
                        "events": [], "llm_provider": "anthropic",
                        "api_key": "sk-from-scan"}
    assert client.post("/api/fix-all", json={"scan_id": "k1"}).status_code == 200
    assert captured["api_key"] == "sk-from-scan"


async def test_run_fix_all_prefers_supplied_key(monkeypatch):
    from isitsecure.server import fix_service

    seen = {}
    monkeypatch.setattr(fix_service, "load_api_key", lambda p: None)
    monkeypatch.setattr("isitsecure.llm.adapters.create_llm_client",
                        lambda provider, key, **kw: seen.setdefault("key", key))

    async def emit(e):
        pass

    res = await fix_service.run_fix_all(report={"findings": []}, llm_provider="anthropic",
                                        emit=emit, api_key="sk-req")
    assert seen["key"] == "sk-req" and res["mode"] == "none"
