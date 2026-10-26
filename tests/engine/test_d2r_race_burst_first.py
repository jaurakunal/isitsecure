"""Race scanner: the control replay is sent AFTER the burst (single-use resources)."""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.enums import AuthProvider, SeverityLevel
from isitsecure.engine.models import InterceptedRequest
from isitsecure.engine.scanners.race_condition_scanner import RaceConditionScanner


def _server(single_use: bool):
    state = {"used": False}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(n)
            if single_use:
                already = state["used"]  # check
                time.sleep(0.15)  # window between check and act
                if already:
                    self.send_response(409)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                state["used"] = True  # act
            self.send_response(201)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


async def _run(srv):
    url = f"http://127.0.0.1:{srv.server_address[1]}/api/redeem"
    req = InterceptedRequest(
        url=url, method="POST", response_status=201,
        request_body='{"code":"X"}', request_headers={},
    )
    session = AuthSession(user_id="u", access_token="t", provider=AuthProvider.SUPABASE)
    return await RaceConditionScanner().scan([req], session)


@pytest.mark.asyncio
async def test_single_use_check_then_act_is_high():
    srv = _server(single_use=True)
    try:
        findings = await _run(srv)
    finally:
        srv.shutdown()
    race = [f for f in findings if "race condition" in f.title.lower()]
    assert race and race[0].severity == SeverityLevel.HIGH
    assert race[0].confidence == pytest.approx(0.80)


@pytest.mark.asyncio
async def test_idempotent_endpoint_is_info_only():
    srv = _server(single_use=False)
    try:
        findings = await _run(srv)
    finally:
        srv.shutdown()
    assert not [f for f in findings if f.severity == SeverityLevel.HIGH]
    assert [f for f in findings if f.severity == SeverityLevel.INFO]
