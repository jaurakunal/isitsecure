"""Real-Chromium tests for the DOM XSS sink hooks (skipped without Playwright).

Serves local pages from 127.0.0.1 only. Guards the two regressions that made the
scanner either silent (hook script never invoked) or noisy (a canary that merely
appeared after escaping counted as confirmed).
"""

from __future__ import annotations

import asyncio
import http.server
import threading

import pytest

from isitsecure.engine.constants import DOMXSSConfig
from isitsecure.engine.scanners import dom_xss_scanner as mod
from isitsecure.engine.scanners.dom_xss_scanner import DOMXSSScanner

pytestmark = pytest.mark.skipif(
    mod.async_playwright is None, reason="playwright not installed"
)

_PAGES = {
    "/innerhtml": "var q=new URLSearchParams(location.search).get('q');"
                  "if(q)document.getElementById('o').innerHTML=q;",
    "/docwrite": "var h=decodeURIComponent(location.hash.slice(1));"
                 "if(h)document.write('<p>'+h+'</p>');",
    "/eval": "var q=new URLSearchParams(location.search).get('q');"
             "if(q){try{eval('var x=\"'+q+'\"')}catch(e){}}",
    "/escaped": "var q=new URLSearchParams(location.search).get('q');"
                "if(q){var t=document.createElement('div');t.textContent=q;"
                "document.getElementById('o').innerHTML=t.innerHTML;}",
    "/urlencoded": "var q=new URLSearchParams(location.search).get('q');"
                   "if(q)document.getElementById('o').innerHTML="
                   "encodeURIComponent(q);",
    "/textcontent": "var q=new URLSearchParams(location.search).get('q');"
                    "if(q)document.getElementById('o').textContent=q;",
}


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0].split("#")[0]
        script = _PAGES.get(path)
        if script is None:
            self.send_response(404)
            self.end_headers()
            return
        body = (
            f"<html><body><div id=o></div><script>{script}</script></body></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence
        pass


@pytest.fixture(scope="module")
def base_url():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture(scope="module")
def findings(base_url):
    # Keep the browser run short: one query param name, short settle waits.
    mp = pytest.MonkeyPatch()
    mp.setattr(DOMXSSConfig, "INJECTION_PARAMS", ("q",))
    mp.setattr(DOMXSSConfig, "POST_INJECT_WAIT_SECONDS", 0.2)
    mp.setattr(DOMXSSConfig, "NETWORK_IDLE_TIMEOUT_MS", 500)
    try:
        res = asyncio.run(
            DOMXSSScanner().scan([f"{base_url}{p}" for p in _PAGES])
        )
    finally:
        mp.undo()
    # scan() swallows launch errors and returns []; distinguish "no Chromium"
    # from "nothing found" so an unlaunchable environment skips, not passes/fails.
    if not res:
        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as pw:
                pw.chromium.launch().close()
        except Exception as exc:  # pragma: no cover
            pytest.skip(f"chromium unavailable: {exc}")
    return {f.endpoint_url.rsplit("/", 1)[1]: f for f in res}


@pytest.mark.parametrize(
    "page,sink",
    [("innerhtml", "innerHTML"), ("docwrite", "document.write"), ("eval", "eval")],
)
def test_real_sink_is_found(findings, page, sink):
    """POSITIVE CONTROL: genuine unescaped flows are still confirmed."""
    assert page in findings, f"{page} not detected"
    assert sink in findings[page].title


@pytest.mark.parametrize("page", ["escaped", "urlencoded", "textcontent"])
def test_escaped_or_safe_flow_not_confirmed(findings, page):
    assert page not in findings
