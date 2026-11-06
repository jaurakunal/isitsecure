#!/usr/bin/env python3
"""Fast LIVE auth smoke — a 1-2 minute guard for the login layer.

The auth providers are unit-tested, but what unit tests cannot cover is the LIVE
reliability of a browser login against a real SPA — which is what silently
breaks after crawl/auth changes and is otherwise only noticed in a long
authenticated benchmark run. This drives ONLY the public auth providers against
a fresh Juice Shop (no LLM, no API key):

  1. REST LOGIN    — RestLoginAuthProvider must log in and return a token.
  2. BROWSER LOGIN — BrowserAuthProvider (Playwright) must log in through the
                     real Angular form and return a token.
  3. TOKEN VALID   — each token must actually authenticate (GET
                     /rest/user/whoami echoes the account), so a captured-but-
                     dead token (HTML shell, expired) is a FAIL, not a pass.

Not covered: the sibling fork's pentest self-signup provisioning check — this
repo has no pentest/provisioning path, so there is nothing public to drive.

Exit 0 = all pass; 1 = a check failed; 2 = infra/setup error (docker, app never
ready, Playwright not installed). Run it after ANY change to auth/crawl code.

    python benchmarks/auth_smoke.py            # brings up its own Juice Shop
    python benchmarks/auth_smoke.py --keep     # leave it running
    AUTH_SMOKE_URL=http://localhost:3000 python benchmarks/auth_smoke.py --no-up
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

PASS, FAIL, INFRA = "pass", "fail", "infra"

IMAGE = os.environ.get("AUTH_SMOKE_IMAGE", "bkimminich/juice-shop:v20.1.1")
CONTAINER = "auth_smoke_juice"
PORT = int(os.environ.get("AUTH_SMOKE_PORT", "3000"))
URL = os.environ.get("AUTH_SMOKE_URL", f"http://localhost:{PORT}")
READY_TIMEOUT = 300
EMAIL = "smoke@isitsecure.test"
PASSWORD = "Passw0rd!23"  # noqa: S105 — throwaway local test account


@dataclass
class CheckResult:
    name: str
    status: str   # PASS | FAIL | INFRA
    detail: str = ""


def exit_code(results: list[CheckResult]) -> int:
    """0 all pass, 2 any infra error (the app wasn't really tested), else 1 on fail."""
    if any(r.status == INFRA for r in results):
        return 2
    return 0 if all(r.status == PASS for r in results) else 1


def _run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)  # noqa: S603


def _wait_ready(url: str, timeout: int) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:  # noqa: S310 — local health check
                if r.status == 200:
                    return True
        except Exception:  # noqa: BLE001,S110 — not-up-yet is expected while polling
            pass
        time.sleep(3)
    return False


def _register(url: str, email: str, pw: str) -> int:
    """Pre-register the account via Juice Shop's REST API; returns the HTTP status."""
    body = json.dumps({
        "email": email, "password": pw, "passwordRepeat": pw,
        "securityQuestion": {"id": 1, "question": "q", "createdAt": "", "updatedAt": ""},
        "securityAnswer": "x",
    }).encode()
    req = urllib.request.Request(  # noqa: S310 — local target
        url.rstrip("/") + "/api/Users/", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:  # noqa: BLE001
        return 0


def whoami_email(url: str, token: str) -> str | None:
    """Email the app attributes to ``token`` (None if it isn't a live session)."""
    req = urllib.request.Request(  # noqa: S310 — local target
        url.rstrip("/") + "/rest/user/whoami",
        headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310
            return (json.loads(r.read()).get("user") or {}).get("email")
    except Exception:  # noqa: BLE001 — a dead token / HTML shell just means "not valid"
        return None


def _classify(exc: Exception) -> str:
    """Playwright/browser missing is an environment problem, not an auth regression."""
    text = str(exc)
    if isinstance(exc, ImportError) or "Executable doesn't exist" in text \
            or "playwright install" in text:
        return INFRA
    return FAIL


async def _check_provider(name: str, provider, creds, url: str) -> CheckResult:
    """Log in with one provider and confirm the token is live."""
    t0 = time.time()
    try:
        session = await provider.authenticate(creds)
    except Exception as exc:  # noqa: BLE001 — any failure is reported, not raised
        return CheckResult(f"{name} ({time.time() - t0:.0f}s)", _classify(exc),
                           f"login raised: {exc}")
    who = whoami_email(url, session.access_token)
    elapsed = f"{time.time() - t0:.0f}s"
    if not who:
        return CheckResult(f"{name} ({elapsed})", FAIL,
                           "token captured but /rest/user/whoami rejected it")
    if who.lower() != creds.email.lower():
        return CheckResult(f"{name} ({elapsed})", FAIL,
                           f"token belongs to {who!r}, expected {creds.email!r}")
    return CheckResult(f"{name} ({elapsed})", PASS, f"live session for {who}")


async def run_checks(url: str, email: str, pw: str) -> list[CheckResult]:
    """Drive the public auth providers against a live app."""
    from isitsecure.engine.auth.browser_auth import BrowserAuthProvider
    from isitsecure.engine.auth.protocols import AuthCredentials
    from isitsecure.engine.auth.rest_login_auth import RestLoginAuthProvider
    from isitsecure.engine.enums import AuthProvider

    rest = AuthCredentials(provider=AuthProvider.TOKEN, email=email, password=pw,
                           login_url=url.rstrip("/") + "/rest/user/login")
    browser = AuthCredentials(provider=AuthProvider.BROWSER, email=email, password=pw,
                              login_url=url.rstrip("/") + "/#/login")
    return [
        await _check_provider("REST login", RestLoginAuthProvider(url), rest, url),
        await _check_provider("browser login", BrowserAuthProvider(), browser, url),
    ]


def print_results(results: list[CheckResult]) -> None:
    print("\n================ AUTH SMOKE ================")
    for r in results:
        print(f"  [{r.status.upper():5}] {r.name}: {r.detail}")
    print("===========================================")
    print("RESULT:", {0: "PASS", 1: "FAIL", 2: "INFRA ERROR"}[exit_code(results)])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--no-up", action="store_true",
                    help="target an already-running app at AUTH_SMOKE_URL")
    ap.add_argument("--keep", action="store_true", help="do not tear the container down")
    args = ap.parse_args()

    brought_up = False
    if not args.no_up:
        if subprocess.run(["docker", "version"], capture_output=True).returncode != 0:  # noqa: S603,S607
            print("SETUP ERROR: docker unavailable")
            return 2
        _run(["docker", "rm", "-f", CONTAINER], timeout=60)
        print(f"bringing up {IMAGE} on :{PORT} ...")
        up = _run(["docker", "run", "-d", "--rm", "--name", CONTAINER, "-p", f"{PORT}:3000", IMAGE],
                  timeout=180)
        if up.returncode != 0:
            print(f"SETUP ERROR: bring-up failed: {(up.stderr or '')[-300:]}")
            return 2
        brought_up = True

    try:
        if not _wait_ready(URL + "/", READY_TIMEOUT):
            print("SETUP ERROR: app never became ready")
            return 2
        print(f"account pre-registered (status {_register(URL, EMAIL, PASSWORD)})")
        results = asyncio.run(run_checks(URL, EMAIL, PASSWORD))
    finally:
        if brought_up and not args.keep:
            _run(["docker", "rm", "-f", CONTAINER], timeout=60)

    print_results(results)
    return exit_code(results)


if __name__ == "__main__":
    sys.exit(main())
