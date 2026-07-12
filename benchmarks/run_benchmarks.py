#!/usr/bin/env python3
"""isitsecure benchmark harness.

Spins up deliberately-vulnerable apps in Docker, runs an isitsecure DAST
scan against each, and scores the findings against a known ground truth —
producing a repeatable recall + false-positive scorecard.

Ground truth is expressed per target as:
  - expect: vulnerability classes the app HAS (recall — did we find each?)
  - forbid: findings that must NOT appear (false positives — e.g. run against
    a "secure" build; any injection/IDOR hit is a false alarm)

Each expectation matches findings by scanner name, category, and/or a
substring of the title.

Usage:
  python benchmarks/run_benchmarks.py                 # run all targets
  python benchmarks/run_benchmarks.py vampi-vulnerable # run one target
  python benchmarks/run_benchmarks.py --keep           # don't tear down containers

Requires: Docker running, and `isitsecure` on PATH (pip install -e ".[all]").
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field


@dataclass
class Expectation:
    label: str
    scanner: str | None = None
    scanners: tuple[str, ...] | None = None    # any-of scanner match
    category: str | None = None
    title_contains: str | None = None
    endpoint_contains: str | None = None       # require the finding be on this route

    def matches(self, finding: dict) -> bool:
        if self.scanner and finding.get("scanner_name") != self.scanner:
            return False
        if self.scanners and finding.get("scanner_name") not in self.scanners:
            return False
        if self.category and finding.get("category") != self.category:
            return False
        if self.title_contains and self.title_contains.lower() not in (
            finding.get("title") or ""
        ).lower():
            return False
        if self.endpoint_contains and self.endpoint_contains.lower() not in (
            finding.get("endpoint_url") or ""
        ).lower():
            return False
        return True


@dataclass
class Target:
    name: str
    up_cmd: list[str]              # docker command to start it (detached)
    url: str                      # base URL to scan once ready
    ready_url: str                # URL to poll for readiness
    scan_mode: str = "url-only"
    expect: list[Expectation] = field(default_factory=list)   # recall
    forbid: list[Expectation] = field(default_factory=list)   # false positives
    ready_timeout: int = 180
    scan_timeout: int = 1800      # hard cap on the scan itself (seconds)
    down_cmd: list[str] = field(default_factory=list)
    notes: str = ""
    # Authenticated scanning (two-user cross-user IDOR uses -b variants; a
    # single credential + browser/token provider drives login-then-crawl).
    auth_email: str | None = None
    auth_password: str | None = None
    auth_email_b: str | None = None      # second user — enables cross-user BOLA/IDOR
    auth_password_b: str | None = None
    auth_provider: str | None = None
    pre_scan: list[str] | None = None   # shell cmd run after ready, before scan
    # When set (e.g. "juiceshop"), score with the per-challenge ground-truth
    # scorer (benchmarks/score.py) instead of the coarse expect/forbid model —
    # producing full recall over the app's documented, DAST-detectable vulns.
    ground_truth: str | None = None


# --- reusable signatures ---
# "SQL injection" (not bare "sql", which also matches "NoSQL injection").
SQLI = dict(scanner="active_injection_scanner", title_contains="SQL injection")
NOSQL = dict(scanner="active_injection_scanner", title_contains="NoSQL")
# IDOR now has a consistent category across the read + mutation paths.
IDOR = dict(category="idor")
HEADERS = dict(category="missing_headers")
# XSS lives under injection_risk; match by either XSS scanner (reflected/POST
# via xss_scanner, DOM via dom_xss_scanner) rather than a nonexistent category.
XSS = dict(scanners=("xss_scanner", "dom_xss_scanner"))
INJECTION = dict(scanner="active_injection_scanner")


TARGETS: list[Target] = [
    Target(
        name="vampi-vulnerable",
        up_cmd=["docker", "run", "-d", "--name", "bench_vampi_vuln",
                "-e", "vulnerable=1", "-p", "5001:5000", "erev0s/vampi:latest"],
        url="http://localhost:5001",
        ready_url="http://localhost:5001/",
        down_cmd=["docker", "rm", "-f", "bench_vampi_vuln"],
        expect=[
            Expectation("SQL injection (OWASP API8/Injection)", **SQLI),
            Expectation("Broken object-level auth / IDOR", **IDOR),
            Expectation("Missing security headers", **HEADERS),
        ],
        notes="Flask REST API, OWASP API Top 10. vulnerable=1 build.",
    ),
    Target(
        name="vampi-secure",
        up_cmd=["docker", "run", "-d", "--name", "bench_vampi_secure",
                "-e", "vulnerable=0", "-p", "5002:5000", "erev0s/vampi:latest"],
        url="http://localhost:5002",
        ready_url="http://localhost:5002/",
        down_cmd=["docker", "rm", "-f", "bench_vampi_secure"],
        # Secure build: injection/IDOR findings would be FALSE POSITIVES.
        forbid=[
            Expectation("SQL injection (should be absent)", **SQLI),
            Expectation("IDOR (should be absent)", **IDOR),
        ],
        notes="Same app, vulnerable=0 — measures the false-positive rate.",
    ),
    # --- Heavier targets: brought up from upstream's own compose (self-
    #     contained via a shallow clone), so we track their real setup. ---
    Target(
        name="nodegoat",
        up_cmd=["bash", "-c",
                "test -d benchmarks/_ext/NodeGoat || git clone --depth 1 "
                "https://github.com/OWASP/NodeGoat benchmarks/_ext/NodeGoat; "
                "cd benchmarks/_ext/NodeGoat && docker compose up -d"],
        url="http://localhost:4000",
        ready_url="http://localhost:4000/",
        down_cmd=["bash", "-c",
                  "cd benchmarks/_ext/NodeGoat 2>/dev/null && docker compose down -v || true"],
        ready_timeout=300,
        expect=[
            Expectation("Missing security headers", **HEADERS),
            Expectation("Injection", **INJECTION),
        ],
        notes="Node/Express OWASP Top 10 — matches isitsecure's primary stack. "
              "Heavy (app + mongo); run on its own.",
    ),
    Target(
        name="nodegoat-auth",
        up_cmd=["bash", "-c",
                "test -d benchmarks/_ext/NodeGoat || git clone --depth 1 "
                "https://github.com/OWASP/NodeGoat benchmarks/_ext/NodeGoat; "
                "cd benchmarks/_ext/NodeGoat && docker compose up -d"],
        url="http://localhost:4000",
        ready_url="http://localhost:4000/",
        down_cmd=["bash", "-c",
                  "cd benchmarks/_ext/NodeGoat 2>/dev/null && docker compose down -v || true"],
        ready_timeout=300,
        scan_mode="authenticated",
        # Register a user so the browser-login crawl can authenticate.
        pre_scan=["bash", "-c",
                  "curl -s -X POST http://localhost:4000/signup "
                  "-H 'Content-Type: application/x-www-form-urlencoded' "
                  "-d 'userName=tester&firstName=T&lastName=U"
                  "&password=Password1%21&verify=Password1%21&email=t@u.com' "
                  "-o /dev/null || true"],
        auth_email="tester",
        auth_password="Password1!",
        auth_provider="browser",
        expect=[
            Expectation("Missing security headers", **HEADERS),
            Expectation("Injection", **INJECTION),
            Expectation("Cross-site scripting", **XSS),
        ],
        notes="NodeGoat AUTHENTICATED (browser login, userName field) — recall "
              "on the server-rendered form surface behind login.",
    ),
    Target(
        name="crapi",
        up_cmd=["bash", "-c",
                "test -d benchmarks/_ext/crAPI || git clone --depth 1 "
                "https://github.com/OWASP/crAPI benchmarks/_ext/crAPI; "
                "cd benchmarks/_ext/crAPI/deploy/docker && docker compose "
                "--profile prod up -d"],
        url="http://localhost:8888",
        ready_url="http://localhost:8888/",
        down_cmd=["bash", "-c",
                  "cd benchmarks/_ext/crAPI/deploy/docker 2>/dev/null && "
                  "docker compose --profile prod down -v || true"],
        ready_timeout=600,
        expect=[
            Expectation("Broken object-level auth / IDOR", **IDOR),
            Expectation("Missing security headers", **HEADERS),
        ],
        notes="OWASP crAPI — API Top 10, microservices. Very heavy (~several GB, "
              "long startup).",
    ),
    # --- OWASP Juice Shop: the headline benchmark. Scored per-challenge against
    #     the app's own /api/Challenges ground truth (45 DAST-detectable of 113),
    #     so the recall number in RESULTS.md is reproducible with one command. ---
    Target(
        name="juiceshop",
        up_cmd=["docker", "run", "-d", "--name", "bench_juiceshop",
                "-p", "3000:3000", "bkimminich/juice-shop:v20.1.1"],
        url="http://localhost:3000",
        ready_url="http://localhost:3000/",
        down_cmd=["docker", "rm", "-f", "bench_juiceshop"],
        ready_timeout=300,
        ground_truth="juiceshop",
        notes="OWASP Juice Shop — url-only recall over the DAST-detectable subset "
              "(the '36% url-only' headline number).",
    ),
    Target(
        name="juiceshop-auth",
        up_cmd=["docker", "run", "-d", "--name", "bench_juiceshop",
                "-p", "3000:3000", "bkimminich/juice-shop:v20.1.1"],
        url="http://localhost:3000",
        ready_url="http://localhost:3000/",
        down_cmd=["docker", "rm", "-f", "bench_juiceshop"],
        ready_timeout=300,
        scan_mode="authenticated",
        # Register TWO users so the scanner can test cross-user object access
        # (BOLA): log in as A, harvest owned resource ids, then verify user B
        # (a different identity) can reach them while anon cannot. This is what
        # surfaces Juice Shop's basket BOLA — the delta over url-only.
        pre_scan=["bash", "-c",
                  "for u in bencha benchb; do "
                  "curl -s -X POST http://localhost:3000/api/Users "
                  "-H 'Content-Type: application/json' "
                  "-d \"{\\\"email\\\":\\\"$u@isitsecure.test\\\","
                  "\\\"password\\\":\\\"Passw0rd!23\\\","
                  "\\\"passwordRepeat\\\":\\\"Passw0rd!23\\\"}\" "
                  "-o /dev/null; done || true"],
        auth_email="bencha@isitsecure.test",
        auth_password="Passw0rd!23",
        auth_email_b="benchb@isitsecure.test",
        auth_password_b="Passw0rd!23",
        auth_provider="token",   # plain REST login (/rest/user/login)
        ground_truth="juiceshop",
        notes="OWASP Juice Shop AUTHENTICATED, two-user cross-user BOLA — adds the "
              "basket object-access challenges (the '~40% authenticated' number).",
    ),
]


def _run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def wait_ready(url: str, timeout: int) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=5)
            return True
        except Exception:
            time.sleep(3)
    return False


def scan(target: Target) -> list[dict] | None:
    """Run isitsecure and return its findings.

    Returns None if the scan ERRORED (non-parseable report) — so a crashed
    scan is not silently scored as a clean "found nothing" (recall 0/N).
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = f.name
    cmd = ["isitsecure", "scan", target.url, "--mode", target.scan_mode,
           "--llm", "none", "--output", "json", "-f", out]
    if target.auth_email and target.auth_password:
        cmd += ["--auth-email", target.auth_email,
                "--auth-password", target.auth_password]
        if target.auth_provider:
            cmd += ["--auth-provider", target.auth_provider]
        if target.auth_email_b and target.auth_password_b:
            cmd += ["--auth-email-b", target.auth_email_b,
                    "--auth-password-b", target.auth_password_b]
    try:
        try:
            r = _run(cmd, timeout=target.scan_timeout)
        except subprocess.TimeoutExpired:
            # A scan that blows its time budget must be recorded as an error,
            # not crash the whole harness (and not be scored as "found nothing").
            print(f"    scan exceeded {target.scan_timeout}s time budget — no report")
            return None
        try:
            data = json.load(open(out))
        except Exception:
            print(f"    scan produced no readable report (exit {r.returncode}): "
                  f"{(r.stderr or '')[-300:]}")
            return None
        return data.get("findings", [])
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass


def score(findings: list[dict], target: Target) -> dict:
    recall_hits = [
        (e.label, any(e.matches(f) for f in findings)) for e in target.expect
    ]
    fp_hits = [
        (e.label, sum(1 for f in findings if e.matches(f))) for e in target.forbid
    ]
    return {"recall": recall_hits, "false_positives": fp_hits,
            "total_findings": len(findings)}


def score_ground_truth(target: Target, findings: list[dict]) -> dict:
    """Score findings against a per-challenge ground truth (benchmarks/score.py).

    Reuses the full scorer so the harness produces the same recall/precision/gap
    breakdown as running score.py by hand — just automated end to end.
    """
    from score import score as gt_score
    from ground_truth import juiceshop

    builders = {"juiceshop": juiceshop.build_ground_truth}
    gt = builders[target.ground_truth]()
    return {"name": target.name, "total_findings": len(findings),
            "ground_truth": target.ground_truth,
            "scorecard": gt_score(findings, gt)}


def run_target(target: Target, keep: bool) -> dict:
    print(f"\n=== {target.name} ===\n    {target.notes}")
    _run(target.down_cmd or ["true"])  # clean any prior instance
    print(f"    starting: {' '.join(target.up_cmd[:6])} ...")
    up = _run(target.up_cmd, timeout=600)
    if up.returncode != 0:
        print(f"    FAILED to start: {up.stderr[-300:]}")
        return {"name": target.name, "error": up.stderr[-300:]}
    try:
        if not wait_ready(target.ready_url, target.ready_timeout):
            print("    app never became ready — skipping")
            return {"name": target.name, "error": "not ready"}
        if target.pre_scan:
            print("    seeding (pre-scan)...")
            _run(target.pre_scan, timeout=120)
        print(f"    app ready — scanning ({target.scan_mode})...")
        findings = scan(target)
        if findings is None:
            return {"name": target.name, "error": "scan failed / no readable report"}
        if target.ground_truth:
            return score_ground_truth(target, findings)
        result = score(findings, target)
        result["name"] = target.name
        return result
    finally:
        if not keep:
            _run(target.down_cmd or ["true"])


def print_scorecard(results: list[dict]) -> None:
    print("\n" + "=" * 64)
    print("BENCHMARK SCORECARD")
    print("=" * 64)
    for r in results:
        # Per-challenge ground-truth targets get the full scorecard (recall %,
        # by-class, gap list) from score.py rather than the coarse breakdown.
        if r.get("scorecard"):
            from score import print_report
            print_report(r["name"], r["scorecard"])
            continue
        print(f"\n{r['name']}  ({r.get('total_findings', 0)} findings)")
        if r.get("error"):
            print(f"  ERROR: {r['error']}")
            continue
        if r.get("recall"):
            hit = sum(1 for _, ok in r["recall"] if ok)
            print(f"  Recall: {hit}/{len(r['recall'])}")
            for label, ok in r["recall"]:
                print(f"    [{'x' if ok else ' '}] {label}")
        if r.get("false_positives"):
            total_fp = sum(n for _, n in r["false_positives"])
            print(f"  False positives: {total_fp} (want 0)")
            for label, n in r["false_positives"]:
                print(f"    {n:>2}  {label}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="*", help="target names (default: vampi both)")
    ap.add_argument("--keep", action="store_true", help="don't tear down containers")
    ap.add_argument("--all", action="store_true", help="include heavy compose targets")
    args = ap.parse_args()

    by_name = {t.name: t for t in TARGETS}
    if args.targets:
        selected = [by_name[n] for n in args.targets if n in by_name]
        missing = [n for n in args.targets if n not in by_name]
        if missing:
            print(f"Unknown targets: {missing}. Available: {list(by_name)}")
            return 2
    elif args.all:
        selected = TARGETS
    else:
        selected = [by_name["vampi-vulnerable"], by_name["vampi-secure"]]

    results = [run_target(t, args.keep) for t in selected]
    print_scorecard(results)
    # Fail the run if any must-detect finding was dropped — a full-scan-path
    # regression (issue #1), distinct from a coverage gap.
    regressions = sum(
        len(r.get("scorecard", {}).get("regression_failures", []))
        for r in results
    )
    if regressions:
        print(f"\n✗ {regressions} regression failure(s) — a finding the scanner "
              f"reliably catches was dropped by the full scan. See ⚠ REGRESSION above.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
