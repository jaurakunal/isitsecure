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

import stability


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
    # Extra CLI flags for the scan. A mode we publish a recall number
    # for has to be reproducible with one command, same as the others.
    extra_args: list[str] = field(default_factory=list)
    expect: list[Expectation] = field(default_factory=list)   # recall
    forbid: list[Expectation] = field(default_factory=list)   # false positives
    ready_timeout: int = 180
    # Hard cap on the scan itself. This is a measurement budget, not a
    # statement about how long a scan should take: when it trips, the run
    # yields no report at all, so a target that outgrows it stops being
    # measured rather than scoring lower. Raised from 1800 when Juice Shop's
    # authenticated scan crossed it — the url-only leg finishes in a few
    # minutes, but the authenticated one probes every endpoint as two users.
    scan_timeout: int = 3600
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

# NodeGoat is unversioned upstream, so pin a commit for a reproducible benchmark
# (like Juice Shop is pinned to v20.1.1). Shallow-fetch exactly this commit.
NODEGOAT_COMMIT = "c5cb68a7084e4ae7dcc60e6a98768720a81841e8"
_NODEGOAT_UP = ["bash", "-c",
                "test -d benchmarks/_ext/NodeGoat || (mkdir -p benchmarks/_ext/NodeGoat && "
                "cd benchmarks/_ext/NodeGoat && git init -q && "
                "git remote add origin https://github.com/OWASP/NodeGoat && "
                f"git fetch --depth 1 origin {NODEGOAT_COMMIT} && git checkout -q FETCH_HEAD); "
                "cd benchmarks/_ext/NodeGoat && docker compose up -d"]
_NODEGOAT_DOWN = ["bash", "-c",
                  "cd benchmarks/_ext/NodeGoat 2>/dev/null && docker compose down -v || true"]


TARGETS: list[Target] = [
    Target(
        name="vampi-vulnerable",
        up_cmd=["docker", "run", "-d", "--name", "bench_vampi_vuln",
                "-e", "vulnerable=1", "-p", "5001:5000", "erev0s/vampi:latest"],
        url="http://localhost:5001",
        ready_url="http://localhost:5001/",
        down_cmd=["docker", "rm", "-f", "bench_vampi_vuln"],
        # VAmPI ships an empty database and seeds it from /createdb. Without
        # this the app answers HTTP 500 to every data route, so IDOR has
        # nothing to find — and /createdb is itself a discovered endpoint, so
        # a scan seeds the target by scanning it. Whether IDOR sees data then
        # depends on whether some scanner reached /createdb first, which made
        # the target's IDOR result a coin flip rather than a measurement.
        pre_scan=["bash", "-c",
                  "curl -s -o /dev/null http://localhost:5001/createdb || true"],

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
        # VAmPI ships an empty database and seeds it from /createdb. Without
        # this the app answers HTTP 500 to every data route, so IDOR has
        # nothing to find — and /createdb is itself a discovered endpoint, so
        # a scan seeds the target by scanning it. Whether IDOR sees data then
        # depends on whether some scanner reached /createdb first, which made
        # the target's IDOR result a coin flip rather than a measurement.
        pre_scan=["bash", "-c",
                  "curl -s -o /dev/null http://localhost:5002/createdb || true"],

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
        up_cmd=_NODEGOAT_UP,
        url="http://localhost:4000",
        ready_url="http://localhost:4000/",
        down_cmd=_NODEGOAT_DOWN,
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
        up_cmd=_NODEGOAT_UP,
        url="http://localhost:4000",
        ready_url="http://localhost:4000/",
        down_cmd=_NODEGOAT_DOWN,
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
        name="juiceshop-writes",
        up_cmd=["docker", "run", "-d", "--name", "bench_juiceshop",
                "-p", "3000:3000", "bkimminich/juice-shop:v20.1.1"],
        url="http://localhost:3000",
        ready_url="http://localhost:3000/",
        down_cmd=["docker", "rm", "-f", "bench_juiceshop"],
        ready_timeout=300,
        extra_args=["--probe-writes"],
        # Measured at 72m16s. The old 3600s default cut this off 12 minutes
        # short and yielded NO report at all -- a timeout is scored as an
        # error, not a lower recall, so too small a budget erases the whole
        # measurement. 3h leaves room for the injection scanner, which used
        # 39 of its 90-minute budget here and is free to use all of it.
        scan_timeout=10800,
        ground_truth="juiceshop",
        notes="OWASP Juice Shop with --probe-writes — the mutation surface. "
              "Writes to the target, so it needs a disposable container.",
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
        auth_provider="token",
        # App-specific login route lives HERE (benchmark config), not in the
        # shipped LOGIN_PROBE_PATHS — the tool auto-discovers generic paths and
        # takes an explicit endpoint via --login-url.
        extra_args=["--login-url", "http://localhost:3000/rest/user/login"],
        ground_truth="juiceshop",
        notes="OWASP Juice Shop AUTHENTICATED, two-user cross-user BOLA — adds the "
              "basket object-access challenges (the '~40% authenticated' number).",
    ),
    # --- Authenticated AND --probe-writes together: the only mode that reaches
    #     auth-gated mutation vulns like feedbackChallenge (Five-Star Feedback),
    #     a BOLA delete of another user's feedback — auth-required (401 anon)
    #     yet needing DELETE endpoints derived, which only --probe-writes does.
    Target(
        name="juiceshop-auth-writes",
        up_cmd=["docker", "run", "-d", "--name", "bench_juiceshop",
                "-p", "3000:3000", "bkimminich/juice-shop:v20.1.1"],
        url="http://localhost:3000",
        ready_url="http://localhost:3000/",
        down_cmd=["docker", "rm", "-f", "bench_juiceshop"],
        ready_timeout=300,
        scan_mode="authenticated",
        extra_args=["--probe-writes",
                    "--login-url", "http://localhost:3000/rest/user/login"],
        scan_timeout=10800,
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
        auth_provider="token",
        ground_truth="juiceshop",
        notes="OWASP Juice Shop AUTHENTICATED + --probe-writes — the combined "
              "mode that reaches auth-gated mutation vulns (feedbackChallenge "
              "BOLA delete). Writes to the target; slow.",
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


# When set, each target's raw report is kept here instead of discarded.
# The scorecard reports how many findings went unmatched but not WHICH --
# and an unmatched finding is either a real-but-undocumented vuln or a
# false positive, which is exactly the distinction you re-run a 30-minute
# scan to make. Keep the report and it is answerable without the re-run.
REPORT_DIR: str | None = None
# Suffix for kept reports under --repeat, so run N doesn't overwrite run N-1.
REPORT_TAG: str = ""


def scan(target: Target) -> list[dict] | None:
    """Run isitsecure and return its findings.

    Returns None if the scan ERRORED (non-parseable report) — so a crashed
    scan is not silently scored as a clean "found nothing" (recall 0/N).
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = f.name
    cmd = ["isitsecure", "scan", target.url, "--mode", target.scan_mode,
           "--llm", "none", "--output", "json", "-f", out]
    cmd += target.extra_args
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
        if REPORT_DIR:
            kept = os.path.join(REPORT_DIR, f"{target.name}{REPORT_TAG}.json")
            try:
                os.replace(out, kept)
                print(f"    report kept at {kept}")
            except OSError:
                pass
        else:
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
        t0 = time.time()
        findings = scan(target)
        if findings is None:
            return {"name": target.name, "error": "scan failed / no readable report"}
        if target.ground_truth:
            result = score_ground_truth(target, findings)
        else:
            result = score(findings, target)
            result["name"] = target.name
        # Extra keys feed --repeat's stability analysis; the scorecard ignores them.
        result["fingerprints"] = sorted(stability.fingerprint_set(findings))
        result["duration_s"] = time.time() - t0
        return result
    finally:
        if not keep:
            _run(target.down_cmd or ["true"])


def recall_counts(result: dict) -> tuple[int, int]:
    """(found, total) recall for either result shape (ground-truth or coarse)."""
    if result.get("scorecard"):
        rec = result["scorecard"]["recall"]
        return rec["found"], rec["in_scope"]
    hits = result.get("recall") or []
    return sum(1 for _, ok in hits if ok), len(hits)


def result_to_run(result: dict) -> stability.RunRecord:
    found, total = recall_counts(result)
    return stability.RunRecord(
        fingerprints=frozenset(result.get("fingerprints", [])),
        found=found, total=total, duration_s=result.get("duration_s", 0.0))


def run_repeated(target: Target, repeat: int, keep: bool,
                 runner=None) -> list[dict]:
    """Run one target ``repeat`` times, each on a fresh bring-up.

    ``repeat == 1`` is exactly the old single run (no report-name suffix).
    ``runner`` is injectable so the loop is testable without Docker.
    """
    global REPORT_TAG
    runner = runner or run_target
    results = []
    try:
        for i in range(1, repeat + 1):
            REPORT_TAG = f".run{i}" if repeat > 1 else ""
            if repeat > 1:
                print(f"\n--- {target.name}: run {i}/{repeat} ---")
            results.append(runner(target, keep))
    finally:
        REPORT_TAG = ""
    return results


def evaluate_repeat(name: str, results: list[dict],
                    baseline: dict | None) -> tuple[int, str, stability.StabilityReport | None]:
    """Stability verdict for one target's repeated runs (pure).

    Returns (exit_code, printable report, StabilityReport). Exit codes: 0 ok
    (or no baseline to gate on), 1 the stable set regressed vs the baseline,
    2 not verifiable: fewer than 2 runs produced a report, or any run errored
    (the stable set is then computed over the good runs only, and called out).
    """
    ok = [r for r in results if not r.get("error")]
    errored = len(results) - len(ok)
    if len(ok) < 2:
        # One good run has no "found in every run" meaning; don't pretend.
        return 2, (f"STABILITY — {name}: only {len(ok)} of {len(results)} run(s) "
                   f"produced a report; need >= 2 to assess stability"), None
    report = stability.compute_stability([result_to_run(r) for r in ok])
    cmp = None
    entry = (baseline or {}).get("targets", {}).get(name)
    if entry is not None:
        cmp = stability.compare_to_baseline(report, entry.get("stable", []))
    text = stability.format_report(name, report, cmp)
    if errored:
        text += f"\n  {errored} of {len(results)} run(s) errored and were excluded"
    sc = ok[0].get("scorecard")
    if entry is not None and entry.get("by_class") and sc:
        from score import class_deltas
        for r in class_deltas(sc, {"by_class": entry["by_class"]}):
            if r["delta"]:
                text += (f"\n  class {r['vuln_class']}: {r['prev_found']}/"
                         f"{r['prev_total']} -> {r['found']}/{r['total']} ({r['delta']:+d})")
    code = 1 if cmp is not None and cmp.regressed else 0
    return (2 if errored else code), text, report


def count_must_detect_regressions(all_runs: dict[str, list[dict]]) -> int:
    """MUST_DETECT misses summed over EVERY ok run (any run missing one fails)."""
    return sum(len(r.get("scorecard", {}).get("regression_failures", []))
               for runs in all_runs.values() for r in runs if not r.get("error"))


def final_exit_code(stability_rc: int, regressions: int, sast_rc: int,
                    go_sast_rc: int) -> int:
    """Combine every gate into one exit code, printing every failure.

    Nothing is short-circuited, so a stability failure can't hide a SAST one.
    Precedence: 2 (something couldn't be verified / bad run) beats 1 (a
    detection regression); otherwise 0.
    """
    if stability_rc:
        print("\n✗ stability check failed (see STABILITY above).")
    if regressions:
        print(f"\n✗ {regressions} regression failure(s) — a finding the scanner "
              f"reliably catches was dropped by the full scan. See ⚠ REGRESSION above.")
    if sast_rc:
        print("\n✗ SAST injection benchmark failed (recall < 100% or FP > 0).")
    if go_sast_rc:
        print("\n✗ Go SAST benchmark failed (class recall < 100%).")
    codes = [stability_rc, 1 if regressions else 0, sast_rc, go_sast_rc]
    return 2 if 2 in codes else (1 if any(codes) else 0)


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


# The SAST injection benchmark is not a Docker/DAST target — it scores a
# code-only scan of a local fixture tree (see sast_injection.py). It's exposed
# here as a pseudo-target so it runs from the same entrypoint (and by default).
SAST_INJECTION = "sast-injection"
# Go SAST recall against the real govwa app. Opt-in only (named or --all): it
# clones an external repo and wants the go/gopls toolchain, so it must not run
# in the default no-arg set (which stays offline-friendly).
GO_SAST = "go-sast"
_PSEUDO = {SAST_INJECTION, GO_SAST}


def resolve_selection(
    targets: list[str], all_flag: bool
) -> tuple[list[str], bool, bool, list[str]]:
    """Plan a run from the CLI args (pure — no Docker, no side effects).

    Returns (docker names, run sast-injection?, run go-sast?, unknown names).
    sast-injection runs when named, with --all, or in the default (no-arg) set.
    go-sast runs only when named or with --all (never in the default set).
    """
    valid = {t.name for t in TARGETS}
    want_sast = SAST_INJECTION in targets or all_flag or not targets
    want_go_sast = GO_SAST in targets or all_flag
    docker_names = [n for n in targets if n not in _PSEUDO]
    if docker_names:
        unknown = [n for n in docker_names if n not in valid]
        return [n for n in docker_names if n in valid], want_sast, want_go_sast, unknown
    if all_flag:
        return [t.name for t in TARGETS], want_sast, want_go_sast, []
    if targets:  # only pseudo-targets were requested
        return [], want_sast, want_go_sast, []
    return ["vampi-vulnerable", "vampi-secure"], want_sast, want_go_sast, []


def run_sast_injection() -> int:
    """Run the SAST injection benchmark; return 0 on full recall + 0 FP, else 1.

    Skips (returns 0) if the semgrep binary is absent — like the Docker targets
    can't run without Docker, this one can't run without semgrep.
    """
    import sast_injection as si

    print(f"\n=== {SAST_INJECTION} ===\n    code-only taint recall / FP on the "
          f"injection fixtures (no Docker; needs the semgrep binary)")
    if not si.semgrep_available():
        print("    SKIPPED — semgrep binary not found (pipx install semgrep).")
        return 0
    try:
        findings = si.run_scan()
    except Exception as e:  # noqa: BLE001 - surface, don't crash the whole suite
        print(f"    SAST injection scan failed: {e}")
        return 1
    r = si.score(findings)
    si.print_report(r)
    return 0 if si.passed(r) else 1


def run_go_sast() -> int:
    """Run the Go SAST benchmark (govwa); 0 on full class recall, else 1.

    Skips (returns 0) when its tools or the network are unavailable — like the
    Docker targets skip without Docker.
    """
    import go_sast as gs

    print(f"\n=== {GO_SAST} ===\n    code-only recall against the real govwa "
          f"app (clones a pinned commit; needs semgrep, and go/gopls for auth)")
    if not gs._have("isitsecure", "semgrep"):
        print("    SKIPPED — need isitsecure + semgrep on PATH.")
        return 0
    if not gs.ensure_clone():
        print("    SKIPPED — could not obtain govwa (git/network unavailable).")
        return 0
    try:
        findings = gs.run_scan()
    except Exception as e:  # noqa: BLE001 - surface, don't crash the whole suite
        print(f"    Go SAST scan failed: {e}")
        return 1
    r = gs.score(findings)
    gs.print_report(r)
    return 0 if gs.passed(r) else 1


def report_stability(all_runs: dict[str, list[dict]], baseline_path: str | None,
                     write: bool) -> int:
    """Print per-target stability; gate on / record the baseline. Returns exit code."""
    baseline = stability.load_baseline(baseline_path) if baseline_path else None
    rc = 0
    print("\n" + "=" * 64)
    for name, runs in all_runs.items():
        code, text, report = evaluate_repeat(name, runs, None if write else baseline)
        print(text)
        if write and report is not None and code == 0:
            ok = [r for r in runs if not r.get("error")]
            by_class = (ok[0].get("scorecard") or {}).get("by_class")
            stability.save_baseline(baseline_path, baseline, name,
                                    stability.baseline_entry(report, by_class))
            print(f"  baseline for {name} written to {baseline_path}")
        rc = max(rc, code)
    if rc == 1:
        print("\n✗ stable finding set regressed vs baseline (LOST/FLAKY above).")
    elif rc == 2:
        print("\n✗ no usable run for at least one target — nothing to verify.")
    return rc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="*", help="target names (default: vampi + sast-injection)")
    ap.add_argument("--keep", action="store_true", help="don't tear down containers")
    ap.add_argument("--all", action="store_true", help="include heavy compose targets")
    ap.add_argument("--report-dir", help="keep each target's raw JSON report here "
                                         "(so unmatched findings can be triaged)")
    ap.add_argument("--repeat", type=int, default=1, metavar="N",
                    help="run each Docker target N times and report the stable "
                         "(found-in-every-run) vs flaky finding sets (default 1 = "
                         "single run, unchanged)")
    ap.add_argument("--baseline", metavar="PATH",
                    help="with --repeat: JSON baseline of stable fingerprints; exit 1 "
                         "if any baseline-stable finding is no longer stable")
    ap.add_argument("--write-baseline", action="store_true",
                    help="with --repeat and --baseline: record this run's stable set "
                         "as the new baseline instead of gating on it")
    args = ap.parse_args()
    if args.repeat < 1:
        print("--repeat must be >= 1")
        return 2
    if (args.baseline or args.write_baseline) and args.repeat < 2:
        print("--baseline/--write-baseline need --repeat N (N >= 2)")
        return 2
    if args.write_baseline and not args.baseline:
        print("--write-baseline needs --baseline PATH")
        return 2

    global REPORT_DIR
    if args.report_dir:
        os.makedirs(args.report_dir, exist_ok=True)
        REPORT_DIR = args.report_dir

    by_name = {t.name: t for t in TARGETS}
    docker_names, want_sast, want_go_sast, unknown = resolve_selection(
        args.targets, args.all
    )
    if unknown:
        print(f"Unknown targets: {unknown}. "
              f"Available: {list(by_name) + [SAST_INJECTION, GO_SAST]}")
        return 2
    selected = [by_name[n] for n in docker_names]

    all_runs = {t.name: run_repeated(t, args.repeat, args.keep) for t in selected}
    results = [runs[0] for runs in all_runs.values()]
    print_scorecard(results)
    stability_rc = 0
    if args.repeat > 1:
        stability_rc = report_stability(all_runs, args.baseline, args.write_baseline)
    # Fail the run if any must-detect finding was dropped — a full-scan-path
    # regression (issue #1), distinct from a coverage gap.
    regressions = count_must_detect_regressions(all_runs)
    sast_rc = run_sast_injection() if want_sast else 0
    go_sast_rc = run_go_sast() if want_go_sast else 0
    return final_exit_code(stability_rc, regressions, sast_rc, go_sast_rc)


if __name__ == "__main__":
    sys.exit(main())
