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
    category: str | None = None
    title_contains: str | None = None

    def matches(self, finding: dict) -> bool:
        if self.scanner and finding.get("scanner_name") != self.scanner:
            return False
        if self.category and finding.get("category") != self.category:
            return False
        if self.title_contains and self.title_contains.lower() not in (
            finding.get("title") or ""
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
    down_cmd: list[str] = field(default_factory=list)
    notes: str = ""


# --- SQLi/IDOR/header signatures reused across targets ---
SQLI = dict(scanner="active_injection_scanner", title_contains="sql")
IDOR = dict(category="idor")
HEADERS = dict(category="missing_headers")


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
            Expectation("Injection", scanner="active_injection_scanner"),
        ],
        notes="Node/Express OWASP Top 10 — matches isitsecure's primary stack. "
              "Heavy (app + mongo); run on its own.",
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


def scan(url: str, mode: str) -> list[dict]:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out = f.name
    r = _run(["isitsecure", "scan", url, "--mode", mode, "--output", "json",
              "-f", out], timeout=1800)
    if r.returncode != 0:
        print(f"    scan exited {r.returncode}: {r.stderr[-300:]}")
    try:
        return json.load(open(out)).get("findings", [])
    except Exception:
        return []


def score(findings: list[dict], target: Target) -> dict:
    recall_hits = [
        (e.label, any(e.matches(f) for f in findings)) for e in target.expect
    ]
    fp_hits = [
        (e.label, sum(1 for f in findings if e.matches(f))) for e in target.forbid
    ]
    return {"recall": recall_hits, "false_positives": fp_hits,
            "total_findings": len(findings)}


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
        print("    app ready — scanning...")
        findings = scan(target.url, target.scan_mode)
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
