#!/usr/bin/env python3
"""Go SAST benchmark — recall against a real vulnerable Go app (govwa).

Unlike ``sast_injection.py`` (a curated fixture tree with per-line ``// EXPECT``
markers), this scores a code-only scan of a *real* intentionally-vulnerable app —
`govwa <https://github.com/0c34/govwa>`_ (Go Vulnerable Web Application) — pinned
to a commit so the ground truth doesn't drift. It exercises the whole Go SAST
path together: the injection taint pack, the route mapper (middleware-wrapped
handlers), route/auth analysis, and OSV dependency scanning.

Ground truth is CLASS-LEVEL, not per-line: govwa is documented to contain SQLi,
XSS, IDOR, and it ships an old gin (CVEs) plus unauthenticated setup routes. We
assert the scan surfaces each class at least once — deliberately NOT pinned to
line numbers or govwa-internal symbols, so the engine stays app-agnostic and the
benchmark survives cosmetic upstream edits.

Usage:
  python benchmarks/go_sast.py                 # clone (pinned) + scan + score
  python benchmarks/go_sast.py findings.json   # score an existing scan JSON

Requires (scan path): ``isitsecure`` + the ``semgrep`` binary, ``git``, and — for
the route/auth half — the ``go`` toolchain + ``gopls`` on PATH. Missing tools
SKIP (exit 0) rather than fail, so CI without them is not blocked.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO_URL = "https://github.com/0c34/govwa"
# Pinned so ground truth can't drift (2025-02-20).
PIN = "4058f79f31eeb4a36d8f1e64bba1f0c899646e6f"
CLONE_DIR = pathlib.Path(__file__).parent / "_ext" / "govwa"

# Class-level ground truth: (label, predicate over a finding dict).
# Each MUST be satisfied by at least one finding. Kept to category + broad
# keywords so it checks capability, not exact wording.
EXPECTED = {
    "sqli": lambda f: _is(f, "injection") and _kw(f, "sql"),
    "xss": lambda f: _is(f, "injection") and _kw(f, "xss", "cross-site", "template.html"),
    "vulnerable-dependency": lambda f: _cat(f) in ("dependency_vuln", "vulnerable_dependency")
    or _kw(f, "vulnerable dependency"),
    "missing-auth": lambda f: _cat(f) == "auth_weakness" and _kw(f, "auth"),
}


def _cat(f: dict) -> str:
    c = f.get("category", "")
    return c.get("value", "") if isinstance(c, dict) else str(c)


def _text(f: dict) -> str:
    return f"{f.get('title', '')} {f.get('description', '')}".lower()


def _kw(f: dict, *words: str) -> bool:
    t = _text(f)
    return any(w in t for w in words)


def _is(f: dict, cat_substr: str) -> bool:
    return cat_substr in _cat(f).lower()


def score(findings: list[dict]) -> dict:
    by_class = {}
    for label, pred in EXPECTED.items():
        hits = [f for f in findings if pred(f)]
        by_class[label] = {"found": len(hits), "detected": bool(hits)}
    found = sum(1 for v in by_class.values() if v["detected"])
    return {
        "by_class": by_class,
        "recall": {"found": found, "total": len(EXPECTED)},
        "total_findings": len(findings),
    }


def passed(result: dict) -> bool:
    return result["recall"]["found"] == result["recall"]["total"]


def _have(*bins: str) -> bool:
    return all(shutil.which(b) for b in bins)


def ensure_clone() -> bool:
    """Clone govwa at the pinned commit. Returns False if git/network is
    unavailable (the benchmark then SKIPs rather than fails)."""
    if (CLONE_DIR / "go.mod").exists():
        return True
    if not shutil.which("git"):
        return False
    CLONE_DIR.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(["git", "clone", REPO_URL, str(CLONE_DIR)],  # noqa: S603,S607
                       check=True, timeout=180, capture_output=True)
        subprocess.run(["git", "-C", str(CLONE_DIR), "checkout", PIN],  # noqa: S603,S607
                       check=True, timeout=60, capture_output=True)
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"    clone failed ({exc}) — skipping")
        shutil.rmtree(CLONE_DIR, ignore_errors=True)
        return False


def run_scan() -> list[dict]:
    out = tempfile.NamedTemporaryFile("r", suffix=".json", delete=False).name
    cmd = ["isitsecure", "scan", "-r", f"file://{CLONE_DIR.resolve()}",
           "--mode", "code-only", "--llm", "none", "--output", "json", "-f", out]
    print(f"$ {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, timeout=600)  # noqa: S603
        data = json.loads(pathlib.Path(out).read_text())
        return data.get("findings", []) if isinstance(data, dict) else data
    finally:
        pathlib.Path(out).unlink(missing_ok=True)


def print_report(r: dict) -> None:
    rec = r["recall"]
    pct = (100 * rec["found"] / rec["total"]) if rec["total"] else 0
    print("=" * 60)
    print("GO SAST BENCHMARK — govwa class-level recall")
    print("=" * 60)
    print(f"\nClass recall:  {rec['found']}/{rec['total']}  ({pct:.0f}%)")
    print(f"Total findings: {r['total_findings']}")
    print("\nBy class (detected? / count):")
    for cls, v in r["by_class"].items():
        mark = "x" if v["detected"] else " "
        print(f"  [{mark}] {cls:22} {v['found']}")


def main() -> int:
    if len(sys.argv) == 2:
        data = json.loads(pathlib.Path(sys.argv[1]).read_text())
        findings = data.get("findings", data) if isinstance(data, dict) else data
    else:
        if not _have("isitsecure", "semgrep"):
            print("SKIPPED — need `isitsecure` and `semgrep` on PATH.")
            return 0
        if not _have("go", "gopls"):
            print("NOTE — `go`/`gopls` not on PATH; route/auth half is degraded "
                  "(injection + dependency recall still scored).")
        if not ensure_clone():
            print("SKIPPED — could not obtain govwa (git/network unavailable).")
            return 0
        findings = run_scan()
    result = score(findings)
    print_report(result)
    ok = passed(result)
    print(f"\n{'PASS' if ok else 'FAIL'} — class recall "
          f"{result['recall']['found']}/{result['recall']['total']}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
