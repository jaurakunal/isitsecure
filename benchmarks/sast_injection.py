#!/usr/bin/env python3
"""SAST injection benchmark — recall + false-positive scorecard for the taint layer.

Unlike the Docker/DAST harness in ``run_benchmarks.py``, this scores a *code-only*
scan of a local fixture tree with known source→sink bugs. It is the deterministic
gate for the Semgrep taint layer (#4) and every future rule-pack change (#93/#94).

Ground truth is the fixtures themselves — no separate file to drift out of sync:

  * ``fixtures/sast-injection/vulnerable/*`` — each line marked ``// EXPECT <class>``
    is a bug the taint layer MUST flag (recall). ``<class>`` is one of
    sqli | reflected-xss | dom-xss | ssrf | path-traversal | command-injection.
  * ``fixtures/sast-injection/safe/*`` — benign near-misses. ANY injection finding
    here (or on an unmarked line in a vulnerable file) is a false positive.

Usage:
  python benchmarks/sast_injection.py                 # scan the fixtures + score
  python benchmarks/sast_injection.py findings.json   # score an existing scan JSON

Requires (for the scan path): ``isitsecure`` on PATH and the ``semgrep`` binary
(``pip install semgrep`` / ``pipx install semgrep``). Scoring an existing JSON
needs neither.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tempfile
from collections import defaultdict

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "sast-injection"
EXPECT_RE = re.compile(r"//\s*EXPECT\s+([a-z-]+)")
CLASSES = ("sqli", "reflected-xss", "dom-xss", "ssrf", "path-traversal", "command-injection")

# Injection finding → vuln class, inferred from the title (findings are all
# category injection_risk). Cues are DISTINCTIVE phrases, not bare substrings, so
# they don't collide (e.g. "dom" would match "domain"/"random"). First hit wins.
_TITLE_CUES = [
    ("dom-xss", ("into the dom", "innerhtml", "document.write", "dom xss")),
    ("reflected-xss", ("reflected", "html response")),
    ("ssrf", ("outbound request", "ssrf")),
    ("path-traversal", ("filesystem write", "path traversal", "request-derived filename")),
    ("command-injection", ("shell command", "command injection")),
    ("sqli", ("sql",)),
]


def expected_bugs() -> list[dict]:
    """Parse ``// EXPECT <class>`` markers out of the vulnerable fixtures."""
    bugs = []
    for f in sorted((FIXTURES / "vulnerable").rglob("*")):
        if not f.is_file():
            continue
        for i, line in enumerate(f.read_text().splitlines(), start=1):
            m = EXPECT_RE.search(line)
            if m:
                bugs.append({"file": f.name, "line": i, "class": m.group(1)})
    return bugs


def is_injection(f: dict) -> bool:
    return f.get("category") == "injection_risk" or f.get("scanner_name") == "semgrep_taint"


def finding_loc(f: dict) -> tuple[str, int | None]:
    loc = f.get("code_location") or {}
    fp = loc.get("file_path") or f.get("file_path") or ""
    return pathlib.Path(fp).name, loc.get("line_number") or f.get("line_number")


def finding_class(f: dict) -> str:
    title = (f.get("title") or "").lower()
    for cls, cues in _TITLE_CUES:
        if any(c in title for c in cues):
            return cls
    return "?"


def _near(fn: str, ln: int | None, bug: dict) -> bool:
    # ±1 line — Semgrep can report the statement head rather than the exact line.
    return fn == bug["file"] and ln is not None and abs(ln - bug["line"]) <= 1


def score(findings: list[dict]) -> dict:
    injection = [f for f in findings if is_injection(f)]
    expected = expected_bugs()

    # Recall: 1:1 greedy match — each expected bug consumes at most one finding,
    # and each finding credits at most one bug (so two bugs can't both be credited
    # to a single finding, and a bug can't be credited twice).
    used: set[int] = set()
    items = []
    for bug in expected:
        hit = None
        for idx, f in enumerate(injection):
            if idx in used:
                continue
            fn, ln = finding_loc(f)
            if _near(fn, ln, bug):
                hit = idx
                used.add(idx)
                break
        class_match = hit is not None and finding_class(injection[hit]) == bug["class"]
        items.append({**bug, "detected": hit is not None, "class_match": class_match})

    # False positives: an injection finding that isn't near ANY expected bug —
    # everything under safe/, plus unmarked lines in vulnerable files. A finding
    # near a real bug is NOT an FP even if the 1:1 match already consumed another
    # finding for it (real Semgrep output double-reports a sink: taint + pattern).
    false_positives = [
        {"file": fn, "line": ln, "title": f.get("title"), "class": finding_class(f)}
        for f in injection
        for fn, ln in [finding_loc(f)]
        if not any(_near(fn, ln, b) for b in expected)
    ]

    by_class: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for it in items:
        by_class[it["class"]][1] += 1
        if it["detected"]:
            by_class[it["class"]][0] += 1

    found = sum(1 for it in items if it["detected"])
    return {
        "recall": {"found": found, "total": len(expected)},
        "false_positives": {"count": len(false_positives), "items": false_positives},
        "by_class": {k: {"found": v[0], "total": v[1]} for k, v in sorted(by_class.items())},
        "gaps": [it for it in items if not it["detected"]],
        "class_mismatches": [it for it in items if it["detected"] and not it["class_match"]],
        "total_injection_findings": len(injection),
    }


def passed(result: dict) -> bool:
    """The gate: full recall AND zero false positives."""
    return (result["recall"]["found"] == result["recall"]["total"]
            and result["false_positives"]["count"] == 0)


def semgrep_available() -> bool:
    """True if the taint layer can actually run (the semgrep binary is present)."""
    try:
        from isitsecure.engine.code_analysis.semgrep_analyzer import SemgrepAnalyzer
        return SemgrepAnalyzer._find_semgrep() is not None
    except Exception:  # noqa: BLE001 - fall back to a PATH probe
        import shutil
        return shutil.which("semgrep") is not None


def run_scan() -> list[dict]:
    out = tempfile.NamedTemporaryFile("r", suffix=".json", delete=False).name
    cmd = ["isitsecure", "scan", "-r", f"file://{FIXTURES.resolve()}",
           "--mode", "code-only", "--llm", "none", "--output", "json", "-f", out]
    print(f"$ {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True, timeout=300)  # noqa: S603 - fixed command, benchmark tool
        data = json.loads(pathlib.Path(out).read_text())
        return data.get("findings", []) if isinstance(data, dict) else data
    finally:
        pathlib.Path(out).unlink(missing_ok=True)


def print_report(r: dict) -> None:
    rec = r["recall"]
    pct = (100 * rec["found"] / rec["total"]) if rec["total"] else 0
    print("=" * 60)
    print("SAST INJECTION BENCHMARK — taint recall / FP scorecard")
    print("=" * 60)
    print(f"\nRecall:          {rec['found']}/{rec['total']}  ({pct:.0f}%)")
    print(f"False positives: {r['false_positives']['count']}  (must be 0)")
    print(f"Total injection findings: {r['total_injection_findings']}")
    print("\nBy class (found / expected):")
    for cls, v in r["by_class"].items():
        mark = "x" if v["found"] == v["total"] else (" " if v["found"] == 0 else "~")
        print(f"  [{mark}] {cls:18} {v['found']}/{v['total']}")
    if r["gaps"]:
        print(f"\nGaps — {len(r['gaps'])} expected bug(s) MISSED:")
        for g in r["gaps"]:
            print(f"  - [{g['class']}] {g['file']}:{g['line']}")
    if r["false_positives"]["count"]:
        print(f"\n⚠ FALSE POSITIVES — {r['false_positives']['count']}:")
        for fp in r["false_positives"]["items"]:
            print(f"  - [{fp['class']}] {fp['file']}:{fp['line']}  {fp['title']}")
    if r["class_mismatches"]:
        print(f"\nNote — {len(r['class_mismatches'])} finding(s) detected but "
              f"labeled a different class than expected (recall still counts):")
        for m in r["class_mismatches"]:
            print(f"  - expected {m['class']} at {m['file']}:{m['line']}")


def main() -> int:
    if len(sys.argv) == 2:
        data = json.loads(pathlib.Path(sys.argv[1]).read_text())
        findings = data.get("findings", data) if isinstance(data, dict) else data
    elif not semgrep_available():
        print("SKIPPED — semgrep binary not found; install it "
              "(pipx install semgrep) to run the SAST injection benchmark.")
        return 0
    else:
        findings = run_scan()
    result = score(findings)
    print_report(result)
    ok = passed(result)
    print(f"\n{'PASS' if ok else 'FAIL'} — recall {result['recall']['found']}/"
          f"{result['recall']['total']}, {result['false_positives']['count']} FP")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
