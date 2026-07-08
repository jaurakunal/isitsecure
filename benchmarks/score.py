#!/usr/bin/env python3
"""Comprehensive benchmark scoring against per-instance ground truth.

Unlike the smoke-test recall in run_benchmarks.py (a few hand-picked classes),
this scores a scan's findings against an app's FULL documented vulnerability
set, reporting:

  - recall over the DAST-detectable (in-scope) items, overall and per class,
    with true-positive verification (finding must match the class signature AND
    land on the expected endpoint);
  - which items are out-of-scope for DAST (crypto/CTF/business-logic), tallied
    separately so they don't distort recall;
  - precision context: how many findings map to a targeted class vs. how many
    are unmatched (undocumented-real OR false-positive — surfaced for triage,
    not auto-labeled).

Usage:
  python benchmarks/score.py juiceshop path/to/scan_findings.json
  # writes <findings>.scorecard.json and prints the scorecard + gap list
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections import defaultdict

from ground_truth import juiceshop
from ground_truth.schema import GroundTruthItem

APPS = {"juiceshop": juiceshop.build_ground_truth}


def score(findings: list[dict], gt: list[GroundTruthItem]) -> dict:
    in_scope = [g for g in gt if g.dast_detectable]
    out_scope = [g for g in gt if not g.dast_detectable]

    # Items WITH an endpoint are verified individually (finding on the right
    # route). Items WITHOUT are credited at class level, but capped at the
    # number of DISTINCT matching findings so one finding can't credit an
    # entire class of challenges.
    classlevel_budget: dict[str, int] = {}
    for g in in_scope:
        if g.endpoint_contains or not g.signature:
            continue
        if g.vuln_class not in classlevel_budget:
            distinct = {f.get("endpoint_url") for f in findings
                        if g.signature.matches(f)}
            classlevel_budget[g.vuln_class] = len(distinct)

    items = []
    for g in in_scope:
        if g.endpoint_contains:
            f = g.detected_by(findings)
            detected, verification = f is not None, "endpoint"
        else:
            budget = classlevel_budget.get(g.vuln_class, 0)
            detected = budget > 0
            if detected:
                classlevel_budget[g.vuln_class] = budget - 1
            f = g.detected_by(findings) if detected else None
            verification = "class"
        items.append({
            "id": g.id, "name": g.name, "vuln_class": g.vuln_class,
            "endpoint": g.endpoint_contains, "auth_required": g.auth_required,
            "verification": verification, "detected": detected,
            "evidence": {"title": f.get("title"), "endpoint": f.get("endpoint_url")}
            if f else None,
        })

    by_class: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for it in items:
        by_class[it["vuln_class"]][1] += 1
        if it["detected"]:
            by_class[it["vuln_class"]][0] += 1

    # Precision context: findings that map to any in-scope target class.
    matched = set()
    for i, f in enumerate(findings):
        if any(g.signature and g.signature.matches(f) for g in in_scope):
            matched.add(i)

    out_by_cat: dict[str, int] = defaultdict(int)
    for g in out_scope:
        out_by_cat[g.category] += 1

    found = sum(1 for it in items if it["detected"])
    verified = sum(1 for it in items if it["detected"] and it["verification"] == "endpoint")
    return {
        "recall": {"found": found, "verified": verified, "in_scope": len(in_scope)},
        "by_class": {k: {"found": v[0], "total": v[1]} for k, v in sorted(by_class.items())},
        "out_of_scope": {"total": len(out_scope), "by_category": dict(out_by_cat)},
        "precision": {"findings_matching_target_class": len(matched),
                      "total_findings": len(findings),
                      "unmatched": len(findings) - len(matched)},
        "items": items,
        "gaps": [it for it in items if not it["detected"]],
    }


def print_report(app: str, r: dict) -> None:
    rec = r["recall"]
    pct = (100 * rec["found"] / rec["in_scope"]) if rec["in_scope"] else 0
    print("=" * 66)
    print(f"BENCHMARK SCORECARD — {app}")
    print("=" * 66)
    print(f"\nRecall (DAST-detectable): {rec['found']}/{rec['in_scope']}  ({pct:.0f}%)")
    print(f"  endpoint-verified: {rec['verified']}  |  class-level (approx): "
          f"{rec['found'] - rec['verified']}")
    print(f"Out of scope for DAST:    {r['out_of_scope']['total']} challenges "
          f"(crypto / CTF / business-logic / SAST-only)")
    p = r["precision"]
    print(f"Findings:                 {p['total_findings']} total, "
          f"{p['findings_matching_target_class']} map to a targeted class, "
          f"{p['unmatched']} unmatched (triage: real-but-undocumented or FP)")

    print("\nBy class (found / detectable):")
    for cls, v in r["by_class"].items():
        mark = "x" if v["found"] == v["total"] else (" " if v["found"] == 0 else "~")
        print(f"  [{mark}] {cls:16} {v['found']}/{v['total']}")

    if r["gaps"]:
        print(f"\nGaps — {len(r['gaps'])} detectable vulns NOT found:")
        for g in r["gaps"]:
            ep = f"  @{g['endpoint']}" if g["endpoint"] else ""
            auth = " (auth)" if g["auth_required"] else ""
            print(f"  - [{g['vuln_class']}] {g['name']}{ep}{auth}")


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in APPS:
        print(f"usage: python benchmarks/score.py <{'|'.join(APPS)}> <findings.json>")
        return 2
    app, findings_path = sys.argv[1], sys.argv[2]
    data = json.loads(pathlib.Path(findings_path).read_text())
    findings = data.get("findings", data) if isinstance(data, dict) else data
    result = score(findings, APPS[app]())
    print_report(app, result)
    out = pathlib.Path(findings_path).with_suffix(".scorecard.json")
    out.write_text(json.dumps(result, indent=2))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
