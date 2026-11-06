"""Repeat-run stability for the benchmark harness.

A single benchmark run hides run-to-run variance (probe ordering, timing, any
LLM-assisted step). Running a target N times and keeping only the findings seen
in EVERY run gives a *stable* set that is safe to hold a regression bar against;
findings seen in only some runs are *flaky* — reported, never gated on.

Pure logic, no scanning and no I/O beyond the optional baseline file, so it is
unit-testable on synthetic reports. ``run_benchmarks.py --repeat N`` drives it.

Baseline file (JSON, optional — ``--baseline PATH``)::

    {"version": 1,
     "targets": {"<target>": {"stable": ["<fingerprint>", ...],
                              "recall": {"found": 12, "total": 45},
                              "by_class": {"sqli": {"found": 2, "total": 3}}}}}
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

BASELINE_VERSION = 1

_ID_SEGMENT = re.compile(
    r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24})$",
    re.IGNORECASE,
)


def _normalise_path(url: str) -> str:
    """Path of a URL with host, query and id-like segments dropped.

    Ids (numeric / UUID / ObjectId) become ``{id}`` so a finding on
    ``/api/Users/7`` and ``/api/Users/9`` is the same vulnerability.
    """
    path = urlsplit(url).path or "/"
    return "/".join("{id}" if _ID_SEGMENT.match(seg) else seg
                    for seg in path.split("/"))


_QUOTED = re.compile(r"""(['"`]).*?\1""")
_NUMBER = re.compile(r"\b(?:[0-9a-f]{8}-[0-9a-f-]{27}|[0-9a-f]{24}|\d+)\b")


def _normalise_title(title: str) -> str:
    """Lower-case a title and mask volatile parts (quoted values, ids, numbers)."""
    t = _QUOTED.sub("'?'", str(title or "").lower())
    t = _NUMBER.sub("#", t)
    return " ".join(t.split())


def _snippet_hash(snippet: str) -> str:
    norm = " ".join(str(snippet or "").split())
    return hashlib.sha1(norm.encode()).hexdigest()[:8] if norm else ""  # noqa: S324 — not security


def finding_fingerprint(finding: dict) -> str:
    """Stable identity of a finding across runs.

    scanner + category + normalised title + location, where location is the
    endpoint path (DAST) or ``file[#snippet-hash]`` (SAST). Line numbers are
    excluded so an unrelated edit above a finding doesn't read as LOST; the
    snippet hash tells apart several findings in one file when available.
    Volatile detail (host, query string, resource ids, numbers, quoted values)
    is excluded on purpose.
    """
    loc = ""
    if finding.get("endpoint_url"):
        loc = _normalise_path(str(finding["endpoint_url"]))
    elif isinstance(finding.get("code_location"), dict):
        cl = finding["code_location"]
        h = _snippet_hash(cl.get("code_snippet", ""))
        loc = f"{cl.get('file_path', '')}" + (f"#{h}" if h else "")
    title = _normalise_title(finding.get("title"))
    return "|".join((str(finding.get("scanner_name") or ""),
                     str(finding.get("category") or ""), title, loc))


def fingerprint_set(findings: list[dict]) -> frozenset[str]:
    return frozenset(finding_fingerprint(f) for f in findings)


@dataclass(frozen=True)
class RunRecord:
    """What one benchmark run contributes to the stability analysis."""
    fingerprints: frozenset[str]
    found: int = 0
    total: int = 0
    duration_s: float = 0.0

    @property
    def recall(self) -> float:
        return self.found / self.total if self.total else 0.0


@dataclass
class StabilityReport:
    runs: list[RunRecord]
    stable: frozenset[str] = frozenset()
    flaky: frozenset[str] = frozenset()
    recall_min: float = 0.0
    recall_max: float = 0.0
    duration_min: float = 0.0
    duration_max: float = 0.0

    @property
    def recall_spread(self) -> float:
        return self.recall_max - self.recall_min


def compute_stability(runs: list[RunRecord]) -> StabilityReport:
    """Stable = fingerprints in every run; flaky = in some but not all."""
    if not runs:
        return StabilityReport(runs=[])
    union = frozenset().union(*(r.fingerprints for r in runs))
    stable = frozenset.intersection(*(r.fingerprints for r in runs))
    recalls = [r.recall for r in runs]
    durations = [r.duration_s for r in runs]
    return StabilityReport(
        runs=list(runs), stable=stable, flaky=union - stable,
        recall_min=min(recalls), recall_max=max(recalls),
        duration_min=min(durations), duration_max=max(durations))


@dataclass
class BaselineComparison:
    # Baseline-stable fingerprints no longer stable now. ``lost`` were not seen
    # in any run; ``demoted`` were seen but not in all runs (became flaky).
    lost: list[str] = field(default_factory=list)
    demoted: list[str] = field(default_factory=list)
    new_stable: list[str] = field(default_factory=list)

    @property
    def regressed(self) -> bool:
        return bool(self.lost or self.demoted)


def compare_to_baseline(report: StabilityReport,
                        baseline_stable: set[str] | frozenset[str] | list[str],
                        ) -> BaselineComparison:
    """The regression bar: every baseline-stable fingerprint must stay stable."""
    base = set(baseline_stable)
    missing = sorted(base - report.stable)
    return BaselineComparison(
        lost=[fp for fp in missing if fp not in report.flaky],
        demoted=[fp for fp in missing if fp in report.flaky],
        new_stable=sorted(report.stable - base))


# --- baseline file ---------------------------------------------------------

def load_baseline(path: str | pathlib.Path) -> dict:
    """Read a baseline file; a missing file is an empty baseline (first run)."""
    p = pathlib.Path(path)
    if not p.exists():
        return {"version": BASELINE_VERSION, "targets": {}}
    data = json.loads(p.read_text())
    if data.get("version") != BASELINE_VERSION:
        raise ValueError(f"unsupported baseline version {data.get('version')!r} "
                         f"in {p} (expected {BASELINE_VERSION})")
    data.setdefault("targets", {})
    return data


def baseline_entry(report: StabilityReport, by_class: dict | None = None) -> dict:
    best = max(report.runs, key=lambda r: r.found) if report.runs else None
    entry: dict = {"stable": sorted(report.stable),
                   "recall": {"found": best.found if best else 0,
                              "total": best.total if best else 0}}
    if by_class:
        entry["by_class"] = by_class
    return entry


def save_baseline(path: str | pathlib.Path, baseline: dict, target: str,
                  entry: dict) -> None:
    baseline.setdefault("targets", {})[target] = entry
    baseline["version"] = BASELINE_VERSION
    pathlib.Path(path).write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n")


# --- reporting -------------------------------------------------------------

def format_report(name: str, report: StabilityReport,
                  cmp: BaselineComparison | None = None) -> str:
    n = len(report.runs)
    lines = [f"STABILITY — {name} ({n} runs)",
             f"  stable findings (in all {n}): {len(report.stable)}   "
             f"flaky (in some): {len(report.flaky)}"]
    for i, r in enumerate(report.runs, 1):
        lines.append(f"  run {i}: recall {r.found}/{r.total} "
                     f"({100 * r.recall:.0f}%)  {r.duration_s:.0f}s  "
                     f"{len(r.fingerprints)} findings")
    lines.append(f"  recall spread: {100 * report.recall_spread:.1f} pts  |  "
                 f"duration {report.duration_min:.0f}s-{report.duration_max:.0f}s "
                 f"(--llm none: no token cost)")
    if cmp is not None:
        lines.append(f"  vs baseline: {len(cmp.lost)} lost, {len(cmp.demoted)} "
                     f"demoted to flaky, {len(cmp.new_stable)} newly stable")
        for tag, fps in (("LOST", cmp.lost), ("FLAKY", cmp.demoted)):
            lines += [f"    - [{tag}] {fp}" for fp in fps]
    return "\n".join(lines)
