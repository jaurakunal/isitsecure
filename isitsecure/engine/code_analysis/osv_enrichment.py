"""Shared OSV helpers: full-record fetch, CVSS v3 scoring, severity and fix version.

The OSV ``/v1/querybatch`` endpoint only returns ``{id, modified}`` per
vulnerability, so severity/summary/fix data must be fetched from
``/v1/vulns/{id}``. Both the npm ``DependencyScanner`` and the multi-ecosystem
``OSVDependencyScanner`` use these helpers.
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
from functools import cmp_to_key

import httpx

from isitsecure.engine.enums import SeverityLevel

logger = logging.getLogger(__name__)

OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
MAX_DETAIL_IDS = 100
DETAIL_CONCURRENCY = 8
DETAIL_TIMEOUT = 10.0
DEFAULT_SEVERITY = SeverityLevel.MEDIUM

_DB_SEVERITY = {
    "CRITICAL": SeverityLevel.CRITICAL,
    "HIGH": SeverityLevel.HIGH,
    "MODERATE": SeverityLevel.MEDIUM,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest 1-decimal number >= value."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Compute the CVSS v3.x base score from a vector string, or None if invalid."""
    if not vector.startswith("CVSS:3"):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        if metrics["S"] not in ("U", "C"):
            return None
        scope_changed = metrics["S"] == "C"
        pr_table = {
            "N": 0.85,
            "L": 0.68 if scope_changed else 0.62,
            "H": 0.5 if scope_changed else 0.27,
        }
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploitability = (
            8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]]
            * pr_table[metrics["PR"]] * _UI[metrics["UI"]]
        )
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def score_to_severity(score: float) -> SeverityLevel:
    if score >= 9.0:
        return SeverityLevel.CRITICAL
    if score >= 7.0:
        return SeverityLevel.HIGH
    if score >= 4.0:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


_v4_noted = False


def _note_unscored_v4() -> None:
    """Log once that CVSS 4.0 vectors are not scored (they default to Medium)."""
    global _v4_noted
    if not _v4_noted:
        _v4_noted = True
        logger.info("OSV: CVSS 4.0 vectors are not scored; such records default to Medium")


def severity_from_osv(vuln: dict) -> SeverityLevel:
    """Severity from an OSV record: database_specific, then CVSS v3 vector, then Medium."""
    db_sev = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    if db_sev in _DB_SEVERITY:
        return _DB_SEVERITY[db_sev]
    for entry in vuln.get("severity", []):
        score_str = str(entry.get("score", ""))
        try:
            score: float | None = float(score_str)
        except ValueError:
            if score_str.startswith("CVSS:4"):
                _note_unscored_v4()
            score = cvss3_base_score(score_str)
        if score is not None and score > 0:
            return score_to_severity(score)
    for affected in vuln.get("affected", []):
        eco_sev = str(affected.get("ecosystem_specific", {}).get("severity", "")).upper()
        if eco_sev in _DB_SEVERITY:
            return _DB_SEVERITY[eco_sev]
    return DEFAULT_SEVERITY


_FIX_RANGE_TYPES = ("ECOSYSTEM", "SEMVER")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.IGNORECASE)
_VERSION_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")


def _compare_versions(a: str, b: str) -> int:
    """Best-effort ecosystem-agnostic version comparison (-1, 0, 1)."""
    ta = _VERSION_TOKEN_RE.findall(a.lstrip("vV").split("+", 1)[0])
    tb = _VERSION_TOKEN_RE.findall(b.lstrip("vV").split("+", 1)[0])
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return -1 if int(x) < int(y) else 1
        if x.isdigit() != y.isdigit():
            return 1 if x.isdigit() else -1  # a release outranks a pre-release tag
        return -1 if x.lower() < y.lower() else 1
    if len(ta) == len(tb):
        return 0
    n = min(len(ta), len(tb))
    rest = ta[n:] if len(ta) > len(tb) else tb[n:]
    sign = 1 if len(ta) > len(tb) else -1  # sign of "a vs b" if the longer is newer
    if not rest[0].isdigit():
        return -sign  # extra tag such as "beta": the longer one is a pre-release
    return sign if any(t.isdigit() and int(t) for t in rest) else 0


def _norm_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _same_ecosystem(a: str, b: str) -> bool:
    return a.split(":", 1)[0].casefold() == b.split(":", 1)[0].casefold()


def _affected_matches(affected: dict, package: str | None, ecosystem: str | None) -> bool:
    pkg = affected.get("package")
    if not pkg:
        return True  # unattributable entry (real OSV records always name the package)
    if package is not None and _norm_name(str(pkg.get("name", ""))) != _norm_name(package):
        return False
    if ecosystem is not None and not _same_ecosystem(str(pkg.get("ecosystem", "")), ecosystem):
        return False
    return True


def _range_intervals(events: list) -> list[tuple[str | None, str | None]]:
    """(introduced, fixed) pairs from one range's events; fixed is None if open."""
    intervals: list[tuple[str | None, str | None]] = []
    start: str | None = None
    open_ = False
    for event in events:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            start, open_ = str(event["introduced"]), True
        elif "fixed" in event and event["fixed"]:
            intervals.append((start if open_ else None, str(event["fixed"])))
            open_ = False
        elif "last_affected" in event:
            intervals.append((start if open_ else None, None))
            open_ = False
    if open_:
        intervals.append((start, None))
    return intervals


def fixed_version_from_osv(
    vuln: dict,
    package: str | None = None,
    ecosystem: str | None = None,
    installed: str | None = None,
) -> str | None:
    """Fixed version for ``package`` from affected[].ranges[].events[], or None.

    Only ECOSYSTEM / SEMVER ranges count (GIT ranges carry commit SHAs), and
    only affected entries whose package name/ecosystem match when given. With
    ``installed``: the fix of the interval containing it, else the smallest fix
    above it, else None. Without it, a fix is returned only when unambiguous.
    """
    fixes: list[tuple[str | None, str]] = []
    for affected in vuln.get("affected", []):
        if not isinstance(affected, dict) or not _affected_matches(affected, package, ecosystem):
            continue
        for rng in affected.get("ranges", []):
            if not isinstance(rng, dict) or rng.get("type") not in _FIX_RANGE_TYPES:
                continue
            for introduced, fixed in _range_intervals(rng.get("events", [])):
                if fixed and not _SHA_RE.match(fixed):
                    fixes.append((introduced, fixed))
    if not fixes:
        return None
    if not installed:
        distinct = {f for _, f in fixes}
        return next(iter(distinct)) if len(distinct) == 1 else None
    try:
        containing = [
            f for intro, f in fixes
            if (intro is None or intro == "0" or _compare_versions(installed, intro) >= 0)
            and _compare_versions(installed, f) < 0
        ]
        if containing:
            return min(containing, key=cmp_to_key(_compare_versions))
        later = [f for _, f in fixes if _compare_versions(f, installed) > 0]
        return min(later, key=cmp_to_key(_compare_versions)) if later else None
    except (ValueError, TypeError):
        return None


def unenriched_message(count: int) -> str:
    """User-facing note for OSV records whose details were not fetched."""
    return (
        f"OSV: {count} vulnerability record(s) were not enriched (could not be fetched or over the "
        f"{MAX_DETAIL_IDS}-record detail cap); their severity defaults to Medium"
    )


async def fetch_vuln_details(
    client: httpx.AsyncClient, vuln_ids: list[str]
) -> tuple[dict[str, dict], int]:
    """Fetch full OSV records for unique ids (capped, concurrency-limited).

    Returns ``(records_by_id, failed_count)``; ids that failed (or exceeded the
    cap) are absent from the map and counted as failed so callers can warn.
    """
    unique = list(dict.fromkeys(i for i in vuln_ids if i))
    capped = unique[:MAX_DETAIL_IDS]
    failed = len(unique) - len(capped)
    if failed:
        logger.warning(
            "OSV: fetching details for %d of %d vulns (cap); %d not enriched",
            len(capped), len(unique), failed,
        )
    sem = asyncio.Semaphore(DETAIL_CONCURRENCY)
    records: dict[str, dict] = {}

    async def _one(vuln_id: str) -> bool:
        async with sem:
            try:
                resp = await client.get(
                    OSV_VULN_URL.format(vuln_id=vuln_id), timeout=DETAIL_TIMEOUT
                )
                if resp.status_code != 200:
                    logger.warning("OSV vuln %s fetch failed: %d", vuln_id, resp.status_code)
                    return False
                data = resp.json()
                if not isinstance(data, dict):
                    return False
                records[vuln_id] = data
                return True
            except Exception as exc:  # network / JSON errors degrade gracefully
                logger.warning("OSV vuln %s fetch failed: %s", vuln_id, exc)
                return False

    results = await asyncio.gather(*(_one(i) for i in capped))
    failed += results.count(False)
    return records, failed
