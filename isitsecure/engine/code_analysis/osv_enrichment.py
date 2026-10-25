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
            score = cvss3_base_score(score_str)
        if score is not None and score > 0:
            return score_to_severity(score)
    for affected in vuln.get("affected", []):
        eco_sev = str(affected.get("ecosystem_specific", {}).get("severity", "")).upper()
        if eco_sev in _DB_SEVERITY:
            return _DB_SEVERITY[eco_sev]
    return DEFAULT_SEVERITY


def fixed_version_from_osv(vuln: dict) -> str | None:
    """First fixed version found in affected[].ranges[].events[]."""
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    return str(fixed)
    return None


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
        logger.warning("OSV: fetching details for %d of %d vulns (cap)", len(capped), len(unique))
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
