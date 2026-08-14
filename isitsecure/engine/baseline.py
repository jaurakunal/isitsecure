"""Baseline mode — surface only findings that are new since an accepted baseline (#52).

A team that has triaged its current findings wants later scans to show only what
is *new*, not re-litigate the whole backlog every run. ``--baseline-accept``
records the fingerprints of the current findings; a later ``--baseline`` scan
hides those and shows only findings whose fingerprint is not in the baseline.

Baselines are keyed per project (repo URL or target URL) and stored under
``~/.isitsecure/baselines/`` — machine-local state, unlike the repo-committed
``.isitsecureignore`` used for suppression (#51). Identity is the shared
:func:`isitsecure.engine.identity.finding_fingerprint`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from isitsecure.config import CONFIG_DIR

if TYPE_CHECKING:
    from isitsecure.engine.models import DeepFinding

BASELINES_DIRNAME = "baselines"
_SLUG_MAX = 40


def baselines_dir() -> Path:
    return CONFIG_DIR / BASELINES_DIRNAME


def project_key(target_url: str | None, repo_url: str | None) -> str:
    """A stable, filesystem-safe key identifying the scanned project.

    Prefers the repo URL (a repo is the same project across environments); falls
    back to the target URL's host+path. The hash is over the NORMALIZED host+path
    (lower-cased, scheme dropped) so `https://x/a`, `x/a` and `X/a` share a key;
    a slug prefix keeps the filename readable. (Deeper git-URL normalization —
    `.git`, `git@` SSH form — is out of scope; those still key separately.)
    """
    identifier = (repo_url or target_url or "unknown").strip()
    parsed = urlparse(identifier if "://" in identifier else f"//{identifier}")
    readable = (f"{parsed.netloc}{parsed.path}" or identifier).lower()
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", readable).strip("-")[:_SLUG_MAX] or "project"
    digest = hashlib.sha256(readable.encode("utf-8")).hexdigest()[:8]
    return f"{slug}-{digest}"


def baseline_path(target_url: str | None, repo_url: str | None) -> Path:
    return baselines_dir() / f"{project_key(target_url, repo_url)}.json"


def load_baseline(path: Path) -> set[str] | None:
    """Fingerprints in the baseline, or ``None`` if the file is absent OR
    unreadable/corrupt (the caller uses ``path.exists()`` to tell those apart).
    A validly-empty baseline returns an empty set, not ``None``."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    fps = data.get("fingerprints", [])
    if not isinstance(fps, list):
        return None
    return {str(x) for x in fps}


def save_baseline(
    path: Path,
    findings: list[DeepFinding],
    *,
    target_url: str | None = None,
    repo_url: str | None = None,
    commit: str = "",
) -> int:
    """Write the current findings' fingerprints as the accepted baseline.

    Returns the number of unique fingerprints recorded.
    """
    fingerprints = sorted({f.fingerprint for f in findings})
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,  # informational; not yet used for migration
        "created": datetime.now(UTC).isoformat(),
        "target_url": target_url,
        "repo_url": repo_url,
        "commit": commit,
        "fingerprints": fingerprints,
    }
    # Atomic write: a crash or concurrent scan must never leave a truncated file
    # (which load_baseline would treat as corrupt).
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return len(fingerprints)


def partition_new(
    findings: list[DeepFinding], baseline: set[str]
) -> tuple[list[DeepFinding], list[DeepFinding]]:
    """Split findings into (new, known) relative to the baseline fingerprints."""
    new: list[DeepFinding] = []
    known: list[DeepFinding] = []
    for f in findings:
        (known if f.fingerprint in baseline else new).append(f)
    return new, known
