"""Persisted finding suppression — the ``.isitsecureignore`` file (#51).

A finding a user has judged not-applicable / accepted-risk should not reappear on
every future scan. Suppressions live in a repo-local ``.isitsecureignore`` file so
they travel with the code and are reviewable in pull requests (the acceptance
criterion). Each line names a finding by its stable :func:`fingerprint`; anything
after ``#`` is human context and is ignored by the parser.

Format (line-based, git-friendly, no external deps)::

    # isitsecure suppressions — findings listed here are hidden on future scans.
    de0e57aeb5f61708   # [injection_risk] GET /createdb — benign IntegrityError
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from isitsecure.engine.models import DeepFinding

IGNORE_FILENAME = ".isitsecureignore"

_HEADER = (
    "# isitsecure suppressions — findings listed here are hidden on future scans.\n"
    "# Format: <fingerprint>   # <context>   (only the first token is read).\n"
    "# Remove a line to un-suppress. Reviewable in code review.\n"
)


def default_ignore_path(base: Path | None = None) -> Path:
    """The ``.isitsecureignore`` path for the given directory (default: CWD)."""
    return (base or Path.cwd()) / IGNORE_FILENAME


def load_suppressed_fingerprints(path: Path) -> set[str]:
    """Read the fingerprints suppressed by an ignore file (empty set if absent)."""
    if not path.exists():
        return set()
    out: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        before_comment = stripped.split("#", 1)[0].split()
        if before_comment:
            out.add(before_comment[0])
    return out


def partition(
    findings: list[DeepFinding], suppressed: set[str]
) -> tuple[list[DeepFinding], list[DeepFinding]]:
    """Split findings into (active, suppressed) by fingerprint."""
    active: list[DeepFinding] = []
    hidden: list[DeepFinding] = []
    for f in findings:
        (hidden if f.fingerprint in suppressed else active).append(f)
    return active, hidden


def _entry_line(finding: DeepFinding, reason: str = "") -> str:
    cat = finding.category.value if hasattr(finding.category, "value") else str(finding.category)
    if finding.code_location and finding.code_location.file_path:
        locus = finding.code_location.file_path
    elif finding.endpoint_url:
        from urllib.parse import urlparse
        locus = f"{finding.http_method or 'GET'} {urlparse(finding.endpoint_url).path or '/'}"
    else:
        locus = ""
    context = f"[{cat}] {locus} — {finding.title}".strip()
    if reason:
        context += f" ({reason})"
    return f"{finding.fingerprint}   # {context}\n"


def add_suppressions(
    path: Path,
    findings: list[DeepFinding],
    fingerprints: list[str],
    reason: str = "",
) -> list[DeepFinding]:
    """Append ignore entries for the given fingerprints, using ``findings`` for
    human-readable context. Skips fingerprints already suppressed or not present
    in this scan. Returns the findings that were newly suppressed.

    Creates the file (with a header) if it does not exist.
    """
    already = load_suppressed_fingerprints(path)
    by_fp: dict[str, DeepFinding] = {}
    for f in findings:
        by_fp.setdefault(f.fingerprint, f)

    newly: list[DeepFinding] = []
    lines: list[str] = []
    for fp in fingerprints:
        if fp in already or fp in {f.fingerprint for f in newly}:
            continue
        finding = by_fp.get(fp)
        if finding is None:
            continue  # not in this scan — nothing to give context; skip
        newly.append(finding)
        lines.append(_entry_line(finding, reason))

    if not lines:
        return []

    existing = path.read_text(encoding="utf-8") if path.exists() else _HEADER
    if existing and not existing.endswith("\n"):
        existing += "\n"
    path.write_text(existing + "".join(lines), encoding="utf-8")
    return newly
