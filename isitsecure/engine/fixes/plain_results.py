"""Plain-language mapping for fix-and-verify results (#50).

Turns the technical outcome of a fix run — how many findings were fixed, and
what a re-scan confirmed — into approachable, jargon-free language for a
non-technical user. Deliberately says nothing about git branches, commits, or
pull requests: the safety net (a backup branch under the hood) is an
implementation detail the user never has to think about.

This is the single source of truth shared by the CLI ``fix`` command and the
web UI's fix-all / per-finding flows, so both speak with one voice.

Three verify buckets (see ``classify_verification``):

* **fixed**        — re-scan confirms the issue is gone.
* **needs review** — the fix was written but the scanner still flags it (a
  partial fix, or a valid fix the scanner can't confirm), OR the finding
  can't be auto-verified (business-logic / live-site issues).
* **couldn't fix** — no fix could be generated for the finding.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VerifyCounts:
    """Verify outcome bucketed into the three plain-language statuses.

    ``fixed`` + ``needs_review`` + ``couldnt_fix`` == ``total`` always holds,
    so the three numbers partition every finding we attempted.
    """

    fixed: int = 0
    needs_review: int = 0
    couldnt_fix: int = 0

    @property
    def total(self) -> int:
        return self.fixed + self.needs_review + self.couldnt_fix


def classify_verification(
    *,
    attempted: int,
    fix_failed: int,
    verification: dict | None,
) -> VerifyCounts:
    """Bucket a fix run into fixed / needs-review / couldn't-fix.

    Args:
        attempted: findings we tried to fix (in scope for this run).
        fix_failed: findings for which no fix could be generated/applied.
        verification: the re-scan verify dict (``resolved`` / ``still_present``
            / ``unverifiable``), or ``None`` if verification didn't run.

    A finding lands in exactly one bucket:

    * ``couldnt_fix``   — no fix was produced (``fix_failed``).
    * ``fixed``         — re-scan confirmed resolved.
    * ``needs_review``  — everything else: still-flagged after the fix, or
      not auto-verifiable, or verification never ran (so we can't claim it).
    """
    v = verification or {}
    resolved = int(v.get("resolved", 0))
    # Findings whose fix WAS written but that we can't confirm as resolved:
    # still-present after re-scan, plus those that aren't auto-verifiable.
    fixed_but_unconfirmed = max(0, attempted - fix_failed - resolved)
    return VerifyCounts(
        fixed=resolved,
        needs_review=fixed_but_unconfirmed,
        couldnt_fix=max(0, fix_failed),
    )


def _plural(n: int, singular: str, plural: str | None = None) -> str:
    return singular if n == 1 else (plural or singular + "s")


def summarize(counts: VerifyCounts) -> str:
    """One-line, plain-language headline for a fix run.

    Examples:
        "Fixed 5 issues in your code and re-checked: 4 confirmed fixed, 1 needs
         your review."
        "Fixed 3 issues in your code and re-checked: all 3 confirmed fixed."
        "Couldn't automatically fix any of the 2 issues — they need a closer look."
    """
    total = counts.total
    if total == 0:
        return "No issues to fix."

    handled = counts.fixed + counts.needs_review
    if handled == 0:
        # Nothing could even be fixed.
        return (
            f"Couldn't automatically fix "
            f"{'the issue' if total == 1 else f'any of the {total} issues'} — "
            f"{'it needs' if total == 1 else 'they need'} a closer look."
        )

    lead = (
        f"Fixed {handled} {_plural(handled, 'issue')} in your code and re-checked: "
    )

    parts: list[str] = []
    if counts.fixed:
        if counts.needs_review == 0 and counts.couldnt_fix == 0 and counts.fixed > 1:
            parts.append(f"all {counts.fixed} confirmed fixed")
        else:
            parts.append(f"{counts.fixed} confirmed fixed")
    if counts.needs_review:
        parts.append(f"{counts.needs_review} {_plural(counts.needs_review, 'needs', 'need')} your review")

    detail = ", ".join(parts) if parts else "changes applied"
    tail = ""
    if counts.couldnt_fix:
        tail = (
            f" ({counts.couldnt_fix} couldn't be fixed automatically "
            f"and {_plural(counts.couldnt_fix, 'needs', 'need')} a closer look.)"
        )
    return f"{lead}{detail}.{tail}"


def next_step_hint(counts: VerifyCounts, *, saved_hint: str = "") -> str:
    """A short, encouraging next-step line (no git jargon).

    ``saved_hint`` optionally names where the original is safely kept, phrased
    for a non-technical reader (e.g. "Your original code is safely backed up.").
    """
    if counts.total == 0:
        return ""
    lines: list[str] = []
    if counts.needs_review:
        lines.append(
            f"{counts.needs_review} {_plural(counts.needs_review, 'change')} "
            f"{_plural(counts.needs_review, 'wants', 'want')} a human eye — "
            "open the changed files and give them a quick look."
        )
    if counts.fixed and not counts.needs_review and not counts.couldnt_fix:
        lines.append("Everything checks out — you're good to test your app.")
    if saved_hint:
        lines.append(saved_hint)
    return "  ".join(lines)


def status_for_single(fix_success: bool, verified: bool | None) -> str:
    """Verify status for a SINGLE finding's fix, as a UI status token.

    Returns one of ``"fixed"`` / ``"needs_review"`` / ``"couldnt_fix"``:

    * ``couldnt_fix`` — no fix was generated.
    * ``fixed``       — fix generated AND re-scan confirmed it gone.
    * ``needs_review``— fix generated but unconfirmed (``verified`` is False or
      ``None`` because it couldn't be auto-verified).
    """
    if not fix_success:
        return "couldnt_fix"
    return "fixed" if verified else "needs_review"
