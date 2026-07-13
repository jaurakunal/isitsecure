"""Tests for the git-free plain-language fix-result mapping (#50).

Covers:
  * verify-status classification into fixed / needs-review / couldn't-fix
  * the plain-language summary + next-step lines
  * the single-finding status token
"""

from __future__ import annotations

import pytest

from isitsecure.engine.fixes import plain_results
from isitsecure.engine.fixes.plain_results import VerifyCounts


# ---------------------------------------------------------------------------
# classify_verification — the core bucketing
# ---------------------------------------------------------------------------

def test_all_confirmed_fixed():
    c = plain_results.classify_verification(
        attempted=3, fix_failed=0,
        verification={"resolved": 3, "still_present": 0, "unverifiable": 0},
    )
    assert c == VerifyCounts(fixed=3, needs_review=0, couldnt_fix=0)
    assert c.total == 3


def test_some_need_review_still_present():
    # 5 attempted, all fixed, re-scan confirms 4 gone, 1 still flagged.
    c = plain_results.classify_verification(
        attempted=5, fix_failed=0,
        verification={"resolved": 4, "still_present": 1, "unverifiable": 0},
    )
    assert c == VerifyCounts(fixed=4, needs_review=1, couldnt_fix=0)


def test_unverifiable_counts_as_needs_review():
    # Fix written but the finding can't be auto-verified (DAST/business-logic).
    c = plain_results.classify_verification(
        attempted=2, fix_failed=0,
        verification={"resolved": 1, "still_present": 0, "unverifiable": 1},
    )
    assert c == VerifyCounts(fixed=1, needs_review=1, couldnt_fix=0)


def test_fix_failed_counts_as_couldnt_fix():
    c = plain_results.classify_verification(
        attempted=4, fix_failed=1,
        verification={"resolved": 3, "still_present": 0, "unverifiable": 0},
    )
    assert c == VerifyCounts(fixed=3, needs_review=0, couldnt_fix=1)


def test_no_verification_means_needs_review():
    # Verification never ran -> we can't claim anything is confirmed fixed.
    c = plain_results.classify_verification(
        attempted=2, fix_failed=0, verification=None,
    )
    assert c == VerifyCounts(fixed=0, needs_review=2, couldnt_fix=0)


def test_buckets_always_partition_the_total():
    c = plain_results.classify_verification(
        attempted=6, fix_failed=2,
        verification={"resolved": 2, "still_present": 1, "unverifiable": 1},
    )
    assert c.total == 6
    assert c == VerifyCounts(fixed=2, needs_review=2, couldnt_fix=2)


def test_never_goes_negative_on_odd_input():
    # resolved reported higher than attempted-failed (shouldn't happen, but be safe).
    c = plain_results.classify_verification(
        attempted=1, fix_failed=0, verification={"resolved": 5},
    )
    assert c.needs_review == 0
    assert c.total >= 0


# ---------------------------------------------------------------------------
# summarize — the plain-language headline (no git jargon)
# ---------------------------------------------------------------------------

def test_summarize_mixed_matches_spec_shape():
    c = VerifyCounts(fixed=4, needs_review=1, couldnt_fix=0)
    s = plain_results.summarize(c)
    assert s == (
        "Fixed 5 issues in your code and re-checked: "
        "4 confirmed fixed, 1 needs your review."
    )
    assert "branch" not in s.lower()
    assert "commit" not in s.lower()
    assert "pull request" not in s.lower()


def test_summarize_all_fixed_uses_all_phrasing():
    s = plain_results.summarize(VerifyCounts(fixed=3, needs_review=0, couldnt_fix=0))
    assert "all 3 confirmed fixed" in s


def test_summarize_single_fixed_is_singular():
    s = plain_results.summarize(VerifyCounts(fixed=1))
    assert "Fixed 1 issue " in s
    assert "1 confirmed fixed" in s


def test_summarize_nothing_fixable():
    s = plain_results.summarize(VerifyCounts(couldnt_fix=2))
    assert "Couldn't automatically fix" in s
    assert "any of the 2 issues" in s


def test_summarize_empty():
    assert plain_results.summarize(VerifyCounts()) == "No issues to fix."


def test_summarize_mentions_couldnt_fix_tail():
    s = plain_results.summarize(VerifyCounts(fixed=2, needs_review=0, couldnt_fix=1))
    assert "1 couldn't be fixed automatically" in s


# ---------------------------------------------------------------------------
# next_step_hint
# ---------------------------------------------------------------------------

def test_next_step_all_clear():
    hint = plain_results.next_step_hint(VerifyCounts(fixed=3))
    assert "good to test" in hint


def test_next_step_needs_review():
    hint = plain_results.next_step_hint(VerifyCounts(fixed=2, needs_review=1))
    assert "human eye" in hint
    assert "1 change" in hint


def test_next_step_includes_saved_hint():
    hint = plain_results.next_step_hint(
        VerifyCounts(fixed=1), saved_hint="Your original code is safely backed up."
    )
    assert "safely backed up" in hint


def test_next_step_empty_when_nothing():
    assert plain_results.next_step_hint(VerifyCounts()) == ""


# ---------------------------------------------------------------------------
# status_for_single — per-finding UI status token
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "success, verified, expected",
    [
        (False, None, "couldnt_fix"),
        (False, True, "couldnt_fix"),
        (True, True, "fixed"),
        (True, False, "needs_review"),
        (True, None, "needs_review"),
    ],
)
def test_status_for_single(success, verified, expected):
    assert plain_results.status_for_single(success, verified) == expected
