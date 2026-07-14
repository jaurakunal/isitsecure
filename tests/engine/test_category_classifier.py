"""Tests for LLM-finding category classification.

The fixtures below are the real finding titles the experiment produced against
jaurakunal/isitsecure-testbed, where all 38 were wrongly grouped under
AUTH_WEAKNESS and collapsed into one unreviewable PR. Each must now route to its
true category so per-category PR grouping is meaningful.
"""

import pytest

from isitsecure.engine.enums import FindingCategory
from isitsecure.engine.code_analysis.category_classifier import (
    classify_finding_category,
)

C = FindingCategory


@pytest.mark.parametrize(
    "title, expected",
    [
        # --- the exact titles that used to all become AUTH_WEAKNESS ---
        ("SQL injection via id parameter in getById()", C.INJECTION_RISK),
        ("SQL injection via id in deleteRow() in db.ts", C.INJECTION_RISK),
        ("DOM XSS via innerHTML from URL hash in page.tsx", C.INJECTION_RISK),
        ("Reflected XSS via unescaped search query", C.INJECTION_RISK),
        ("Unrestricted file type / stored XSS and RCE", C.INJECTION_RISK),
        ("Server-Side Request Forgery (SSRF) via url param", C.INJECTION_RISK),
        ("Open redirect via unvalidated redirect_to", C.OPEN_REDIRECT),
        ("Mass assignment allows privilege escalation", C.PRIVILEGE_ESCALATION),
        ("Mass assignment / user_id spoofing on tasks", C.PRIVILEGE_ESCALATION),
        ("Privilege escalation via unrestricted role update", C.PRIVILEGE_ESCALATION),
        ("Missing ownership verification / potential IDOR", C.IDOR),
        ("Hardcoded default admin credentials in route", C.EXPOSED_SECRETS),
        ("Sensitive data over-exposure in GET response", C.INFO_DISCLOSURE),
        ("Password reset token returned in HTTP response", C.INFO_DISCLOSURE),
        ("Unrestricted GraphQL introspection in route", C.EXPOSED_API_ENDPOINT),
        ("No rate limiting on login endpoint in route", C.EXPOSED_API_ENDPOINT),
        # --- genuinely auth findings still land on AUTH_WEAKNESS ---
        ("JWT 'alg:none' bypass allows authentication forgery", C.AUTH_WEAKNESS),
        ("API route missing authentication check", C.AUTH_WEAKNESS),
        ("Weak/default JWT signing secret in auth.ts", C.AUTH_WEAKNESS),
    ],
)
def test_real_experiment_titles_classify_correctly(title, expected):
    assert classify_finding_category(title) == expected


def test_rls_default_used_when_no_keyword_match():
    # RLS review of an opaque finding falls back to the RLS default.
    assert (
        classify_finding_category("policy needs review", default=C.RLS_MISCONFIGURATION)
        == C.RLS_MISCONFIGURATION
    )


def test_injection_default_used_when_no_keyword_match():
    assert (
        classify_finding_category("suspicious sink", default=C.INJECTION_RISK)
        == C.INJECTION_RISK
    )


def test_default_is_auth_weakness():
    assert classify_finding_category("something vague") == C.AUTH_WEAKNESS


def test_empty_text_returns_default():
    assert classify_finding_category("") == C.AUTH_WEAKNESS
    assert classify_finding_category(None) == C.AUTH_WEAKNESS


def test_specific_beats_generic_ordering():
    # Contains both "authentication" and "sql injection" — injection must win.
    assert (
        classify_finding_category("Broken authentication enables SQL injection")
        == C.INJECTION_RISK
    )
