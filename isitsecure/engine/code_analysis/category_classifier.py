"""Deterministic vulnerability-category classification for LLM findings.

The LLM code reviewer emits a free-text ``title`` + ``description`` per finding
but does not classify it, so historically every LLM finding was stamped
``AUTH_WEAKNESS``. That mislabels SQLi/XSS/SSRF/IDOR/etc. and — because the
remote fix flow groups pull requests by category — collapses dozens of unrelated
findings into a single, unreviewable "authentication weakness" PR.

This module infers the real :class:`FindingCategory` from the finding's text
using ordered keyword rules. It is deterministic (no extra LLM call, no added
variance), so it is cheap and fully unit-testable. The most specific categories
are matched first; anything unmatched falls back to a caller-supplied default
(driven by the review trigger — e.g. injection reviews default to
``INJECTION_RISK``, RLS reviews to ``RLS_MISCONFIGURATION``).
"""

from __future__ import annotations

from isitsecure.engine.enums import FindingCategory

# Ordered (category, keyword-substrings) rules. Order matters: the first rule
# with a substring present in the lowercased text wins, so place the most
# specific / highest-signal categories before broader, auth-adjacent ones.
# Every substring must already be lowercase.
_RULES: tuple[tuple[FindingCategory, tuple[str, ...]], ...] = (
    (FindingCategory.RLS_MISCONFIGURATION, (
        "row level security", "row-level security", "rls policy",
        "rls enabled", "rls disabled", "without rls", " rls ", "rls on",
    )),
    (FindingCategory.CORS_MISCONFIGURATION, (
        "cors", "cross-origin resource sharing",
        "access-control-allow-origin", "wildcard origin",
    )),
    (FindingCategory.OPEN_REDIRECT, (
        "open redirect", "open-redirect", "unvalidated redirect",
        "unvalidated forward",
    )),
    (FindingCategory.INJECTION_RISK, (
        "sql injection", "sqli", "nosql injection", "cross-site scripting",
        "xss", "command injection", "os command", "code injection",
        "template injection", "ssti", "ldap injection", "xpath injection",
        "server-side request forgery", "ssrf", "path traversal",
        "directory traversal", "prototype pollution", "insecure deserialization",
        "deserialization of untrusted",
    )),
    (FindingCategory.IDOR, (
        "idor", "insecure direct object", "ownership verification",
        "ownership check", "missing ownership", "another user's",
        "other users'", "access another user", "read another user",
        "direct object reference",
    )),
    (FindingCategory.PRIVILEGE_ESCALATION, (
        "privilege escalation", "privilege-escalation", "mass assignment",
        "mass-assignment", "escalate privilege", "role escalation",
        "arbitrary role", "user_id spoofing", "elevate privilege",
        "become admin", "grant admin",
    )),
    (FindingCategory.EXPOSED_SECRETS, (
        "hardcoded credential", "hardcoded secret", "hardcoded password",
        "hardcoded api key", "hardcoded default admin", "default admin credential",
        "connection string", "leaked secret", "exposed secret", "api key found",
    )),
    (FindingCategory.UNENCRYPTED_PII, (
        "unencrypted pii", "pii column", "pii without encryption",
        "personal data in plain", "unencrypted personal", "plaintext pii",
    )),
    (FindingCategory.MISSING_HEADERS, (
        "security header", "strict-transport", "hsts",
        "content-security-policy", "x-frame-options", "x-content-type-options",
    )),
    (FindingCategory.MISSING_SRI, ("subresource integrity", "missing sri", "integrity attribute")),
    (FindingCategory.MIXED_CONTENT, ("mixed content", "http resource on https")),
    (FindingCategory.SOURCE_MAP_LEAK, ("source map", "sourcemap", ".map file")),
    (FindingCategory.DEPENDENCY_VULNERABILITY, (
        "vulnerable dependency", "outdated dependency", "known cve",
        "vulnerable package", "outdated package",
    )),
    (FindingCategory.CLIENT_EXPOSURE, (
        "exposed to the client", "leaked to the browser", "client bundle",
        "shipped to the browser", "exposed in client",
    )),
    (FindingCategory.EXPOSED_API_ENDPOINT, (
        "no rate limit", "rate limiting", "publicly accessible endpoint",
        "unrestricted introspection", "graphql introspection",
    )),
    (FindingCategory.INFO_DISCLOSURE, (
        "information disclosure", "info disclosure", "sensitive data",
        "over-exposure", "over-exposed", "data over-exposure",
        "returned in response", "returned in the response",
        "internal response content", "sensitive user record", "stack trace",
        "verbose error", "token returned in", "reset token returned",
        "leaks internal", "exposes internal",
    )),
)


def classify_finding_category(
    text: str, default: FindingCategory = FindingCategory.AUTH_WEAKNESS
) -> FindingCategory:
    """Infer a :class:`FindingCategory` from a finding's title/description.

    Args:
        text: Free text to classify — typically ``f"{title} {description}"``.
        default: Category to return when no rule matches. Callers pass a
            trigger-appropriate default (injection reviews -> ``INJECTION_RISK``,
            RLS reviews -> ``RLS_MISCONFIGURATION``, general route reviews ->
            ``AUTH_WEAKNESS``).

    Returns:
        The most specific matching category, else ``default``.
    """
    haystack = (text or "").lower()
    for category, keywords in _RULES:
        if any(keyword in haystack for keyword in keywords):
            return category
    return default
