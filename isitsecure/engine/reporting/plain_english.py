"""Rule-based, LLM-free plain-English framing for security findings.

This module is the single source of truth for the "vibe-coder readiness"
layer: it turns technical findings into jargon-free language a non-technical
site owner can act on — WITHOUT calling an LLM. Everything here is pure,
deterministic, and keyed on a finding's ``FindingCategory`` (with severity
and scanner as secondary signals).

It provides the rule-based capabilities behind Wave 1:

* :func:`explain_finding` — a three-part plain-English explanation per
  finding (*what it is · what an attacker could do · what to do*).  (#41)
* :func:`expand_glossary` / :data:`GLOSSARY` — inline acronym/jargon
  definitions (XSS, IDOR, RLS, CSRF, ...).  (#42)
* :func:`calculate_grade` / :data:`GRADE_LEGEND` — the granular
  A+/A/A-/B+/B/C+/C/D/F ladder with a plain-language legend.  (#43)
* :func:`business_impact` — consequence-first framing ("someone could read
  your customers' data") used to lead the risk summary and order the
  checklist.  (#44)
* :func:`launch_verdict` — the go/no-go launch-readiness line rendered at
  the very top of every report.  (#57)

The existing LLM owner-summary can still layer on top of this baseline, but
this baseline is human-readable on its own and works with ``--llm none``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from isitsecure.engine.enums import FindingCategory


# ---------------------------------------------------------------------------
# #42 — Inline glossary / acronym expansion
# ---------------------------------------------------------------------------

# Jargon term (lowercased key) -> one-line, plain-language definition.
# Definitions avoid further jargon so a non-technical reader gets it in one
# read. Keys are matched case-insensitively as whole words.
GLOSSARY: dict[str, str] = {
    "xss": "Cross-Site Scripting — an attacker can make your page run their "
           "code in a visitor's browser",
    "idor": "Insecure Direct Object Reference — one user can open another "
            "user's records just by changing an ID in the address bar",
    "bola": "Broken Object-Level Authorization — the API hands back a "
            "record without checking it belongs to the caller (same idea "
            "as IDOR)",
    "rls": "Row-Level Security — the database rule that stops one user from "
           "reading another user's rows",
    "csrf": "Cross-Site Request Forgery — a malicious site tricks a "
            "logged-in user's browser into making changes they didn't intend",
    "ssrf": "Server-Side Request Forgery — an attacker makes your server "
            "fetch a URL of their choosing, often to reach internal systems",
    "xxe": "XML External Entity — a booby-trapped XML file makes your server "
           "read local files or make network requests",
    "ssti": "Server-Side Template Injection — attacker input is run as code "
            "by your page-rendering engine",
    "sqli": "SQL Injection — attacker input is run as a database command, "
            "letting them read or change your data",
    "cors": "Cross-Origin Resource Sharing — the browser rule that decides "
            "which other websites may read responses from your API",
    "jwt": "JSON Web Token — the signed token your app uses to remember a "
           "logged-in user",
    "sast": "Static analysis — inspecting your source code for security "
            "problems without running it",
    "dast": "Dynamic analysis — probing your running app from the outside, "
            "the way a real attacker would",
    "pii": "Personally Identifiable Information — data that identifies a "
           "person, like names, emails, or payment details",
    "rce": "Remote Code Execution — an attacker can run their own programs "
           "on your server",
    "sri": "Subresource Integrity — a check that a third-party script "
           "hasn't been tampered with before your page runs it",
    "csp": "Content Security Policy — a browser rule-set that limits what "
           "scripts your page is allowed to run",
    "mfa": "Multi-Factor Authentication — a second login step (like a code "
           "from your phone) on top of a password",
    "rbac": "Role-Based Access Control — deciding what a user can do based "
            "on their assigned role",
    "kms": "Key Management Service — a managed vault for encryption keys and "
           "secrets",
    "tls": "Transport Layer Security — the encryption behind HTTPS that "
           "protects data in transit",
    "cve": "Common Vulnerabilities and Exposures — a public catalog ID for "
           "a known security flaw",
}


def expand_glossary(term: str) -> str | None:
    """Return the plain-language definition for a jargon ``term``, or None.

    Matching is case-insensitive on the whole term.
    """
    return GLOSSARY.get(term.strip().lower())


def annotate_first_use(text: str) -> str:
    """Add a parenthetical definition after the first glossary term in ``text``.

    Used for CLI output where tooltips aren't available. Only the FIRST
    matching term is annotated, to keep lines readable. Returns ``text``
    unchanged when no known term is present.
    """
    lowered = text.lower()
    best: tuple[int, str] | None = None
    for term in GLOSSARY:
        # Whole-word, case-insensitive match.
        match = re.search(rf"\b{re.escape(term)}\b", lowered)
        if match and (best is None or match.start() < best[0]):
            best = (match.start(), term)

    if best is None:
        return text

    start, term = best
    definition = GLOSSARY[term]
    # Insert the parenthetical right after the matched term (preserve casing).
    end = start + len(term)
    return f"{text[:end]} ({definition}){text[end:]}"


# ---------------------------------------------------------------------------
# #41 — Rule-based plain-English explanation per finding
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlainExplanation:
    """Three-part jargon-free explanation of a finding.

    Every part is a complete sentence written for a non-technical reader.
    """

    what_it_is: str
    attacker_could: str
    what_to_do: str

    def as_dict(self) -> dict[str, str]:
        return {
            "what_it_is": self.what_it_is,
            "attacker_could": self.attacker_could,
            "what_to_do": self.what_to_do,
        }

    def as_text(self) -> str:
        """Render as a compact multi-line block for CLI/plain-text output."""
        return (
            f"What it is: {self.what_it_is}\n"
            f"What an attacker could do: {self.attacker_could}\n"
            f"What to do: {self.what_to_do}"
        )


# Per-category plain-English explanations. Keyed on FindingCategory.value.
# Seed material adapted from the triage remediation fallbacks so the wording
# stays consistent with the rest of the tool.
_CATEGORY_EXPLANATIONS: dict[str, PlainExplanation] = {
    FindingCategory.EXPOSED_SECRETS.value: PlainExplanation(
        what_it_is=(
            "A password, API key, or other secret is sitting in a place "
            "people outside your team can reach — such as your code, your "
            "git history, or the files your website ships to browsers."
        ),
        attacker_could=(
            "Use that secret to log in as your app, run up charges on your "
            "paid services, or read and change your customers' data."
        ),
        what_to_do=(
            "Rotate (replace) the exposed secret now so the old one stops "
            "working, then store secrets in environment variables or a "
            "secrets manager instead of in code."
        ),
    ),
    FindingCategory.MISSING_HEADERS.value: PlainExplanation(
        what_it_is=(
            "Your site is missing some standard safety settings that tell "
            "browsers how to protect your visitors."
        ),
        attacker_could=(
            "Make attacks like clickjacking or content-sniffing easier, "
            "which can trick your users or leak information."
        ),
        what_to_do=(
            "Add the recommended security headers (your framework usually "
            "has a one-line setting or a helmet-style middleware for this)."
        ),
    ),
    FindingCategory.DEAD_FUNCTIONALITY.value: PlainExplanation(
        what_it_is=(
            "There is leftover or unused functionality in your app that no "
            "longer serves a purpose."
        ),
        attacker_could=(
            "Poke at forgotten, unmaintained code paths that often have "
            "weaker protections than the rest of your app."
        ),
        what_to_do=(
            "Remove code and endpoints you no longer use so there is less "
            "surface for an attacker to probe."
        ),
    ),
    FindingCategory.DEPENDENCY_VULNERABILITY.value: PlainExplanation(
        what_it_is=(
            "Your app uses an outside software package that has a publicly "
            "known security flaw."
        ),
        attacker_could=(
            "Use a ready-made, published exploit for that flaw against your "
            "app — no custom effort required on their part."
        ),
        what_to_do=(
            "Update the affected package to a patched version (e.g. run your "
            "package manager's audit/upgrade command) and redeploy."
        ),
    ),
    FindingCategory.CLIENT_EXPOSURE.value: PlainExplanation(
        what_it_is=(
            "Sensitive information is being sent to the visitor's browser "
            "where anyone can view it."
        ),
        attacker_could=(
            "Read that information straight from the page or the browser's "
            "developer tools without any special access."
        ),
        what_to_do=(
            "Keep secrets and private data on the server; only send the "
            "browser what it actually needs to display."
        ),
    ),
    FindingCategory.SOURCE_MAP_LEAK.value: PlainExplanation(
        what_it_is=(
            "Your published site includes source maps that reveal your "
            "original, un-minified source code."
        ),
        attacker_could=(
            "Read your real code to find hidden endpoints, secrets, or logic "
            "flaws to attack."
        ),
        what_to_do=(
            "Stop publishing source maps to production, or restrict them so "
            "only your team can access them."
        ),
    ),
    FindingCategory.AUTH_WEAKNESS.value: PlainExplanation(
        what_it_is=(
            "Part of your app doesn't properly check who is asking or "
            "whether they're allowed to do what they're asking."
        ),
        attacker_could=(
            "Access pages, actions, or data meant for other users — or for "
            "no one but you — by simply asking for them."
        ),
        what_to_do=(
            "Add a login/permission check on the affected action and confirm "
            "the requester actually owns the resource they're touching."
        ),
    ),
    FindingCategory.INJECTION_RISK.value: PlainExplanation(
        what_it_is=(
            "Your app takes text from a user and hands it to your database "
            "or system without cleaning it first, so the input can be "
            "treated as commands instead of plain data."
        ),
        attacker_could=(
            "Craft input that reads, changes, or deletes your data, or runs "
            "commands on your server."
        ),
        what_to_do=(
            "Use parameterized queries and validate all user input, so text "
            "is always treated as data and never as a command."
        ),
    ),
    FindingCategory.RLS_MISCONFIGURATION.value: PlainExplanation(
        what_it_is=(
            "Your database's per-user access rules (Row-Level Security) are "
            "missing or too loose, so the database isn't separating one "
            "user's rows from another's."
        ),
        attacker_could=(
            "Read or change other customers' records directly, even if your "
            "app's screens try to hide them."
        ),
        what_to_do=(
            "Turn on Row-Level Security and add a policy so each user can "
            "only see and edit rows that belong to them."
        ),
    ),
    FindingCategory.UNENCRYPTED_PII.value: PlainExplanation(
        what_it_is=(
            "Personal customer information is being stored without "
            "encryption, so it's readable to anyone who reaches the data."
        ),
        attacker_could=(
            "Walk away with names, emails, or payment details in plain text "
            "if they get into your database — and you may face legal "
            "penalties for the leak."
        ),
        what_to_do=(
            "Encrypt personal data at rest (ideally with a managed key "
            "service) to meet privacy rules like GDPR and CCPA."
        ),
    ),
    FindingCategory.CORS_MISCONFIGURATION.value: PlainExplanation(
        what_it_is=(
            "Your API tells browsers that other websites are allowed to read "
            "its responses when they shouldn't be."
        ),
        attacker_could=(
            "Build a malicious website that quietly reads your logged-in "
            "users' data from your API."
        ),
        what_to_do=(
            "Restrict cross-origin access to only the specific websites you "
            "trust, and never combine a wildcard origin with credentials."
        ),
    ),
    FindingCategory.OPEN_REDIRECT.value: PlainExplanation(
        what_it_is=(
            "A link on your site can be pointed at any external website an "
            "attacker chooses."
        ),
        attacker_could=(
            "Send a link that looks like it goes to your trusted site but "
            "bounces users to a phishing page."
        ),
        what_to_do=(
            "Only allow redirects to a known list of safe, in-app "
            "destinations."
        ),
    ),
    FindingCategory.EXPOSED_API_ENDPOINT.value: PlainExplanation(
        what_it_is=(
            "An API address that should be private is reachable by anyone on "
            "the internet."
        ),
        attacker_could=(
            "Call that endpoint directly to pull data or trigger actions "
            "without going through your app."
        ),
        what_to_do=(
            "Require authentication on the endpoint, or block it at the "
            "network/firewall level if it isn't meant to be public."
        ),
    ),
    FindingCategory.MISSING_SRI.value: PlainExplanation(
        what_it_is=(
            "Your page loads a third-party script without checking that it "
            "hasn't been tampered with."
        ),
        attacker_could=(
            "Swap in a malicious version of that script and run it for every "
            "one of your visitors."
        ),
        what_to_do=(
            "Add a Subresource Integrity check so the browser refuses to "
            "run a modified version of the script."
        ),
    ),
    FindingCategory.MIXED_CONTENT.value: PlainExplanation(
        what_it_is=(
            "A secure (HTTPS) page on your site loads some resources over an "
            "insecure (HTTP) connection."
        ),
        attacker_could=(
            "Intercept or alter those insecure resources on public Wi-Fi to "
            "attack your visitors."
        ),
        what_to_do=(
            "Load every resource over HTTPS so the whole page is encrypted "
            "end to end."
        ),
    ),
    FindingCategory.INFO_DISCLOSURE.value: PlainExplanation(
        what_it_is=(
            "Your app reveals internal details — like error traces, version "
            "numbers, or hidden fields — that it shouldn't share publicly."
        ),
        attacker_could=(
            "Use those details to map out your system and find a more "
            "specific way in."
        ),
        what_to_do=(
            "Return only the information a user needs; hide internal errors, "
            "identifiers, and metadata from public responses."
        ),
    ),
    FindingCategory.IDOR.value: PlainExplanation(
        what_it_is=(
            "Your app trusts an ID from the user (in the URL or request) to "
            "decide what to show, without checking that the record actually "
            "belongs to them."
        ),
        attacker_could=(
            "Change that ID to read, edit, or delete another customer's "
            "records — for example bumping /order/41 to /order/42."
        ),
        what_to_do=(
            "On every request, confirm the logged-in user owns the record "
            "they asked for before returning or changing it."
        ),
    ),
    FindingCategory.PRIVILEGE_ESCALATION.value: PlainExplanation(
        what_it_is=(
            "A regular user can gain powers meant only for admins or other "
            "higher-privilege roles."
        ),
        attacker_could=(
            "Give themselves admin access and then take over accounts, data, "
            "or your whole app."
        ),
        what_to_do=(
            "Enforce role checks on every privileged action on the server, "
            "and never trust a role sent by the client."
        ),
    ),
}


# Fallback used when a category has no specific entry (keeps output safe and
# still human-readable rather than blank).
_GENERIC_EXPLANATION = PlainExplanation(
    what_it_is=(
        "The scan found a security issue in this part of your app."
    ),
    attacker_could=(
        "Potentially misuse this weakness to reach data or actions they "
        "shouldn't have."
    ),
    what_to_do=(
        "Review the finding details below and apply the recommended fix for "
        "this type of issue before launch."
    ),
)


def explain_finding_category(category: FindingCategory | str) -> PlainExplanation:
    """Return the rule-based plain-English explanation for a category."""
    key = category.value if isinstance(category, FindingCategory) else str(category)
    return _CATEGORY_EXPLANATIONS.get(key, _GENERIC_EXPLANATION)


def explain_finding(finding) -> PlainExplanation:
    """Return a plain-English explanation for a :class:`DeepFinding`.

    Rule-based and LLM-free — keyed on the finding's category.  The
    ``finding`` is duck-typed (only ``.category`` is required) so this can
    be called on any finding-like object without importing the model.
    """
    return explain_finding_category(getattr(finding, "category", ""))


# ---------------------------------------------------------------------------
# #44 — Business-impact-first framing
# ---------------------------------------------------------------------------

# Consequence-first, one-line framing per category. This leads with what it
# means for the OWNER ("someone could read your customers' data") rather than
# the technical label. Used to order the checklist and headline the summary.
_CATEGORY_BUSINESS_IMPACT: dict[str, str] = {
    FindingCategory.EXPOSED_SECRETS.value:
        "Someone could steal a key and run up charges or access your data.",
    FindingCategory.MISSING_HEADERS.value:
        "Your visitors are more exposed to browser-based tricks and scams.",
    FindingCategory.DEAD_FUNCTIONALITY.value:
        "Forgotten, unmaintained code gives attackers an extra way in.",
    FindingCategory.DEPENDENCY_VULNERABILITY.value:
        "Attackers can use a known, off-the-shelf exploit against your app.",
    FindingCategory.CLIENT_EXPOSURE.value:
        "Private information is visible to anyone who opens your page.",
    FindingCategory.SOURCE_MAP_LEAK.value:
        "Your original source code is readable by anyone, revealing secrets.",
    FindingCategory.AUTH_WEAKNESS.value:
        "Someone could do things or see pages meant only for logged-in users.",
    FindingCategory.INJECTION_RISK.value:
        "Someone could read, change, or delete your data through a form field.",
    FindingCategory.RLS_MISCONFIGURATION.value:
        "One customer could read or change another customer's records.",
    FindingCategory.UNENCRYPTED_PII.value:
        "A breach would expose your customers' personal data in plain text.",
    FindingCategory.CORS_MISCONFIGURATION.value:
        "A malicious website could quietly read your users' data from your API.",
    FindingCategory.OPEN_REDIRECT.value:
        "Your links could be used to send users to phishing sites.",
    FindingCategory.EXPOSED_API_ENDPOINT.value:
        "Anyone on the internet can call an API that should be private.",
    FindingCategory.MISSING_SRI.value:
        "A tampered third-party script could run for all your visitors.",
    FindingCategory.MIXED_CONTENT.value:
        "Part of your secure page is sent unencrypted and can be tampered with.",
    FindingCategory.INFO_DISCLOSURE.value:
        "Your app leaks internal details that help an attacker plan a break-in.",
    FindingCategory.IDOR.value:
        "Someone could read or change other customers' data by changing an ID.",
    FindingCategory.PRIVILEGE_ESCALATION.value:
        "A regular user could give themselves admin powers.",
}

_GENERIC_BUSINESS_IMPACT = (
    "This weakness could let someone reach data or actions they shouldn't."
)


def business_impact(category: FindingCategory | str) -> str:
    """Return the consequence-first, owner-facing one-liner for a category."""
    key = category.value if isinstance(category, FindingCategory) else str(category)
    return _CATEGORY_BUSINESS_IMPACT.get(key, _GENERIC_BUSINESS_IMPACT)


# ---------------------------------------------------------------------------
# #43 — Granular grade ladder A+/A/A-/B+/B/C+/C/D/F
# ---------------------------------------------------------------------------

# Plain-language legend for the whole ladder, shown near the grade.
GRADE_LEGEND = "A = safe to ship · C = fix soon · F = fix before launch"

# Per-grade plain-language labels. Reused by the report/CLI.
GRADE_LADDER_LABELS: dict[str, str] = {
    "A+": "Excellent — hardened, no issues found. Safe to ship.",
    "A": "Great — no meaningful issues. Safe to ship.",
    "A-": "Very good — a couple of minor issues to tidy up.",
    "B+": "Good — a few low-risk issues worth fixing.",
    "B": "Good — several low-risk issues to work through.",
    "C+": "Fair — a medium-risk issue or two need attention.",
    "C": "Fair — several medium-risk issues need attention.",
    "D": "Poor — at least one high-risk issue. Fix before launch.",
    "F": "Critical — a critical issue could expose data. Fix before launch.",
}


@dataclass(frozen=True)
class GradeResult:
    """A granular grade plus its plain-language label and legend."""

    grade: str
    label: str
    legend: str = GRADE_LEGEND


def calculate_grade(
    critical: int,
    high: int,
    medium: int,
    low: int,
    *,
    hardened: bool = False,
) -> GradeResult:
    """Compute the granular A+/A/A-/B+/B/C+/C/D/F grade (first match wins).

    Thresholds (per #43), evaluated top to bottom:

    * any critical            -> F
    * any high                -> D
    * 3+ medium               -> C
    * 1-2 medium              -> C+
    * 6+ low                  -> B
    * 3-5 low                 -> B+
    * 1-2 low                 -> A-
    * otherwise (0 findings)  -> A   (A+ only when ``hardened`` is True)

    ``hardened`` reserves A+ for a clean result that also passed extra
    hardening checks; callers that can't determine this pass False and a
    clean scan grades as a plain A.
    """
    if critical > 0:
        grade = "F"
    elif high > 0:
        grade = "D"
    elif medium >= 3:
        grade = "C"
    elif medium >= 1:
        grade = "C+"
    elif low >= 6:
        grade = "B"
    elif low >= 3:
        grade = "B+"
    elif low >= 1:
        grade = "A-"
    else:
        grade = "A+" if hardened else "A"

    return GradeResult(
        grade=grade,
        label=GRADE_LADDER_LABELS.get(grade, ""),
        legend=GRADE_LEGEND,
    )


def grade_base_letter(grade: str) -> str:
    """Return the base letter (A-F) of a granular grade like 'A-' or 'C+'.

    Used for coloring so 'A+', 'A', 'A-' all share the 'A' color, etc.
    """
    return grade[0] if grade else "?"


# ---------------------------------------------------------------------------
# #57 — Launch-readiness verdict
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LaunchVerdict:
    """A go/no-go launch-readiness line for the top of the report."""

    ready: bool
    headline: str  # includes a leading status emoji
    detail: str    # short supporting sentence (may be empty)

    def as_line(self) -> str:
        """Single-line rendering: headline plus detail."""
        if self.detail:
            return f"{self.headline} {self.detail}"
        return self.headline


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def launch_verdict(critical: int, high: int, medium: int = 0) -> LaunchVerdict:
    """Derive the go/no-go launch verdict from severity counts (#57).

    Rule-based and LLM-free. Leads with the consequence to the owner.
    """
    if critical > 0:
        return LaunchVerdict(
            ready=False,
            headline=(
                f"⛔ Not safe to launch yet — "
                f"{_plural(critical, 'critical issue')} could expose "
                f"customer data."
            ),
            detail="Fix these first.",
        )
    if high > 0:
        return LaunchVerdict(
            ready=False,
            headline=(
                f"⚠️ Hold off on launch — "
                f"{_plural(high, 'high-risk issue')} should be fixed first."
            ),
            detail="No critical issues, but these are serious.",
        )
    if medium > 0:
        return LaunchVerdict(
            ready=True,
            headline=(
                "✅ No critical or high-risk issues found — safe to launch."
            ),
            detail=(
                f"{_plural(medium, 'medium-risk issue')} to clean up soon."
            ),
        )
    return LaunchVerdict(
        ready=True,
        headline="✅ No critical issues found — safe to launch.",
        detail="",
    )
