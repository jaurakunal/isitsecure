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

It is also the single source of truth for Wave 2 remediation:

* :func:`remediation_for` / :data:`_CATEGORY_REMEDIATION` — specific,
  concrete fix guidance for every ``FindingCategory`` (no generic
  fallback for any of the 18 known categories).  (#47)
* :func:`framework_remediation` / :func:`remediation_detail` — stack-tailored,
  copy-pasteable snippets for config/DAST findings (Express / Next / FastAPI
  / Django / Flask / Supabase), with a generic fallback.  (#48)
* :func:`walkthrough_for` / :data:`_WALKTHROUGHS` — numbered step-by-step
  walkthroughs for the top-4 fixes (enable Supabase RLS · lock down CORS ·
  add an ownership check · rotate an exposed secret).  (#49)

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
# #47 — Specific remediation guidance for ALL 18 categories
# ---------------------------------------------------------------------------
#
# This is the SINGLE SOURCE OF TRUTH for remediation guidance. The triage
# service (``llm_triage_service._category_remediation``) and the report/CLI/UI
# renderers all delegate here so there is exactly one copy of every string.
#
# Each entry is SPECIFIC and concrete: it names the actual control to apply,
# the command to run, or the pattern to adopt — never a generic "review this
# finding". Guidance is rule-based and works with ``--llm none``.


def _key(category: FindingCategory | str) -> str:
    """Normalise a category (enum or string) to its ``.value`` key."""
    return category.value if isinstance(category, FindingCategory) else str(category)


_CATEGORY_REMEDIATION: dict[str, str] = {
    FindingCategory.EXPOSED_SECRETS.value: (
        "Rotate the exposed secret now so the leaked value stops working, "
        "then move it out of code and into an environment variable or a "
        "secrets manager (e.g. AWS Secrets Manager, Doppler, Vault). Scrub "
        "it from git history (git filter-repo / BFG) and, if it shipped to "
        "the browser, from your built bundle. Add a pre-commit secret scanner "
        "(gitleaks) so it can't be re-committed."
    ),
    FindingCategory.MISSING_HEADERS.value: (
        "Add the standard security response headers — Content-Security-Policy, "
        "X-Content-Type-Options: nosniff, X-Frame-Options: DENY (or "
        "frame-ancestors 'none' in CSP), Strict-Transport-Security, and "
        "Referrer-Policy. Most stacks set these with one middleware (e.g. "
        "Helmet on Express, next.config headers() on Next.js, "
        "SecurityMiddleware on Django)."
    ),
    FindingCategory.DEAD_FUNCTIONALITY.value: (
        "Delete the unused code path, route, or feature flag rather than "
        "leaving it disabled — dead code still ships and still runs if "
        "reached. Remove its routes, its tests, and any config that keeps "
        "it wired up, then redeploy so the attack surface actually shrinks."
    ),
    FindingCategory.DEPENDENCY_VULNERABILITY.value: (
        "Upgrade the affected package to the first patched version listed in "
        "the advisory. Run your package manager's audit-and-fix "
        "(`npm audit fix`, `pnpm audit --fix`, `pip-audit`, or "
        "`poetry update <pkg>`), verify nothing breaks, and redeploy. If no "
        "fix exists yet, pin to a safe version or apply the advisory's "
        "workaround."
    ),
    FindingCategory.CLIENT_EXPOSURE.value: (
        "Move the sensitive value off the client. Keep secrets and private "
        "data server-side and expose only what the UI must render, through "
        "an authenticated API. In bundlers, only variables with a public "
        "prefix (NEXT_PUBLIC_, VITE_, REACT_APP_) should ever reach the "
        "browser — audit those, and rotate anything already leaked."
    ),
    FindingCategory.SOURCE_MAP_LEAK.value: (
        "Stop publishing source maps to production. Turn off source-map "
        "emission for prod builds (`productionBrowserSourceMaps: false` in "
        "Next.js, `build.sourcemap: false` in Vite, `devtool: false` in "
        "Webpack), or upload them privately to your error tracker (Sentry) "
        "and block `.map` files at the CDN/edge so they aren't publicly "
        "downloadable."
    ),
    FindingCategory.AUTH_WEAKNESS.value: (
        "Add a server-side authentication and authorization check on the "
        "affected route: verify the request carries a valid session/token, "
        "then confirm that user is allowed to perform this action on this "
        "specific resource. Enforce it in middleware or a shared guard, not "
        "per-handler, and back it with a database-level constraint so it "
        "can't be bypassed."
    ),
    FindingCategory.INJECTION_RISK.value: (
        "Never build queries or commands by concatenating user input. Use "
        "parameterized queries / prepared statements (or your ORM's safe "
        "query builder), and validate input against an allow-list of the "
        "shape you expect. For shell calls, pass an argument array instead "
        "of a string and avoid a shell entirely where possible."
    ),
    FindingCategory.RLS_MISCONFIGURATION.value: (
        "Enable Row-Level Security on the table (`ALTER TABLE <t> ENABLE ROW "
        "LEVEL SECURITY;`) and add a policy that scopes every row to its "
        "owner, e.g. `USING (auth.uid() = user_id)`. Add policies for each "
        "of SELECT/INSERT/UPDATE/DELETE you allow — with RLS on and no "
        "policy, access is denied by default, which is the safe state."
    ),
    FindingCategory.UNENCRYPTED_PII.value: (
        "Encrypt personal data at rest. Turn on your database's encryption "
        "(e.g. Postgres pgcrypto or a managed KMS-backed volume) and apply "
        "application-level field encryption to the most sensitive columns. "
        "Store keys in a KMS, not in the app, and confirm backups are "
        "encrypted too — this is required for GDPR/CCPA."
    ),
    FindingCategory.CORS_MISCONFIGURATION.value: (
        "Replace any wildcard `Access-Control-Allow-Origin: *` (and any "
        "origin-reflecting logic) with an explicit allow-list of the exact "
        "origins you trust. Never combine a wildcard origin with "
        "`Allow-Credentials: true`. Limit allowed methods and headers to "
        "what your API actually uses."
    ),
    FindingCategory.OPEN_REDIRECT.value: (
        "Don't redirect to a raw user-supplied URL. Validate the target "
        "against an allow-list of in-app paths (or a set of trusted hosts), "
        "and prefer redirecting to a relative path that starts with a single "
        "`/`. Reject absolute URLs, protocol-relative `//evil.com`, and "
        "anything that resolves off-site."
    ),
    FindingCategory.EXPOSED_API_ENDPOINT.value: (
        "Put the endpoint behind authentication and authorization, or block "
        "it at the network edge (firewall, security group, WAF, or an "
        "ingress allow-list) if it isn't meant to be public. Remove any "
        "debug/admin/internal route from the public deployment entirely."
    ),
    FindingCategory.MISSING_SRI.value: (
        "Add a Subresource Integrity hash to every third-party <script> and "
        "<link> tag: `integrity=\"sha384-...\" crossorigin=\"anonymous\"`. "
        "Generate the hash with `openssl dgst -sha384 -binary file.js | "
        "openssl base64 -A`. Better still, self-host the asset so its "
        "contents can't change under you."
    ),
    FindingCategory.MIXED_CONTENT.value: (
        "Load every subresource over HTTPS — change `http://` URLs for "
        "scripts, styles, images, and fetch calls to `https://` (or "
        "protocol-relative `//`). Add `Content-Security-Policy: "
        "upgrade-insecure-requests` so the browser auto-upgrades any "
        "remaining HTTP requests, and fix the origin of the asset."
    ),
    FindingCategory.INFO_DISCLOSURE.value: (
        "Return only the fields the client needs — apply explicit field "
        "projection / a serializer allow-list and strip internal IDs and "
        "metadata. Disable stack traces and verbose errors in production "
        "(generic 500 responses), and remove server/framework version "
        "banners from responses."
    ),
    FindingCategory.IDOR.value: (
        "On every request that takes a record ID, confirm the authenticated "
        "user owns (or is authorized for) that specific record before "
        "returning or modifying it — e.g. scope the query with "
        "`WHERE id = :id AND user_id = :current_user`. Prefer that a lookup "
        "for someone else's record returns 404/403, and consider "
        "non-guessable IDs (UUIDs) as defence in depth."
    ),
    FindingCategory.PRIVILEGE_ESCALATION.value: (
        "Enforce the required role on the server for every privileged action "
        "— never trust a role, flag, or `isAdmin` value sent by the client. "
        "Check the role against the session/token on the backend, keep the "
        "authoritative role in the database, and deny by default when the "
        "role is missing or unrecognised."
    ),
}


_GENERIC_REMEDIATION = (
    "Apply the appropriate security control for this issue type: validate "
    "and restrict the affected input, action, or exposure, and confirm the "
    "fix on the running app before launch."
)


def remediation_for(category: FindingCategory | str) -> str:
    """Return the specific, concrete remediation guidance for a category.

    Single source of truth for #47. Falls back to a safe generic string only
    for a genuinely unknown category (never for one of the 18 known ones).
    """
    return _CATEGORY_REMEDIATION.get(_key(category), _GENERIC_REMEDIATION)


# ---------------------------------------------------------------------------
# #48 — Framework-aware remediation for DAST (config/instructional) findings
# ---------------------------------------------------------------------------
#
# DAST findings have no code location, so their fix is configuration or an
# instruction. Where we know the stack (framework/backend from the report), we
# emit a concrete, copy-pasteable snippet TAILORED to it; otherwise we return
# ``None`` and callers fall back to the generic ``remediation_for`` text.
#
# Keyed as _STACK_REMEDIATION[category][stack_key]. ``stack_key`` matches a
# FrameworkType / BackendType ``.value`` (e.g. "express", "nextjs", "fastapi",
# "django", "flask", "supabase").


def _normalize_stack(value: str | None) -> str:
    """Lower-case, trimmed stack token; '' when unknown/empty."""
    v = (value or "").strip().lower()
    return "" if v in ("", "unknown", "custom", "none") else v


# Category -> { framework_or_backend_key -> copy-pasteable snippet }.
_STACK_REMEDIATION: dict[str, dict[str, str]] = {
    FindingCategory.MISSING_HEADERS.value: {
        "express": (
            "Install and mount Helmet — it sets the core security headers in "
            "one line:\n"
            "    import helmet from 'helmet';\n"
            "    app.use(helmet());"
        ),
        "nextjs": (
            "Add the headers in next.config.js so they apply to every route:\n"
            "    async headers() {\n"
            "      return [{ source: '/:path*', headers: [\n"
            "        { key: 'X-Content-Type-Options', value: 'nosniff' },\n"
            "        { key: 'X-Frame-Options', value: 'DENY' },\n"
            "        { key: 'Strict-Transport-Security',\n"
            "          value: 'max-age=63072000; includeSubDomains; preload' },\n"
            "        { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },\n"
            "      ]}];\n"
            "    }"
        ),
        "fastapi": (
            "Add a middleware that stamps the headers on every response:\n"
            "    @app.middleware('http')\n"
            "    async def security_headers(request, call_next):\n"
            "        resp = await call_next(request)\n"
            "        resp.headers['X-Content-Type-Options'] = 'nosniff'\n"
            "        resp.headers['X-Frame-Options'] = 'DENY'\n"
            "        resp.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'\n"
            "        return resp"
        ),
        "flask": (
            "Set the headers in an after_request hook (or use flask-talisman):\n"
            "    @app.after_request\n"
            "    def set_secure_headers(resp):\n"
            "        resp.headers['X-Content-Type-Options'] = 'nosniff'\n"
            "        resp.headers['X-Frame-Options'] = 'DENY'\n"
            "        resp.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains'\n"
            "        return resp"
        ),
        "django": (
            "Django ships these — set in settings.py:\n"
            "    SECURE_HSTS_SECONDS = 63072000\n"
            "    SECURE_CONTENT_TYPE_NOSNIFF = True\n"
            "    X_FRAME_OPTIONS = 'DENY'\n"
            "    SECURE_SSL_REDIRECT = True\n"
            "and keep django.middleware.security.SecurityMiddleware enabled."
        ),
    },
    FindingCategory.CORS_MISCONFIGURATION.value: {
        "express": (
            "Configure the cors package with an explicit origin allow-list — "
            "not '*':\n"
            "    import cors from 'cors';\n"
            "    app.use(cors({\n"
            "      origin: ['https://app.example.com'],\n"
            "      credentials: true,\n"
            "    }));"
        ),
        "nextjs": (
            "In your route handler, echo back only allowed origins — never '*' "
            "with credentials:\n"
            "    const ALLOWED = new Set(['https://app.example.com']);\n"
            "    const origin = req.headers.get('origin') ?? '';\n"
            "    if (ALLOWED.has(origin)) {\n"
            "      res.headers.set('Access-Control-Allow-Origin', origin);\n"
            "      res.headers.set('Access-Control-Allow-Credentials', 'true');\n"
            "    }"
        ),
        "fastapi": (
            "Use CORSMiddleware with explicit origins (a list, never ['*'] "
            "alongside credentials):\n"
            "    from fastapi.middleware.cors import CORSMiddleware\n"
            "    app.add_middleware(CORSMiddleware,\n"
            "        allow_origins=['https://app.example.com'],\n"
            "        allow_credentials=True,\n"
            "        allow_methods=['GET', 'POST'],\n"
            "        allow_headers=['Authorization', 'Content-Type'])"
        ),
        "flask": (
            "Use flask-cors scoped to specific origins:\n"
            "    from flask_cors import CORS\n"
            "    CORS(app, origins=['https://app.example.com'],\n"
            "         supports_credentials=True)"
        ),
        "django": (
            "With django-cors-headers, allow-list explicit origins in "
            "settings.py (never CORS_ALLOW_ALL_ORIGINS = True with "
            "credentials):\n"
            "    CORS_ALLOWED_ORIGINS = ['https://app.example.com']\n"
            "    CORS_ALLOW_CREDENTIALS = True"
        ),
    },
    FindingCategory.OPEN_REDIRECT.value: {
        "express": (
            "Validate the redirect target against an allow-list before "
            "res.redirect():\n"
            "    const ALLOWED = new Set(['/dashboard', '/settings']);\n"
            "    const to = String(req.query.next || '');\n"
            "    res.redirect(ALLOWED.has(to) ? to : '/');"
        ),
        "nextjs": (
            "Only redirect to in-app relative paths; reject absolute/"
            "protocol-relative URLs:\n"
            "    const to = searchParams.get('next') ?? '/';\n"
            "    const safe = to.startsWith('/') && !to.startsWith('//');\n"
            "    redirect(safe ? to : '/');"
        ),
        "fastapi": (
            "Allow-list redirect targets rather than trusting the parameter:\n"
            "    ALLOWED = {'/dashboard', '/settings'}\n"
            "    target = request.query_params.get('next', '/')\n"
            "    return RedirectResponse(target if target in ALLOWED else '/')"
        ),
        "flask": (
            "Check the target is a local path before redirecting:\n"
            "    from urllib.parse import urlparse\n"
            "    target = request.args.get('next', '/')\n"
            "    if urlparse(target).netloc or not target.startswith('/'):\n"
            "        target = '/'\n"
            "    return redirect(target)"
        ),
        "django": (
            "Use Django's built-in safe-URL check:\n"
            "    from django.utils.http import url_has_allowed_host_and_scheme\n"
            "    nxt = request.GET.get('next', '')\n"
            "    if not url_has_allowed_host_and_scheme(nxt, {request.get_host()}):\n"
            "        nxt = '/'\n"
            "    return redirect(nxt)"
        ),
    },
    FindingCategory.IDOR.value: {
        "express": (
            "Scope the lookup to the current user so another user's ID can't "
            "be fetched:\n"
            "    const row = await db.order.findFirst({\n"
            "      where: { id: req.params.id, userId: req.user.id },\n"
            "    });\n"
            "    if (!row) return res.sendStatus(404);"
        ),
        "nextjs": (
            "In the route handler, filter by the session user, not just the "
            "id:\n"
            "    const session = await auth();\n"
            "    const row = await db.order.findFirst({\n"
            "      where: { id: params.id, userId: session.user.id },\n"
            "    });\n"
            "    if (!row) return new Response(null, { status: 404 });"
        ),
        "fastapi": (
            "Add the ownership predicate to the query and 404 on a miss:\n"
            "    row = db.query(Order).filter(\n"
            "        Order.id == order_id,\n"
            "        Order.user_id == current_user.id,\n"
            "    ).first()\n"
            "    if row is None:\n"
            "        raise HTTPException(status_code=404)"
        ),
        "django": (
            "Filter the queryset by the request user (or use get_object_or_404 "
            "with the owner):\n"
            "    order = get_object_or_404(Order, id=pk, user=request.user)"
        ),
        "supabase": (
            "Let Row-Level Security enforce ownership at the database so the "
            "id alone can't reach another user's row:\n"
            "    alter table orders enable row level security;\n"
            "    create policy owner_read on orders\n"
            "      for select using (auth.uid() = user_id);"
        ),
    },
    FindingCategory.PRIVILEGE_ESCALATION.value: {
        "express": (
            "Gate privileged routes with a server-side role check middleware "
            "— never trust a client-sent role:\n"
            "    const requireAdmin = (req, res, next) =>\n"
            "      req.user?.role === 'admin' ? next() : res.sendStatus(403);\n"
            "    app.post('/admin/:x', requireAdmin, handler);"
        ),
        "nextjs": (
            "Check the role from the server session inside the handler:\n"
            "    const session = await auth();\n"
            "    if (session?.user.role !== 'admin')\n"
            "      return new Response(null, { status: 403 });"
        ),
        "fastapi": (
            "Enforce the role with a dependency on every privileged route:\n"
            "    def require_admin(user=Depends(get_current_user)):\n"
            "        if user.role != 'admin':\n"
            "            raise HTTPException(status_code=403)\n"
            "        return user\n"
            "    @app.post('/admin/x')\n"
            "    def action(admin=Depends(require_admin)): ..."
        ),
        "django": (
            "Protect the view with a permission check against the DB role:\n"
            "    from django.contrib.auth.decorators import "
            "permission_required\n"
            "    @permission_required('app.admin_action', raise_exception=True)\n"
            "    def admin_action(request): ..."
        ),
    },
    FindingCategory.MISSING_SRI.value: {
        "nextjs": (
            "Next.js can add SRI to its own build output — enable it, and "
            "self-host third-party scripts where possible:\n"
            "    // next.config.js\n"
            "    experimental: { sri: { algorithm: 'sha384' } }\n"
            "For external <script> tags, add integrity + crossorigin by hand."
        ),
    },
    FindingCategory.SOURCE_MAP_LEAK.value: {
        "nextjs": (
            "Disable browser source maps for production builds:\n"
            "    // next.config.js\n"
            "    module.exports = { productionBrowserSourceMaps: false };"
        ),
    },
    FindingCategory.CLIENT_EXPOSURE.value: {
        "nextjs": (
            "Only NEXT_PUBLIC_-prefixed env vars are sent to the browser — "
            "rename anything sensitive to drop that prefix and read it only in "
            "server components / route handlers, then rotate the leaked value."
        ),
    },
}


def framework_remediation(
    category: FindingCategory | str,
    framework: str | None = None,
    backend: str | None = None,
) -> str | None:
    """Return a stack-tailored remediation snippet for a DAST category, or None.

    Prefers a match on ``backend`` (e.g. Supabase RLS/IDOR) then ``framework``
    (Express/Next/FastAPI/…). Returns ``None`` when the stack is unknown or no
    tailored snippet exists — callers then fall back to ``remediation_for``.
    """
    per_category = _STACK_REMEDIATION.get(_key(category))
    if not per_category:
        return None
    for token in (_normalize_stack(backend), _normalize_stack(framework)):
        if token and token in per_category:
            return per_category[token]
    return None


def remediation_detail(
    category: FindingCategory | str,
    framework: str | None = None,
    backend: str | None = None,
) -> str:
    """Full remediation text: generic guidance + a stack-tailored snippet.

    This is the one call renderers use. It always returns the specific #47
    guidance, and appends the #48 stack-tailored, copy-pasteable snippet when
    the framework/backend is known and a snippet exists.
    """
    base = remediation_for(category)
    snippet = framework_remediation(category, framework, backend)
    if snippet:
        return f"{base}\n\nFor your stack:\n{snippet}"
    return base


# ---------------------------------------------------------------------------
# #49 — Step-by-step walkthroughs for the top 4 fixes
# ---------------------------------------------------------------------------
#
# Structured, numbered-step walkthroughs (data, not prose) for the four fixes
# owners hit most. Rendered as an expandable "How to fix, step by step" block
# on the HTML report, the web UI, and the CLI.


@dataclass(frozen=True)
class Walkthrough:
    """An ordered, numbered how-to for a specific fix."""

    title: str
    steps: tuple[str, ...]

    def as_dict(self) -> dict:
        return {"title": self.title, "steps": list(self.steps)}


# Keyed by FindingCategory.value. Only the top-4 fixes have a walkthrough;
# everything else relies on the (already specific) remediation text.
_WALKTHROUGHS: dict[str, Walkthrough] = {
    FindingCategory.RLS_MISCONFIGURATION.value: Walkthrough(
        title="Enable Supabase Row-Level Security",
        steps=(
            "Open your Supabase project → Table Editor, and pick the table "
            "that holds per-user data (e.g. `orders`).",
            "Turn on RLS for it: in SQL, run "
            "`alter table orders enable row level security;` (or toggle "
            "\"Enable RLS\" in the table's settings).",
            "Add a policy that limits each row to its owner, e.g. "
            "`create policy owner_all on orders for all "
            "using (auth.uid() = user_id) with check (auth.uid() = user_id);`.",
            "Make sure the table actually has the owner column the policy "
            "references (e.g. `user_id uuid references auth.users`), and "
            "backfill it on existing rows.",
            "Test as a real logged-in user: you should see only your own "
            "rows, and a query for someone else's id should return nothing.",
            "Repeat for every table with user data — with RLS on and no "
            "matching policy, access is denied, which is the safe default.",
        ),
    ),
    FindingCategory.CORS_MISCONFIGURATION.value: Walkthrough(
        title="Lock down CORS to trusted origins",
        steps=(
            "Find where your API sets CORS (a `cors()` call, a middleware, or "
            "an `Access-Control-Allow-Origin` header).",
            "Replace any `*` wildcard or origin-reflecting logic with an "
            "explicit allow-list of the exact origins you own "
            "(e.g. `https://app.example.com`).",
            "If your API uses cookies or auth headers, keep "
            "`Allow-Credentials: true` — but ONLY alongside an explicit "
            "origin, never with `*`.",
            "Restrict allowed methods and headers to what your API really "
            "uses (e.g. GET, POST + Authorization, Content-Type).",
            "Redeploy, then from a browser on a DIFFERENT origin confirm the "
            "request is now blocked, while your real frontend still works.",
        ),
    ),
    FindingCategory.IDOR.value: Walkthrough(
        title="Add an ownership check",
        steps=(
            "Locate the handler that reads an ID from the URL or body "
            "(e.g. `/orders/:id`).",
            "Identify the column that ties a record to its owner "
            "(commonly `user_id`).",
            "Change the lookup so it filters by BOTH the id and the current "
            "user, e.g. `where id = :id and user_id = :currentUser`.",
            "When no row matches, return 404 (or 403) — don't reveal that the "
            "record exists for someone else.",
            "Do the same for update and delete on that resource, not just "
            "read.",
            "Verify: log in as user A, note one of their record ids, then as "
            "user B try to open it — you should get denied.",
        ),
    ),
    FindingCategory.EXPOSED_SECRETS.value: Walkthrough(
        title="Rotate an exposed secret",
        steps=(
            "Treat the secret as compromised: in the provider's dashboard "
            "(Stripe, AWS, etc.) generate a NEW key/secret.",
            "Update your app to use the new value from an environment variable "
            "or secrets manager — never hard-code it back into the source.",
            "Revoke/delete the OLD secret so the leaked value stops working.",
            "Remove the secret from git history with git filter-repo or BFG, "
            "then force-push, and rotate again if others may have cloned it.",
            "If it shipped to the browser, rebuild so it's gone from your "
            "bundle, and check it isn't in any source map.",
            "Add a pre-commit secret scanner (e.g. gitleaks) so a secret "
            "can't be committed again.",
        ),
    ),
}


def walkthrough_for(category: FindingCategory | str) -> Walkthrough | None:
    """Return the step-by-step walkthrough for a category, or None.

    Only the top-4 fixes (#49) have a walkthrough; other categories rely on
    their specific remediation text.
    """
    return _WALKTHROUGHS.get(_key(category))


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
