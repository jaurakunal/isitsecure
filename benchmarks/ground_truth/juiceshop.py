"""Ground truth for OWASP Juice Shop v20.1.1.

Seeded from the app's own `/api/Challenges` (113 challenges, saved in
`juiceshop_challenges.json`) and annotated per challenge:

- DETECTABLE maps each challenge our DAST can find *in principle* to its
  vulnerability class and (where known) the vulnerable endpoint. These form the
  recall denominator.
- Every other challenge is marked out-of-scope for DAST (crypto, CTF mechanics,
  deep business logic, LLM prompt injection, vulnerable-dependency/SAST items)
  and is reported separately, not counted against recall.

Endpoints are substrings matched against a finding's `endpoint_url`.
"""

from __future__ import annotations

import json
import pathlib

from .schema import SIGNATURES, GroundTruthItem

_HERE = pathlib.Path(__file__).parent
_CHALLENGES = _HERE / "juiceshop_challenges.json"

# key -> (vuln_class, endpoint_substring | None, auth_required)
DETECTABLE: dict[str, tuple[str, str | None, bool]] = {
    # --- Injection: SQLi ---
    "loginAdminChallenge": ("sqli", "user/login", False),
    "loginBenderChallenge": ("sqli", "user/login", False),
    "loginJimChallenge": ("sqli", "user/login", False),
    "ephemeralAccountantChallenge": ("sqli", "user/login", False),
    "unionSqlInjectionChallenge": ("sqli", "products/search", False),
    "dbSchemaChallenge": ("sqli", "products/search", False),
    "christmasSpecialChallenge": ("sqli", "products/search", False),
    # --- Injection: NoSQL ---
    "noSqlOrdersChallenge": ("nosql", "track-order", False),
    "noSqlReviewsChallenge": ("nosql", "products", True),
    "noSqlCommandChallenge": ("nosql", "products", True),
    # --- Injection: SSTI ---
    "sstiChallenge": ("ssti", None, True),
    # --- XSS ---
    "reflectedXssChallenge": ("xss", None, False),
    "restfulXssChallenge": ("xss", "Products", True),
    "localXssChallenge": ("xss", None, False),
    "persistedXssFeedbackChallenge": ("xss", "Feedback", False),
    "persistedXssUserChallenge": ("xss", "User", True),
    "httpHeaderXssChallenge": ("xss", None, False),
    "usernameXssChallenge": ("xss", None, True),
    # --- Broken Access Control ---
    "basketAccessChallenge": ("idor", "basket", True),
    "basketManipulateChallenge": ("idor", "BasketItem", True),
    "csrfChallenge": ("csrf", None, True),
    "ssrfChallenge": ("ssrf", None, True),
    "forgedFeedbackChallenge": ("idor", "Feedback", True),
    "forgedReviewChallenge": ("idor", "products", True),
    "feedbackChallenge": ("mass_assignment", "Feedback", False),
    "changeProductChallenge": ("idor", "Product", True),
    # --- Security Misconfiguration ---
    "errorHandlingChallenge": ("info_disclosure", None, False),
    "deprecatedInterfaceChallenge": ("file_upload", "file-upload", False),
    "svgInjectionChallenge": ("ssrf", "file-upload", True),
    # --- Unvalidated Redirects ---
    "redirectChallenge": ("open_redirect", "redirect", False),
    "redirectCryptoCurrencyChallenge": ("open_redirect", "redirect", False),
    # --- XXE ---
    "xxeFileDisclosureChallenge": ("xxe", "file-upload", True),
    "xxeDosChallenge": ("xxe", "file-upload", True),
    # --- Sensitive Data Exposure (exposed files / data leaks) ---
    "directoryListingChallenge": ("exposed_data", None, False),
    "forgottenBackupChallenge": ("exposed_data", None, False),
    "forgottenDevBackupChallenge": ("exposed_data", None, False),
    "exposedCredentialsChallenge": ("exposed_data", None, False),
    "leakedApiKeyChallenge": ("exposed_data", None, False),
    "passwordHashLeakChallenge": ("info_disclosure", None, True),
    # --- Broken Authentication ---
    "weakPasswordChallenge": ("auth", "user/login", False),
    # --- Broken Anti Automation ---
    "captchaBypassChallenge": ("rate_limit", None, False),
    # --- Improper Input Validation (file upload / mass assignment) ---
    "uploadSizeChallenge": ("file_upload", "file-upload", False),
    "uploadTypeChallenge": ("file_upload", "file-upload", False),
    "nullByteChallenge": ("file_upload", "file-upload", False),
    "registerAdminChallenge": ("mass_assignment", "User", False),
}

# Fallback class label for out-of-scope challenges (for the report breakdown).
_CATEGORY_CLASS = {
    "Injection": "injection", "XSS": "xss",
    "Broken Access Control": "access_control",
    "Sensitive Data Exposure": "info_disclosure",
    "Broken Authentication": "auth", "Vulnerable Components": "vulnerable_dependency",
    "Cryptographic Issues": "crypto", "Insecure Deserialization": "deserialization",
    "Improper Input Validation": "input_validation",
    "Broken Anti Automation": "anti_automation",
    "Security Misconfiguration": "misconfig", "Observability Failures": "observability",
    "Security through Obscurity": "obscurity", "Miscellaneous": "misc",
    "Unvalidated Redirects": "open_redirect", "XXE": "xxe",
}


def build_ground_truth() -> list[GroundTruthItem]:
    challenges = json.loads(_CHALLENGES.read_text())
    items: list[GroundTruthItem] = []
    for c in challenges:
        key = c["key"]
        if key in DETECTABLE:
            vuln_class, endpoint, auth = DETECTABLE[key]
            items.append(GroundTruthItem(
                id=key, name=c["name"], category=c["category"],
                vuln_class=vuln_class, dast_detectable=True,
                signature=SIGNATURES.get(vuln_class),
                endpoint_contains=endpoint, auth_required=auth,
            ))
        else:
            items.append(GroundTruthItem(
                id=key, name=c["name"], category=c["category"],
                vuln_class=_CATEGORY_CLASS.get(c["category"], "other"),
                dast_detectable=False,
            ))
    return items
