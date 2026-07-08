# Benchmark Results

Measured results from the [benchmark harness](run_benchmarks.py) against public,
deliberately-vulnerable applications. Two things are scored, and both matter:

- **Recall** — of the vulnerability classes an app is known to have, how many did
  we produce at least one finding for?
- **False positives** — findings that must not appear (e.g. against a hardened
  build). A scanner that cries wolf is untrusted.

_Run: 2026-07-07 · isitsecure commit `0c0dc5f` · mode `url-only` unless noted ·
`--llm none` (pure DAST detection, no LLM)._

## Summary

| Target | Type | Recall | False positives | Notes |
|---|---|---|---|---|
| OWASP Juice Shop v20.1.1 | SPA + REST (Angular) | SQLi ✓, IDOR ✓ | command-inj **0** | 56 endpoints; SQLi + IDOR caught end-to-end |
| Juice Shop (authenticated) | SPA + REST, two users | **8 BOLA** | **0** | basket BOLA via owned-resource-id harvesting |
| VAmPI (vulnerable) | REST API, no frontend | **3/3** | — | OpenAPI discovery: 0→19 endpoints |
| VAmPI (secure) | REST API, no frontend | — | **2** (IDOR) | unauth heuristic can't tell public from broken-access |
| VAmPI (authenticated) | REST API, two users | **2/2 BOLA** | **0** | cross-user IDOR; anon guard clears the 2 FPs above |
| NodeGoat | Server-rendered (EJS) | **0→10 endpoints** | 0 | HTML form/link discovery + form-scoped login surface the full authenticated form surface |

## Detail

### OWASP Juice Shop v20.1.1 — `url-only`

56 endpoints discovered, 25 findings:

| Class | Result |
|---|---|
| SQL injection | **2** — error-based on `/rest/products/search` (real) |
| IDOR | **4** — object-level access on id-bearing REST endpoints |
| Command-injection false positives | **0** (previously 5; fixed) |

The two classes an earlier third-party review claimed isitsecure was blind to —
SQLi and IDOR — are caught end-to-end by the real pipeline (discover → prioritize
→ confirm), not hand-fed.

**Authenticated cross-user (BOLA):** the two-user flow logs in successfully
(generic REST login against Juice Shop's `/rest/user/login`, token read from the
nested `authentication.token`) and, with **owned-resource-id harvesting**, finds
**8 confirmed cross-user read IDOR** on `/api/BasketItems/{id}` — Juice Shop's
real "view another user's basket" BOLA — with **0 false positives**.

Juice Shop's resources use **opaque numeric object ids** that aren't derivable
from a user's identity, so the scanner first reads the parent collection
(`/api/BasketItems`) as user A to learn the real ids, then tests each as user B.
Three false-positive guards keep it honest: the **anonymous** probe drops public
endpoints, the id **shape is inferred from the harvested real ids** (so a string
identity is never injected into an opaque object-id slot, and UUID ids are
not dropped), and a **content-match** check requires user B to see
the *same resource* user A sees (not their own data via a coerced id).

### VAmPI — `url-only` (recall) and `vulnerable=0` (false positives)

VAmPI is a frontend-less Flask REST API. It publishes an OpenAPI spec, so
spec-based discovery is what makes it testable at all.

| Build | Findings | Result |
|---|---|---|
| `vulnerable=1` | 14–16 | Recall **3/3** — SQL injection ✓, IDOR ✓, missing headers ✓ |
| `vulnerable=0` | 13–15 | **2 false positives** (IDOR) |

Before OpenAPI discovery, recall here was **1/3** (0 endpoints found beyond the
homepage). Spec parsing took it to **19 endpoints** and **3/3**.

The 2 IDOR false positives on the secure build are inherent to *unauthenticated*
IDOR: with no second identity, a public id-bearing endpoint is indistinguishable
from a broken-access one (authenticated mode resolves them — see below).

A **transient 3rd false positive** (a time-based SQL injection) appeared on one
`vulnerable=0` run executed under heavy concurrent load. It was traced to
*single-shot* time-based detection: one slow response (system contention — and
VAmPI is SQLite, which never honors the `SLEEP()` payload) crossed the delay
threshold. Fixed by requiring the delay to **reproduce on an independent
re-measurement** before flagging; it does not recur.

### VAmPI — `authenticated` (cross-user IDOR / BOLA)

Two users (alice, bob) via generic REST login against `/users/v1/login`:

| Result | Detail |
|---|---|
| **2 confirmed cross-user write IDOR** | bob can modify alice's `/users/v1/{username}/email` and `/password` (real BOLA) |
| **0 false positives** | the public `GET /users/v1/{username}` is **not** flagged — the anonymous-access guard recognizes it as public |

This is the payoff of authenticated testing: the exact 2 endpoints that were
*false positives* unauthenticated become *correct confirmations* with two users,
while the public endpoint is correctly cleared.

### NodeGoat — `url-only`

Originally **0 findings, recall 0/2**: NodeGoat is a **server-rendered**
Express/EJS app with no JavaScript API bundle and no OpenAPI spec, so discovery
(which relied on one or the other) surfaced nothing to test.

**Now addressed** by server-rendered HTML discovery — a `<form>`/`<input>`/
query-link extractor that reads the attack surface out of the HTML. In
`url-only` mode a bounded same-origin HTML crawl discovers NodeGoat's public
forms (**0 → 2**: `login` and `signup`, with all their input fields as
parameters). The full authenticated surface (profile, allocations, memos) needs
the logged-in crawler, which now runs the same extractor on every page it
visits — so a credentialed scan captures server-rendered forms in addition to
the XHR/fetch calls it already intercepts. Driving NodeGoat's login works too:
its identity field is named `userName` (not `email`), which a **form-scoped
login-field detector** now handles — it finds the password field, scopes to its
`<form>`, and fills the identity input in that same form.

End-to-end, a credentialed crawl logs in, walks 32 pages, and discovers **10
form endpoints (0 → 10)** — NodeGoat's actual vulnerable surface: `POST /profile`
(`ssn`, `dob`, `bankAcc` — mass assignment), `POST /contributions`
(business-logic), `POST /memos` (stored XSS), `GET /research?symbol` and
`GET /learn?url=` (SSRF), and `GET /allocations/{id}?threshold` (IDOR).

## What these results say

- **Strong** where an attack surface is discoverable: SPA + REST (Juice Shop) and
  spec-publishing APIs (VAmPI). SQLi/IDOR are caught end-to-end.
- **Authenticated cross-user IDOR works** and is false-positive-resistant on
  both identity-based ids (VAmPI: 2 real BOLAs, 0 FPs) and **opaque object ids**
  via owned-resource-id harvesting (Juice Shop: 8 basket BOLAs, 0 FPs).
- **Known gaps, each surfaced by a benchmark:**
  1. ~~Server-rendered apps (NodeGoat) — discovery needs HTML crawling.~~ —
     **addressed** via HTML form/link discovery (url-only crawl + the same
     extractor inside the authenticated crawler) plus a form-scoped login-field
     detector that handles non-standard identity fields (`userName`).
  2. ~~Opaque object ids (Juice Shop BOLA)~~ — **resolved** via owned-resource-id
     harvesting (read the parent collection as A, test the real ids as B).
  3. Unauthenticated IDOR is FP-prone by nature — authenticated mode is the
     answer, and it works.

## Reproduce

```bash
pip install -e ".[all]"
python benchmarks/run_benchmarks.py                # VAmPI (both builds)
python benchmarks/run_benchmarks.py nodegoat       # NodeGoat

# authenticated cross-user IDOR (register two users first)
isitsecure scan http://localhost:5001 --mode authenticated --auth-provider token \
  --auth-email alice --auth-password pw \
  --auth-email-b bob --auth-password-b pw
```
