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
| VAmPI (vulnerable) | REST API, no frontend | **3/3** | — | OpenAPI discovery: 0→19 endpoints |
| VAmPI (secure) | REST API, no frontend | — | **2** (IDOR) | unauth heuristic can't tell public from broken-access |
| VAmPI (authenticated) | REST API, two users | **2/2 BOLA** | **0** | cross-user IDOR; anon guard clears the 2 FPs above |
| NodeGoat | Server-rendered (EJS) | **0/2** | 0 | no JS bundle / no OpenAPI spec → discovery finds nothing |

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
nested `authentication.token`), but finds **0** cross-user IDOR. Honest reason:
Juice Shop's resources use **opaque numeric object ids** (`/api/BasketItems/{id}`),
which are not derivable from a user's identity. The scanner substitutes user A's
identifier into the path, so it only reaches resources whose id *is* the user
identifier. Catching Juice Shop's basket/feedback BOLA needs **owned-resource-id
harvesting** (as user A, discover A's real object ids, then attempt them as B) —
the clear next enhancement.

### VAmPI — `url-only` (recall) and `vulnerable=0` (false positives)

VAmPI is a frontend-less Flask REST API. It publishes an OpenAPI spec, so
spec-based discovery is what makes it testable at all.

| Build | Findings | Result |
|---|---|---|
| `vulnerable=1` | 14 | Recall **3/3** — SQL injection ✓, IDOR ✓, missing headers ✓ |
| `vulnerable=0` | 13 | **2 false positives** (IDOR), 0 SQLi FPs |

Before OpenAPI discovery, recall here was **1/3** (0 endpoints found beyond the
homepage). Spec parsing took it to **19 endpoints** and **3/3**.

The 2 IDOR false positives on the secure build are inherent to *unauthenticated*
IDOR: with no second identity, a public id-bearing endpoint is indistinguishable
from a broken-access one.

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

**0 findings, recall 0/2.** The clone/build/startup/scan all succeeded against a
live, known-vulnerable target — the scanner simply found nothing. NodeGoat is a
**server-rendered** Express/EJS app: no JavaScript API bundle and no OpenAPI
spec, so endpoint discovery (which relies on one or the other) surfaces nothing
to test. This is the same blind spot as a frontend-less API, but for
server-rendered HTML — the fix is HTML form/link crawling for endpoint discovery.

## What these results say

- **Strong** where an attack surface is discoverable: SPA + REST (Juice Shop) and
  spec-publishing APIs (VAmPI). SQLi/IDOR are caught end-to-end.
- **Authenticated cross-user IDOR works** and is false-positive-resistant (VAmPI:
  2 real BOLAs, 0 FPs) — provided resource ids map to user identity.
- **Known gaps, each surfaced by a benchmark:**
  1. Server-rendered apps (NodeGoat) — discovery needs HTML crawling.
  2. Opaque object ids (Juice Shop BOLA) — cross-user needs owned-id harvesting.
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
