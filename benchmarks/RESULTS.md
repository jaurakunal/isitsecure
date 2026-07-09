# Benchmark Results

Results from testing isitsecure against public, deliberately-vulnerable apps.

**Read [How to read these numbers](#how-to-read-these-numbers) first** — this is
currently a **smoke test**, not a fully-scored benchmark. Recall is class-level
over a *selected subset* of each app's known vulnerabilities, and precision is
only measured on one hardened build. Numbers below are split by provenance:
**harness-scored** (reproducible via `run_benchmarks.py`) vs **manually
verified** (run by hand, not yet automated).

_Runs: 2026-07 · `--llm none` (pure DAST detection, no LLM)._

## Harness-scored (reproducible: `python benchmarks/run_benchmarks.py <target>`)

| Target | Mode | Recall (of checked) | False positives | Findings |
|---|---|--:|--:|--:|
| `vampi-vulnerable` | url-only | **3/3** (SQLi, IDOR, headers) | — | 14–16 |
| `vampi-secure` | url-only | — | **2** (IDOR) | 13–15 |
| `nodegoat-auth` | authenticated | **2/3** (headers, XSS; injection missed) | unmeasured | 28 |

> `nodegoat` (url-only) is in `TARGETS` but its recall number predates HTML
> form discovery — pending a re-run. `crapi` is wired but not yet run here.

## Manually verified (NOT yet scored by the harness)

These were run by hand via `isitsecure scan ...` and confirmed; they are **not**
produced by `run_benchmarks.py` and are not part of the automated scorecard yet.

| Target | Mode | Result |
|---|---|---|
| OWASP Juice Shop v20.1.1 | url-only | SQLi **2** (`/rest/products/search`), IDOR **4**, command-inj FP **0**; 56 endpoints |
| Juice Shop | authenticated (2 users) | recall **16/45 (36%)**; **8** cross-user read BOLA on `/api/BasketItems` (0 FP) — now surfaces end-to-end |
| VAmPI | authenticated (2 users) | **2** cross-user write BOLA (email/password), 0 FP |

## Detail

### VAmPI (harness-scored)

Frontend-less Flask REST API that publishes an OpenAPI spec — spec-based
discovery is what makes it testable (before it, recall was **1/3** with 0
endpoints found; spec parsing → **19 endpoints**, **3/3**).

| Build | Findings | Result |
|---|---|---|
| `vulnerable=1` | 14–16 | Recall **3/3** — SQLi ✓, IDOR ✓, missing headers ✓ |
| `vulnerable=0` | 13–15 | **2 false positives** (IDOR) |

The 2 IDOR FPs on the secure build are inherent to *unauthenticated* IDOR (no
second identity to distinguish public from broken-access). A transient 3rd FP (a
time-based SQLi) appeared once under heavy concurrent load and was fixed by
requiring the delay to reproduce on re-measurement.

### NodeGoat authenticated (harness-scored)

Server-rendered Express/EJS app — no JS API bundle, no OpenAPI spec. url-only
discovery originally found **nothing**; HTML form/link discovery + a form-scoped
login detector (its identity field is `userName`) now let a credentialed crawl
log in, walk ~32 pages, and discover **10 form endpoints** — NodeGoat's real
surface: `POST /profile` (ssn/bankAcc), `/contributions`, `/memos`, `GET
/research?symbol`, `GET /learn?url=` (SSRF), `/allocations/{id}` (IDOR).

Harness recall **2/3**: **missing headers ✓, XSS ✓, injection ✗** (28 total
findings — count is undifferentiated; see caveats). The injection miss on the
server-rendered forms is a real, reportable gap.

### Juice Shop (manually verified)

url-only: 56 endpoints; **SQLi 2** (error-based on `/rest/products/search`),
**IDOR 4**, **command-injection FP 0**. Authenticated cross-user: generic REST
login (`/rest/user/login`, nested `authentication.token`) + owned-resource-id
harvesting finds **8 confirmed read BOLA** on `/api/BasketItems/{id}`, 0 FP.
Guards: anonymous probe (public endpoints), id-shape inference from harvested
ids, and a content-match check (B must see the *same* resource as A). These 8
BOLA now appear in a full `--mode authenticated` scan (comprehensive recall
31% url-only -> 36% authenticated): an earlier gate (`not owned_resources`)
skipped the REST cross-user phase whenever the browser crawler populated
resource ids, which it does even on a failed SPA login — fixed.

## How to read these numbers

This benchmark is honest about being **limited**:

- **Recall is "of checked", not "of known".** Each target checks 2–3 classes we
  chose. VAmPI has ~13 documented OWASP-API issues, NodeGoat the full Top 10,
  Juice Shop ~113 challenges. **"3/3" means 3 of 3 checked — not coverage.**
- **Precision is barely measured.** Only `vampi-secure` has a false-positive
  allow-list. On vulnerable builds, the findings count (e.g. "28") is
  **undifferentiated** — not split into true vs false positives.
- **Matching is class/scanner/endpoint-level**, not per-instance: a class counts
  as "found" if *any* matching finding exists; it does not verify how many of N
  instances were caught.
- **Known variance:** time-based checks are load-sensitive; VAmPI's `/createdb`
  resets its DB mid-scan. Findings counts are given as ranges where they varied.

A **per-instance scored benchmark** now exists for Juice Shop:
`benchmarks/score.py` grades a scan against all 113 challenges (from the app's
own `/api/Challenges`), reporting recall over the 45 DAST-detectable ones with
true-positive endpoint verification, plus the out-of-scope tally. The Juice Shop
36%/31% figures above come from it. Extending it to VAmPI/NodeGoat/crAPI and
wiring it into `run_benchmarks.py` is the remaining work (tracked as issues).

## Reproduce

```bash
pip install -e ".[all]"
python benchmarks/run_benchmarks.py                 # VAmPI (both builds)
python benchmarks/run_benchmarks.py nodegoat-auth   # NodeGoat, authenticated

# manually-verified cross-user BOLA (not scored by the harness):
isitsecure scan http://localhost:5001 --mode authenticated --auth-provider token \
  --auth-email alice --auth-password pw \
  --auth-email-b bob --auth-password-b pw
```
