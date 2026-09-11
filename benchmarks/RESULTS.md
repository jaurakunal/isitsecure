# Benchmark Results

Results from testing isitsecure against public, deliberately-vulnerable apps.

**Read [How to read these numbers](#how-to-read-these-numbers) first.** OWASP Juice
Shop is now **per-challenge scored and reproducible in one command**
(`python benchmarks/run_benchmarks.py juiceshop`). The other targets (VAmPI,
NodeGoat) are a coarser class-level **smoke test** over a selected subset, and
precision is measured only on one hardened build (`vampi-secure`).

_Runs: 2026-09 · `--llm none` (pure DAST detection, no LLM) · Juice Shop pinned to `v20.1.1`._

## Harness-scored (reproducible: `python benchmarks/run_benchmarks.py <target>`)

| Target | Mode | Recall | False positives | Findings |
|---|---|--:|--:|--:|
| `juiceshop` | url-only | **26/45 (58%)** — per-challenge, deterministic | not yet measured | 26 |
| `juiceshop` | url-only + `--probe-writes` | **32/45 (71%)** | not yet measured | 74 |
| `juiceshop-auth` | authenticated, two-user | **29/45 (64%)** | not yet measured | 35 |
| `vampi-vulnerable` | url-only | **3/3** (SQLi, IDOR, headers) | — | 8–10 |
| `vampi-secure` | url-only | — | **2** (IDOR) | 7–9 |
| `nodegoat-auth` | authenticated | **3/3** (headers + injection + XSS) | unmeasured | 19 |
| `sast-injection` | code-only | **46/46 (100%)** — taint, per-class, deterministic | **0** | 46 |

> **VAmPI numbers before 2026-09 were not measurements.** The app ships an empty
> database and seeds it from `/createdb`, which nothing called — so whether IDOR
> had any data to find depended on whether some scanner happened to reach that
> endpoint first. Both targets now seed in `pre_scan`, and three consecutive runs
> give identical results.

### SAST injection (`sast-injection`, code-only, taint layer #4 + #93 + #102 + #104)

The deterministic Semgrep taint layer scored on an independent injection fixture
(not `test-app`, which the JS rules were tuned on) covering **JS/TS (#4)**,
**Python (#93)**, **Java/Spring (#102)**, and **Kotlin/Spring (#104)** — the
languages isitsecure supports for the rest of the scan. Recall **46/46** with
**0 false positives** across all classes, deterministic across runs:

| Class | JS/TS | Python | Java | Kotlin | Class | JS/TS | Python | Java | Kotlin |
|---|--:|--:|--:|--:|---|--:|--:|--:|--:|
| sqli | 5/5 | 7/7 | 5/5 | 4/4 | path-traversal | 1/1 | 2/2 | 1/1 | 2/2 |
| reflected-xss | 2/2 | — | — | — | command-injection | 1/1 | 3/3 | 2/2 | 2/2 |
| dom-xss | 2/2 | — | — | — | ssti | — | 1/1 | — | — |
| ssrf | 1/1 | 2/2 | 2/2 | 1/1 | | | | | |

The FP side is exercised by benign near-misses in each language — parameterized
queries, constant-path writes, non-DB `.query()`, escaped output, fixed-URL
fetch (JS); parameterized/bound queries (including request-derived values in the
params tuple), a bare `text()` i18n alias, `subprocess` without `shell=True`,
constant-path `open()`, fixed-URL requests (Python); `PreparedStatement`/bound
`JdbcTemplate` queries, constant SQL, constant-path `File` (Java/Kotlin) — none
flagged. Cross-checked against the real, non-vulnerable **spring-petclinic** (30
Java files, 10 `@RequestParam`/`@PathVariable`, 8 query/File/exec call sites) and
**spring-petclinic-kotlin** (24 Kotlin files, 7 annotated params): **0 FP** each;
and isitsecure's own 164 Python files (real `subprocess`/`requests`/`open`): **0
FP**. This is the baseline the taint layer and future rule packs must hold.

> Juice Shop recall is scored **per challenge** — a finding must match the class
> signature AND land on the right endpoint — over the 45 DAST-detectable
> challenges of 113 (not a hand-picked subset). It was **identical across repeat
> runs**. `nodegoat` (url-only) and `crapi` are wired but their numbers are
> pending a re-run.

## Juice Shop — per-class breakdown (`juiceshop`, url-only, v20.1.1)

Recall **26/45 (58%)** url-only, deterministic across runs. Of 113 challenges,
68 are out of scope for DAST (crypto, CTF mechanics, deep business logic,
SAST-only).

Three columns, because two of them cost something: `--probe-writes` writes to
the target and doubles the runtime, and the authenticated pass needs two
registered users.

| Class | url-only | `--probe-writes` | authenticated |
|---|--:|--:|--:|
| sqli | **7/7** | **7/7** | **7/7** |
| file_upload | **4/4** | **4/4** | **4/4** |
| exposed_data | 4/5 | 4/5 | 4/5 |
| xxe | **2/2** | **2/2** | **2/2** |
| open_redirect | 2/2 | 2/2 | 2/2 |
| info_disclosure | 2/2 | 2/2 | 2/2 |
| nosql | 2/3 | 2/3 | 2/3 |
| idor | 2/5 | 3/5 | **4/5** |
| xss | 1/7 | **4/7** | 2/7 |
| csrf | 0/1 | **1/1** | 0/1 |
| ssti | 0/1 | **1/1** | 0/1 |
| mass_assignment | 0/2 | 0/2 | 0/2 |
| ssrf | 0/2 | 0/2 | 0/2 |
| auth | 0/1 | 0/1 | 0/1 |
| rate_limit | 0/1 | 0/1 | 0/1 |
| **total** | **26/45** | **32/45** | **29/45** |

**Biggest gaps (the recall levers):**

- **XSS is 1/7 url-only, 4/7 with `--probe-writes`** — the reflected/DOM
  search-box case comes from an interactive input oracle that types into fields
  and observes the sink ([#3](https://github.com/jaurakunal/isitsecure/issues/3)).
  Three of the remaining six are stored variants that need a POST, which is
  exactly what `--probe-writes` supplies. The last two need `/api/Users` and
  `/api/Feedbacks`, which are not literals in the SPA bundle and so are not
  reachable by static extraction at all.
- **Login / auth-bypass SQLi is now detected** — `sqli` is **7/7**. A differential
  oracle probes conventional login paths and flags a SQL tautology that
  authenticates (returns a session token) where a benign credential is rejected —
  reaching the login POST that url-only discovery can't recover from the SPA
  bundle ([#2](https://github.com/jaurakunal/isitsecure/issues/2)). The remaining
  recall levers are SSRF (0/2), mass assignment (0/2) and the remaining XSS
  variants.

- **file_upload 0/4 and XXE 0/2 are fixed.** Neither was a detection gap: the
  endpoint was never discovered. `/file-upload` is a literal in the SPA bundle,
  but discovery discarded it against a list of interesting-looking directory
  names, and once discovered it ranked 73rd of 77 for injection because an
  upload endpoint has no parameters to score. The XXE probe also only ever
  posted a raw XML body, where that endpoint takes XML as an uploaded file.
  Three separate fixes, none of them to a scanner's detection logic.

- **mass_assignment is 0/2 even with `--probe-writes`**, despite both challenges
  needing a POST that the flag now supplies — so something beyond method
  discovery blocks them. Open.

## Authenticated cross-user BOLA (manually verified — heavy to reproduce)

A **two-user** authenticated run (`juiceshop-auth`: register users A + B, token
login, `--auth-email-b`) exercises cross-user object access — it harvests owned
resource ids as user A and confirms user B (a different identity) can reach them
while an anonymous request cannot. This surfaces Juice Shop's **basket BOLA**
challenges, taking `idor` from 2/5 to **4/5**.

It is now harness-scored at **29/45 (64%)** rather than measured by hand, and
runs in one command like the others. Note it scores *lower* than
`--probe-writes` (32/45) while finding different things — authentication buys
the object-access challenges, writes buy the stored/CSRF/SSTI ones. Nothing
stops both being used together; that combination has not been measured.

**Caveat, stated plainly:** this sweep is expensive — replaying every id-bearing
endpoint as A/B/anon across Juice Shop's full surface takes roughly 30 minutes
on our test machine, so it is **not** part of the fast one-command number above.
The target exists (`run_benchmarks.py juiceshop-auth`, with a raised
`scan_timeout`), but treat it as a long-running measurement, not a quick check.

## VAmPI (harness-scored)

Frontend-less Flask REST API that publishes an OpenAPI spec — spec-based
discovery is what makes it testable (before it, recall was **1/3** with 0
endpoints found; spec parsing → **19 endpoints**, **3/3**).

| Build | Findings | Result |
|---|---|---|
| `vulnerable=1` | 14–16 | Recall **3/3** — SQLi ✓, IDOR ✓, missing headers ✓ |
| `vulnerable=0` | 13–15 | **2 false positives** (IDOR) |

The 2 IDOR FPs on the secure build are inherent to *unauthenticated* IDOR (no
second identity to distinguish public from broken-access). A cross-user
authenticated run finds **2 write BOLA** (email/password) with 0 FP.

## NodeGoat authenticated (harness-scored)

Server-rendered Express/EJS app — no JS API bundle, no OpenAPI spec. url-only
discovery originally found **nothing**; HTML form/link discovery + a form-scoped
login detector (identity field `userName`) now let a credentialed crawl log in,
walk ~32 pages, and discover **10 form endpoints**. NodeGoat is now **pinned to
commit `c5cb68a`** for reproducibility (it's unversioned upstream, unlike Juice
Shop's `v20.1.1` tag).

Harness recall **3/3**: missing headers ✓, injection ✓, XSS ✓ (19 findings),
climbing from **1/3** (auth mechanism, #111 → #114 + #115) to **2/3** to the
full **3/3** once reflected XSS was wired into the quick-depth set (#118).

**Injection — caught (#114 + #115).** NodeGoat is a cookie-session app (no bearer
token), so before the fix the HTTP DAST scanners probed *unauthenticated* and
every protected endpoint bounced them to the login page — nothing to attack. The
authenticated crawl now captures the session cookie (#114) and the orchestrator
propagates it to every HTTP DAST scanner via the `AuthAwareScanner` mixin (#115),
so `ActiveInjectionScanner` probes the protected endpoints behind the login wall
and the injection surfaces.

**XSS — caught (#118).** NodeGoat's `POST /profile` reflected XSS
(`firstName`/`lastName` echoed unescaped) is real, the form is discovered with
its real field names, and the POST-body XSS scanner tests the discovered fields
(#110) with the session cookie attached. The last gap was that the full
`XSSScanner` only ran at `--depth deep`. #118 adds a **lightweight XSS pass to the
quick-depth set** (reflected + POST-body network phases on a tighter 2-min budget;
the static DOM sink analysis stays deep-only), so the authenticated reflected XSS
is now caught at the benchmark's default depth. Juice Shop stays stable and
vampi-secure gains no false positives (the quick XSS pass is canary-based:
unescaped reflection of a unique probe, which a hardened app doesn't produce).

## How to read these numbers

- **Juice Shop is per-instance scored**: recall over the 45 DAST-detectable
  challenges (of 113), each verified by class signature AND endpoint. This is the
  honest headline number, and it is reproducible and deterministic.
- **Regression guard:** a few reliably-caught findings (e.g. the products/search
  SQLi) are marked `MUST_DETECT`. The harness prints `⚠ REGRESSION` and exits
  non-zero if the full-scan path drops one — so a confirmed finding can't
  silently vanish again ([#1](https://github.com/jaurakunal/isitsecure/issues/1)).
- **VAmPI/NodeGoat recall is "of checked", not "of known"** — each checks 2–3
  classes we chose, so "3/3" means 3 of 3 checked, not full coverage. Extending
  the per-challenge scorer to them is tracked work.
- **Precision is only measured on `vampi-secure`** (a false-positive allow-list).
  On vulnerable builds, the findings count is undifferentiated.
- **NoSQL injection is a known false-positive-prone class**
  ([#5](https://github.com/jaurakunal/isitsecure/issues/5)). The oracle keys on
  response-size / document deltas and can fire on endpoints with naturally
  variable responses (e.g. `/redirect`). A tightening attempt over-corrected and
  killed the real detections (2/3 → 0/3), so it was reverted — the honest trade
  is to keep the 2/3 detections and flag the class as noisy. Treat NoSQL findings
  as leads to confirm, not confirmed bugs.
- **Known variance:** time-based checks are load-sensitive; VAmPI's `/createdb`
  resets its DB mid-scan. Juice Shop url-only was deterministic across runs.

## Reproduce

```bash
pip install -e ".[all]"
python benchmarks/run_benchmarks.py juiceshop       # OWASP Juice Shop — the headline number (~27 min)
python benchmarks/run_benchmarks.py                 # VAmPI (both builds)
python benchmarks/run_benchmarks.py nodegoat-auth   # NodeGoat, authenticated

# authenticated two-user cross-user BOLA (heavy / long-running, may exceed 30 min):
python benchmarks/run_benchmarks.py juiceshop-auth
```
