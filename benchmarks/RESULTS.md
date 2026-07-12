# Benchmark Results

Results from testing isitsecure against public, deliberately-vulnerable apps.

**Read [How to read these numbers](#how-to-read-these-numbers) first.** OWASP Juice
Shop is now **per-challenge scored and reproducible in one command**
(`python benchmarks/run_benchmarks.py juiceshop`). The other targets (VAmPI,
NodeGoat) are a coarser class-level **smoke test** over a selected subset, and
precision is measured only on one hardened build (`vampi-secure`).

_Runs: 2026-07 · `--llm none` (pure DAST detection, no LLM) · Juice Shop pinned to `v20.1.1`._

## Harness-scored (reproducible: `python benchmarks/run_benchmarks.py <target>`)

| Target | Mode | Recall | False positives | Findings |
|---|---|--:|--:|--:|
| `juiceshop` | url-only | **16/45 (36%)** — per-challenge, deterministic | not yet measured | ~24 |
| `vampi-vulnerable` | url-only | **3/3** (SQLi, IDOR, headers) | — | 14–16 |
| `vampi-secure` | url-only | — | **2** (IDOR) | 13–15 |
| `nodegoat-auth` | authenticated | **2/3** (headers, XSS; injection missed) | unmeasured | 28 |

> Juice Shop recall is scored **per challenge** — a finding must match the class
> signature AND land on the right endpoint — over the 45 DAST-detectable
> challenges of 113 (not a hand-picked subset). It was **identical across repeat
> runs**. `nodegoat` (url-only) and `crapi` are wired but their numbers are
> pending a re-run.

## Juice Shop — per-class breakdown (`juiceshop`, url-only, v20.1.1)

Recall **16/45 (36%)**, deterministic across runs. Of 113 challenges, 68 are out
of scope for DAST (crypto, CTF mechanics, deep business logic, SAST-only).

| Class | Found / detectable | Class | Found / detectable |
|---|--:|---|--:|
| exposed_data | 4/5 | mass_assignment | 0/2 |
| sqli | 3/7 | ssrf | 0/2 |
| idor | 2/5 | xxe | 0/2 |
| nosql | 2/3 | auth | 0/1 |
| open_redirect | 2/2 | csrf | 0/1 |
| info_disclosure | 2/2 | rate_limit | 0/1 |
| xss | **1/7** | ssti | 0/1 |
| file_upload | **0/4** | | |

**Biggest gaps (the recall levers):**

- **XSS is 1/7** — the reflected/DOM search-box case is now detected by an
  interactive input oracle that types into fields and observes the sink
  ([#3](https://github.com/jaurakunal/isitsecure/issues/3)). The remaining six
  are stored, HTTP-header, or auth-gated variants. (Fixing #3 also exposed a real
  bug: DOM-XSS findings were being *discarded* when the scan hit its timeout —
  now they're returned, which is what moved this from 0/7 to 1/7.)
- The four **login SQLi** challenges at `/rest/user/login` are missed because
  url-only discovery can't reach the SPA's login POST endpoint
  ([#2](https://github.com/jaurakunal/isitsecure/issues/2)).

## Authenticated cross-user BOLA (manually verified — heavy to reproduce)

A **two-user** authenticated run (`juiceshop-auth`: register users A + B, token
login, `--auth-email-b`) exercises cross-user object access — it harvests owned
resource ids as user A and confirms user B (a different identity) can reach them
while an anonymous request cannot. This surfaces Juice Shop's **basket BOLA**
challenges (manually measured at **~18/45, 40%**, with 8 confirmed read BOLA on
`/api/BasketItems`, 0 false positives).

**Caveat, stated plainly:** this sweep is expensive — replaying every id-bearing
endpoint as A/B/anon across Juice Shop's full surface **exceeded a 30-minute cap**
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
walk ~32 pages, and discover **10 form endpoints**. Harness recall **2/3**:
missing headers ✓, XSS ✓, injection ✗ — the injection miss on the server-rendered
forms is a real, reportable gap.

## How to read these numbers

- **Juice Shop is per-instance scored**: recall over the 45 DAST-detectable
  challenges (of 113), each verified by class signature AND endpoint. This is the
  honest headline number, and it is reproducible and deterministic.
- **VAmPI/NodeGoat recall is "of checked", not "of known"** — each checks 2–3
  classes we chose, so "3/3" means 3 of 3 checked, not full coverage. Extending
  the per-challenge scorer to them is tracked work.
- **Precision is only measured on `vampi-secure`** (a false-positive allow-list).
  On vulnerable builds, the findings count is undifferentiated.
- **Known variance:** time-based checks are load-sensitive; VAmPI's `/createdb`
  resets its DB mid-scan. Juice Shop url-only was deterministic across runs.

## Reproduce

```bash
pip install -e ".[all]"
python benchmarks/run_benchmarks.py juiceshop       # OWASP Juice Shop — the headline number (~10 min)
python benchmarks/run_benchmarks.py                 # VAmPI (both builds)
python benchmarks/run_benchmarks.py nodegoat-auth   # NodeGoat, authenticated

# authenticated two-user cross-user BOLA (heavy / long-running, may exceed 30 min):
python benchmarks/run_benchmarks.py juiceshop-auth
```
