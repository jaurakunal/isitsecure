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
| `juiceshop` | url-only | **20/45 (44%)** — per-challenge, deterministic | not yet measured | ~25 |
| `vampi-vulnerable` | url-only | **3/3** (SQLi, IDOR, headers) | — | 14–16 |
| `vampi-secure` | url-only | — | **2** (IDOR) | 13–15 |
| `nodegoat-auth` | authenticated | **3/3** (headers + injection + XSS) | unmeasured | 19 |
| `sast-injection` | code-only | **46/46 (100%)** — taint, per-class, deterministic | **0** | 46 |

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

Recall **20/45 (44%)**, deterministic across runs. Of 113 challenges, 68 are out
of scope for DAST (crypto, CTF mechanics, deep business logic, SAST-only).

| Class | Found / detectable | Class | Found / detectable |
|---|--:|---|--:|
| exposed_data | 4/5 | mass_assignment | 0/2 |
| sqli | **7/7** | ssrf | 0/2 |
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
- **Login / auth-bypass SQLi is now detected** — `sqli` is **7/7**. A differential
  oracle probes conventional login paths and flags a SQL tautology that
  authenticates (returns a session token) where a benign credential is rejected —
  reaching the login POST that url-only discovery can't recover from the SPA
  bundle ([#2](https://github.com/jaurakunal/isitsecure/issues/2)). The remaining
  recall levers are file-upload (0/4), XXE / SSRF (0/2 each), and the stored /
  header XSS variants.

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

## CVE-Bench — pentest exploitation (opt-in, `cve-bench`)

A **separate, pentest-driven** benchmark: the autonomous `pentest` agent is run
against real-world vulnerable web apps from
[CVE-Bench](https://github.com/uiuc-kang-lab/cve-bench)
([arXiv:2503.17332](https://arxiv.org/abs/2503.17332)), and scored by whether the
exploit **actually landed** — judged by **CVE-Bench's own independent grader**
(`GET :9091/done`), not by isitsecure's findings or self-report. This drives
`pentest`, not `scan`; it needs Docker **and an LLM API key**, and is heavy /
opt-in (never in the default or `--all` set).

_Placeholder — numbers pending a live run (requires an LLM key + Docker; ~$4/CVE)._

| CVE | App | Objective | Grader verdict | isitsecure self-report |
|---|---|---|---|---|
| `CVE-2024-34359` | llama-cpp-python | remote code execution (Jinja2 SSTI) | _pending_ | _pending_ |
| `CVE-2024-2624` | lollms-webui | file access (path traversal) | _pending_ | _pending_ |
| `CVE-2024-32964` | Lobe Chat | outbound / SSRF | _pending_ | _pending_ |
| `CVE-2024-3408` | dtale | unauthorized admin login → RCE | _pending_ | _pending_ |

Scorecard shape: **exploited / attempted / skipped-by-safety-design**. The bare
`cve-bench` selector runs the 4-CVE default subset above; all 40 critical CVEs are
runnable via `cve-bench:CVE-XXXX-YYYY` (or `cve-bench:all`).

> **Denial-of-service is out of scope by design.** isitsecure's pentest safety
> floor (anti-DoS RPS cap + no unbounded destruction) prevents it, so any
> DoS-only objective is reported as `skipped_by_safety_design` and logged —
> **never** counted as a failure. This is a deliberate capability boundary, not a
> coverage gap.

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
python benchmarks/run_benchmarks.py juiceshop       # OWASP Juice Shop — the headline number (~10 min)
python benchmarks/run_benchmarks.py                 # VAmPI (both builds)
python benchmarks/run_benchmarks.py nodegoat-auth   # NodeGoat, authenticated

# authenticated two-user cross-user BOLA (heavy / long-running, may exceed 30 min):
python benchmarks/run_benchmarks.py juiceshop-auth

# CVE-Bench pentest exploitation (opt-in; needs an LLM API key + Docker; ~$4/CVE):
git clone --depth 1 https://github.com/uiuc-kang-lab/cve-bench benchmarks/_ext/cve-bench
python benchmarks/run_benchmarks.py cve-bench                  # default 4-CVE subset
python benchmarks/run_benchmarks.py cve-bench:CVE-2024-34359   # a single CVE
```
