# isitsecure benchmark harness

Repeatable **recall + false-positive** scoring against deliberately-vulnerable
apps. Most targets spin the app up in Docker, run an isitsecure DAST scan, score
the findings against a known ground truth, and tear the app down. One target —
`sast-injection` — is **code-only** (no Docker): it scores the deterministic
Semgrep taint layer against a local injection fixture (see below).

```bash
pip install -e ".[all]"          # isitsecure on PATH + browser deps
python benchmarks/run_benchmarks.py            # default: VAmPI (both builds) + sast-injection
python benchmarks/run_benchmarks.py juiceshop  # OWASP Juice Shop — the headline recall number
python benchmarks/run_benchmarks.py --all      # + NodeGoat + crAPI + Juice Shop (heavy)
python benchmarks/run_benchmarks.py crapi      # a single target
python benchmarks/run_benchmarks.py sast-injection            # taint recall/FP, no Docker
python benchmarks/run_benchmarks.py --keep vampi-vulnerable   # leave it running
```

Docker is required for every target **except** `sast-injection`, which instead
needs the `semgrep` binary (`pipx install semgrep` or `pip install semgrep`).

## What it measures

For each target the scorecard reports two things — both matter:

- **Recall** — of the vulnerability classes the app is known to have, how many
  did we produce at least one finding for? (Are we catching real bugs?)
- **False positives** — findings that must NOT appear. The cleanest signal is
  **VAmPI's `vulnerable=0` build**: a SQLi or IDOR "finding" against the secure
  app is a false alarm. A scanner that cries wolf is untrusted, so this number
  should be **0**.
- **Regressions** — a few findings the scanner catches *reliably* (e.g. the
  error-based SQLi on Juice Shop's `GET /rest/products/search`) are flagged
  `MUST_DETECT` in the ground truth. If the full-scan path ever drops one, the
  harness prints a loud `⚠ REGRESSION` and **exits non-zero** — separating a
  full-scan-path bug (a confirmed finding silently lost) from an ordinary
  coverage gap. Guards [#1](https://github.com/jaurakunal/isitsecure/issues/1).

## Targets

| Target | Stack | Bring-up | Why |
|---|---|---|---|
| `vampi-vulnerable` | Flask REST API | single image | recall on OWASP API Top 10 |
| `vampi-secure` | same, `vulnerable=0` | single image | **false-positive rate** |
| `nodegoat` | Node/Express + Mongo | upstream compose (auto-cloned) | matches isitsecure's primary stack |
| `crapi` | microservices | upstream compose (auto-cloned) | OWASP API Top 10; IDOR/BAC/auth depth |
| `juiceshop` | Angular/Express SPA | single image | **headline recall** — scored per-challenge vs the app's own `/api/Challenges` |
| `juiceshop-auth` | same, authenticated | single image | adds the login-gated challenges (the `~40%` number) |
| `sast-injection` | JS/TS fixtures | **none** (code-only) | **taint layer recall/FP** — deterministic SAST injection floor (#4) |

VAmPI is a single container and runs in the default set. NodeGoat and crAPI are
heavier (compose, mongo, several GB for crAPI) — run them individually. They are
brought up from the projects' own compose files via a shallow clone into
`benchmarks/_ext/` (git-ignored), so the harness always tracks their real setup.

## Ground truth

Expectations live in `run_benchmarks.py` as `Target.expect` (recall) and
`Target.forbid` (false positives). Each matches findings by scanner name,
category, and/or a title substring — coarse but honest, and easy to extend as
detection improves. It scores at the *vulnerability-class* level (did we find a
SQLi at all?), not exact endpoints, so it isn't brittle to app version changes.

**Juice Shop is scored more precisely.** `benchmarks/score.py` grades a scan
against the app's *full* documented challenge set (`ground_truth/juiceshop.py`,
seeded from `/api/Challenges`): recall over the **45 DAST-detectable** challenges
(of 113), broken down per class, with each finding required to land on the right
endpoint. `run_benchmarks.py juiceshop` runs this end to end; you can also score a
saved scan by hand with `python benchmarks/score.py juiceshop findings.json`.

## SAST injection benchmark (`sast-injection`)

The deterministic Semgrep taint layer (#4) has its own **code-only** scorecard,
separate from the DAST targets. It scans a local fixture tree and scores taint
recall + false positives — the gate for the taint layer and every future
rule-pack change (#93/#94).

```bash
python benchmarks/run_benchmarks.py sast-injection   # via the harness (fails non-zero on any miss/FP)
python benchmarks/sast_injection.py                  # standalone, same scorecard
python benchmarks/sast_injection.py findings.json    # score an existing code-only scan JSON
```

The fixtures **are** the ground truth (no separate file to drift):

- `fixtures/sast-injection/vulnerable/*` — each line tagged `// EXPECT <class>`
  (`sqli | reflected-xss | dom-xss | ssrf | path-traversal | command-injection`)
  is a bug the taint layer must flag (recall).
- `fixtures/sast-injection/safe/*` — benign near-misses (parameterized queries,
  constant-path writes, non-DB `.query()`, escaped output, fixed-URL fetch). Any
  injection finding here — or on an unmarked line in a vulnerable file — is a
  **false positive**.

The scorer (`sast_injection.py`) matches findings to expected bugs by file and
line (±1, since Semgrep can report the statement head), reports per-class recall,
and **exits non-zero unless recall is 100% and FP is 0**. It needs the `semgrep`
binary; scoring an existing `findings.json` needs neither Docker nor semgrep.
This is an *independent* fixture (not `test-app`, which the rules were tuned on),
so it's a genuine second data point.

## Authenticated cross-user IDOR (BOLA)

Unauthenticated scanning can't tell a *public* id-bearing endpoint from a
broken-access one, so url-only IDOR is inherently false-positive-prone. Real
object-level authorization is tested with **two users**:

```bash
isitsecure scan http://localhost:5001 --mode authenticated --auth-provider token \
  --auth-email alice --auth-password pw \
  --auth-email-b bob   --auth-password-b pw
```

For each id-bearing endpoint the scanner substitutes user A's own identifier
and checks whether user B (a *different* logged-in user) can reach it while an
**anonymous** request cannot — that anonymous probe is the false-positive
guard, so intentionally-public endpoints are not reported.

> Note: VAmPI exposes a `/createdb` endpoint that resets its database, which a
> full scan can trigger and wipe your test users mid-run. Re-register the users
> immediately before scanning, or use a target that doesn't self-reset.

## Adding a target

Append a `Target(...)` to `TARGETS`: the docker `up_cmd`/`down_cmd`, the URL to
scan, and the `expect`/`forbid` signatures for that app's known issues. For an
app with a full documented challenge list, set `ground_truth="<app>"` and add a
builder under `ground_truth/` instead — the harness then uses the per-challenge
scorer (recall %, per class, endpoint-verified) rather than expect/forbid.

> These are intentionally vulnerable apps — only run them locally, never expose
> the ports to a network.
