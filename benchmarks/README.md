# isitsecure benchmark harness

Repeatable **recall + false-positive** scoring against deliberately-vulnerable
apps. Each run spins the app up in Docker, runs an isitsecure DAST scan, scores
the findings against a known ground truth, and tears the app down.

```bash
pip install -e ".[all]"          # isitsecure on PATH + browser deps
python benchmarks/run_benchmarks.py            # default: VAmPI (both builds)
python benchmarks/run_benchmarks.py --all      # + NodeGoat + crAPI (heavy)
python benchmarks/run_benchmarks.py crapi      # a single target
python benchmarks/run_benchmarks.py --keep vampi-vulnerable   # leave it running
```

Requires Docker running.

## What it measures

For each target the scorecard reports two things — both matter:

- **Recall** — of the vulnerability classes the app is known to have, how many
  did we produce at least one finding for? (Are we catching real bugs?)
- **False positives** — findings that must NOT appear. The cleanest signal is
  **VAmPI's `vulnerable=0` build**: a SQLi or IDOR "finding" against the secure
  app is a false alarm. A scanner that cries wolf is untrusted, so this number
  should be **0**.

## Targets

| Target | Stack | Bring-up | Why |
|---|---|---|---|
| `vampi-vulnerable` | Flask REST API | single image | recall on OWASP API Top 10 |
| `vampi-secure` | same, `vulnerable=0` | single image | **false-positive rate** |
| `nodegoat` | Node/Express + Mongo | upstream compose (auto-cloned) | matches isitsecure's primary stack |
| `crapi` | microservices | upstream compose (auto-cloned) | OWASP API Top 10; IDOR/BAC/auth depth |

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
scan, and the `expect`/`forbid` signatures for that app's known issues.

> These are intentionally vulnerable apps — only run them locally, never expose
> the ports to a network.
