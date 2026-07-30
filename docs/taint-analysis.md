# Taint Analysis for SAST (#4) — Design

Status: **implemented** (Phase 2/3) — the `SemgrepAnalyzer` and the first JS/TS
rule pack ship as of this change, backed by the run-on-`test-app` spike below.
This doc records the design; see
[docs/scanners/semgrep-taint.md](scanners/semgrep-taint.md) for the user-facing
scanner reference.

## Problem

isitsecure's code-only (SAST) scan has **no taint/dataflow analysis**. Today,
injection detection works like this (`injection_analyzer.py`):

1. Regex **flags** files that look injection-relevant (SQL template literals,
   `innerHTML`, `exec`, `fs` with variable paths).
2. Those files are handed to the **LLM code reviewer**, which does an
   *approximate, in-its-head* taint analysis and produces the findings.

That works surprisingly well, but the LLM is:

- **non-deterministic** — finding counts wobble run-to-run (visible in scans),
- **costly** — every injection judgment burns tokens,
- **slow** — seconds-to-minutes per scan,
- **occasionally wrong** — both misses and false alarms.

So injection detection — SQLi, XSS, SSRF, path traversal, command injection —
rests entirely on the LLM. There is no deterministic floor beneath it. That is
what #4 is about.

## What taint analysis is (one line)

*Can attacker-controlled data (a **source**) reach a dangerous operation (a
**sink**) without passing through a **sanitizer**?* If yes → a finding. See the
"noob" walkthrough in the issue thread; the three moving parts are **sources**
(`req.query`, `searchParams.get`, `location.hash`), **sinks** (`sql.unsafe`,
`.innerHTML`, `fetch`, `writeFile`, `exec`), and **sanitizers** (parameterized
queries, escaping, allow-lists).

## The spike (what we validated on `test-app`)

We wired **Semgrep** (OSS, `mode: taint`) against `test-app` and compared to the
current LLM approach.

| Approach | Result on `test-app` |
|---|---|
| **Off-the-shelf packs** (`p/typescript`, `p/javascript`, `p/security-audit`) | **0 findings** — scanned 27 files cleanly but caught none of the blatant injections |
| **~50 lines of stack-tuned rules** | **11 findings**, covering **every** injection class, deterministic, instant, $0 |

The tuned pack caught: **6 SQLi** (`db.ts`, every CRUD helper — sink pattern on
`sql.unsafe(\`…\`)`), **DOM XSS** (`window.location.hash → innerHTML`, real
taint), **reflected XSS** (`searchParams.get → html → new Response`, taint),
**SSRF** (`searchParams.get → fetch`, taint), **path traversal / upload**
(`writeFile(path.join(…, filename))`). Command-injection rule fired **nowhere**
(none in the app) — no false positive. One mild double-label (the SSRF'd
response also tripped the reflected-XSS rule) — a real vulnerable spot, just
counted twice.

**Conclusion: ~50 lines of tuned rules ≈ the LLM's entire injection coverage on
this app — but deterministic, instant, and free.** Two lessons: (a) stock packs
don't cover a given stack's sinks (here the `postgres` library's `.unsafe()`),
and (b) rules must match the framework's *actual* code shapes (destructured
`searchParams`, `window.location.hash`) — one tuning pass closed the gap.

## Design: layered detection (Semgrep taint + LLM)

**Don't replace the LLM — put a deterministic floor beneath it.**

- **Semgrep taint/sink rules** handle the *mechanical* source→sink injections
  (SQLi/XSS/SSRF/path-traversal/command-injection) on the stacks we've
  catalogued: deterministic, cheap, same every run.
- **The LLM code reviewer** keeps doing what only it can: business-logic flaws,
  the long tail of libraries we haven't written rules for, and nuanced cases.

The two are complementary. Deterministic engines give recall + reproducibility on
the common case; the LLM gives coverage of the uncommon case and semantics.

## Rule packs are per-**stack**, not per-app

The critical scaling property: **rules target framework/library APIs, not
app-specific code.** `searchParams.get()` is Next.js; `sql.unsafe()` is the
`postgres` library; `writeFile` is Node `fs`. A rule written for the
`postgres.unsafe` sink catches injection in **any** app using that library.

So we curate a **bounded catalog** of rules per **(framework × library)** — the
popular vibe-coder stacks:

- **Sources** per framework: Next.js `searchParams`, Express `req.*`, FastAPI /
  Flask / Django request objects, browser `location.*`.
- **Sinks** per library: SQL (`postgres.unsafe`, `Prisma.$queryRawUnsafe`,
  `Drizzle sql.raw`, raw `db.query` concat), DOM (`innerHTML`,
  `dangerouslySetInnerHTML`), `fs`, `fetch`/`axios`, `exec`/`spawn`.
- **Sanitizers** per library: parameterized queries, escapers, allow-lists.

Written once, applied to every app on that stack. This is how Semgrep / CodeQL /
Snyk all work — packs per ecosystem, never per app.

**We already detect the stack.** The scan reports `framework: nextjs`,
`backend: supabase`, etc., so we **auto-select the matching rule packs per scan**
— no user config. Apps on an uncatalogued library fall through to the LLM
backstop (the whole point of the layered design).

## Why Semgrep (vs. alternatives)

- **Roll our own AST + dataflow** — rejected: it's building a compiler; huge
  per-language effort.
- **CodeQL** — powerful but heavier (build a database, non-OSS licensing for some
  uses), steeper rule language.
- **Semgrep (OSS)** — first-class `mode: taint` with
  `pattern-sources`/`sinks`/`sanitizers`, multi-language (JS/TS/Python/…),
  deterministic, fast, and rules are readable YAML. The spike proves it fits.
  Caveat: **OSS taint is intra-file**; true inter-procedural (route → helper →
  sink across files) is Semgrep Pro. In practice, flagging the **sink itself**
  (`sql.unsafe` with interpolation is essentially always wrong) recovers most of
  the value without Pro — see the spike.

## Architecture (proposed)

A new `SemgrepAnalyzer` behind the existing SAST scanner interface:

1. On a code-only scan, detect the stack (already done) → select rule packs.
2. Shell out to the bundled `semgrep` binary with those packs (`--json`), scoped
   to the cloned repo. No network (rules ship with us).
3. Parse Semgrep's output → map each result to a `CodeFinding` (category from the
   rule, `code_location` from `path`/`start.line`, severity from the rule,
   `scanner_name = "semgrep_taint"`).
4. Feed those findings into the same triage/dedup/plain-English pipeline as every
   other scanner — so they get grades, remediation, MCP/report treatment for free.
5. The LLM code reviewer still runs; dedup collapses overlaps (a finding both
   Semgrep and the LLM raise counts once).

Packaging: ship Semgrep as an **optional extra** (`isitsecure[taint]`) kept
**separate from `all`** — semgrep's tightly-pinned dependency tree (rich/click/
boltons/colorama) does not co-resolve with the `[all]` stack, so folding it in
would break `pip install isitsecure[all]`. Since the analyzer only shells out to
the `semgrep` **binary**, it's found via PATH or the venv, so an isolated install
(`pipx install semgrep`, brew, or a separate venv) works just as well. The rule
packs live under `isitsecure/engine/code_analysis/semgrep_rules/`. Degrade
gracefully if the binary is missing (fall back to LLM-only, like today).

## Precision — the eternal SAST battle

- **False positives** erode trust fastest (this is a vibe-coder tool). Bias rules
  toward high-confidence sinks; recognise the common sanitizers per library so a
  parameterized query doesn't get flagged.
- **Categorisation** must map cleanly onto our `FindingCategory` values
  (injection_risk, etc.) and reuse the #64 classifier where sensible.
- **Double-labels** (spike showed one) — dedup/verify should collapse a location
  flagged by multiple rules into the most specific finding.

## Non-negotiable: the benchmark gate

Per `CLAUDE.md`, this is **detection logic** — unit tests are not enough. Before
anything ships:

- Run the benchmark (Juice Shop / VAmPI, pinned targets):
  `python benchmarks/run_benchmarks.py <target>`.
- Confirm **no recall regression** and **no new false positives** vs. the current
  LLM-only baseline. The Semgrep layer must *add* recall (deterministic injection
  catches) without introducing FP noise.
- Discuss results and get explicit go-ahead before commit/push.

Note: the original benchmark was DAST-oriented, so this work added a **SAST
injection benchmark** — a fixture set with known source→sink bugs giving the taint
layer its own recall/FP scorecard. **Delivered** (#92): `benchmarks/sast_injection.py`
+ `benchmarks/fixtures/sast-injection/`, run via `python benchmarks/run_benchmarks.py
sast-injection`. Baseline **27/27 recall, 0 FP** across JS/TS + Python ([benchmarks/RESULTS.md](../benchmarks/RESULTS.md)).

## Risks & open questions

- **Rule maintenance** — new frameworks/libraries need new rules; the catalog is
  ongoing work. Mitigation: start with the top stacks, LLM backstops the rest.
- **Inter-file taint** needs Semgrep Pro; sink-focused rules recover most value
  in OSS. Revisit if Pro's value justifies the cost.
- **Binary dependency** — bundling/pinning Semgrep; graceful fallback when absent.
- **Semgrep licensing** — OSS engine + our own rules are fine; confirm no
  reliance on registry rules with restrictive terms (we ship our own packs).
- **Language coverage** — JS/TS (#4) and Python/Flask/Django (#93) ship today;
  other stacks (Go, Ruby, Java) are future packs.

## Phasing

1. ✅ **SAST injection benchmark fixtures** + a recall/FP harness (#92) — the
   `sast-injection` target, baseline 27/27 recall / 0 FP (JS/TS + Python).
2. ✅ **`SemgrepAnalyzer`** (subprocess → parse → `CodeFinding`) with a first rule
   pack for the top stack (Next.js/Express + postgres/Prisma/Drizzle + DOM) — #4.
3. ✅ **Benchmark**: proved it adds recall without FP vs. LLM-only. Shipped in #4.
4. 🚧 **Broaden rule packs** iteratively, each gated by the benchmark — #93 adds
   the **Python** pack (Flask/Django sources; DB-API/SQLAlchemy/Django ORM, os/
   subprocess, requests/urllib, Jinja sinks; SQLi/cmdi/SSRF/path/SSTI). Further
   stacks/libraries continue here.
5. **Keep the LLM layer** as the long-tail + business-logic backstop throughout.
