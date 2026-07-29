# Semgrep Taint Analyzer

**Type:** SAST | **Severity:** High–Critical | **Category:** Injection Risk

## What It Does

Runs [Semgrep](https://semgrep.dev) with isitsecure's own taint/sink rule packs over your cloned repo and maps the results to findings. It is a **deterministic injection floor beneath the LLM code reviewer**: the same input always produces the same findings, instantly and at no token cost.

The current rule pack (`semgrep_rules/injection-js.yaml`) targets **JavaScript/TypeScript** and covers five injection classes:

1. **SQL injection** — raw-query sinks (`sql.unsafe`, Prisma `$queryRawUnsafe`/`$executeRawUnsafe`, `knex.raw`, Drizzle `sql.raw`) and user-input → raw-query taint flows.
2. **Reflected XSS** — request data flowing into an HTML response (`new Response(html)`, `res.send`, `res.write`) without escaping.
3. **DOM XSS** — `location.hash`/`location.search` → `innerHTML`/`outerHTML`/`document.write`.
4. **SSRF** — user-controlled URLs flowing into `fetch`/`axios`/`http.get`.
5. **Path traversal / unrestricted upload** — request-derived filenames flowing into `fs.writeFile`/`createWriteStream` via `path.join` (constant paths are excluded).
6. **Command injection** — user input flowing into `exec`/`spawn`.

Rules target **framework/library APIs** (Next.js `searchParams`, Express `req.*`, the `postgres`/Prisma/Drizzle/Knex sinks, Node `fs`), so they apply to **any app on those stacks — not per-app**. Apps on an uncatalogued library fall through to the LLM backstop.

Findings are emitted with `scanner_name = "semgrep_taint"`, `confidence = 0.85`, and category `injection_risk`, then flow through the same triage → dedup → plain-English → grading pipeline as every other scanner.

## Requirements & Graceful Degradation

The analyzer needs the `semgrep` binary, shipped via the optional extra:

```bash
pip install -e ".[taint]"   # or ".[all]", which includes it
```

It is **best-effort and self-contained**:

- If the `semgrep` binary isn't installed, the analyzer **no-ops and returns nothing** — the LLM layer still runs, exactly as before.
- A crash or timeout in Semgrep **never fails the scan**; it logs and returns no findings. The subprocess is always killed and reaped (never orphaned), even if the overall scan is cancelled.
- It only runs when the repo contains JS/TS files.
- No network: the rule packs ship with isitsecure; Semgrep runs with `--metrics off`.

## Why It Matters

Before this analyzer, injection detection (SQLi/XSS/SSRF/path-traversal/command-injection) rested **entirely on the LLM**, which is non-deterministic (finding counts wobble run-to-run), costs tokens, and is slow. The Semgrep layer gives a reproducible, instant, free floor for the mechanical source→sink cases, while the LLM keeps covering business-logic flaws and the long tail of libraries without rules.

See [docs/taint-analysis.md](../taint-analysis.md) for the full design rationale, the spike results, and the per-stack rule model. The layer has its own recall/FP scorecard — **12/12 recall, 0 false positives** on an independent JS/TS injection fixture — via `python benchmarks/run_benchmarks.py sast-injection` (see [benchmarks/RESULTS.md](../../benchmarks/RESULTS.md)).

## What Vulnerable Code Looks Like

```typescript
// BAD: user input interpolated into a raw SQL query (flagged: critical)
const id = searchParams.get("id");
const rows = await sql.unsafe(`SELECT * FROM users WHERE id = ${id}`);

// BAD: user-controlled URL fetched server-side (flagged: high — SSRF)
const target = searchParams.get("url");
const res = await fetch(target);
```

```typescript
// GOOD: parameterized query — not flagged
const rows = await sql`SELECT * FROM users WHERE id = ${id}`;
```

## Limitations

- **Intra-file only.** OSS Semgrep taint tracks dataflow within a single file. A route that hands user input to a helper in another file which then reaches a sink (inter-procedural) is not tracked — that path falls back to the LLM reviewer. (Inter-file taint is Semgrep Pro territory.)
- **JS/TS today.** Python and other stacks are future rule-pack work; those apps rely on the LLM layer meanwhile.
- **Per-stack rules.** Sinks for libraries we haven't catalogued won't fire deterministically (again, the LLM backstops them).

## Configuration

No configuration. The analyzer auto-runs on any code-only/full scan when the `semgrep` binary is available and the repo has JS/TS files. The rule packs live in `isitsecure/engine/code_analysis/semgrep_rules/`.
