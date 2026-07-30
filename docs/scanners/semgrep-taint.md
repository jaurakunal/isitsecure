# Semgrep Taint Analyzer

**Type:** SAST | **Severity:** High–Critical | **Category:** Injection Risk

## What It Does

Runs [Semgrep](https://semgrep.dev) with isitsecure's own taint/sink rule packs over your cloned repo and maps the results to findings. It is a **deterministic injection floor beneath the LLM code reviewer**: the same input always produces the same findings, instantly and at no token cost.

Three rule packs ship today — **JavaScript/TypeScript** (`injection-js.yaml`, #4), **Python** (`injection-python.yaml`, #93), and **Java/Spring** (`injection-java.yaml`, #102). The analyzer **auto-selects the packs whose languages are present in the repo** (#94): a JS-only repo runs only the JS pack, a mixed repo the relevant ones. (Semgrep also scopes each rule to its declared language, so selection is about not loading irrelevant rules — faster, and ready for per-framework packs later.)

**JavaScript/TypeScript** — six classes:

1. **SQL injection** — raw-query sinks (`sql.unsafe`, Prisma `$queryRawUnsafe`/`$executeRawUnsafe`, `knex.raw`, Drizzle `sql.raw`) and user-input → raw-query taint flows.
2. **Reflected XSS** — request data flowing into an HTML response (`new Response(html)`, `res.send`, `res.write`) without escaping.
3. **DOM XSS** — `location.hash`/`location.search` → `innerHTML`/`outerHTML`/`document.write`.
4. **SSRF** — user-controlled URLs flowing into `fetch`/`axios`/`http.get`.
5. **Path traversal / unrestricted upload** — request-derived filenames flowing into `fs.writeFile`/`createWriteStream` via `path.join` (constant paths are excluded).
6. **Command injection** — user input flowing into `exec`/`spawn`.

**Python** (Flask/Django request sources) — five classes:

1. **SQL injection** — string-built queries in `cursor.execute`/`executemany` (f-string/`%`/`.format`/concat), SQLAlchemy `execute(text(f"…"))`, Django `.objects.raw(…)`, plus a taint rule for the build-then-execute shape. Parameterized queries are never flagged — the taint sink focuses on the query-string argument, so a request value in the `params` tuple is safe.
2. **Command injection** — request input → `os.system`/`os.popen`/`subprocess(..., shell=True)`.
3. **SSRF** — request input → `requests`/`httpx`/`urllib.request.urlopen`.
4. **Path traversal** — request-derived path → `open(...)`.
5. **SSTI** — request input → `render_template_string(...)`.

**Java** (Spring MVC / servlet request sources: `@RequestParam`/`@PathVariable`/`@RequestHeader` params, `HttpServletRequest.getParameter`/`getHeader`) — four classes:

1. **SQL injection** — string-concatenated queries in JDBC `Statement.execute*`, JPA `EntityManager.createQuery`/`createNativeQuery`, Spring `JdbcTemplate.query*`/`update`, plus a taint rule focused on the query-string argument (bound parameters are safe).
2. **Command injection** — request input → `Runtime.getRuntime().exec(...)` / `new ProcessBuilder(...)`.
3. **SSRF** — request input → `new URL(...)` / `RestTemplate.getForObject`/`getForEntity`/`exchange`.
4. **Path traversal** — request-derived path → `new File(...)` / `new FileInputStream(...)` / `new FileReader(...)`.

Rules target **framework/library APIs** (Next.js `searchParams`, Express `req.*`, the `postgres`/Prisma/Drizzle/Knex sinks, Node `fs`; Flask/Django `request.*`, DB-API/SQLAlchemy/Django ORM, `os`/`subprocess`, `requests`/`urllib`, Jinja; Spring `@RequestParam`/`HttpServletRequest`, JDBC/JPA/JdbcTemplate, `Runtime`/`ProcessBuilder`, `URL`/`RestTemplate`, `java.io.File`), so they apply to **any app on those stacks — not per-app**. Apps on an uncatalogued library fall through to the LLM backstop.

Findings are emitted with `scanner_name = "semgrep_taint"`, `confidence = 0.85`, and category `injection_risk`, then flow through the same triage → dedup → plain-English → grading pipeline as every other scanner.

## Requirements & Graceful Degradation

The analyzer needs the `semgrep` binary, shipped via the optional extra:

```bash
pip install -e ".[taint]"   # or ".[all]", which includes it
```

It is **best-effort and self-contained**:

- If the `semgrep` binary isn't installed, the analyzer **no-ops and returns nothing** — the LLM layer still runs, exactly as before.
- A crash or timeout in Semgrep **never fails the scan**; it logs and returns no findings. The subprocess is always killed and reaped (never orphaned), even if the overall scan is cancelled.
- It only runs when the repo contains JS/TS, Python, or Java files.
- No network: the rule packs ship with isitsecure; Semgrep runs with `--metrics off`.

## Why It Matters

Before this analyzer, injection detection (SQLi/XSS/SSRF/path-traversal/command-injection) rested **entirely on the LLM**, which is non-deterministic (finding counts wobble run-to-run), costs tokens, and is slow. The Semgrep layer gives a reproducible, instant, free floor for the mechanical source→sink cases, while the LLM keeps covering business-logic flaws and the long tail of libraries without rules.

See [docs/taint-analysis.md](../taint-analysis.md) for the full design rationale, the spike results, and the per-stack rule model. The layer has its own recall/FP scorecard — **37/37 recall, 0 false positives** on an independent JS/TS + Python + Java injection fixture — via `python benchmarks/run_benchmarks.py sast-injection` (see [benchmarks/RESULTS.md](../../benchmarks/RESULTS.md)).

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
- **JS/TS, Python, and Java today.** Other stacks (Go, Ruby, …) are future rule-pack work; those apps rely on the LLM layer meanwhile. Python and Java server-side XSS (template-autoescaping nuance) is not yet covered.
- **Python taint sources are Flask/Django** (`request.*`); FastAPI endpoint parameters aren't yet tracked, so FastAPI command-injection/SSRF/path/SSTI fall to the LLM layer (string-built SQL is still caught on any stack).
- **Java taint sources are Spring MVC / servlet** (`@RequestParam`/`@PathVariable`/`getParameter`); other Java web frameworks (JAX-RS, `@RequestBody` fields, etc.) fall to the LLM layer. String-concatenated SQL on the unambiguous DB verbs (`executeQuery`/`executeUpdate`/`prepareStatement`/`createNativeQuery`/`queryFor*`) is still caught source-free; the generic verbs (`execute`/`createQuery`/`update`) need a recognized Spring source to fire.
- **Per-stack rules.** Sinks for libraries we haven't catalogued won't fire deterministically (again, the LLM backstops them).

## Configuration

No configuration. The analyzer auto-runs on any code-only/full scan when the `semgrep` binary is available and the repo has files a rule pack covers (JS/TS, Python, or Java) — selecting the matching packs automatically. The rule packs live in `isitsecure/engine/code_analysis/semgrep_rules/`; register a new one in `_RULE_PACKS` in `semgrep_analyzer.py`.
