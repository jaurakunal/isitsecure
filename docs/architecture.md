# Architecture

isitsecure is a unified security scanning pipeline that runs SAST, DAST, and LLM-powered analysis in a single orchestrated flow. This document explains how the pieces fit together.

## The 10-Phase Pipeline

Every scan follows this sequence. Phases are skipped automatically based on scan mode and available inputs.

```
Phase 1:  URL Ingestion          ─── Playwright captures HTML + JS bundles
Phase 2:  Endpoint Discovery     ─── JS bundles + OpenAPI specs + HTML forms + active probing
Phase 3:  Authenticated Crawl    ─── Browser login + BFS page discovery
Phase 3.5: OOB Registration      ─── Setup blind SSRF/injection callbacks
Phase 4:  DAST Scanners          ─── 16 scanners run in parallel (quick; deep adds 3)
Phase 5:  Authenticated DAST     ─── JWT, RLS, privilege escalation, cross-user IDOR
Phase 5.5: Probe Analysis        ─── Cross-scanner pattern detection on HTTP pairs
Phase 5.6: OOB Collection        ─── Poll for blind vulnerability callbacks
Phase 6:  Repo Ingestion         ─── Clone + index repository
Phase 6.5: LSP Initialization    ─── Start TypeScript Language Server
Phase 7:  SAST Scanners          ─── 18 scanners run in parallel
Phase 7.5: LSP Validation        ─── Trace auth flows, suppress false positives
Phase 8:  LLM Code Review        ─── AI analyzes high-risk routes
Phase 9:  Cross-Reference        ─── Match DAST findings to SAST findings
Phase 9.1: SAST-Guided DAST     ─── Generate targeted tests from code findings
Phase 9.2: LLM Business Logic    ─── AI plans business logic attacks
Phase 9.4: Injection Adjudication ── AI drops heuristic injection false positives
Phase 9.5: LLM Triage           ─── Deduplicate, enrich, prioritize, theme
Phase 10: Report                 ─── Build DeepScanReport
Phase 11: Fix Generation         ─── AI generates code patches (optional, --output fixes)
```

## How Each Phase Works

### Phase 1–2: Discovery

The scanner first understands your application's attack surface using **four complementary discovery strategies** (`EndpointDiscoveryScanner`), so it works on SPAs, classic server-rendered apps, and frontend-less REST APIs alike:

1. **Playwright** navigates to your URL and captures the rendered HTML + all loaded JavaScript bundles.
   Bundles are collected from `<script src>` **and** from `<link href="….js">` — modulepreload,
   preload and prefetch. A code-split SPA ships its entry bundle as a `<script>` and every lazy
   route chunk as a `<link>`, so a script-only sweep sees the shell and none of the routes. On
   Juice Shop that gap hid 10 of the 13 JavaScript files, and with them `/api/Users` and
   `/api/Feedbacks`: adding the `<link>` source took url-only discovery from 61 endpoints to 123
2. **Seven regex patterns** extract API endpoints from the JS code: fetch calls, axios requests, Supabase `from()` queries, route definitions, parameterized paths
3. **OpenAPI/Swagger spec discovery** — probes 13 well-known spec locations (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/v2/api-docs`, `/swagger/v1/swagger.json`, `/.well-known/openapi.json`, …) for each API base, parses any spec it finds, and extracts every declared endpoint with its methods, path parameters (including `{templated}` segments), and query parameters. This surfaces APIs with no crawlable frontend
4. **HTML form/link discovery** (`html_endpoint_extractor`) — parses server-rendered pages with a stdlib `HTMLParser` to extract `<form action>` targets (with their `<input>`/`<select>`/`<textarea>` field names as parameters) and `<a href>` links that carry query parameters. This surfaces classic MVC apps that have no JS API bundle. It runs both in url-only discovery (bounded same-origin crawl) and inside the authenticated crawler after each page load
5. **Active probing** hits common API base paths (`/api`, `/graphql`, `/rest/v1/`) to discover endpoints not visible in JS
6. Each endpoint is categorized: `USER_DATA`, `RESOURCE_CRUD`, `AUTH`, `ADMIN`, `PAYMENT`, `FILE_ACCESS`, `PUBLIC`

This matters because SPAs hide their API surface in JavaScript bundles, server-rendered apps expose it only in HTML forms, and REST APIs may expose nothing but an OpenAPI spec. Traditional crawlers miss most of it.

**Endpoint prioritization + time budget** — before the DAST scanners run, a shared prioritizer (`endpoint_prioritizer.rank()`) scores endpoints per attack dimension (INJECTION, IDOR, XSS, CSRF, AUTH) so the most likely-vulnerable endpoints are tested first. Each scanner then works within a per-scanner `TimeBudget`, checking `budget.expired()` between endpoints so high-risk paths get covered before the external hard timeout cancels the scanner. The injection, XSS, IDOR, CSRF, auth-bypass, and HTTP-probe scanners all use this shared prioritizer.

Ranking has to account for injection that arrives somewhere other than a parameter. A file upload takes no query string, no path parameter and no body field — its payload *is* the file — so every parameter-shaped signal scores it zero and a cap of 30 never reaches it. `EndpointCategory.FILE_ACCESS` therefore counts toward the INJECTION dimension: on Juice Shop that moved `/file-upload` from 73rd of 77 to 6th, and with it the two XXE vulnerabilities behind it.

### Phase 3: Authenticated Crawl

If credentials are provided:

1. Playwright launches a headless browser and logs in via the actual login form. **Form-scoped login-field detection** (`BrowserLoginHelper.detect_and_fill_login`) locates the visible password field, scopes to its enclosing `<form>`, and fills the identity field in that same form — so it logs in even when the identity field isn't named `email` (e.g. `userName`, `login`, `handle`) without any hardcoded selectors
2. Network interception captures every API call the authenticated app makes
3. BFS (breadth-first search) crawls dashboard pages, discovering endpoints that only appear after login — the same HTML form/link extractor runs after each page load
4. The crawler extracts **owned resource IDs** — UUIDs and numeric IDs that belong to the authenticated user
5. These IDs are used later for IDOR testing: "can User B access User A's resources?"

For frontend-less REST APIs, `RestLoginAuthProvider` (the `token` auth provider) skips the browser entirely: it POSTs credentials to a login endpoint (auto-discovered, or given via `--login-url`), extracts the bearer token from the JSON response (or via JWT regex), and builds an authenticated session directly.

After the crawl, the orchestrator hands the captured auth (bearer token and/or session cookie) to every HTTP DAST scanner that exposes `_auth_headers` (the `AuthAwareScanner` mixin in `engine/shared/auth_aware.py`). Each such scanner passes those headers as `extra_headers` to its `RateLimitedClient`, so the standard probes — injection, CSRF, SSRF, CORS, headers, open-redirect, mass-assignment, file-upload, GraphQL, HTTP-probe, source-map — run behind the login wall against protected endpoints instead of being redirected to the login page. Two deep-only scanners that use a raw `httpx` client (rate-limit and password-reset) are also auth-aware (#119): they merge the session into their client's base headers so behind-login rate-limit/reset endpoints are reachable. The auth-bypass scanner is deliberately **not** auth-aware — its tests depend on the absence or manipulation of auth, so injecting a live session would make bypass attempts spuriously succeed; the `hasattr(_, "_auth_headers")` guard skips it.

### Phase 4–5: DAST Scanners

16 standard scanners run in parallel at quick depth (deep adds 3 aggressive
ones — rate-limit, auth-bypass, password-reset), each with per-scanner timeouts:

```
┌──────────────────────────────────────────────────────┐
│                  DAST Scanners (parallel)             │
├──────────┬──────────┬──────────┬──────────┬──────────┤
│ XSS      │ SQLi     │ CSRF     │ CORS     │ SSRF     │
│ (3600s)  │ (5400s)  │ (600s)   │ (600s)   │ (600s)   │
├──────────┼──────────┼──────────┼──────────┼──────────┤
│ Headers  │ GraphQL  │ Upload   │ Redirect │ Session  │
│ (600s)   │ (600s)   │ (600s)   │ (600s)   │ (600s)   │
├──────────┼──────────┼──────────┼──────────┼──────────┤
│ AuthByp  │ MassAsgn │ RateLimit│ PwdReset │ HTTPProbe│
│ (1800s)  │ (600s)   │ (900s)   │ (600s)   │ (900s)   │
└──────────┴──────────┴──────────┴──────────┴──────────┘
```

**Timeout isolation**: If one scanner hangs or crashes, the rest continue. `run_scanner_safe()` wraps every scanner with timeout + exception handling, and publishes its deadline so a scanner short of time returns what it found rather than being cancelled holding it.

**Rate limiting**: All HTTP requests go through `RateLimitedClient` with configurable concurrency and per-request delays. This prevents getting blocked by the target's WAF.

Authenticated scanners run separately with two sessions (User A and User B) for cross-user testing:
- **JWT Scanner**: Tests alg:none bypass, weak secrets, key confusion
- **RLS Deep Scanner**: Queries Supabase tables with anon key and cross-user tokens
- **Privilege Escalation**: 8 tests including admin route access, role self-elevation, RPC bypass
- **Cross-User IDOR (BOLA)**: User B tries to read/write/delete User A's resources. The scanner harvests User A's real object IDs from parent collections (e.g. `GET /api/tasks` yields task IDs — handling both numeric and UUID id shapes), then swaps them into User B's requests. An **anonymous-access guard** first probes each resource without any auth and suppresses the finding if the endpoint is simply public, and a content-match check confirms User B actually received User A's data rather than an empty or generic response

### Phase 6–7: SAST Scanners

The repository is cloned (shallow, to temp dir) and indexed:

1. **Framework detection** — reads `package.json` to identify Next.js, Remix, SvelteKit, Express, etc.
2. **Backend detection** — identifies Supabase, Firebase, Prisma, Drizzle, tRPC
3. **Route mapping** — framework-specific mappers extract route files and their HTTP methods:
   - `NextJSRouteMapper`: `app/api/**/route.ts` → route pattern + methods
   - `ExpressRouteMapper`: `app.get('/path', ...)` → route pattern + methods
   - `TRPCRouteMapper`: `router.query/mutation` → procedures
   - `GraphQLRouteMapper`: schema definitions → query/mutation types
4. **File indexing** — reads all source files into memory (filtered by extension, size limit, skip `node_modules`)

18 SAST scanners then run in parallel against the indexed codebase (plus the LLM-powered Semantic Rule Verifier when an API key is available). One of them, the **Semgrep Taint Analyzer** (`semgrep_taint`), is a deterministic source→sink injection floor for JS/TS, Python, Java, and Kotlin that sits beneath the LLM code reviewer: it catches the mechanical SQLi/XSS/SSRF/path-traversal/command-injection/SSTI cases reproducibly and for free, leaving the LLM to cover business logic and uncatalogued libraries. It is opt-in (`[taint]` extra) and no-ops if the `semgrep` binary is absent.

Each phase is a method on the agent (`_phase_url_ingestion`,
`_phase_dast_scanners`, …) taking a `ScanContext` — the twenty-seven values
that cross a phase boundary, named in `engine/scan_context.py` rather than
held as locals. `scan()` itself is the sequence of those calls.

### Phase 7.5: LSP Validation

If TypeScript and Node.js are available, the **TypeScript Language Server** is used to trace auth flows.

The server carries no TypeScript of its own and resolves one from the workspace — but ingestion strips `node_modules`, so there is never one there. Phase 6.5 therefore locates a TypeScript 5.x `tsserver.js` (`lsp/tsserver_locator.py`: `$ISITSECURE_TSSERVER_PATH` → the scanned project → `~/.isitsecure/lsp` → the global npm root) and passes it as `tsserver.path` in the handshake. Without it the server refuses to start and this phase is skipped entirely.



```
Route file: app/api/tasks/[id]/route.ts
  → imports protectedProcedure from @/lib/trpc
    → LSP go-to-definition → trpc.ts:42
      → finds supabase.auth.getUser() call
        → Auth IS genuinely applied → suppress false positive
```

Findings the tracer disproves are removed from the report, matched back **per
route** — a finding carries the route it is about, so one guarded route in a
file of a hundred cannot vouch for the rest.

This is unique — no commercial SAST tool uses compiler-level definition resolution to verify that auth middleware actually works.

### Phase 8: LLM Code Review

Not every route gets LLM review (too expensive). Five **review triggers** select which routes are worth the API cost:

| Trigger | Priority | Logic |
|---|---|---|
| **Financial Operation** | 0 (always) | Route pattern or content contains payment/checkout/billing keywords |
| **Cross-Scanner Flagged** | 1 | Route flagged by 2+ different SAST scanners |
| **State Mutation** | 2 | POST/PUT/PATCH/DELETE routes |
| **Risk Indicator** | 3 | Route content matches risk patterns (eval, exec, raw SQL) |
| **Import Graph Centrality** | 4 | Non-route files imported by many high-risk routes |

Each trigger type gets a **specialized system prompt**. The financial operation trigger uses a prompt focused on race conditions, idempotency, and price manipulation. The injection trigger uses a prompt focused on data flow and sanitization.

**Import graph centrality** is worth explaining: the scanner builds a module dependency graph, identifies files with high fan-in from already-selected routes, and sends those shared helpers to LLM review too. A bug in `lib/db.ts` imported by 15 routes has massive blast radius — this catches it regardless of content.

### Phase 9: Cross-Referencing

The cross-referencer matches DAST and SAST findings:

```
DAST: IDOR on /api/tasks/[id]    ──┐
                                     ├── CONFIRMED: IDOR + missing auth on same endpoint
SAST: Missing auth on tasks/[id]  ──┘
```

Matching rules:
- IDOR (DAST) + Missing auth (SAST) → **Confirmed IDOR** (severity boosted)
- RLS bypass (DAST) + Missing RLS (SAST) → **Confirmed RLS gap**
- Injection (DAST) + Injection risk (SAST) → **Confirmed injection**
- Secret exposure (DAST) + Secret in code (SAST) → **Confirmed secret leak**

Cross-referenced findings get higher confidence and boosted severity because they're proven from both sides.

### Phase 9.1: SAST-Guided DAST

This is the core differentiator. Six strategies generate targeted DAST tests from SAST findings:

| Strategy | SAST Input | DAST Test Generated |
|---|---|---|
| **Auth Bypass** | Route missing auth check | Send unauthenticated request to the endpoint |
| **IDOR Targeted** | Route missing ownership check | Swap path parameter ID and check response |
| **Injection Targeted** | Raw SQL concatenation detected | Send `' OR '1'='1' --` to the flagged parameter |
| **Mass Assignment** | Schema has `isAdmin` field | POST `{"isAdmin": true}` to the endpoint |
| **Race Condition** | LLM flags TOCTOU | Fire 5 concurrent identical mutations |
| **RLS Bypass** | Table missing RLS policy | Query Supabase REST API with anon key |

Commercial tools call DAST↔SAST correlation "IAST" and sell it as post-hoc matching. isitsecure's approach is **generative** — code findings create new dynamic tests that wouldn't have been run otherwise.

### Phase 9.4: Injection Adjudication

The active DAST injection scanner uses heuristics — response-size deltas and error strings — to flag SQL/NoSQL/command/template/XXE injection. Those heuristics misfire on benign behaviour: a redirect that renders the single-page-app shell, pagination, timestamps, or dynamic content can inflate a response just as much as a real data leak (issue #5).

The **injection adjudicator** (`engine/triage/injection_adjudicator.py`) runs before triage and hands the LLM, for each borderline DAST injection finding, the payload plus the **baseline (safe-value) response** and the **injected response**, asking whether the difference is genuinely caused by injection or is normal application behaviour. Findings judged benign are dropped. Design guarantees:

- It only ever **removes** a candidate — never creates or mutates findings — and only DAST injection findings whose title is in the adjudicated set. The deterministic Semgrep taint (SAST) findings are never touched.
- It **fails open** on any LLM or parse error (a failed/malformed response keeps every finding), and the prompt resolves genuine uncertainty to "genuine." It is a precision filter, not a hard guarantee: a confident-but-wrong `benign` verdict can still drop a true positive, so it trades a little recall for fewer false positives. The target's response bodies are fenced as untrusted data in the prompt so a hostile target cannot inject a "benign" verdict to suppress its own findings.
- It is a **strict no-op without an LLM client**, so the deterministic `--llm none` scan (and the benchmark floor) is unaffected — the false positives it removes are a with-API-key precision improvement, not a change to the rule-based detection.

To make this possible, the scanner attaches the baseline (safe-value) response body to the borderline findings — the NoSQL size-oracle findings and the error-based SQLi findings (`DeepFinding.baseline_response_preview`) — so the model has both sides to compare. For error-based SQLi this lets it separate a real injection (the SQL error appears only under the payload) from a false positive (the "error" text is already in the baseline, or isn't really a query error) — the flaky `vampi-secure` SQLi false positives (#125). As with the rest of this phase, that clean-up only happens when an API key is present; the `--llm none` scan still emits the raw finding.

### Phase 9.5: LLM Triage

The triage service processes all findings through four stages:

**Stage 0: Rule-based deduplication** (no LLM cost)
- Pass 1: Exact title match → keep highest severity
- Pass 2: Same file + line number → merge
- Pass 3: Same scanner + category + file with 3+ findings → group into one
- Pass 4: Fuzzy title match (60% word overlap) → deduplicate

**Stage 1: LLM enrichment** (batched, bounded concurrency)
- Assigns impact category (FINANCIAL, DATA_BREACH, LEGAL, OPERATIONAL, REPUTATIONAL)
- Assigns likelihood level (ACTIVELY_EXPLOITABLE, REQUIRES_AUTH, REQUIRES_ADMIN, THEORETICAL)
- Derives priority (1–4) from impact × likelihood matrix

**Stage 1.5: Calibration**
- Auto-escalates HIGH → CRITICAL if impact is financial/data_breach AND likelihood is actively_exploitable

**Stage 2: Owner summary**
- Generates a plain-language summary for non-technical site owners
- Assigns A–F grade
- Lists top 5 key risks in plain English
- Provides phased remediation plan

### Phase 11: AI Fix Generation (Optional)

Fix generation (`isitsecure/engine/fixes/`) turns findings into applied code
changes. For each critical/high finding with a code location, the full source
file plus finding details are sent to the LLM with a security-aware system
prompt, and the fixed file is parsed back out. There are three delivery modes:

**a) Markdown fix plan** — `scan --output fixes` exports a unified diff +
explanation per finding, designed to paste directly into Cursor or Claude Code
("Apply all the security fixes in this document").

**b) Local apply + verify** (`isitsecure fix --repo <path>`) — git-free:
`fixes/safety_net.py` snapshots the working tree first (git-stash-create ref or
file-copy backup), the fixes are written in place, then the code is **re-scanned
to verify each finding is resolved**. `fixes/plain_results.py` classifies the
outcome (fixed / needs review / couldn't fix) into a plain-language summary
(`--technical` surfaces the git/backup mechanics).

**c) Remote clone → per-category PRs** (`isitsecure fix --repo <github-url>`) —
`fixes/pr_flow.py` clones the repo, groups fixed findings (per-category by
default; also per-file / per-finding / single), and opens one pull request per
group — one commit per finding, onto a feature branch, never the default branch.
`--max-prs` caps the count; excess low-severity categories batch into one PR.
Grouping relies on findings carrying their true `FindingCategory`, which for
LLM-review findings is assigned by `code_analysis/category_classifier.py`.

### Language-Specific Route Mapping

The repo ingestion phase uses framework-specific route mappers:

| Mapper | Framework | What It Parses |
|---|---|---|
| `NextJSRouteMapper` | Next.js App Router | `app/api/**/route.ts` |
| `ExpressRouteMapper` | Express.js | `app.get('/path', handler)` |
| `TRPCRouteMapper` | tRPC | `router.query/mutation` |
| `GraphQLRouteMapper` | GraphQL | Schema types |
| `DjangoRouteMapper` | Django/DRF | `urls.py`, `path()`, `router.register()` |
| `FastAPIRouteMapper` | FastAPI/Flask | `@app.get()`, `@app.route()` |
| `SpringRouteMapper` | Spring Boot | `@GetMapping`, `@RequestMapping` |

All mappers implement `RouteMapperProtocol` and are registered in `factory.py`. Adding a new language requires implementing one mapper — no changes to existing code.

`ExpressRouteMapper` searches the whole repository rather than a list of
directory names, because Express projects put routes wherever they like — a
list of `src`, `routes`, `api` mapped **zero** routes for a project keeping
them in `app/routes`, and downstream nothing can tell "no routes" apart from
"did not look". Vendored and generated directories (`node_modules`, `dist`,
`.git`, …) are pruned, and the walk is capped at
`ExpressRouteMapperConfig.MAX_FILES_SCANNED`.

Searching everywhere then raises a second question, since a repo also holds
route-shaped code that never runs — Juice Shop ships 135 route definitions
under `data/static/codefixes` as fixtures for its own coding challenges. A
candidate is kept only if it is **reachable**: imported by another file
(per `ImportGraphBuilder`), or an entry point nothing imports because it *is*
the start (a top-level script, or `server`/`app`/`index`/`main`). Route files
are often loaded by globbing a directory, which leaves no import to find, so
one reachable route file keeps every route file beside it; and if *nothing*
looks reachable the graph is uninformative — the entry point may be a `.jsx`
or a compiled artefact — so the filter stands down rather than dropping the
whole project.

### Endpoint Discovery

For a single-page app, the served HTML is a shell: the routes and the API
calls both live in the JavaScript bundle, which `EndpointDiscoveryScanner`
parses alongside the HTML.

Two kinds of path appear there, and only one is attack surface — the routes
the app's own router renders are not endpoints, while the paths it calls are.
They are told apart by **how each is written**, a request-making token
(`fetch`, `axios`, `url:`, `hostServer`, …) just before the path:

```js
uploader = new Es({url: Z.hostServer + "/file-upload", ...})   // an endpoint
{path: "/about", component: AboutComponent}                    // a route
```

This replaced a list of interesting-looking directory names (`/dashboard`,
`/api`, `/apps`, `/admin`, `/account`). On Juice Shop that list kept 11 of 55
paths and discarded `/file-upload`, `/dataerasure`, `/profile` and
`/data-export` — and a scanner cannot test an endpoint nothing told it about,
so the four file-upload vulnerabilities behind `/file-upload` were unreachable
no matter how good the file-upload scanner was.

### Coverage limits

Scanners used to stop after a fixed number of endpoints — 20 for XSS, 30 for
injection, 5 for CORS. Against an app with 77 endpoints those caps decided
which quarter got examined, in ranked order, and nothing said so.

They are gone. Probing costs HTTP requests rather than tokens: measured over
nine scans, a DAST run costs $0.12–$0.18 whether it covers 59 endpoints or
154, while a SAST run is a flat ~$1.28 because its cost is the LLM reading
files. The endpoint was never the scarce thing.

What bounds a scan now is **time**, per scanner, via `TimeBudget` — raised
accordingly, since timing out should mean something is wrong rather than that
the app was large. A scan that takes half an hour and finishes beats one that
takes ten minutes having skipped two thirds of the surface, provided it says
what it is doing: every scanner that walks endpoints emits per-endpoint
progress, so a long run is legible rather than silent.

Two caps remain because they bound something genuinely scarce:
`MAX_ENDPOINTS_IN_PROMPT` (LLM tokens) and `MAX_OOB_POST_ENDPOINTS`
(registrations against an external callback service).

### When a scanner runs out of time

`run_scanner_safe` cancels a scanner at its hard timeout, and a cancelled
coroutine cannot hand anything back — so every finding it had accumulated is
discarded. Measured: `http_probe_scanner` ran 901s against a 900s timeout
holding four real findings, an exposed `/.env` among them, and reported none
of them.

Scanners therefore stop *themselves*. The runner publishes its deadline; a
`TimeBudget()` with no argument inherits it, so a scanner opts in with two
lines and never needs to know its own timeout — which is how the inner and
outer values drift apart. The hard cancel remains as a backstop for something
genuinely hung, and logs loudly when it fires, because reaching it now means
a scanner failed to yield rather than merely ran long.

Granularity matters more than it looks. Checking between phases is not
enough when one phase walks the whole inventory: it enters before the
deadline, runs 800s, and is cancelled with everything in it. The check
belongs in the per-endpoint loop.

Order matters too. `http_probe` runs its fixed-cost checks — the ones probing
a handful of known paths — before the ones that scale with the inventory, so
a large app cannot spend its whole budget on method tampering and never reach
the check that finds an exposed `.env`.

### Testing the mutation surface

`--probe-writes` derives state-changing endpoints from REST shape — POST to a
collection, PUT to an item — because a path in a JS bundle carries no method,
so everything is otherwise discovered as a GET and scanners filtering on
POST/PUT find nothing to do. Stored XSS, mass assignment and CSRF all live
behind that filter.

It is off by default: it makes a scan write to whatever it is pointed at.
DELETE is derived and deliberately never emitted — a scanner that destroys a
record to prove it could is not worth the finding.

Measured on Juice Shop, url-only: **24/45 → 30/45**, gaining CSRF, SSTI,
three of the five XSS challenges and one IDOR, losing nothing. The scan takes
about 48 minutes against 27, since the inventory doubles.

That number was not always what it looked like. The first measurement read
neutral — six gained, six lost — and the six "lost" were `exposed_data` and
`info_disclosure`, both of which score off `http_probe_scanner`. It was
running one second past its timeout and having every finding discarded by the
hard cancel; the doubled inventory pushed it over. One bug wearing the
costume of a trade-off, and worth remembering when a measurement shows a
suspiciously tidy wash.

### Remediation scope

Findings arrive one per affected location, which is right for detection and
wrong for reporting. `RemediationScope` says how many places a category has
to be fixed in, and deduplication follows it:

| scope | means | reported | categories |
|---|---|---|---|
| `SERVER` | one config change covers everything | once, listing affected endpoints as evidence | missing headers, CORS, mixed content, source maps, SRI |
| `INSTANCE` | each occurrence is its own fix | every one, never collapsed across locations | IDOR, injection, auth, privilege escalation, business logic, open redirect |
| `SHARED_ROOT` | one cause, many call sites | grouped under the cause, sites listed | exposed secrets, dependencies, RLS, client exposure |

The two failure modes point opposite ways, which is why one rule cannot serve
both. "Missing Content-Security-Policy" restated on 76 endpoints buries a
report; four IDORs collapsed into one hides three vulnerabilities behind
something that looks handled. Deduplicating on the title alone — the only
signal available before this existed — does the first correctly and the
second silently.

Every pass consults it, the fuzzy title pass included: that one is the
loosest, so a wrong merge there is both most likely and least visible.

Deduplication needs no LLM, and no longer waits for one. It used to sit
behind the triage phase, so `--llm none` shipped the raw list — 296 findings
on Juice Shop, of which 272 were five issues restated per endpoint.

## Design Principles

### Protocol-Based (Dependency Inversion)

Every component depends on protocols (interfaces), not concrete implementations:

```python
class DASTScannerProtocol(Protocol):
    @property
    def scanner_name(self) -> str: ...

    async def scan(self, endpoints, snapshot) -> list[DeepFinding]: ...
```

This means:
- New scanners are added by implementing the protocol and appending to the list in `factory.py`
- No existing code changes when adding new scanners (Open/Closed Principle)
- Every scanner is independently testable with mocked dependencies

### Graceful Degradation

The scanner works at any completeness level:

| Missing | What Happens |
|---|---|
| No LLM API key | Rule-based scanners only. No business logic review, no semantic verification, no triage enrichment |
| No Playwright | URL ingestion falls back to httpx. No authenticated crawl, no DOM XSS |
| No language server for the project's language | LSP validation skipped. Auth flow tracing unavailable, more false positives. The server is chosen from the code (see [lsp-setup.md](lsp-setup.md)), so an installed server for a *different* language is never substituted |
| No TypeScript 5.x runtime | Same — `typescript-language-server` won't start without a `tsserver.js`. `isitsecure setup --lsp` provisions one; see [lsp-setup.md](lsp-setup.md) |
| No repo URL | SAST skipped entirely. DAST-only scan |
| Repo fails to clone | Code-only: the scan stops and exits 1 (no report). Full: DAST findings are kept, the reason is recorded in `ingestion_errors`, and the CLI exits 1 — a zero-finding report must never read as "your code is fine" |
| No target URL | SAST-only scan against code |
| No credentials | Authenticated scanners skipped. No IDOR cross-user, no privilege escalation |

### Timeout Isolation

Every scanner runs inside `run_scanner_safe()`:

```python
async def run_scanner_safe(scanner_name, scan_coro, timeout_seconds):
    try:
        # Publishes the deadline so the scanner can stop itself and RETURN
        # what it found — a cancel here discards everything.
        with scanner_deadline(timeout_seconds):
            return await asyncio.wait_for(scan_coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning(f"{scanner_name} timed out — findings discarded")
        return []
    except Exception as e:
        logger.error(f"{scanner_name} failed: {e}")
        return []
```

A single scanner failure never kills the scan. Timeouts are per-scanner-type
and generous, because the endpoint caps are gone and time is the only bound
left: the default is 600s, injection gets 5400s, XSS 3600s.

Reaching the `asyncio.TimeoutError` branch is now a **failure signal**, not
the ordinary way a scanner ends — it means the scanner did not stop on the
cooperative deadline, so it either has no `TimeBudget` or blocked between
checks. See [When a scanner runs out of time](#when-a-scanner-runs-out-of-time).

### Event-Driven Progress

The scan generator yields `DeepScanEvent` objects for real-time progress:

```python
async for event in agent.scan(target_url=url, repo_url=repo):
    print(f"[{event.progress}%] {event.phase}: {event.message}")
```

This powers both the CLI progress bar and the web UI's real-time dashboard.

## Package Structure

```
isitsecure/
├── engine/                     # The scanner engine
│   ├── agent.py                # 10-phase orchestrator
│   ├── factory.py              # Dependency injection + wiring
│   ├── models.py               # DeepFinding, DeepScanReport, etc.
│   ├── enums.py                # All enumerations
│   ├── constants.py            # All configuration constants
│   ├── identity.py             # Stable cross-scan finding fingerprint (#38 trust)
│   ├── suppression.py          # .isitsecureignore parsing + filter (#51)
│   ├── baseline.py             # Baseline accept/diff — show only new findings (#52)
│   ├── reverify.py             # Per-finding re-verification (SAST + DAST) (#53)
│   ├── cross_referencer.py     # DAST ↔ SAST finding matcher
│   ├── scan_config.py          # User-configurable scan settings
│   ├── scanners/               # 16 DAST scanners (quick) + special scanners
│   ├── code_analysis/          # 18 SAST scanners + route mappers + LSP + semgrep_rules/
│   │   └── category_classifier.py  # Maps LLM-review findings to their FindingCategory
│   ├── fixes/                  # AI fix gen: safety_net, verifier, plain_results, pr_flow
│   ├── guided_dast/            # SAST → DAST test generation (6 strategies)
│   ├── auth/                   # Auth providers (Supabase, Firebase, Browser, Token)
│   ├── shared/                 # Rate limiter, OOB callbacks, JWT utils
│   ├── triage/                 # LLM triage + priority calculator
│   ├── reporting/              # Report gen (JSON, HTML) + plain_english remediation layer
│   ├── ingestion/              # URL snapshot capture
│   ├── verification/           # Ownership verification
│   ├── projects/               # Project + certification management
│   └── integrations/           # CI/CD + notification services
├── llm/                        # LLM client adapters
│   ├── protocol.py             # LLMClientProtocol (DIP)
│   └── adapters.py             # Anthropic + Google implementations
├── server/                     # FastAPI server for web UI
│   ├── app.py                  # API routes + SSE streaming
│   └── static/                 # Pre-built Next.js UI (bundled)
├── mcp_server.py               # Local stdio MCP server (`scan` tool for AI coding tools)
└── cli.py                      # Typer CLI (scan, fix, badge, launch, mcp, setup)
```

## Data Flow

```
                    ┌─────────────────────┐
                    │   User Input        │
                    │   URL / Repo / Creds│
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   URL Ingestion     │
                    │   (Playwright)      │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Endpoint Discovery  │──── DiscoveredEndpoint[]
                    │ (JS bundle parsing) │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
    ┌─────────▼────────┐ ┌────▼────────┐ ┌─────▼──────────┐
    │  DAST Scanners   │ │ Auth DAST   │ │ Repo Ingestion │
    │  (16 parallel)   │ │ (JWT, IDOR  │ │ (git clone +   │
    │                  │ │  RLS, PrivE) │ │  index)        │
    └─────────┬────────┘ └────┬────────┘ └─────┬──────────┘
              │               │                 │
              │               │         ┌───────▼──────────┐
              │               │         │  SAST Scanners   │
              │               │         │  (18 parallel)   │
              │               │         └───────┬──────────┘
              │               │                 │
              └───────────────┼─────────────────┘
                              │
                   ┌──────────▼──────────┐
                   │  Cross-Reference    │
                   │  DAST ↔ SAST match  │
                   └──────────┬──────────┘
                              │
                   ┌──────────▼──────────┐
                   │  SAST-Guided DAST   │
                   │  (6 strategies)     │
                   └──────────┬──────────┘
                              │
                   ┌──────────▼──────────┐
                   │  LLM Triage         │
                   │  Dedup + Enrich     │
                   └──────────┬──────────┘
                              │
                   ┌──────────▼──────────┐
                   │  DeepScanReport     │
                   │  (JSON/HTML/SARIF)  │
                   └─────────────────────┘
```
