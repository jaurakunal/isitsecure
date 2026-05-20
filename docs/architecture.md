# Architecture

isitsecure is a unified security scanning pipeline that runs SAST, DAST, and LLM-powered analysis in a single orchestrated flow. This document explains how the pieces fit together.

## The 10-Phase Pipeline

Every scan follows this sequence. Phases are skipped automatically based on scan mode and available inputs.

```
Phase 1:  URL Ingestion          ─── Playwright captures HTML + JS bundles
Phase 2:  Endpoint Discovery     ─── Extract API endpoints from JS code
Phase 3:  Authenticated Crawl    ─── Browser login + BFS page discovery
Phase 3.5: OOB Registration      ─── Setup blind SSRF/injection callbacks
Phase 4:  DAST Scanners          ─── 15 scanners run in parallel
Phase 5:  Authenticated DAST     ─── JWT, RLS, privilege escalation, cross-user IDOR
Phase 5.5: Probe Analysis        ─── Cross-scanner pattern detection on HTTP pairs
Phase 5.6: OOB Collection        ─── Poll for blind vulnerability callbacks
Phase 6:  Repo Ingestion         ─── Clone + index repository
Phase 6.5: LSP Initialization    ─── Start TypeScript Language Server
Phase 7:  SAST Scanners          ─── 16 scanners run in parallel
Phase 7.5: LSP Validation        ─── Trace auth flows, suppress false positives
Phase 8:  LLM Code Review        ─── AI analyzes high-risk routes
Phase 9:  Cross-Reference        ─── Match DAST findings to SAST findings
Phase 9.1: SAST-Guided DAST     ─── Generate targeted tests from code findings
Phase 9.2: LLM Business Logic    ─── AI plans business logic attacks
Phase 9.5: LLM Triage           ─── Deduplicate, enrich, prioritize, theme
Phase 10: Report                 ─── Build DeepScanReport
Phase 11: Fix Generation         ─── AI generates code patches (optional, --output fixes)
```

## How Each Phase Works

### Phase 1–2: Discovery

The scanner first understands your application's attack surface:

1. **Playwright** navigates to your URL and captures the rendered HTML + all loaded JavaScript bundles
2. **Seven regex patterns** extract API endpoints from the JS code: fetch calls, axios requests, Supabase `from()` queries, route definitions, parameterized paths
3. **Active probing** hits common API base paths (`/api`, `/graphql`, `/rest/v1/`) to discover endpoints not visible in JS
4. Each endpoint is categorized: `USER_DATA`, `RESOURCE_CRUD`, `AUTH`, `ADMIN`, `PAYMENT`, `FILE_ACCESS`, `PUBLIC`

This matters because SPAs hide their API surface in JavaScript bundles. Traditional crawlers miss most of it.

### Phase 3: Authenticated Crawl

If credentials are provided:

1. Playwright launches a headless browser and logs in via the actual login form
2. Network interception captures every API call the authenticated app makes
3. BFS (breadth-first search) crawls dashboard pages, discovering endpoints that only appear after login
4. The crawler extracts **owned resource IDs** — UUIDs and numeric IDs that belong to the authenticated user
5. These IDs are used later for IDOR testing: "can User B access User A's resources?"

### Phase 4–5: DAST Scanners

15 standard scanners run in parallel with per-scanner timeouts:

```
┌──────────────────────────────────────────────────────┐
│                  DAST Scanners (parallel)             │
├──────────┬──────────┬──────────┬──────────┬──────────┤
│ XSS      │ SQLi     │ CSRF     │ CORS     │ SSRF     │
│ (600s)   │ (900s)   │ (60s)    │ (60s)    │ (60s)    │
├──────────┼──────────┼──────────┼──────────┼──────────┤
│ Headers  │ GraphQL  │ Upload   │ Redirect │ Session  │
│ (60s)    │ (60s)    │ (60s)    │ (60s)    │ (60s)    │
├──────────┼──────────┼──────────┼──────────┼──────────┤
│ AuthByp  │ MassAsgn │ RateLimit│ PwdReset │ HTTPProbe│
│ (300s)   │ (60s)    │ (300s)   │ (60s)    │ (180s)   │
└──────────┴──────────┴──────────┴──────────┴──────────┘
```

**Timeout isolation**: If one scanner hangs or crashes, the rest continue. `run_scanner_safe()` wraps every scanner with timeout + exception handling.

**Rate limiting**: All HTTP requests go through `RateLimitedClient` with configurable concurrency and per-request delays. This prevents getting blocked by the target's WAF.

Authenticated scanners run separately with two sessions (User A and User B) for cross-user testing:
- **JWT Scanner**: Tests alg:none bypass, weak secrets, key confusion
- **RLS Deep Scanner**: Queries Supabase tables with anon key and cross-user tokens
- **Privilege Escalation**: 8 tests including admin route access, role self-elevation, RPC bypass
- **Cross-User IDOR**: User B tries to read/write/delete User A's resources

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

14 SAST scanners then run in parallel against the indexed codebase.

### Phase 7.5: LSP Validation

If TypeScript and Node.js are available, the **TypeScript Language Server** is used to trace auth flows:

```
Route file: app/api/tasks/[id]/route.ts
  → imports protectedProcedure from @/lib/trpc
    → LSP go-to-definition → trpc.ts:42
      → finds supabase.auth.getUser() call
        → Auth IS genuinely applied → suppress false positive
```

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

When `--output fixes` is used, the scanner generates code patches:

1. For each critical/high finding with a code location, read the full source file
2. Send the finding details + file content to the LLM with a security-aware system prompt
3. Parse the LLM response to extract the fixed code
4. Generate a unified diff between original and fixed code
5. Export as a Markdown fix plan with diffs and explanations

The fix plan is designed to be pasted directly into Cursor or Claude Code:
> "Apply all the security fixes in this document"

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
| No TypeScript/Node.js | LSP validation skipped. Auth flow tracing unavailable, more false positives |
| No repo URL | SAST skipped entirely. DAST-only scan |
| No target URL | SAST-only scan against code |
| No credentials | Authenticated scanners skipped. No IDOR cross-user, no privilege escalation |

### Timeout Isolation

Every scanner runs inside `run_scanner_safe()`:

```python
async def run_scanner_safe(scanner_name, scan_coro, timeout_seconds):
    try:
        return await asyncio.wait_for(scan_coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning(f"{scanner_name} timed out after {timeout_seconds}s")
        return []
    except Exception as e:
        logger.error(f"{scanner_name} failed: {e}")
        return []
```

A single scanner failure never kills the scan. Timeouts are per-scanner-type (XSS gets 600s, headers get 60s).

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
│   ├── cross_referencer.py     # DAST ↔ SAST finding matcher
│   ├── scan_config.py          # User-configurable scan settings
│   ├── scanners/               # 15 DAST scanners + special scanners
│   ├── code_analysis/          # 14 SAST scanners + route mappers + LSP
│   ├── guided_dast/            # SAST → DAST test generation (6 strategies)
│   ├── auth/                   # Auth providers (Supabase, Firebase, Browser, Token)
│   ├── shared/                 # Rate limiter, OOB callbacks, JWT utils
│   ├── triage/                 # LLM triage + priority calculator
│   ├── reporting/              # Report generation (JSON, HTML)
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
└── cli.py                      # Typer CLI (scan, launch, setup)
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
    │  (15 parallel)   │ │ (JWT, IDOR  │ │ (git clone +   │
    │                  │ │  RLS, PrivE) │ │  index)        │
    └─────────┬────────┘ └────┬────────┘ └─────┬──────────┘
              │               │                 │
              │               │         ┌───────▼──────────┐
              │               │         │  SAST Scanners   │
              │               │         │  (14 parallel)   │
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
