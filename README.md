# isitsecure

AI-powered security scanner for modern web apps. SAST + DAST + LLM code review in a single scan.

Built for developers and **vibe coders** shipping web apps who need to know if their code is secure — without becoming security experts.

**Supports:** TypeScript/JavaScript (Next.js, Express, tRPC), Python (Django, FastAPI, Flask), Java/Kotlin (Spring Boot) — and any HTTP API for DAST.

---

## What It Does

isitsecure runs **29+ security scanners** against your web app in a single command. It combines four approaches that commercial tools sell separately:

- **SAST (Static Analysis)** — scans your source code for vulnerabilities without running it
- **DAST (Dynamic Analysis)** — tests your live app by sending real HTTP requests
- **LLM Code Review** — uses AI to find business logic flaws that pattern matchers can't detect
- **AI Fix Generation** — generates code patches with unified diffs for every finding

The unique parts:
1. **SAST findings automatically generate targeted DAST tests**. Code shows no auth check → scanner sends an unauthenticated request and confirms it's exploitable.
2. **AI generates fixes, not just reports**. `--output fixes` produces a Markdown fix plan you can paste into Cursor or Claude Code.

```
Code → SAST → Findings → Guide DAST → Test → Cross-Reference → LLM Triage → Report → Fixes
  ↑                                                                                       |
  └──────────────── LSP validates / suppresses false positives ───────────────────────────┘
```

## Quick Start

```bash
# Install
pip install isitsecure

# First-time setup (API keys + browser install)
isitsecure setup

# Scan a live URL (DAST only, no API key needed)
isitsecure scan https://your-app.com

# Scan source code (SAST only)
isitsecure scan --repo https://github.com/you/your-app --mode code-only

# Full scan (SAST + DAST + LLM review)
isitsecure scan https://your-app.com --repo https://github.com/you/your-app --mode full

# Generate AI-powered fixes for all findings
isitsecure scan --repo https://github.com/you/your-app --output fixes

# Export for GitHub Code Scanning
isitsecure scan --repo https://github.com/you/your-app --output sarif

# Open the web UI (for non-CLI users)
isitsecure launch
```

## What It Costs

isitsecure is free and open source. The only cost is LLM API tokens for the AI-powered features:

| Scan Mode | API Key Needed | Estimated Cost |
|---|---|---|
| **URL-only** (DAST without LLM) | No | $0 |
| **Code-only** (SAST without LLM) | No | $0 |
| **Code-only + LLM review** | Yes | ~$5–8 |
| **Full scan** (SAST + DAST + LLM) | Yes | ~$10–15 |

Without an API key, you still get 23 rule-based scanners. The LLM adds business logic review, semantic rule verification, and intelligent triage — things no pattern matcher can do.

**Supported LLM providers:** Anthropic (Claude), Google (Gemini)

## Scan Modes

| Mode | What It Does | Requires |
|---|---|---|
| `url-only` | DAST scanners against a live URL | Target URL |
| `code-only` | SAST scanners against source code | GitHub repo URL |
| `authenticated` | DAST with login credentials (IDOR, RLS, privilege escalation) | URL + credentials |
| `full` | Everything: SAST + DAST + authenticated + LLM review + cross-referencing | URL + repo + credentials + API key |
| `auto` (default) | Detects mode from what you provide | Whatever you give it |

## What It Scans

### DAST Scanners (15) — Tests Your Live App

| Scanner | What It Finds |
|---|---|
| XSS Scanner | Reflected, POST body, and DOM-based cross-site scripting |
| Active Injection Scanner | SQL injection (error + time-based), command injection, NoSQL injection, XXE, SSTI |
| CSRF Scanner | Cross-site request forgery on state-changing endpoints |
| Rate Limit Scanner | Missing or bypassable rate limiting on auth endpoints |
| Session Scanner | Insecure token storage (localStorage), missing cookie flags, long-lived JWTs |
| GraphQL Scanner | Introspection enabled, no depth limits, batch query abuse |
| SSRF Scanner | Server-side request forgery (internal IPs, cloud metadata) |
| File Upload Scanner | Unrestricted file types, path traversal in filenames |
| Mass Assignment Scanner | Accepting privileged fields (role, isAdmin) in request body |
| Security Headers Scanner | Missing CSP, HSTS, X-Frame-Options; server version disclosure |
| CORS Scanner | Wildcard origins, credentials with permissive CORS |
| Open Redirect Scanner | Unvalidated redirect parameters |
| Auth Bypass Scanner | Username enumeration, default credentials, account lockout bypass |
| HTTP Probe Scanner | Method tampering, host header injection, directory listing, .env exposure |
| Password Reset Scanner | Token leakage in response body, email enumeration, no rate limiting |

### Special DAST Scanners (8)

| Scanner | What It Finds |
|---|---|
| IDOR Scanner | Insecure direct object references with ID swapping and cross-user testing |
| JWT Scanner | Algorithm none bypass, weak secrets, key confusion attacks |
| RLS Deep Scanner | Supabase Row Level Security bypass via anon key and cross-user queries |
| Privilege Escalation Scanner | Admin route access, role self-elevation, object-level write bypass |
| Authenticated Crawler | Playwright-based login + BFS crawl to discover authenticated endpoints |
| Race Condition Scanner | TOCTOU bugs via concurrent mutation requests |
| DOM XSS Scanner | Playwright-based sink hooking (innerHTML, eval, location.assign) |
| Body Param Fuzzer | Prototype pollution, type confusion, injection via JSON body fields |

### SAST Scanners (16) — Analyzes Your Code

| Scanner | What It Finds |
|---|---|
| Git Secret Scanner | API keys, tokens, and credentials in git history (not just HEAD) |
| Route Auth Analyzer | Next.js/Express/Django/FastAPI/Spring routes missing authentication |
| RLS Policy Analyzer | Supabase tables without Row Level Security enabled |
| Middleware Analyzer | Incomplete middleware coverage (protects pages but not API routes) |
| Express Middleware Analyzer | Express-specific auth middleware gaps |
| Drizzle Schema Analyzer | Sensitive fields (isAdmin, role) exposed to mass assignment |
| Prisma Schema Analyzer | Similar checks for Prisma schemas |
| IaC Scanner | Terraform/CloudFormation misconfigurations (public S3, no encryption) |
| Docker Scanner | Running as root, exposed ports, .env copied into image |
| Shell Script Scanner | Command injection in deploy scripts |
| Dependency Scanner (npm) | Known CVEs in package.json dependencies |
| Python Dependency Scanner | Known CVEs in requirements.txt / pyproject.toml (Django, Flask, FastAPI, PyJWT, etc.) |
| Java Dependency Scanner | Known CVEs in pom.xml / build.gradle (Log4Shell, Spring, Struts, Jackson, etc.) |
| Firebase Rules Analyzer | Overly permissive Firestore/RTDB security rules |
| OpenAPI Scanner | Internal endpoints exposed in API specifications |
| K8s Scanner | Privileged containers, no resource limits, hostPath mounts |

### LLM-Powered Analysis (requires API key)

| Scanner | What It Finds |
|---|---|
| LLM Code Reviewer | Business logic flaws: missing ownership checks, race conditions in payments, incorrect authorization logic |
| Semantic Rule Verifier | Logical errors in RLS policies and Firebase rules (wrong column references, tenant isolation bugs) |
| LLM Business Logic Scanner | Attack planning: price manipulation, double-spend, privilege escalation via application logic |
| LLM Triage Service | Deduplicates findings, assigns priority, generates plain-language owner summary with A–F grade |
| AI Fix Generator | Generates code patches (unified diffs) for each finding — paste into Cursor/Claude Code to fix |

### Cross-Referencing + Guided DAST

| Feature | What It Does |
|---|---|
| SAST→DAST Feedback Loop | SAST findings generate targeted DAST tests (6 strategies: auth bypass, IDOR, injection, mass assignment, race condition, RLS bypass) |
| Cross-Referencer | Matches DAST + SAST findings for high-confidence confirmed vulnerabilities |
| Import Graph Centrality | Identifies shared utility files imported by many risky routes for LLM review |
| LSP Auth Flow Tracing | Uses TypeScript Language Server to verify auth middleware is genuinely applied |

## Language Support

| Language | Route Mapping | Auth Detection | Dependency Scan | DAST |
|---|---|---|---|---|
| **TypeScript/JavaScript** (Next.js, Express, tRPC, GraphQL) | Yes | Yes | Yes (npm) | Yes |
| **Python** (Django, FastAPI, Flask) | Yes | Yes | Yes (pip) | Yes |
| **Java/Kotlin** (Spring Boot) | Yes | Yes | Yes (Maven, Gradle) | Yes |
| **Go, Ruby, Rust, etc.** | No | No | No | Yes (DAST works against any HTTP API) |

DAST scanners test live HTTP endpoints regardless of backend language. SAST route mapping, auth detection, and dependency scanning are language-specific.

## Output Formats

```bash
isitsecure scan URL --output table   # Terminal table (default)
isitsecure scan URL --output json    # Full JSON report
isitsecure scan URL --output html    # Self-contained HTML report
isitsecure scan URL --output sarif   # SARIF 2.1.0 for GitHub Code Scanning
isitsecure scan URL --output fixes   # AI-generated fix plan (Markdown with diffs)
```

## What It Does NOT Cover

- **Formal taint analysis** — No intermediate representation or dataflow tracking. Injection detection uses regex + LLM reasoning, not compiler-level analysis
- **WAF evasion** — Payload lists don't include advanced WAF bypass techniques
- **Compliance mapping** — No OWASP Top 10, CWE, or PCI-DSS tagging on findings (yet)
- **Authenticated testing beyond Supabase/Firebase** — Custom auth systems need the `token` provider with a manually obtained JWT
- **Network-level scanning** — No port scanning, TLS configuration analysis, or infrastructure enumeration
- **Mobile apps** — Web APIs only
- **Go/Ruby/Rust SAST** — Route mapping and dependency scanning not yet implemented (DAST still works)

## Configuration

### API Keys

Set via environment variable, `.env` file, or `~/.isitsecure/config.toml`:

```bash
# Environment variable
export ANTHROPIC_API_KEY=sk-ant-...

# Or .env file in your project
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# Or interactive setup
isitsecure setup
```

### OOB Callbacks (Blind Vulnerability Detection)

isitsecure detects blind SSRF, XXE, and injection vulnerabilities using out-of-band (OOB) callbacks. By default it uses `oob.isitsecure.ai` — a free community server running [interactsh](https://github.com/projectdiscovery/interactsh).

**What data is sent?** Only the scan *target* makes DNS/HTTP requests to the OOB server. Your source code never leaves your machine.

**Self-host your own:**
```bash
# Deploy interactsh
docker run projectdiscovery/interactsh-server

# Point isitsecure to it in ~/.isitsecure/config.toml
[oob]
server = "http://oob.yourdomain.com"
```

**Disable entirely:** Add `enabled = false` under `[oob]` in config.

### Authenticated Scanning

```bash
# Supabase auth
isitsecure scan https://your-app.com \
  --auth-email user@example.com \
  --auth-password yourpassword \
  --auth-provider supabase

# Firebase auth
isitsecure scan https://your-app.com \
  --auth-email user@example.com \
  --auth-password yourpassword \
  --auth-provider firebase

# Direct token
isitsecure scan https://your-app.com \
  --auth-provider token \
  --auth-token "eyJ..."
```

## CLI Reference

```
isitsecure scan [URL] [OPTIONS]

Arguments:
  URL                    Target URL to scan (DAST)

Options:
  -r, --repo TEXT        GitHub repo URL (SAST)
  -b, --branch TEXT      Git branch [default: main]
  -m, --mode TEXT        Scan mode: auto|url-only|code-only|authenticated|full
  --llm TEXT             LLM provider: anthropic|google|none [default: anthropic]
  -o, --output TEXT      Output format: table|json|html|sarif|fixes [default: table]
  -f, --output-file TEXT Write report to file
  --auth-email TEXT      Auth email for authenticated scanning
  --auth-password TEXT   Auth password
  --auth-provider TEXT   Auth provider: supabase|firebase|browser|token
  --github-token TEXT    GitHub token for private repos
  -v, --verbose          Enable debug logging

isitsecure launch [OPTIONS]
  -p, --port INT         Port for web UI [default: 3000]
  --host TEXT            Host to bind [default: 127.0.0.1]

isitsecure setup          Interactive first-time setup
isitsecure version        Show version
```

## Web UI

For non-CLI users, `isitsecure launch` opens a local web interface:

```bash
isitsecure launch
# Opens http://localhost:3000 in your browser
```

The UI provides:
- Visual scan configuration (no CLI flags to remember)
- Real-time scan progress with scanner status cards
- Finding browser with severity filtering and search
- Plain-language risk summary with A–F grade
- One-click fix code snippets
- JSON and HTML report export

## Try It on the Test App

The repo includes **VibeTasks** — an intentionally vulnerable Next.js + Supabase app with 50 security issues:

```bash
# Start the vulnerable app
cd test-app
npm install
npm run dev   # runs on port 4000

# Scan it (SAST only — fast, no API key needed)
isitsecure scan --repo file://./test-app --mode code-only

# Full scan (SAST + DAST)
isitsecure scan http://localhost:4000 --repo file://./test-app --mode full
```

See `examples/sample-report.json` for what a scan produces.

## Privacy

- **Your code stays on your machine.** SAST scanners clone your repo to a local temp directory and analyze it locally.
- **DAST scanners send HTTP requests to your target URL.** Nothing is proxied through external servers.
- **LLM prompts are sent to your chosen API provider** (Anthropic or Google). The prompts contain code snippets from files flagged by rule-based scanners — not your entire codebase.
- **OOB callbacks** only involve your scan target making DNS/HTTP requests to the callback server. Your code is never sent there.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full pipeline design, including how SAST feeds DAST, how LLM review is prioritized, and how cross-referencing works.

## Scanner Documentation

See [docs/scanners/](docs/scanners/) for detailed documentation on every scanner — what it detects, why it matters, real-world breach examples, and how to fix the vulnerabilities it finds.

## LSP Setup (Optional, Reduces False Positives)

See [docs/lsp-setup.md](docs/lsp-setup.md) for instructions on setting up the TypeScript Language Server for auth flow tracing. This is optional — scans work without it using regex-based detection.

## Contributing

isitsecure is built on protocols and the strategy pattern. Adding a new scanner is straightforward:

1. Implement `DASTScannerProtocol` or `CodeScannerProtocol`
2. Add it to the scanner list in `factory.py`
3. Add tests

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Acknowledgements

- [interactsh](https://github.com/projectdiscovery/interactsh) by ProjectDiscovery for the OOB callback protocol
- [Playwright](https://playwright.dev/) for browser automation in authenticated crawling and DOM XSS detection
