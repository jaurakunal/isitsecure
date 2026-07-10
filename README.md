# isitsecure

AI-powered security scanner for modern web apps. SAST + DAST + LLM code review in a single scan.

Built for developers and **vibe coders** shipping web apps who need to know if their code is secure — without becoming security experts.

**Supports:** TypeScript/JavaScript (Next.js, Express, tRPC), Python (Django, FastAPI, Flask), Java/Kotlin (Spring Boot) — and any HTTP API for DAST.

---

## Contents

- [What It Does](#what-it-does)
- [Install](#install) · [Quick Start](#quick-start) · [What It Costs](#what-it-costs)
- [Scan Modes](#scan-modes) · [Scan Depth](#scan-depth)
- [What It Scans](#what-it-scans) — [DAST](#dast-scanners-19--tests-your-live-app) · [Special DAST](#special-dast-scanners-8) · [SAST](#sast-scanners-17--analyzes-your-code) · [LLM](#llm-powered-analysis-requires-api-key) · [Cross-Referencing](#cross-referencing--guided-dast)
- [Language Support](#language-support) · [Output Formats](#output-formats)
- [Auto-Fix](#auto-fix-one-command-to-fix-your-app) · [Security Badge](#security-badge)
- [How We Compare](#how-we-compare) · [What It Does NOT Cover](#what-it-does-not-cover)
- [Configuration](#configuration) — [API Keys](#api-keys) · [OOB Callbacks](#oob-callbacks-blind-vulnerability-detection) · [Authenticated Scanning](#authenticated-scanning)
- [CLI Reference](#cli-reference) · [Web UI](#web-ui) · [Try It on the Test App](#try-it-on-the-test-app)
- [Benchmarks](#benchmarks) · [Privacy](#privacy) · [Architecture](#architecture)
- [Scanner Documentation](#scanner-documentation) · [LSP Setup](#lsp-setup-optional-reduces-false-positives)
- [Contributing](#contributing) · [License](#license) · [Acknowledgements](#acknowledgements)

## What It Does

isitsecure runs **44 rule-based scanners** (plus optional AI code review) against your web app in a single command. It combines four approaches that commercial tools sell separately:

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

## Install

isitsecure is not yet on PyPI (the `isitsecure` name there belongs to an unrelated project — don't `pip install` it). Install from source:

**Requirements:** Python 3.11+ and `git`. No Node.js needed for the CLI.

```bash
# 1. Clone the repo
git clone https://github.com/jaurakunal/isitsecure.git
cd isitsecure

# 2. Install into a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install with all features (browser DAST, LLM review, OOB detection)
pip install -e ".[all]"

# 4. First-time setup — installs the Chromium browser, optionally saves an API key
isitsecure setup
```

`pip install -e ".[all]"` is the recommended install and enables every scanner. If you want a lighter footprint, the extras are opt-in:

| Install | What works |
|---|---|
| `pip install -e .` | SAST / code-only scans only (`--mode code-only`) |
| `pip install -e ".[browser]"` | Adds DAST / live-URL scanning (requires `isitsecure setup` to install Chromium) |
| `pip install -e ".[llm]"` | Adds LLM code review, triage, and AI fixes (requires an API key) |
| `pip install -e ".[all]"` | Everything |

URL/DAST scanning needs the `[browser]` extra — without it, `isitsecure scan <url>` exits with a message telling you to install it.

## Quick Start

```bash
# Scan a live URL (DAST only, no API key needed)
isitsecure scan https://your-app.com --llm none

# Scan source code (SAST only)
isitsecure scan --repo https://github.com/you/your-app --mode code-only --llm none

# Full scan (SAST + DAST + LLM review)
isitsecure scan https://your-app.com --repo https://github.com/you/your-app --mode full

# One command: scan + fix everything (the magic)
isitsecure fix --repo ./your-app

# Or dry-run first to preview fixes
isitsecure fix --repo ./your-app --dry-run

# Generate a security badge for your README
isitsecure badge --repo ./your-app

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

Without an API key, you still get all 44 rule-based scanners (19 DAST + 8 special DAST + 17 SAST). The LLM adds business logic review, semantic rule verification, and intelligent triage — things no pattern matcher can do.

**Supported LLM providers:** Anthropic (Claude), Google (Gemini)

## Scan Modes

| Mode | What It Does | Requires |
|---|---|---|
| `url-only` | DAST scanners against a live URL | Target URL |
| `code-only` | SAST scanners against source code | GitHub repo URL |
| `authenticated` | DAST with login credentials (IDOR, cross-user BOLA, RLS, privilege escalation) | URL + credentials (add a second account for cross-user tests) |
| `full` | Everything: SAST + DAST + authenticated + LLM review + cross-referencing | URL + repo + credentials + API key |
| `auto` (default) | Detects mode from what you provide | Whatever you give it |

## Scan Depth

Orthogonal to mode, `--depth` trades speed for coverage:

| Depth | What runs | When to use |
|---|---|---|
| `quick` (default) | Structural + config checks, error-based injection, and the snapshot-based scanners (headers, CORS, RLS, source-map, SRI, client-exposure, redirects…). Fast. | Everyday scans — a solid first pass in a fraction of the time. |
| `deep` | Everything in `quick` **plus** the slow/aggressive probes: time-based (blind) SQL injection, active XSS, auth-bypass timing, rate-limit bursts, and password-reset flows. | When you want the full arsenal and can wait. |

```bash
# Fast pass (default)
isitsecure scan https://your-app.com --llm none

# Full, aggressive DAST
isitsecure scan https://your-app.com --depth deep --llm none
```

The scan narrates each phase and every scanner as it runs (with elapsed time), so a longer `deep` scan shows continuous progress rather than appearing to hang.

## What It Scans

### DAST Scanners (19) — Tests Your Live App

| Scanner | What It Finds |
|---|---|
| XSS Scanner | Reflected, POST body, and DOM-based cross-site scripting |
| Active Injection Scanner | SQL injection (error + time-based, incl. SQLAlchemy/sqlite3/psycopg errors), command injection, NoSQL injection, XXE, SSTI — injects query, body, and path parameters |
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
| Source Map Scanner | Publicly exposed `.map` files leaking original source (verified, not just present) |
| Mixed Content Scanner | `http://` resources loaded on an HTTPS page |
| SRI Scanner | External CDN scripts/styles loaded without Subresource Integrity hashes |
| Client Exposure Scanner | Secrets in client JS — Supabase `service_role` keys, internal URLs, unreplaced env placeholders |

### Special DAST Scanners (8)

| Scanner | What It Finds |
|---|---|
| IDOR Scanner | Insecure direct object references via ID swapping, plus authenticated cross-user (BOLA) testing with two accounts and an anonymous-access false-positive guard |
| JWT Scanner | Algorithm none bypass, weak secrets, key confusion attacks |
| RLS Deep Scanner | Supabase Row Level Security bypass via anon key and cross-user queries |
| Privilege Escalation Scanner | Admin route access, role self-elevation, object-level write bypass |
| Authenticated Crawler | Playwright-based login + BFS crawl to discover authenticated endpoints |
| Race Condition Scanner | TOCTOU bugs via concurrent mutation requests |
| DOM XSS Scanner | Playwright-based sink hooking (innerHTML, eval, location.assign) |
| Body Param Fuzzer | Prototype pollution, type confusion, injection via JSON body fields |

### SAST Scanners (17) — Analyzes Your Code

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
| OSV Dependency Scanner | Real-time CVE lookups against Google's OSV.dev database (200K+ vulns, all ecosystems: npm, PyPI, Maven, Gradle, Go, Rust) — no hardcoded CVE list, no API key |
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
| OpenAPI/Swagger Discovery | Probes `/openapi.json`, `/swagger.json`, `/v3/api-docs` and parses the spec into testable endpoints — finds attack surface on APIs with no crawlable frontend |
| HTML Form/Link Discovery | Reads `<form>`/`<input>`/query-links from server-rendered pages (bounded url-only crawl + inside the authenticated crawler) — finds attack surface on classic MVC apps with no JS API bundle |
| Endpoint Prioritizer + Time Budget | Ranks likely-vulnerable endpoints first and tests within a per-scanner time budget, so high-risk paths get covered before the clock runs out |
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

## Auto-Fix: One Command to Fix Your App

```bash
# Scan your code and apply AI-generated fixes automatically
isitsecure fix --repo ./my-app

# Preview fixes without applying (dry run)
isitsecure fix --repo ./my-app --dry-run

# Only fix critical issues
isitsecure fix --repo ./my-app --severity critical
```

What it does:
1. Scans your repo with all SAST scanners
2. For each critical/high finding with a code location, sends the file to the LLM
3. Generates a fixed version of the file
4. Writes the fixed code directly to your files
5. Shows a summary of what changed

After running, check `git diff` to review the changes, run your tests, and commit.

## Security Badge

Add a security grade badge to your README:

```bash
isitsecure badge --repo ./my-app -o badge.svg
```

Then add to your README:
```markdown
![Security Grade](./badge.svg)
```

The badge shows your grade (A–F) and total finding count, styled like a shields.io badge.

## How We Compare

isitsecure is not a replacement for enterprise security platforms. It's designed to be the **one tool a solo developer or small team needs** — combining capabilities that otherwise require 4-5 separate tools.

### What only isitsecure does (no other OSS tool)

- SAST findings automatically generate targeted DAST tests (closed feedback loop)
- LLM reviews business logic (race conditions, price manipulation, ownership checks)
- One command scans + generates + applies AI fixes (`isitsecure fix`)
- Cross-references DAST + SAST findings for confirmed vulnerabilities
- LSP traces auth flows through call chains (TypeScript, Python, Java)

### Where specialized tools go deeper

| Need | Best specialized tool | How isitsecure compares |
|---|---|---|
| Deep SAST (30+ languages) | [Semgrep](https://semgrep.dev) | We cover 3 languages with regex+LLM (no taint analysis) |
| DAST with advanced exploitation | [OWASP ZAP](https://zaproxy.org) / [Burp Suite](https://portswigger.net) | Our DAST is simpler — fewer payloads, no WAF evasion |
| Secret scanning (800+ patterns) | [TruffleHog](https://github.com/trufflesecurity/trufflehog) / [Gitleaks](https://github.com/gitleaks/gitleaks) | Our git scanner covers common patterns, not exhaustive |
| Container + IaC scanning | [Trivy](https://github.com/aquasecurity/trivy) / [Checkov](https://github.com/bridgecrewio/checkov) | Our IaC/Docker scanners are basic — use Trivy for depth |
| Enterprise compliance (SOC2, PCI) | [Snyk](https://snyk.io) / [Checkmarx](https://checkmarx.com) | No compliance mapping (yet) |
| Template-based vuln scanning | [Nuclei](https://github.com/projectdiscovery/nuclei) (28K+ stars) | Not template-based — different approach |

### Who should use what

| You are | Use this |
|---|---|
| Solo dev / vibe coder shipping a web app | **isitsecure** — one tool, one command |
| Team with $25K+ security budget | Snyk + GitHub Advanced Security |
| Enterprise with compliance requirements | Checkmarx / Veracode |
| Pentester doing deep exploitation | Burp Suite Pro + Nuclei |
| DevOps focused on containers/IaC | Trivy + Checkov + Gitleaks |

isitsecure works well alongside other tools. Run `isitsecure scan` for the combined SAST+DAST+LLM view, and use specialized tools where you need deeper coverage.

## What It Does NOT Cover

- **Formal taint analysis** — No dataflow tracking across function boundaries. Uses regex + LLM reasoning instead
- **WAF evasion** — DAST payloads don't include advanced bypass techniques
- **Compliance mapping** — No OWASP Top 10, CWE, or PCI-DSS tagging (yet)
- **Network-level scanning** — No port scanning, TLS analysis, or infrastructure enumeration
- **Mobile apps** — Web APIs only
- **Go/Ruby/Rust SAST** — Route mapping not yet implemented (DAST and dependency scanning via OSV still work)

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

**Cross-user IDOR / BOLA** — supply a *second* account and isitsecure logs in as both users and checks whether one user can read or mutate another user's objects (broken object-level authorization). An anonymous-access guard suppresses false positives from endpoints that are simply public.

```bash
isitsecure scan https://your-app.com \
  --auth-email  alice@example.com --auth-password alicepass \
  --auth-email-b bob@example.com  --auth-password-b bobpass \
  --mode authenticated
```

**Frontend-less / plain REST APIs** — use `--auth-provider token`, which logs in against a generic REST login endpoint (auto-discovered, or pass it explicitly with `--login-url`):

```bash
isitsecure scan https://api.your-app.com \
  --auth-provider token \
  --auth-email alice@example.com --auth-password alicepass \
  --auth-email-b bob@example.com --auth-password-b bobpass \
  --login-url https://api.your-app.com/login
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
  --depth TEXT           Scan depth: quick|deep [default: quick]
  --llm TEXT             LLM provider: anthropic|google|none [default: anthropic]
  -o, --output TEXT      Output format: table|json|html|sarif|fixes [default: table]
  -f, --output-file TEXT Write report to file
  --auth-email TEXT      Auth email/username for authenticated scanning (user A)
  --auth-password TEXT   Auth password (user A)
  --auth-provider TEXT   Auth provider: supabase|firebase|browser|token
                         (use token for a plain REST login)
  --auth-email-b TEXT    Second user's email — enables cross-user IDOR/BOLA testing
  --auth-password-b TEXT Second user's password (paired with --auth-email-b)
  --login-url TEXT       Explicit login endpoint (else auto-discovered)
  --github-token TEXT    GitHub token for private repos
  -v, --verbose          Enable debug logging

isitsecure launch [OPTIONS]
  -p, --port INT         Port for web UI [default: 3000]
  --host TEXT            Host to bind [default: 127.0.0.1]

isitsecure setup          Interactive first-time setup
isitsecure version        Show version
```

## Web UI

Prefer a GUI? `isitsecure launch` starts a local web interface backed by the same scan engine — no CLI flags to remember:

```bash
isitsecure launch
# Opens http://localhost:3000 in your browser
```

The UI provides:
- **Visual scan configuration** — target URL, repo, scan mode, AI provider, and optional login credentials
- **Live scan progress** — a progress bar and a streaming scanner log
- **Finding browser** — filter by severity or scanner, plus full-text search, with each finding expandable for evidence, technical detail, and remediation
- **Plain-language risk summary** — an A–F grade, key risks, and a phased remediation plan
- **One-click AI fixes** — a "Generate Fix" button on any finding produces a unified diff inline (one finding at a time)
- **Report export** — download JSON, or open the self-contained HTML report in a new tab
- **Scan history** — recent scans are remembered locally in your browser

The web server resolves your LLM API key the same way the CLI does (`ANTHROPIC_API_KEY`, a `.env` file, or `isitsecure setup`), so scans and fixes work without pasting a key into the browser. You can still enter one in the scan form to override it.

## Try It on the Test App

The repo includes **VibeTasks** — an intentionally vulnerable Next.js + Supabase app with ~50 security issues. All commands below are run from the repo root.

```bash
# Scan the bundled app's source (SAST only — fast, no API key needed)
isitsecure scan --repo ./test-app --mode code-only --llm none
```

To also run the live-app (DAST) scanners, start the app first, then scan its URL:

```bash
# In one terminal: start the vulnerable app
cd test-app && npm install && npm run dev   # serves on port 4000

# In another terminal, from the repo root: full scan (SAST + DAST)
isitsecure scan http://localhost:4000 --repo ./test-app --mode full
```

`--repo` accepts a local directory (scanned in place, including uncommitted changes) or a remote git URL like `https://github.com/you/your-app`. See `examples/sample-report.json` for what a scan produces.

## Benchmarks

isitsecure ships a repeatable benchmark harness that scores **recall** (of the vulnerability classes an app is known to have, how many we catch) and **false positives** (findings that must not appear against a hardened build) on public, deliberately-vulnerable apps.

**Measured coverage — be realistic about what a scanner catches.** On [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — a deliberately hard benchmark of 100+ challenges — isitsecure detects roughly **40% of the 45 DAST-detectable challenge classes** in an authenticated scan (36% url-only), scored automatically against the app's own `/api/Challenges` list. It's strong on authentication bypass, cross-user BOLA/IDOR, injection and misconfiguration, and open redirects; it's weak on interactive client-side XSS and challenges that require multi-step business-logic exploitation. In other words: it's a solid automated first pass that catches whole classes of real bugs in one command — **not** a substitute for a manual pentest. Full per-class breakdown and methodology are in [benchmarks/RESULTS.md](benchmarks/RESULTS.md).

```bash
python benchmarks/run_benchmarks.py          # VAmPI (vulnerable + secure builds)
python benchmarks/run_benchmarks.py --all    # + NodeGoat + crAPI (heavy)
```

Each run spins the target up in Docker, runs a DAST scan, scores against a known ground truth, and tears it down (requires Docker). Measured results are tracked in [benchmarks/RESULTS.md](benchmarks/RESULTS.md); see [benchmarks/README.md](benchmarks/README.md) for targets and how scoring works.

## Privacy

- **Rule-based scanning is fully local.** SAST scanners clone your repo to a local temp directory and analyze it on your machine — no code leaves your computer unless you enable LLM review.
- **DAST scanners send HTTP requests to your target URL.** Nothing is proxied through external servers.
- **LLM review sends code to your chosen API provider** (Anthropic or Google). To be precise: it sends the **full contents of files flagged by the rule-based scanners** (capped at ~50 KB per file) — not your entire codebase, but for most source files that is the whole file, not just a snippet. Run `--llm none` to keep everything local.
- **OOB callbacks** only involve your scan target making DNS/HTTP requests to the callback server. Your code is never sent there.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full pipeline design, including how SAST feeds DAST, how LLM review is prioritized, and how cross-referencing works.

## Scanner Documentation

See [docs/scanners/](docs/scanners/) for detailed documentation on every scanner — what it detects, why it matters, real-world breach examples, and how to fix the vulnerabilities it finds.

## LSP Setup (Optional, Reduces False Positives)

Language servers let the scanner trace auth flows through your code (via go-to-definition) and suppress false positives — confirming auth middleware is genuinely *applied*, not just imported.

**Let isitsecure install them for you:**

```bash
isitsecure setup --lsp      # install/verify the Python, TypeScript, and Java language servers
isitsecure setup --check    # report what's installed (API key, DAST browser, LSP) — installs nothing
```

`setup --lsp` installs what it can cleanly (Python via pip always; TypeScript via npm if Node is present; Java via Homebrew if available) and prints guidance for anything it can't. It's also offered as a step in the full `isitsecure setup`. This is optional — scans still work without it using regex-based detection. For manual setup and per-language detail, see [docs/lsp-setup.md](docs/lsp-setup.md).

## Contributing

isitsecure is built on protocols and the strategy pattern. Adding a new scanner is straightforward:

1. Implement `DASTScannerProtocol` or `CodeScannerProtocol`
2. Add it to the scanner list in `isitsecure/engine/factory.py`
3. Add tests under `tests/`

Set up a dev environment with `pip install -e ".[all,dev]"`, then run the suite with `pytest`. Issues and pull requests welcome at [github.com/jaurakunal/isitsecure](https://github.com/jaurakunal/isitsecure).

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Acknowledgements

- [interactsh](https://github.com/projectdiscovery/interactsh) by ProjectDiscovery for the OOB callback protocol
- [Playwright](https://playwright.dev/) for browser automation in authenticated crawling and DOM XSS detection
