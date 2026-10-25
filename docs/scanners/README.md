# Scanner Documentation

Detailed documentation for every scanner in isitsecure.

Several scanners also have an **animated, step-by-step explainer** under [`docs/interactive/`](../interactive/index.html) (open the HTML in a browser; no build step). Those pages are linked next to the scanner below where one exists.

## DAST Scanners (Dynamic Application Security Testing)

These scanners test your live, running application by sending real HTTP requests.

- [XSS Scanner](./xss-scanner.md) · [animated](../interactive/xss.html) — Cross-site scripting (reflected, POST body, DOM-based)
- [Active Injection Scanner](./active-injection-scanner.md) · [animated](../interactive/active-injection.html) — SQL injection, command injection, NoSQL, XXE, SSTI
- [CSRF Scanner](./csrf-scanner.md) · [animated](../interactive/csrf.html) — Cross-site request forgery
- [Rate Limit Scanner](./rate-limit-scanner.md) · [animated](../interactive/rate-limit.html) — Missing or bypassable rate limiting
- [Session Scanner](./session-scanner.md) · [animated](../interactive/session.html) — Insecure token storage, cookie flags, JWT expiration
- [GraphQL Scanner](./graphql-scanner.md) · [animated](../interactive/graphql.html) — Introspection, depth limits, batch queries
- [SSRF Scanner](./ssrf-scanner.md) · [animated](../interactive/ssrf.html) — Server-side request forgery
- [File Upload Scanner](./file-upload-scanner.md) · [animated](../interactive/file-upload.html) — Unrestricted file types, path traversal
- [Mass Assignment Scanner](./mass-assignment-scanner.md) · [animated](../interactive/mass-assignment.html) — Accepting privileged fields
- [Security Headers Scanner](./security-headers-scanner.md) · [animated](../interactive/security-headers.html) — Missing CSP, HSTS, X-Frame-Options
- [CORS Scanner](./cors-scanner.md) · [animated](../interactive/cors.html) — Wildcard origins, credentials leakage
- [Open Redirect Scanner](./open-redirect-scanner.md) · [animated](../interactive/open-redirect.html) — Unvalidated redirect parameters
- [Auth Bypass Scanner](./auth-bypass-scanner.md) · [animated](../interactive/auth-bypass.html) — Username enumeration, default credentials
- [HTTP Probe Scanner](./http-probe-scanner.md) · [animated](../interactive/http-probe.html) — Method tampering, .env exposure, directory listing
- [Password Reset Scanner](./password-reset-scanner.md) · [animated](../interactive/password-reset.html) — Token leakage, enumeration

## Special DAST Scanners

These scanners require authentication or use specialized techniques.

- [IDOR Scanner](./idor-scanner.md) · [animated](../interactive/idor-bola.html) — Insecure direct object references
- [JWT Scanner](./jwt-scanner.md) · [animated](../interactive/jwt-attacks.html) — Algorithm bypass, weak secrets, key confusion
- [RLS Deep Scanner](./rls-deep-scanner.md) · [animated](../interactive/rls-supabase.html) — Supabase Row Level Security bypass
- [Privilege Escalation Scanner](./privilege-escalation-scanner.md) · [animated](../interactive/privilege-escalation.html) — Admin access, role elevation
- [Race Condition Scanner](./race-condition-scanner.md) · [animated](../interactive/race-conditions.html) — TOCTOU in concurrent requests
- [DOM XSS Scanner](./dom-xss-scanner.md) · [animated](../interactive/dom-xss.html) — Browser-based sink detection
- [Body Param Fuzzer](./body-param-fuzzer.md) · [animated](../interactive/body-param-fuzzer.html) — Prototype pollution, type confusion

## SAST Scanners (Static Application Security Testing)

These scanners analyze your source code without running it.

- [Semgrep Taint Analyzer](./semgrep-taint.md) · [animated](../interactive/taint-analysis.html) — Deterministic source→sink injection for JS/TS, Python, Java, and Kotlin (SQLi, XSS, SSRF, path traversal, command injection, SSTI)
- [Git Secret Scanner](./git-secret-scanner.md) · [animated](../interactive/git-secrets.html) — Secrets in git history
- [Route Auth Analyzer](./route-auth-analyzer.md) · [animated](../interactive/route-auth-lsp.html) — Routes missing authentication
- [RLS Policy Analyzer](./rls-policy-analyzer.md) · [animated](../interactive/rls-supabase.html) — Missing Supabase Row Level Security
- [Middleware Analyzer](./middleware-analyzer.md) · [animated](../interactive/middleware.html) — Incomplete middleware coverage
- [Dependency Scanner (npm)](./dependency-scanner.md) · [animated](../interactive/npm-dependencies.html) — Known CVEs in package.json
- [Python Dependency Scanner](./python-dependency-scanner.md) · [animated](../interactive/python-dependencies.html) — Known CVEs in requirements.txt / pyproject.toml
- [Java Dependency Scanner](./java-dependency-scanner.md) · [animated](../interactive/java-dependencies.html) — Known CVEs in pom.xml / build.gradle
- OSV Dependency Scanner — Real-time CVE lookups against Google's OSV.dev database (200K+ vulns, extracts npm, PyPI, Maven/Gradle, and Go dependencies; other ecosystems such as Rust are not extracted)
- [Docker Scanner](./docker-scanner.md) · [animated](../interactive/docker.html) — Dockerfile security issues
- [Drizzle Schema Analyzer](./drizzle-schema-analyzer.md) · [animated](../interactive/drizzle-schema.html) — Schema-level vulnerabilities
- [IaC Scanner](./iac-scanner.md) · [animated](../interactive/iac.html) — Infrastructure as Code misconfigurations

## LLM-Powered Scanners

These use AI for analysis that pattern matchers cannot perform.

- [LLM Code Reviewer](./llm-code-reviewer.md) · [animated](../interactive/llm-review-and-fixes.html) — Business logic vulnerability detection
- [Semantic Rule Verifier](./semantic-rule-verifier.md) · [animated](../interactive/semantic-rule-verifier.html) — Logical errors in security rules
- [Injection Adjudicator](../architecture.md#phase-94-injection-adjudication) · [animated](../interactive/active-injection.html) — Drops heuristic DAST injection false positives by comparing the baseline vs. injected response (no-op without an API key)
- [AI Fix Generator](./fix-generator.md) · [animated](../interactive/llm-review-and-fixes.html) — Generates code patches for findings

## Interactive explainers

Every scanner has an animated, step-by-step page under [`docs/interactive/`](../interactive/index.html). Start from the group that matches what you are looking for:

- [Injection](../interactive/group-injection.html) — SQL/command/NoSQL/XXE/SSTI, XSS, SSRF, file upload, taint analysis
- [Access control](../interactive/group-access-control.html) — IDOR/BOLA, RLS, route auth, privilege escalation, mass assignment, body fuzzing
- [Authentication and sessions](../interactive/group-auth-sessions.html) — JWT, session storage, auth bypass, password reset, rate limiting
- [Browser-side defenses](../interactive/group-browser-defenses.html) — CSRF, CORS, open redirect, security headers, mixed content, SRI, source maps, client exposure
- [Business logic](../interactive/group-business-logic.html) — race conditions, LLM review, LLM business-logic planning, semantic rule verification
- [Attack surface](../interactive/group-surface.html) — endpoint discovery, HTTP probes, GraphQL, OpenAPI
- [Secrets and dependencies](../interactive/group-secrets-dependencies.html) — git history, npm/Python/Java CVEs, OSV
- [Infrastructure configuration](../interactive/group-infrastructure.html) — Docker, Kubernetes, IaC, shell scripts
- [Schemas and middleware](../interactive/group-schema-middleware.html) — Prisma, Drizzle, Firebase rules, Next.js and Express middleware
- [Architecture deep dive](../interactive/architecture.html) — how a scan is wired and run
