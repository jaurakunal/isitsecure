# Scanner Documentation

Detailed documentation for every scanner in isitsecure.

## DAST Scanners (Dynamic Application Security Testing)

These scanners test your live, running application by sending real HTTP requests.

- [XSS Scanner](./xss-scanner.md) — Cross-site scripting (reflected, POST body, DOM-based)
- [Active Injection Scanner](./active-injection-scanner.md) — SQL injection, command injection, NoSQL, XXE, SSTI
- [CSRF Scanner](./csrf-scanner.md) — Cross-site request forgery
- [Rate Limit Scanner](./rate-limit-scanner.md) — Missing or bypassable rate limiting
- [Session Scanner](./session-scanner.md) — Insecure token storage, cookie flags, JWT expiration
- [GraphQL Scanner](./graphql-scanner.md) — Introspection, depth limits, batch queries
- [SSRF Scanner](./ssrf-scanner.md) — Server-side request forgery
- [File Upload Scanner](./file-upload-scanner.md) — Unrestricted file types, path traversal
- [Mass Assignment Scanner](./mass-assignment-scanner.md) — Accepting privileged fields
- [Security Headers Scanner](./security-headers-scanner.md) — Missing CSP, HSTS, X-Frame-Options
- [CORS Scanner](./cors-scanner.md) — Wildcard origins, credentials leakage
- [Open Redirect Scanner](./open-redirect-scanner.md) — Unvalidated redirect parameters
- [Auth Bypass Scanner](./auth-bypass-scanner.md) — Username enumeration, default credentials
- [HTTP Probe Scanner](./http-probe-scanner.md) — Method tampering, .env exposure, directory listing
- [Password Reset Scanner](./password-reset-scanner.md) — Token leakage, enumeration

## Special DAST Scanners

These scanners require authentication or use specialized techniques.

- [IDOR Scanner](./idor-scanner.md) — Insecure direct object references
- [JWT Scanner](./jwt-scanner.md) — Algorithm bypass, weak secrets, key confusion
- [RLS Deep Scanner](./rls-deep-scanner.md) — Supabase Row Level Security bypass
- [Privilege Escalation Scanner](./privilege-escalation-scanner.md) — Admin access, role elevation
- [Race Condition Scanner](./race-condition-scanner.md) — TOCTOU in concurrent requests
- [DOM XSS Scanner](./dom-xss-scanner.md) — Browser-based sink detection
- [Body Param Fuzzer](./body-param-fuzzer.md) — Prototype pollution, type confusion

## SAST Scanners (Static Application Security Testing)

These scanners analyze your source code without running it.

- [Git Secret Scanner](./git-secret-scanner.md) — Secrets in git history
- [Route Auth Analyzer](./route-auth-analyzer.md) — Routes missing authentication
- [RLS Policy Analyzer](./rls-policy-analyzer.md) — Missing Supabase Row Level Security
- [Middleware Analyzer](./middleware-analyzer.md) — Incomplete middleware coverage
- [Dependency Scanner (npm)](./dependency-scanner.md) — Known CVEs in package.json
- [Python Dependency Scanner](./python-dependency-scanner.md) — Known CVEs in requirements.txt / pyproject.toml
- [Java Dependency Scanner](./java-dependency-scanner.md) — Known CVEs in pom.xml / build.gradle
- OSV Dependency Scanner — Real-time CVE lookups against Google's OSV.dev database (200K+ vulns, all ecosystems: npm, PyPI, Maven, Gradle, Go, Rust)
- [Docker Scanner](./docker-scanner.md) — Dockerfile security issues
- [Drizzle Schema Analyzer](./drizzle-schema-analyzer.md) — Schema-level vulnerabilities
- [IaC Scanner](./iac-scanner.md) — Infrastructure as Code misconfigurations

## LLM-Powered Scanners

These use AI for analysis that pattern matchers cannot perform.

- [LLM Code Reviewer](./llm-code-reviewer.md) — Business logic vulnerability detection
- [Semantic Rule Verifier](./semantic-rule-verifier.md) — Logical errors in security rules
- [AI Fix Generator](./fix-generator.md) — Generates code patches for findings
