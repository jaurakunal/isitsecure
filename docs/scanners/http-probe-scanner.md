# HTTP Probe Scanner

**Type:** DAST | **Severity:** Medium–High | **Category:** Info Disclosure / Auth Weakness

## What It Does

Performs five checks against the target, in this order (the fixed-cost checks on the base URL run first so a large app does not spend its budget before reaching them):

1. **Verbose errors** — requests four error-triggering paths (a nonexistent path, a nonexistent `/api/` path, `/%00`, and an oversized path) and checks 4xx/5xx bodies for stack traces, file paths, or framework details. Medium.
2. **Sensitive files and directory listing** — fetches `/.git/HEAD` (looks for `ref:`), `/.env` and `/.env.local` (need a non-HTML response with `KEY=VALUE` lines, so an SPA catch-all page is not flagged), plus index pages at `/api/`, `/static/`, `/assets/`, `/backup/` and `/backups/` (look for "Index of /" style listings). Exposed `.git` and `.env` files are High; directory listings are Medium. `robots.txt` is public by design and is not reported.
3. **Method tampering** — sends OPTIONS and TRACE to each endpoint. TRACE or CONNECT in the `Allow` header is reported (TRACE High, CONNECT Medium), and a TRACE request that echoes the request back is High (cross-site tracing can leak auth headers).
4. **Host header injection** — sends a forged `Host` header, and also `X-Forwarded-Host`, to the homepage and the first two endpoints, without following redirects (so the poisoned `Location` is seen, not fetched). If the forged value is reflected in the response body or the `Location` header, it can enable cache poisoning or password reset poisoning. High. A `Location` that keeps the request path (or is `/`) and only changes scheme or host is a canonicalising redirect (http to https, trailing slash): still reported, but Low with confidence 0.4. A `Location` to a different path, or body reflection, stays High.
5. **CRLF injection** — injects `\r\n` plus a canary header into 9 query-param names (`url`, `redirect`, `next`, `return`, `callback`, `path`, `ref`, `location`, `goto`) with 3 payloads each, and checks whether the canary appears as a response header (response splitting). High.

## Why It Matters

These issues individually seem low-risk but chain together dangerously:
- `.env` exposure → attacker gets database credentials
- `.git` exposure (`/.git/HEAD`) → attacker can reconstruct your source code
- Stack traces → reveal framework version, file paths, query structure
- TRACE method → reflects auth cookies in response body (cross-site tracing)

## Real-World Context

Exposed `.env` files and `.git` directories are among the most common findings in bug bounty programs. Automated scanners continuously probe the internet for these paths, and thousands of production sites have leaked database credentials and API keys through exposed `.env` files.

## How to Fix

```typescript
// GOOD: Block sensitive paths in middleware or hosting config
// vercel.json
{
  "headers": [
    { "source": "/.env", "headers": [{ "key": "x-robots-tag", "value": "noindex" }] }
  ],
  "rewrites": [
    { "source": "/.env", "destination": "/404" },
    { "source": "/.git/(.*)", "destination": "/404" }
  ]
}
```
