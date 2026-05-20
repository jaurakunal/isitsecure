# HTTP Probe Scanner

**Type:** DAST | **Severity:** Medium–High | **Category:** Info Disclosure / Auth Weakness

## What It Does

Performs five checks against the target:

1. **Method tampering** — sends OPTIONS and TRACE requests. TRACE enabled can leak auth headers; unexpected methods may bypass security controls.
2. **Host header injection** — sends requests with a forged Host header. If reflected in the response or Location header, it can enable cache poisoning or password reset poisoning.
3. **Verbose errors** — requests paths that trigger 4xx/5xx and checks for stack traces, framework details, or database error messages.
4. **Directory listing** — checks for `.git/config`, `.env`, directory index pages.
5. **CRLF injection** — injects `\r\n` in headers to test for response splitting.

## Why It Matters

These issues individually seem low-risk but chain together dangerously:
- `.env` exposure → attacker gets database credentials
- `.git/config` exposure → attacker can reconstruct your source code
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
