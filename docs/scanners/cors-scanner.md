# CORS Scanner

**Type:** DAST | **Severity:** Medium–Critical | **Category:** Auth Weakness

## What It Does

Tests Cross-Origin Resource Sharing configuration by sending requests with forged `Origin` headers:

1. **Wildcard + Credentials** — Sends `Origin: https://evil.com` and checks if the response has `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. This is the most dangerous combo — any website can read authenticated responses. **Severity: Critical.**

2. **Arbitrary Origin Reflected** — Checks if the response mirrors back whatever Origin is sent. This means any website can make authenticated cross-origin requests. **Severity: High.**

3. **Null Origin Allowed** — Sends `Origin: null` (used by sandboxed iframes). If accepted, attackers can use sandboxed iframes to steal data. **Severity: High.**

4. **Wildcard Without Credentials** — `Access-Control-Allow-Origin: *` without credentials. Less dangerous but still allows any site to read public responses. **Severity: Medium.**

## Why It Matters

CORS misconfigurations allow malicious websites to:

- **Read your API responses** — if a user visits evil.com while logged into your app, evil.com's JavaScript can fetch your API and read the response (account data, messages, tokens)
- **Steal tokens** — if the API returns tokens or session data, the attacker captures them
- **Perform actions** — make state-changing requests (transfers, purchases) from the victim's browser session

## Real-World Breaches

**Cryptocurrency exchanges (2016–2018)** — Multiple exchanges were found reflecting arbitrary Origin headers in CORS responses, allowing attacker-controlled websites to read authenticated API responses containing balances and API keys.

## What Vulnerable Code Looks Like

```typescript
// BAD: Wildcard CORS with credentials
response.headers.set("Access-Control-Allow-Origin", "*")
response.headers.set("Access-Control-Allow-Credentials", "true")

// BAD: Reflecting the Origin header without validation
const origin = request.headers.get("Origin")
response.headers.set("Access-Control-Allow-Origin", origin)
```

## How to Fix

```typescript
// GOOD: Allowlist specific origins
const ALLOWED_ORIGINS = ["https://your-app.com", "https://admin.your-app.com"]

const origin = request.headers.get("Origin")
if (ALLOWED_ORIGINS.includes(origin)) {
  response.headers.set("Access-Control-Allow-Origin", origin)
  response.headers.set("Access-Control-Allow-Credentials", "true")
}
// If origin not in list, no CORS headers = browser blocks the request
```
