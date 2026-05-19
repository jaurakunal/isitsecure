# Session Scanner

**Type:** DAST | **Severity:** High | **Category:** Auth Weakness

## What It Does

Analyzes session management for three issues:

1. **localStorage token storage** — scans JavaScript for `localStorage.setItem` patterns with token-related keys. Tokens in localStorage are accessible to any JavaScript on the page, including XSS payloads.

2. **Cookie flags** — checks auth cookies for `HttpOnly` (prevents JS access) and `Secure` (HTTPS only) flags. Missing flags expose tokens to theft.

3. **JWT expiration** — decodes JWT tokens and checks the `exp` claim. Tokens valid for more than 24 hours are flagged (stolen tokens remain valid too long).

## Why It Matters

- **localStorage + XSS = game over** — any XSS vulnerability instantly gives the attacker the auth token
- **Missing HttpOnly** — JavaScript can read the cookie, so XSS steals the session
- **Missing Secure** — token sent over HTTP, interceptable on public WiFi
- **Long-lived tokens** — a stolen token works for days/weeks instead of minutes

## How to Fix

```typescript
// GOOD: Use httpOnly cookies instead of localStorage
response.cookies.set("session", token, {
  httpOnly: true,   // JS can't read it
  secure: true,     // HTTPS only
  sameSite: "lax",  // CSRF protection
  maxAge: 3600      // 1 hour expiration
})

// GOOD: Short-lived JWTs with refresh tokens
const token = jwt.sign(payload, SECRET, { expiresIn: "15m" })
const refreshToken = jwt.sign({ userId }, REFRESH_SECRET, { expiresIn: "7d" })
```
