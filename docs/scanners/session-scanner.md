# Session Scanner

**Type:** DAST | **Severity:** Medium to High | **Category:** Auth Weakness

## What It Does

Analyzes session management for three issues:

1. **localStorage token storage** — scans JavaScript for `localStorage.setItem(...)` or `localStorage[...]` with the keys `token`, `access_token`, `auth_token` or `jwt` (High). Tokens in localStorage are accessible to any JavaScript on the page, including XSS payloads.

2. **Cookie flags** — checks auth cookies (names containing `token`, `session`, `sid`, `jwt`, `__session`, `connect.sid`, etc.) for `HttpOnly` (prevents JS access, High) and `Secure` (HTTPS only, Medium) flags. Missing flags expose tokens to theft.

3. **JWT expiration** — decodes the session JWT and checks the `exp` claim. A token with more than 24 hours of validity remaining is flagged (Medium, confidence 0.60). A token with no `exp`, or one already expired, is not reported here. The token comes from the authenticated session, which the factory wires in lazily (shared with the JWT scanner); an unauthenticated scan has no session, so this check is skipped.

## Why It Matters

- **localStorage + XSS = game over** — any XSS vulnerability instantly gives the attacker the auth token
- **Missing HttpOnly** — JavaScript can read the cookie, so XSS steals the session
- **Missing Secure** — token sent over HTTP, interceptable on public WiFi
- **Long-lived tokens** — a stolen token works for days/weeks instead of minutes

## Real-World Context

Token theft via XSS is one of the most common attack chains in modern web apps. If tokens are stored in `localStorage`, any XSS vulnerability — even a minor reflected XSS — becomes a full account takeover. The 2018 British Airways breach demonstrated this: injected JavaScript could access client-side storage, enabling exfiltration of payment data and session tokens.

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
