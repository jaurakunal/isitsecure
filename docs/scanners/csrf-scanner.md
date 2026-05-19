# CSRF Scanner

**Type:** DAST | **Severity:** Medium–High | **Category:** Auth Weakness

## What It Does

Tests for Cross-Site Request Forgery by sending state-changing requests (POST, PUT, DELETE) with forged `Origin` headers and checking if the server accepts them. Also analyzes:

- **Cookie SameSite attribute** — auth cookies without `SameSite=Strict` or `SameSite=Lax` are vulnerable
- **Hidden CSRF token fields** — checks if HTML forms include CSRF tokens
- **Origin/Referer validation** — checks if the server rejects requests from unknown origins

## Why It Matters

CSRF tricks a victim's browser into making requests to your app while the victim is logged in. If a user visits a malicious page while authenticated:

- **Fund transfers** — the attacker's page submits a form to your `/api/transfer` endpoint
- **Password changes** — changes the victim's password or email
- **Data deletion** — deletes the victim's account or data
- **Purchases** — places orders using the victim's payment method

## Real-World Breaches

**Netflix (2006)** — CSRF attacks could change account email, password, and DVD queue because the site lacked CSRF tokens.

**ING Direct (2008)** — CSRF allowed attackers to initiate fund transfers from a victim's bank account when they visited a malicious page while logged in.

## How to Fix

```typescript
// GOOD: Use SameSite cookies (modern defense)
response.cookies.set("session", token, {
  httpOnly: true,
  secure: true,
  sameSite: "strict"  // or "lax" for GET-safe scenarios
})

// GOOD: Validate Origin header on mutations
const origin = request.headers.get("Origin")
if (origin !== "https://your-app.com") {
  return new Response("Forbidden", { status: 403 })
}
```
