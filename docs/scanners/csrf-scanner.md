# CSRF Scanner

**Type:** DAST | **Severity:** Medium–High | **Category:** Auth Weakness

## What It Does

Tests for Cross-Site Request Forgery by sending state-changing requests (POST, PUT, PATCH, DELETE) with a forged `Origin` and `Referer` (`https://evil-attacker.com`) and checking if the server accepts them. The probe sends an empty body and treats any 2xx response as acceptance, which is reported as High (confidence 0.90). Also analyzes:

- **Cookie SameSite attribute** — cookies in the response snapshot with no `SameSite` attribute, or with `SameSite=None`, are reported as Medium (0.70)
- **Hidden CSRF token fields** — checks whether POST forms on the scanned page include a hidden field with a known CSRF token name (`csrf_token`, `_csrf`, `authenticity_token`, `xsrf-token`, `token`, ...); a form without one is reported as Medium (0.85)

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
