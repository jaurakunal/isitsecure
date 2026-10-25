# Auth Bypass Scanner

**Type:** DAST | **Severity:** Medium to Critical | **Category:** Auth Weakness

## What It Does

Tests authentication mechanisms for five weaknesses:

1. **Username enumeration** — sends valid vs invalid emails and compares error messages (High), response times (Medium, a gap over 0.5 s) and status codes (Medium). Different responses reveal which accounts exist.

2. **Password reset token leaks** — checks if reset endpoints return tokens in the response body (first 500 characters) or headers instead of only sending them via email. It is a plain substring search for strings such as `reset_token`, `token=` or `verify_token` (High).

3. **Account lockout detection** — sends 10 failed login attempts, then an 11th. Only a 423 status counts as lockout; if it never appears, brute force is possible (Medium). A 429 rate limiter does not satisfy this check.

4. **Default credentials** — tests seven common email/password pairs (`admin@admin.com` with `admin`, `password`, `admin123` or `changeme`; `test@test.com`/`test`; `root@root.com`/`root`; `user@user.com`/`password123`). A pair counts only when the reply is 2xx and the body contains a token-like word (Critical).

5. **Auth header bypass** — sends exactly three probes to endpoints that look auth-protected: no Authorization header, an empty Bearer token, and `Basic admin:admin`. Any 2xx response is flagged on status alone (High).

**Runs unauthenticated by design (#119):** unlike the other DAST scanners, this one is deliberately not made "auth-aware" — every test above depends on the absence or manipulation of authentication. Injecting the crawl's live session would ride on every request and make bypass attempts spuriously succeed (false positives), so the orchestrator's session propagation intentionally skips this scanner.

## Why It Matters

Authentication is the front door. If attackers can enumerate valid usernames, there's no lockout, and default credentials work:

- **Targeted attacks** — knowing which emails have accounts lets attackers focus phishing or credential stuffing
- **Brute force** — without lockout, automated tools try thousands of passwords per minute
- **Instant access** — default credentials (`admin/admin`) give immediate admin access with zero effort

## Real-World Breaches

**iCloud (2014)** — No account lockout on the Find My iPhone API allowed brute-force password attacks against celebrity accounts.

## How to Fix

```typescript
// GOOD: Same error message for all auth failures
if (!user || !validPassword) {
  return NextResponse.json(
    { error: "Invalid email or password" },  // Same message regardless of cause
    { status: 401 }
  )
}

// GOOD: Account lockout after N attempts
const attempts = await getLoginAttempts(email)
if (attempts >= 5) {
  return NextResponse.json({ error: "Account locked. Try again in 15 minutes." }, { status: 423 })
}
```
