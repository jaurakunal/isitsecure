# Auth Bypass Scanner

**Type:** DAST | **Severity:** High | **Category:** Auth Weakness

## What It Does

Tests authentication mechanisms for five weaknesses:

1. **Username enumeration** — sends valid vs invalid emails and compares error messages, response times, and status codes. Different responses reveal which accounts exist.

2. **Password reset token leaks** — checks if reset endpoints return tokens in the response body or headers instead of only sending them via email.

3. **Account lockout detection** — sends 5+ failed login attempts. If no lockout (423 status) occurs, brute force is possible.

4. **Default credentials** — tests common username/password pairs: `admin/admin`, `admin/password`, `test/test`, etc.

5. **Auth header bypass** — sends requests with no auth, empty Bearer token, and Basic auth tricks to check for bypass paths.

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
