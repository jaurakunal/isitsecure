# Password Reset Scanner

**Type:** DAST | **Severity:** Medium–High | **Category:** Auth Weakness

## What It Does

Tests password reset flows for three issues:

1. **Email enumeration** — sends reset requests for valid and invalid emails. Different responses reveal which accounts exist.
2. **Rate limiting bypass** — sends 10+ rapid reset requests. No rate limit means an attacker can flood a user's inbox or brute-force tokens.
3. **Token leakage in response** — checks if the reset token appears in the HTTP response body (it should only be sent via email).

## Real-World Breaches

**Snapchat (2014)** — The password reset flow allowed enumeration and confirmation of phone numbers linked to accounts, enabling targeted attacks.

## How to Fix

```typescript
// GOOD: Same response regardless of email validity
return NextResponse.json({ message: "If an account exists, a reset link was sent." })
// Never reveal whether the email exists

// GOOD: Rate limit reset requests
// GOOD: Never return the token in the HTTP response
// Send it via email only:
await sendEmail(email, `Reset: https://app.com/reset?token=${token}`)
return NextResponse.json({ message: "Check your email" })
```
