# Rate Limit Scanner

**Type:** DAST | **Severity:** Medium–High | **Category:** Auth Weakness

## What It Does

Sends rapid bursts of requests to auth-sensitive endpoints (login, password reset, registration) without rate-limiting middleware and checks:

- **Threshold detection** — how many requests before a 429 (Too Many Requests)?
- **Burst testing** — sends 10, 50, 100 concurrent requests to detect limits
- **Per-IP vs per-user** — does changing the auth header bypass the rate limit?

If the endpoint accepts all requests without returning 429, it has no rate limiting.

## Why It Matters

Without rate limiting, attackers can:

- **Brute-force passwords** — try thousands of passwords per minute against a login endpoint
- **Credential stuffing** — test stolen username/password pairs from other breaches at scale
- **Denial of service** — overwhelm the server with requests
- **Enumerate accounts** — rapid-fire email checks to discover valid accounts

## Real-World Breaches

**iCloud / "The Fappening" (2014)** — Apple's "Find My iPhone" API lacked rate limiting, allowing attackers to brute-force celebrity iCloud passwords. This led to the mass leak of private photos.

**Dunkin' Donuts (2015)** — Credential-stuffing attacks against Dunkin's app (no rate limiting) took over customer accounts and drained stored value.

## How to Fix

```typescript
// GOOD: Use a rate limiting library
import { Ratelimit } from "@upstash/ratelimit"

const limiter = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, "1m"),  // 5 attempts per minute
})

export async function POST(request: Request) {
  const ip = request.headers.get("x-forwarded-for") || "anonymous"
  const { success } = await limiter.limit(ip)

  if (!success) {
    return NextResponse.json({ error: "Too many attempts" }, { status: 429 })
  }
  // ... login logic
}
```
