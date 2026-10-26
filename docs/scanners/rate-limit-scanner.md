# Rate Limit Scanner

**Type:** DAST | **Severity:** Info to High | **Category:** Auth Weakness

## What It Does

Sends rapid bursts of requests to auth-sensitive endpoints (URLs containing `/login`, `/signin`, `/auth`, `/signup`, `/register`, `/password`, `/reset`, `/forgot`, `/token` or `/otp`) and checks:

- **Threshold detection** — sends up to 150 sequential requests (0.05 s apart) and counts how many succeed before a 429 (Too Many Requests). A 429 gives an Info finding with the measured threshold (0.90); no 429 in 150 gives a High finding (0.85). If the connection is dropped or reset part-way through, the run is inconclusive (a throttle or WAF is cutting the connection), so the High finding is not raised; the number of responses received before the cut-off is reported as Info instead.
- **Burst testing** — sends concurrent bursts of 10, 50, then 100 requests and stops at the first burst that returns a 429 (Info, 0.90; a working limiter is not a vulnerability). It is skipped when the sequential pass already reported a threshold, since it would duplicate that Info finding
- **Limit keyed on the Authorization header** — after a 429 with one synthetic Authorization header, does a second synthetic header from the same address get through? If so, the limiter is keyed on a client-supplied value rather than the IP, so rotating the header bypasses it (Medium, 0.90). The finding keeps the title "Rate limit appears IP-based only" so existing baselines still match, but its description and detail now state the actual trigger.

If the endpoint accepts all 150 sequential requests without returning 429, it has no rate limiting.

**Authenticated scans (#119):** on an authenticated deep scan the scanner carries the captured session so behind-login critical endpoints are reachable and the burst tests measure the authenticated user's rate limit. The Authorization-header test is the one exception — it strips the session and uses two synthetic identities, since that test must vary who is making the request.

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
