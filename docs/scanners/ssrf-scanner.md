# SSRF Scanner

**Type:** DAST | **Severity:** High–Critical | **Category:** Injection Risk

## What It Does

Tests for Server-Side Request Forgery by injecting internal/cloud IP addresses into URL parameters and checking if the server fetches them. Probes include:

- **Internal IPs**: `127.0.0.1`, `192.168.x.x`, `10.x.x.x`, `172.16.x.x`
- **AWS metadata**: `169.254.169.254/latest/meta-data/` (IMDSv1)
- **Cloud endpoints**: GCP, Azure metadata services
- **Localhost variations**: `0.0.0.0`, `[::1]`, `localhost`

The scanner also integrates with **OOB callbacks** for blind SSRF — where the server fetches the URL but doesn't return the response content. OOB detection proves the fetch happened via DNS/HTTP interaction with the callback server.

## Why It Matters

SSRF lets attackers use your server as a proxy to reach internal resources:

- **Steal cloud credentials** — AWS metadata endpoint returns IAM role credentials (Access Key + Secret Key)
- **Access internal services** — databases, admin panels, caches (Redis, Memcached) not exposed to the internet
- **Port scan internal networks** — map your private infrastructure from outside
- **Read local files** — `file:///etc/passwd` on some implementations

## Real-World Breaches

**Capital One (2019)** — An SSRF vulnerability in a WAF configuration allowed an attacker to access the AWS metadata endpoint (IMDSv1), steal IAM credentials, and exfiltrate 100+ million customer records from S3. The attacker was convicted. Capital One was fined $80 million.

**Shopify (2020)** — A bug bounty researcher found SSRF in Shopify's infrastructure allowing access to internal cloud metadata endpoints. Patched via their bug bounty program.

## What Vulnerable Code Looks Like

```typescript
// BAD: Fetches any URL provided by the user
export async function GET(request: Request) {
  const url = new URL(request.url).searchParams.get("url")
  const response = await fetch(url!)  // No validation
  const data = await response.text()
  return new Response(data)
}
```

## How to Fix

```typescript
// GOOD: Validate URL against allowlist
const ALLOWED_DOMAINS = ["images.example.com", "cdn.example.com"]

export async function GET(request: Request) {
  const url = new URL(request.url).searchParams.get("url")
  const parsed = new URL(url!)

  if (!ALLOWED_DOMAINS.includes(parsed.hostname)) {
    return new Response("Forbidden", { status: 403 })
  }

  // Also block internal IPs
  const ip = await dns.resolve(parsed.hostname)
  if (isPrivateIP(ip)) {
    return new Response("Forbidden", { status: 403 })
  }

  const response = await fetch(url!)
  return new Response(await response.arrayBuffer())
}
```
