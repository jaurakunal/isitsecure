# SSRF Scanner

**Type:** DAST | **Severity:** High–Critical | **Category:** Injection Risk

## What It Does

Tests for Server-Side Request Forgery by injecting internal/cloud addresses into URL parameters (exact names such as `url`, `uri`, `link`, `src`, `redirect`, `callback`, `image`, `avatar`, `webhook`, `proxy`) and checking if the response shows the server fetched them. There are six probes, tried in order until one hits:

- **Localhost**: `http://127.0.0.1`, `http://localhost`, `http://0.0.0.0`, `http://[::1]`
- **AWS metadata**: `http://169.254.169.254/latest/meta-data/` (IMDSv1)
- **GCP metadata**: `http://metadata.google.internal/`

Before probing, the scanner fetches a baseline with a benign URL (`http://example.invalid/`). The in-band check passes on a 2xx response whose body contains a cloud-metadata marker (`ami-id`, `instance-id`, `iam/security-credentials`, `computeMetadata`, `project/project-id`) that the baseline body does not already contain. Generic page content (an HTML doctype, a bare `iam/` or `meta-data` substring) is not an indicator. It is reported as High (0.80). Not probed today: RFC1918 ranges (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`) and the Azure metadata endpoint. Blind (OOB) hits are reported as Critical.

The scanner also integrates with **OOB callbacks** for blind SSRF — where the server fetches the URL but doesn't return the response content. OOB detection proves the fetch happened via DNS/HTTP interaction with the callback server.

### URL sinks in POST bodies (not just query strings)

Many real SSRF sinks are a **form field**, not a query parameter — e.g. an
`imageUrl` a profile page POSTs so the server fetches a remote avatar. The
OOB path recognises URL-shaped param names by substring (`imageUrl`, `avatarUrl`,
`callbackUri`, …; the in-band probe above matches names exactly) and POSTs the callback URL into those body
fields, form-encoded, using the authenticated session (including its **cookie** —
server-rendered routes often authenticate by cookie, not a bearer header). When
the crawler can't reach an auth-gated page, the OOB SSRF step fetches the common
authenticated pages over HTTP and reads their `<form>` targets directly, so the
sink is found regardless of the crawl. A single OOB callback from the server
confirms the blind SSRF.

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
