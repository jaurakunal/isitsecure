# Open Redirect Scanner

**Type:** DAST | **Severity:** Medium | **Category:** Auth Weakness

## What It Does

Tests URL parameters commonly used for redirects (`redirect_to`, `return_url`, `next`, `callback`, etc.) by injecting external URLs and checking if the server issues a 3xx redirect to the attacker's domain. Also checks for JavaScript/meta redirects in response bodies.

Payload types tested: absolute URLs (`https://evil.com`), protocol-relative (`//evil.com`), data URIs.

## Why It Matters

Open redirects let attackers craft links that look legitimate (your domain) but redirect to phishing pages:

- **Credential theft** — `yourapp.com/auth/callback?redirect_to=evil.com/fake-login` — user sees your domain, trusts it, enters credentials on the fake page
- **OAuth token theft** — chained with OAuth flows to steal authorization codes
- **Malware delivery** — redirect to malicious downloads from a trusted domain

## Real-World Breaches

**Google (ongoing)** — Google's redirect endpoints (`google.com/url?q=...`) have been repeatedly abused in phishing campaigns to make malicious links appear to originate from google.com.

## How to Fix

```typescript
// GOOD: Only allow relative paths, block absolute URLs
const redirectTo = searchParams.get("redirect_to") || "/"
if (redirectTo.startsWith("http") || redirectTo.startsWith("//")) {
  return NextResponse.redirect(new URL("/", request.url))
}
return NextResponse.redirect(new URL(redirectTo, request.url))
```
