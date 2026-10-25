# Open Redirect Scanner

**Type:** DAST | **Severity:** Medium–High | **Category:** Auth Weakness

## What It Does

Tests URL parameters commonly used for redirects (`redirect`, `return_url`, `next`, `callback`, etc.) by injecting external URLs and checking if the server issues a 3xx redirect to the attacker's domain (High, confidence 0.90). Also checks for JavaScript/meta redirects in response bodies (Medium, confidence 0.75).

Payload types tested: absolute URL (`https://evil.com`), protocol-relative (`//evil.com`), path confusion (`/\/evil.com`), and a null-byte host (`https://evil.com%00.target.com`). A `Location` counts as external only when its host contains `evil.com`: this covers `https://evil.com`, `//evil.com`, and the backslash and extra-slash forms browsers normalise to the same host (`/\/evil.com`, `///evil.com`). A protocol-relative redirect to the site's own host (`//app.example.com/home`) is not reported. When the parameter already carries a value, an allowlist-bypass payload (`https://evil.com/?_=<existing value>`) is tried first. There is no data-URI payload.

## Why It Matters

Open redirects let attackers craft links that look legitimate (your domain) but redirect to phishing pages:

- **Credential theft** — `yourapp.com/auth/callback?redirect_to=evil.com/fake-login` — user sees your domain, trusts it, enters credentials on the fake page
- **OAuth token theft** — chained with OAuth flows to steal authorization codes
- **Malware delivery** — redirect to malicious downloads from a trusted domain

## Real-World Breaches

**Google (ongoing)** — Google's redirect endpoints (`google.com/url?q=...`) have been repeatedly abused in phishing campaigns to make malicious links appear to originate from google.com.

## How to Fix

```typescript
// GOOD: Resolve against your own origin, then compare origins.
// A starts-with check on "http" or "//" is not enough: browsers treat a
// backslash as a slash, so "/\/evil.com" slips past it.
const redirectTo = searchParams.get("redirect_to") || "/"
const target = new URL(redirectTo, request.url)
if (target.origin !== new URL(request.url).origin) {
  return NextResponse.redirect(new URL("/", request.url))
}
return NextResponse.redirect(target)
```
