# Security Headers Scanner

**Type:** DAST | **Severity:** Medium–Low | **Category:** Missing Headers / Info Disclosure

## What It Does

Checks HTTP response headers for eight security headers:

| Header | What It Prevents |
|---|---|
| `Strict-Transport-Security` | Downgrade attacks (HTTP → HTTPS stripping) |
| `Content-Security-Policy` | XSS, data injection, clickjacking |
| `X-Content-Type-Options` | MIME-type sniffing attacks |
| `X-Frame-Options` | Clickjacking (embedding your site in iframes) |
| `Permissions-Policy` | Restricts browser features (camera, mic, geolocation) |
| `Referrer-Policy` | Leaking sensitive URLs to third parties |
| `Server` | Version disclosure (e.g., `Server: Apache/2.4.51`) |
| `X-Powered-By` | Technology disclosure (e.g., `X-Powered-By: Express`) |

Also deduplicates: if the same header is missing on all endpoints, it reports once instead of per-endpoint.

## Why It Matters

Missing security headers make other attacks easier:

- **No CSP** → XSS attacks can load external scripts, exfiltrate data, mine crypto
- **No HSTS** → man-in-the-middle can strip HTTPS and intercept traffic
- **No X-Frame-Options** → attacker embeds your site in an iframe and tricks users into clicking hidden buttons (clickjacking)
- **Server version exposed** → attacker knows exactly which CVEs to try

## Real-World Context

**British Airways (2018)** — The Magecart XSS attack was worsened by the absence of Content Security Policy. A CSP with `script-src 'self'` would have blocked the injected third-party script from executing.

## How to Fix

```javascript
// next.config.js
const securityHeaders = [
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" },
  { key: "Content-Security-Policy", value: "default-src 'self'; script-src 'self'" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
]

module.exports = {
  async headers() {
    return [{ source: "/(.*)", headers: securityHeaders }]
  }
}
```
