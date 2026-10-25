# Security Headers Scanner

**Type:** DAST | **Severity:** Low–High | **Category:** Missing Headers / Info Disclosure

## What It Does

Checks HTTP response headers for eight security headers:

| Header | What It Prevents | Severity when flagged |
|---|---|---|
| `Strict-Transport-Security` | Downgrade attacks (HTTP → HTTPS stripping) | High (0.95) |
| `Content-Security-Policy` | XSS, data injection, clickjacking | Medium (0.85) |
| `X-Content-Type-Options` | MIME-type sniffing attacks (also flagged if the value is not `nosniff`) | Medium (0.95) |
| `X-Frame-Options` | Clickjacking (embedding your site in iframes). Reported only when both this header and a CSP `frame-ancestors` directive are absent | Medium (0.90) |
| `Permissions-Policy` | Restricts browser features (camera, mic, geolocation) | Low (0.80) |
| `Referrer-Policy` | Leaking sensitive URLs to third parties | Low (0.80) |
| `Server` | Version disclosure (e.g., `Server: Apache/2.4.51`). Flagged only when the value contains a version such as `/2.4` | Low (0.90) |
| `X-Powered-By` | Technology disclosure (e.g., `X-Powered-By: Express`). Flagged whenever present | Low (0.90) |

Every unique discovered URL is requested once with GET, shortest URL first (so the homepage is tested first).

Also deduplicates: if the same header is missing on all endpoints, it reports once instead of per-endpoint (when the number of findings with the same title is at least the number of distinct URLs that produced a finding, and there is more than one such URL).

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
