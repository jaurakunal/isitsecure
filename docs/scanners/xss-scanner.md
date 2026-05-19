# XSS Scanner

**Type:** DAST | **Severity:** High–Critical | **Category:** Injection Risk

## What It Does

Tests for Cross-Site Scripting (XSS) by injecting canary strings into URL parameters and POST body fields, then checking if the canary is reflected in the response without proper encoding.

Three detection modes:

1. **Reflected XSS** — Injects a unique canary (`<canary_xss_abc123>`) into GET query parameters. If the canary appears unescaped in the HTML response, the parameter is vulnerable.

2. **POST Body XSS** — Sends JSON payloads with canary strings in common field names. Checks if the canary is reflected in the response body.

3. **DOM XSS (static)** — Scans JavaScript bundles for dangerous DOM sinks: `innerHTML`, `eval()`, `document.write()`, `setTimeout(string)`, `location.assign()`. Flags code paths where user input flows into these sinks.

The scanner is **context-aware**: if the canary lands inside an HTML attribute vs. a script block vs. raw HTML, it adjusts the severity and reports the injection context.

## Why It Matters

XSS allows attackers to execute JavaScript in your users' browsers. This means they can:

- **Steal session tokens** — read `localStorage`, cookies, and send them to an attacker-controlled server
- **Impersonate users** — make API calls as the victim (transfer money, change passwords, delete data)
- **Deface the application** — modify what users see, inject fake login forms
- **Deliver malware** — redirect users to malicious downloads
- **Bypass CSRF protections** — JavaScript running in-context can submit any form with valid tokens

## Real-World Breaches

**British Airways (2018)** — The Magecart group injected malicious JavaScript into BA's payment page, skimming 380,000 customers' payment card details. BA was fined $26 million by the ICO. The attack was possible because there was no Content Security Policy and user input was rendered without sanitization.

**eBay (2015–2016)** — Attackers injected malicious JavaScript into eBay product listings, redirecting users to phishing pages to steal credentials.

## What Vulnerable Code Looks Like

```typescript
// BAD: User input reflected directly in HTML
export async function GET(request: Request) {
  const query = new URL(request.url).searchParams.get("q")
  return new Response(`<h1>Results for: ${query}</h1>`, {
    headers: { "Content-Type": "text/html" }
  })
}

// BAD: React dangerouslySetInnerHTML with user data
function Comment({ text }) {
  return <div dangerouslySetInnerHTML={{ __html: text }} />
}
```

## How to Fix

```typescript
// GOOD: Use a templating engine that auto-escapes
// React JSX auto-escapes by default:
function Comment({ text }) {
  return <div>{text}</div>  // Safe — React escapes HTML entities
}

// GOOD: If you must return raw HTML, sanitize with DOMPurify
import DOMPurify from "dompurify"
const clean = DOMPurify.sanitize(userInput)

// GOOD: Set Content Security Policy header
// next.config.js
headers: [{ key: "Content-Security-Policy", value: "default-src 'self'" }]
```
