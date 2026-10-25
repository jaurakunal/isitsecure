# XSS Scanner

**Type:** DAST | **Severity:** Low–Critical | **Category:** Injection Risk

## What It Does

Tests for Cross-Site Scripting (XSS) by injecting canary strings into URL parameters and POST body fields, then checking if the canary is reflected in the response without proper encoding.

Four detection modes:

1. **Reflected XSS** — Injects a unique canary (`<canary_xss_abc123>`) into GET query parameters. If the canary appears unescaped in the HTML response, the parameter is vulnerable.

2. **POST Body XSS** — Sends a body with a canary in each field of the crawled form (falling back to a generic field-name list when the endpoint carried none), first as `application/x-www-form-urlencoded` and then as JSON, and checks whether a canary is reflected in the response. Only a `text/html` response counts: a JSON or plain-text echo of the created resource is ignored. An unescaped canary is High (0.90); canary text reflected with its HTML characters encoded is Low (0.40).

3. **Stored XSS** — If the POST response does not reflect the canary, the scanner issues a GET to the same URL and checks whether the canary now appears unescaped in an `text/html` response (POST then GET read-back). A hit is reported as **Critical** (0.95). JSON API responses are skipped to avoid false positives.

4. **DOM XSS (static)** — A regex scan over the JavaScript bundles for dangerous sink patterns: `.innerHTML =`, `.outerHTML =`, `document.write(`, `document.writeln(`, `eval(`, `setTimeout("`, `setInterval("`, `Function("`, `.insertAdjacentHTML(`, `location.href =`, `location.replace(`, `dangerouslySetInnerHTML`. It does no data-flow analysis: it cannot tell whether user input reaches the sink. One finding is emitted per matched sink pattern (not per occurrence), as **Low** with confidence 0.60. A pattern is skipped only when every match is a static-string assignment. For tainted-flow detection in a real browser see the [DOM XSS scanner](dom-xss-scanner.md).

Only the angle-bracket probe (`<canary>`) can produce an unescaped-reflection High finding. The quote-only probes (`"canary"`, `'canary'`) only feed the context check below, and their own quotes are not mistaken for an attribute or JS string, so a server that strips tags but echoes text is not reported as confirmed XSS.

The scanner is **context-aware**: when the canary text is reflected but its HTML characters are encoded, it detects whether the canary landed in a double- or single-quoted attribute, a JS string, a template literal, an `href`, or an HTML comment, and sends a matching breakout payload. If that payload comes back unescaped the finding is High (0.95) and names the context; if not, the result stays an unconfirmed reflection (Low, 0.40).

**Scan depth (#118):** at `quick` depth (the default) the scanner runs the two network phases (reflected and POST-body, which includes the stored read-back) on a tighter 15-minute budget (`XSS_QUICK_SECONDS` = 900 s, versus 3600 s at deep), so server-reflected XSS on protected endpoints is caught even in a fast pass. The static **DOM XSS** sink analysis (mode 4) is a noisy static heuristic and runs only at `--depth deep`; the deterministic Semgrep taint layer already provides a DOM-XSS floor at quick depth.

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
