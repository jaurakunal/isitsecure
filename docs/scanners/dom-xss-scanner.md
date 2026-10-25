# DOM XSS Scanner

**Type:** DAST (Special) | **Severity:** High | **Category:** Injection Risk

## What It Does

Uses **Playwright** (real browser) to detect DOM-based XSS by hooking dangerous JavaScript sinks at runtime:

- Hooks 12 sinks: `innerHTML`, `outerHTML`, `document.write()`, `document.writeln()`, `eval`, `Function()`, `insertAdjacentHTML()`, `location.assign()`, `location.replace()`, `window.open()`, `setTimeout(string)`, `setInterval(string)`
- The hook script is installed as a self-invoking function (`add_init_script` only evaluates source), before any page script runs
- Injects a canary through four vectors, tried in order per page, stopping at the first confirmed hit:
  1. URL query parameters (one navigation per name, 17 names: `q`, `query`, `search`, `s`, `keyword`, `term`, `redirect`, `url`, `next`, `return`, `callback`, `ref`, `page`, `view`, `tab`, `id`, `name`)
  2. URL hash fragment
  3. `postMessage` (4 payload shapes: a bare string, `{"data": ...}`, `{"type": "navigate", "url": ...}`, and an `{"html": ..., "action": "render"}` object)
  4. Typed form inputs: text-like inputs, textareas and contenteditable fields (up to 8 per page) are filled with `<img src=x id="<canary>">`, then Enter is pressed. This vector confirms either when the string reaches a hooked sink or when an element with the canary id appears in the DOM (a DOM-element oracle).
- The injected value is inert markup, `<i id="<canary>">` (query, hash and `postMessage` vectors; the typed-input vector uses `<img src=x id="<canary>">`). A sink call is recorded only if that markup reaches the sink raw. A flow that HTML-escapes, URL-encodes or strips the `<` and `"` characters still contains the bare canary token but is not exploitable, so it is not reported.
- The canary match is case-insensitive, so a flow that lower-cases the value (`q.toLowerCase()` into `innerHTML`) is still detected; the raw-markup rule is unchanged.
- Known recall limits: `iframe.srcdoc` and `location.href` assignments are not hooked.
- If a canary reaches a hooked sink raw (or materializes as an element), the finding is confirmed with the exact sink name and source
- Limits: at most 30 pages per run and a 300 s soft wall-clock budget (the scan stops and returns the findings gathered so far)

The scanner is not a `DASTScannerProtocol` scanner that takes endpoints and a snapshot. It is invoked by the agent during the authenticated crawl phase, reusing the crawl's Playwright browser context, and it needs Playwright installed (it returns nothing if Playwright is unavailable). Confirmed findings are High with confidence 0.95.

Unlike the static XSS scanner, this runs code in a real browser — catching dynamic patterns where user input flows through framework abstractions, event handlers, or async code paths before reaching a sink.

## Why It Matters

DOM XSS is harder to detect than reflected XSS because the payload never touches the server — it flows entirely within the browser's JavaScript. This means:

- **WAFs can't block it** — the payload is in the URL fragment (`#`) which isn't sent to the server
- **Server-side sanitization doesn't help** — the vulnerability is in client-side code
- **Same impact as reflected XSS** — full token theft, session hijacking, defacement

Modern SPAs (React, Next.js, Vue) are especially vulnerable because they read URL parameters and render them dynamically.

## Real-World Breaches

**Google Search (2019)** — A DOM XSS vulnerability where URL fragment input was unsafely injected into the DOM. Google patched it and awarded a bounty.

**Salesforce (2020)** — DOM XSS in the Lightning component framework where URL parameters were reflected into the page DOM without sanitization.

## How to Fix

```typescript
// BAD: innerHTML with user input
document.getElementById("preview").innerHTML = location.hash.slice(1)

// GOOD: Use textContent instead
document.getElementById("preview").textContent = location.hash.slice(1)

// GOOD: Use React's built-in escaping
function Preview() {
  const content = window.location.hash.slice(1)
  return <div>{content}</div>  // React auto-escapes
}
```
