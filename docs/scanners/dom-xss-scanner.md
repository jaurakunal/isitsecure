# DOM XSS Scanner

**Type:** DAST (Special) | **Severity:** High | **Category:** Injection Risk

## What It Does

Uses **Playwright** (real browser) to detect DOM-based XSS by hooking dangerous JavaScript sinks at runtime:

- Overrides 10+ sinks: `innerHTML`, `eval`, `Function()`, `setTimeout(string)`, `setInterval(string)`, `location.assign()`, `location.replace()`, `document.write()`
- Injects canary values via URL query parameters, URL hash fragment, and `postMessage`
- If a canary reaches a hooked sink, the finding is confirmed with the exact sink name and source

Unlike the static XSS scanner, this runs code in a real browser — catching dynamic patterns where user input flows through framework abstractions, event handlers, or async code paths before reaching a sink.

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
