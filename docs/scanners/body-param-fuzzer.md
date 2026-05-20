# Body Param Fuzzer

**Type:** DAST (Special) | **Severity:** Medium–High | **Category:** Injection Risk

## What It Does

Fuzzes JSON body parameters from intercepted authenticated requests with:

- **SQL injection** — injects `'` and checks for SQL error patterns in responses
- **XSS reflection** — injects canary HTML and checks if reflected
- **Type confusion** — sends wrong types (string instead of number, null, array) to find error handling bugs
- **Prototype pollution** — sends `__proto__` and `constructor.prototype` keys to check if the server merges them into objects

## Why It Matters

Body parameter fuzzing catches vulnerabilities that scanners targeting URL parameters miss. Many APIs accept complex JSON bodies where individual fields are unsanitized:

- **Prototype pollution** — polluting `Object.prototype` can override security checks, bypass authorization, or achieve RCE in Node.js
- **Type confusion** — sending `null` where a string is expected can crash the app or bypass validation
- **Nested injection** — SQL/XSS payloads hidden in deeply nested JSON fields often bypass WAFs

## Real-World Breaches

**Lodash CVE-2019-10744 (2019)** — Prototype pollution via `defaultsDeep` in Lodash (100M+ downloads/month) enabled DoS or RCE in Node.js apps.

**jQuery CVE-2019-11358 (2019)** — Prototype pollution in `$.extend()` affected ~74% of all websites at the time.

## How to Fix

```typescript
// GOOD: Strip dangerous keys before spreading
function sanitize(obj: Record<string, unknown>) {
  const { __proto__, constructor, prototype, ...safe } = obj
  return safe
}

const body = sanitize(await request.json())
```
