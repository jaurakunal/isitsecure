# Body Param Fuzzer

**Type:** DAST (Special) | **Severity:** Medium to Critical | **Category:** Injection Risk

## What It Does

Fuzzes JSON body parameters from intercepted authenticated requests (up to 20 successful POST/PUT/PATCH captures, up to 10 keys each; at most 123 requests per captured write) with:

- **SQL injection** — injects three payloads (for example `' OR '1'='1' --`) and checks the reply against a 13-pattern error regex, with no baseline comparison. Six of the patterns are generic runtime errors (`stack trace`, `Traceback`, `TypeError`, `ValueError`, `Internal Server Error`, `NullPointerException`), so a crash message can match (Critical)
- **XSS reflection** — injects two canary HTML payloads and checks if they are reflected verbatim (High)
- **Type confusion** — for string-valued keys, sends seven other values (number, boolean, empty array, null, -1, 0, a large number) and reports a 5xx response (Medium, 0.70)
- **Prototype pollution** — adds `__proto__`, `constructor.prototype` and `__proto__.polluted` keys to the body and reports when the server answers with a status below 400 (High). It does not verify that the server merged them; a server that simply ignores unknown keys is reported too

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
