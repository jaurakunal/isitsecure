# Body Param Fuzzer

**Type:** DAST (Special) | **Severity:** Low to Critical | **Category:** Injection Risk

## What It Does

Fuzzes JSON body parameters from intercepted authenticated requests (up to 20 successful POST/PUT/PATCH captures, up to 10 keys each; at most 123 requests per captured write) with:

- **SQL injection** — injects three payloads (for example `' OR '1'='1' --`; the stacked-statement probe is the harmless syntax breaker `1'; SELECT--`, never a destructive statement) and checks the reply against database-specific error patterns (`SQL syntax`, `SQLSTATE`, `ORA-nnnnn`, `syntax error at or near`, ...) that are not already present in the recorded response (Critical). Generic crash strings no longer count; a payload that turns a successful request into a 5xx without a database error is reported as a Medium "Possible SQL injection" (confidence 0.50)
- **XSS reflection** — injects two canary HTML payloads and checks if they are reflected verbatim (High)
- **Type confusion** — for string-valued keys, sends seven other values (number, boolean, empty array, null, -1, 0, a large number) and reports a 5xx response (Medium, 0.70)
- **Prototype pollution** — adds `__proto__`, `constructor.prototype` and `__proto__.polluted` keys to the body with a unique marker value. It reports High only when a follow-up clean request returns the marker (the pollution persisted). A server that merely answers below 400 gets one Low "accepts prototype-pollution key (not confirmed)" note per request (confidence 0.30)

### Request contracts

A probe that the API's request validation rejects (400/422) never reaches the code that would be vulnerable. The fuzzer parses the rejection (`engine/shared/request_contract.py`: FastAPI/Pydantic, DRF, Rails, Laravel, Zod, Spring, ASP.NET, Joi and similar), repairs the sibling fields the endpoint requires or pins to a fixed value, and re-sends the probe (at most 2 retries per probe and 6 per endpoint; learned contracts repair later probes up front). A 415 switches the body to form encoding. Fields the server pins to a closed set are skipped rather than fuzzed.

A probe that is still rejected after repair is never evaluated, so a validation error that merely quotes the payload no longer reads as reflected XSS. Instead the endpoint gets one Info finding, "Injection probes blocked by request validation (not tested)", listing the fields whose every SQLi/XSS/prototype probe was rejected. It is a coverage note: the absence of a finding on those fields is not evidence they are safe. Type-confusion probes are not tracked this way, since a rejection is the behaviour they test.

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
