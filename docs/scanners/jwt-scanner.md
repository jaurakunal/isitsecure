# JWT Scanner

**Type:** DAST (Special) | **Severity:** Critical | **Category:** Auth Weakness

## What It Does

Tests JWT (JSON Web Token) implementations for five common vulnerabilities:

1. **Missing Claims** — Checks if the token lacks `exp` (expiration), `iat` (issued at), or `iss` (issuer). Tokens without expiration are valid forever.

2. **Algorithm None Bypass** — Forges a new JWT with `"alg": "none"` and no signature, then sends it. If the server accepts it, any user can forge tokens without knowing the secret.

3. **Weak Secret Signing** — Tests 10+ common secrets (`""`, `"secret"`, `"password"`, `"123456"`, `"your-256-bit-secret"`, etc.) by signing a forged token and sending it. If accepted, the secret can be brute-forced.

4. **RS256/ES256 Key Confusion** — If the server uses RSA (RS256), attempts to use the RSA public key as an HMAC secret (HS256). This exploits libraries that don't enforce algorithm restrictions.

5. **Token in URL** — Scans JavaScript bundles for patterns like `?token=eyJ...` where JWT tokens are passed as URL parameters (logged by proxies, cached by browsers).

## Why It Matters

JWTs are the authentication foundation of most modern web apps. If the JWT implementation is broken:

- **Forge tokens as any user** — alg:none or weak secrets let attackers create valid tokens for any user ID, including admins
- **Permanent access** — tokens without expiration never expire, so a stolen token works forever
- **Undetectable impersonation** — forged tokens are indistinguishable from real ones

## Real-World Breaches

**Auth0 / jsonwebtoken CVE-2015-9235 (2015)** — The `jsonwebtoken` npm library (millions of downloads) accepted `alg: "none"` by default, allowing complete authentication bypass in any app using the library without explicit algorithm restriction.

**Palo Alto Networks CVE-2020-2021 (2020)** — Improper SAML/JWT signature validation in PAN-OS allowed authentication bypass when the "Validate Identity Provider Certificate" option was disabled.

## What Vulnerable Code Looks Like

```typescript
// BAD: No algorithm restriction — accepts alg:none
const payload = jwt.verify(token, SECRET)

// BAD: Weak secret
const JWT_SECRET = "secret"
const token = jwt.sign(payload, JWT_SECRET)

// BAD: No expiration
const token = jwt.sign({ userId: "123", role: "admin" }, SECRET)
// Missing: expiresIn option
```

## How to Fix

```typescript
// GOOD: Restrict algorithms explicitly
const payload = jwt.verify(token, SECRET, { algorithms: ["HS256"] })

// GOOD: Strong random secret (256+ bits)
const JWT_SECRET = crypto.randomBytes(64).toString("hex")

// GOOD: Set expiration
const token = jwt.sign(payload, SECRET, { expiresIn: "1h" })

// GOOD: Use asymmetric keys (RSA) for production
const token = jwt.sign(payload, PRIVATE_KEY, { algorithm: "RS256", expiresIn: "1h" })
const decoded = jwt.verify(token, PUBLIC_KEY, { algorithms: ["RS256"] })
```
