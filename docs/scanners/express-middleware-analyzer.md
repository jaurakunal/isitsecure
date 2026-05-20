# Express Middleware Analyzer

**Type:** SAST | **Severity:** High | **Category:** Auth Weakness

## What It Does

Analyzes Express.js middleware chains for authentication gaps. Checks:

- **Missing auth middleware on routes** — routes defined with `app.get()` / `router.post()` without auth middleware in the chain
- **Middleware ordering** — auth middleware defined after route handlers (too late to protect them)
- **Middleware bypass via route specificity** — a wildcard auth middleware exists but specific routes are defined before it, bypassing protection

This scanner activates when Express is detected as the backend framework.

## Why It Matters

Express middleware is applied in order. A single route defined before the auth middleware runs without authentication:

```javascript
// Route defined BEFORE auth middleware — unprotected!
app.get("/api/admin/users", getUsers)

// Auth middleware applied too late
app.use(authMiddleware)
```

This is the Express equivalent of the Next.js middleware gap — auth exists but doesn't cover all routes.

## Real-World Context

**Peloton (2021)** — Unauthenticated API endpoints exposed user data. The API likely had auth middleware but it wasn't applied to all routes — exactly the pattern this scanner detects.

## How to Fix

```javascript
// GOOD: Apply auth middleware BEFORE routes
app.use("/api", authMiddleware)  // Covers all /api/* routes

// Then define routes
app.get("/api/admin/users", getUsers)  // Protected by middleware above

// GOOD: Exclude public routes explicitly
app.use("/api", (req, res, next) => {
  const publicPaths = ["/api/auth/login", "/api/health"]
  if (publicPaths.includes(req.path)) return next()
  return authMiddleware(req, res, next)
})
```
