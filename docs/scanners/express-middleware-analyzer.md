# Express Middleware Analyzer

**Type:** SAST | **Severity:** Low–High | **Category:** Auth Weakness

## What It Does

Analyzes Express.js middleware and routes for authentication gaps and hygiene. Checks:

- **Missing auth middleware on routes** — routes defined with `app.get()` / `router.post()` where no known guard name (such as `requireAuth`, `authenticate`, `verifyToken`, `authMiddleware`) appears in that route's own arguments, for non-public sensitive paths (`/api/`, `/admin`, `/user`, `/billing`, ...); one finding per method (Medium)
- **Auth middleware quality** — no token/session verification anywhere (High), or a middleware that only checks a header or cookie exists (High)
- **Rate limiting** — none found, or an in-memory store (Medium)
- **Security headers** — missing recommended headers when helmet is not used (Low)
- **CORS** — `origin: '*'` together with `credentials: true` in one file (High)
- **Tenant isolation** — a multi-tenant app with no tenant-isolation middleware (High)

Not covered today: middleware ordering (auth registered after routes) and bypass by route specificity.

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
