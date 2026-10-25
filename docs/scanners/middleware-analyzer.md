# Middleware Analyzer

**Type:** SAST | **Severity:** Low–High | **Category:** Auth Weakness

## What It Does

Analyzes Next.js `middleware.ts`/`middleware.js` files (repo root or `src/`) for incomplete protection patterns:

- **No middleware file** — API routes exist but no middleware was found and the repo has no Express-style middleware (High)
- **Partial matcher coverage** — middleware protects `/dashboard/*` but not `/api/*`, leaving API routes exposed. Only API routes (`app/api/**/route.ts`, `pages/api/**`) are compared with the matcher, one finding per uncovered route (Medium)
- **Missing auth check patterns** — middleware only checks that a cookie exists and has no token/session verification call (Medium)
- **Matcher bypass hints** — a literal matcher with no trailing `*` or `/`, or lowercase literal paths, may miss `/admin/` or differently cased requests (Low)

## Why It Matters

Middleware is often the first line of defense. If it only protects page routes but not API routes, attackers bypass it by calling APIs directly:

```
Browser → /dashboard (protected by middleware) → OK
curl → /api/tasks (NOT protected by middleware) → Data leak
```

## Real-World Context

**Optus (2022)** — The catastrophic breach that exposed 9.8 million records was caused by an API endpoint with no authentication. The middleware (or equivalent) protected user-facing pages but not the API — exactly the pattern this scanner detects.

## How to Fix

```typescript
// GOOD: Protect both pages and API routes
export const config = {
  matcher: ["/dashboard/:path*", "/api/:path*"]
}

export function middleware(request: NextRequest) {
  // Exclude public API routes explicitly
  const publicPaths = ["/api/auth/login", "/api/auth/register", "/api/health"]
  if (publicPaths.some(p => request.nextUrl.pathname.startsWith(p))) {
    return NextResponse.next()
  }

  const token = request.headers.get("Authorization")
  if (!token) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }
}
```
