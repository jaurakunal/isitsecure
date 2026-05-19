# Middleware Analyzer

**Type:** SAST | **Severity:** High | **Category:** Auth Weakness

## What It Does

Analyzes Next.js `middleware.ts` files for incomplete protection patterns:

- **Partial matcher coverage** — middleware protects `/dashboard/*` but not `/api/*`, leaving API routes exposed
- **Missing auth check patterns** — middleware runs but doesn't verify auth tokens
- **Bypass paths** — public paths that accidentally match protected route patterns

## Why It Matters

Middleware is often the first line of defense. If it only protects page routes but not API routes, attackers bypass it by calling APIs directly:

```
Browser → /dashboard (protected by middleware) → OK
curl → /api/tasks (NOT protected by middleware) → Data leak
```

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
