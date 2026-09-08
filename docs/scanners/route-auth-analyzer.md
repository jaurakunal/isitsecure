# Route Auth Analyzer

**Type:** SAST | **Severity:** High | **Category:** Auth Weakness

## What It Does

Analyzes every API route file in your codebase for two things:

1. **Missing Authentication** — Checks if the route calls any authentication function (`getUser`, `getSession`, `auth()`, `verifyToken`, `requireAuth`, etc.). Routes without these calls are flagged as unprotected.

2. **Missing Input Validation** — Checks if the route validates incoming data before processing it. Routes that directly use `request.json()` or `searchParams.get()` without validation are flagged.

The analyzer is **framework-aware**:
- **Next.js App Router**: Scans `app/api/**/route.ts` files, understands `GET`, `POST`, `PUT`, `PATCH`, `DELETE` exports
- **Express**: Scans `app.get()`, `router.post()` patterns
- **tRPC**: Checks if procedures use `protectedProcedure` vs `publicProcedure`

### Routes it deliberately stays quiet about

Some routes are meant to be open, and flagging them is noise. The exemption
list is deliberately short and is about what a route **is**, not about what we
found on it:

- health and status endpoints (`/health`, `/ping`, `/status`, `/ready`, …)
- API documentation (`/docs`, `/swagger`, `/openapi`) and the root path
- webhook receivers (`/webhook`, `/stripe`), which are signature-verified
  rather than auth-gated

App-specific route names are kept out of it on purpose: a scanned app that
happens to reuse one would have a real finding silently suppressed.

Not finding a guard is never itself grounds for staying quiet. A rule that
exempted any GET route the mapper reported no auth on read that backwards —
it is the exact condition a missing-auth finding exists to report — and
because the Express mapper always answers true or false and never "unknown",
no Express GET route could produce a missing-auth finding at all.

## Why It Matters

A single API route without authentication is often enough for a full data breach:

- **Data theft** — unauthenticated read endpoints expose all data to anyone
- **Data manipulation** — unauthenticated write endpoints let attackers create, modify, or delete records
- **Privilege escalation** — admin endpoints without auth let any user perform admin actions

This is especially common in "vibe coded" apps where developers add routes quickly and forget to add auth, or add auth to pages but not API routes.

## Real-World Breaches

**Optus Australia (2022)** — An unauthenticated API endpoint exposed personal records of 9.8 million customers including passport numbers and driver's licenses. No API key or auth token was required.

**Peloton (2021)** — API endpoints lacked authentication, allowing anyone to query user account data (age, gender, city, weight) for any Peloton user without logging in.

## What Vulnerable Code Looks Like

```typescript
// BAD: No auth check — anyone can list all users
export async function GET() {
  const users = await db.select().from(profiles)
  return NextResponse.json(users)
}

// BAD: Auth on the page but not the API route
// src/app/dashboard/page.tsx → has auth check
// src/app/api/tasks/route.ts → no auth check (accessible directly)
```

## How to Fix

```typescript
// GOOD: Check authentication on every API route
export async function GET(request: Request) {
  const user = await getAuthUser(request)
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  // Only return this user's data
  const tasks = await db.select().from(tasks).where(eq(tasks.userId, user.id))
  return NextResponse.json(tasks)
}

// GOOD: Use middleware to protect all /api routes
// middleware.ts
export function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith("/api")) {
    const token = request.headers.get("Authorization")
    if (!token) return new Response("Unauthorized", { status: 401 })
  }
}
```
