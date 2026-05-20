# LSP Setup Guide

isitsecure uses Language Server Protocol (LSP) integration to trace authentication flows through your codebase. This reduces false positives by verifying that auth middleware is genuinely applied — not just imported.

## What LSP Does

Without LSP, the route auth analyzer checks if auth-related keywords (`getUser`, `requireAuth`, `@login_required`) appear in your route files. This catches most cases but can produce false positives when:

- Auth middleware is imported but not actually called
- A wrapper function claims to check auth but doesn't
- Auth is applied at a different layer (e.g., tRPC middleware) and the route file doesn't reference it directly

With LSP enabled, the scanner uses **go-to-definition** to trace the actual call chain:

```
Route file: app/api/tasks/[id]/route.ts
  → calls protectedProcedure
    → LSP go-to-definition → trpc.ts:42
      → finds supabase.auth.getUser() call
        → Auth IS genuinely applied → suppress false positive
```

## Current LSP Support

| Language | LSP Status | Auth Tracing | Notes |
|---|---|---|---|
| **TypeScript/JavaScript** | Supported | Full trace via tsserver | Traces through imports, middleware, decorators |
| **Python** | Not yet | Regex-only | `@login_required`, `Depends(get_current_user)` detected by pattern |
| **Java/Kotlin** | Not yet | Regex-only | `@PreAuthorize`, `@Secured` detected by pattern |

Python and Java LSP support is planned. The regex-based detection works well for these languages because their auth patterns are more explicit (decorators/annotations) than TypeScript's (middleware chains, higher-order functions).

## TypeScript LSP Setup

### Prerequisites

1. **Node.js** (v16+) — required to run the TypeScript Language Server

```bash
# Check if Node.js is installed
node --version

# Install if needed (macOS)
brew install node

# Install if needed (Ubuntu/Debian)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

2. **TypeScript Language Server** — the actual LSP server

```bash
# Option A: Install globally (recommended)
npm install -g typescript-language-server typescript

# Option B: npx (no install needed, slower startup)
# isitsecure will automatically use npx if typescript-language-server is not found
```

### Verification

```bash
# Check if everything is set up
typescript-language-server --version
# Should output a version number

# Or check via npx
npx typescript-language-server --version
```

### How isitsecure Detects LSP

When a scan starts, isitsecure automatically checks:

1. Is Node.js available? (`node --version`)
2. Is `typescript-language-server` installed globally? (`which typescript-language-server`)
3. Is `npx` available as a fallback? (`which npx`)

If all checks fail, you'll see:

```
LSP DISABLED: Node.js not found on this system.
Install Node.js to enable TypeScript flow analysis.
Scan will use regex-only analysis (higher false positive rate).
```

The scan still works — you just get regex-based auth detection instead of LSP-based tracing.

### What Gets Traced

When LSP is enabled, the `AuthFlowTracer` traces these patterns:

**tRPC procedures:**
```typescript
// Does protectedProcedure actually call getUser()?
export const taskRouter = router({
  list: protectedProcedure.query(async ({ ctx }) => {
    // LSP traces: protectedProcedure → middleware → getUser()
  })
})
```

**Express middleware chains:**
```typescript
// Does requireAuth actually verify the token?
router.get('/tasks', requireAuth, async (req, res) => {
  // LSP traces: requireAuth → verifyToken → jwt.verify()
})
```

**Next.js inline auth:**
```typescript
// Is getServerSession actually called before data access?
export async function GET() {
  const session = await getServerSession()
  // LSP traces: getServerSession → authOptions → providers
}
```

### Performance Impact

LSP adds ~2-5 seconds to the scan for initialization and ~0.5s per route traced. For a typical project with 20 routes, this adds ~12 seconds total. The accuracy improvement (fewer false positives) is worth the time.

### Troubleshooting

**"LSP DISABLED: Node.js found but typescript-language-server is not installed"**

```bash
npm install -g typescript-language-server typescript
```

**"LSP initialization timed out"**

The project may have a very large `node_modules` or complex tsconfig. Try:
```bash
# Ensure node_modules is installed (LSP needs it for type resolution)
cd your-project && npm install
```

**"LSP trace returned no results for route X"**

The route may use a pattern the tracer doesn't recognize yet. The scan falls back to regex analysis for that route. File an issue with the route code and we'll add support.

## Future: Python LSP

When implemented, Python LSP will use `pylsp` or `pyright` to trace:

```python
# Does Depends(get_current_user) actually verify the token?
@app.get("/tasks")
async def list_tasks(user=Depends(get_current_user)):
    # LSP would trace: get_current_user → verify_token → jwt.decode()
```

For now, the regex-based detection catches `Depends(get_current_user)`, `@login_required`, and other standard patterns reliably.

## Future: Java LSP

When implemented, Java LSP will use `jdtls` (Eclipse JDT Language Server) to trace:

```java
// Does @PreAuthorize actually check the right role?
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/users")
public List<User> getUsers() {}
// LSP would trace: hasRole → SecurityConfig → role hierarchy
```

For now, `@PreAuthorize`, `@Secured`, and `@RolesAllowed` annotations are detected by regex.
