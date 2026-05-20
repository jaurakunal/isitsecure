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

| Language | LSP Server | Install Command | Auth Tracing |
|---|---|---|---|
| **TypeScript/JavaScript** | typescript-language-server | `npm install -g typescript-language-server typescript` | Full trace via go-to-definition |
| **Python** | pylsp or pyright | `pip install python-lsp-server` or `pip install pyright` | Traces Depends(), decorators |
| **Java/Kotlin** | jdtls | See [jdtls install guide](https://github.com/eclipse-jdtls/eclipse.jdt.ls#installation) | Traces @PreAuthorize, SecurityConfig |

isitsecure auto-detects which LSP servers are installed and uses the first available one. If none are installed, regex-based auth detection is used (still effective, slightly higher false positive rate).

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

## Python LSP Setup

### Install pylsp (recommended)

```bash
pip install python-lsp-server

# Verify
pylsp --help
```

### Or install pyright

```bash
pip install pyright
# or
npm install -g pyright

# Verify
pyright-langserver --version
```

### What Gets Traced

```python
# Does Depends(get_current_user) actually verify the token?
@app.get("/tasks")
async def list_tasks(user=Depends(get_current_user)):
    # LSP traces: get_current_user → verify_token → jwt.decode()
```

```python
# Does @login_required actually check the session?
@login_required
def profile(request):
    # LSP traces: login_required → django.contrib.auth → session check
```

### Virtual Environment Detection

The Python LSP client auto-detects virtual environments at `.venv/`, `venv/`, or `env/` in your project root for proper import resolution.

## Java LSP Setup

### Install jdtls

The Eclipse JDT Language Server is the standard Java LSP:

```bash
# macOS (Homebrew)
brew install jdtls

# Linux — download from GitHub releases:
# https://github.com/eclipse-jdtls/eclipse.jdt.ls/releases
# Extract and add to PATH

# Verify
jdtls --version
```

### Or install kotlin-language-server (for Kotlin projects)

```bash
# https://github.com/fwcd/kotlin-language-server/releases
# Download, extract, add to PATH

kotlin-language-server --version
```

### What Gets Traced

```java
// Does @PreAuthorize actually check the right role?
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/users")
public List<User> getUsers() {}
// LSP traces: hasRole → SecurityConfig → role hierarchy
```

```java
// Does the SecurityFilterChain apply to this endpoint?
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/api/admin/**").hasRole("ADMIN")
    );
}
// LSP traces: filterChain → matcher → role check
```

### Prerequisites

- **Java 17+** — required for jdtls
- **Maven or Gradle** — jdtls needs a build tool to resolve dependencies

## How Auto-Detection Works

isitsecure tries LSP servers in this order:

1. **TypeScript** — if `typescript-language-server` or `npx` is available
2. **Python** — if `pylsp` or `pyright-langserver` is available
3. **Java** — if `java` runtime + `jdtls` is available
4. **NoOp** — fallback, regex-only analysis

The first available server is used. If your project is Python but you have TypeScript LSP installed, the TS LSP will be initialized — but it won't find any routes and auth flow tracing will be skipped. The regex-based Python auth detection still works regardless of which LSP is active.

To force a specific LSP, install only the server for your language.
