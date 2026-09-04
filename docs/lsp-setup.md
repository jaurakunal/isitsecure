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
| **TypeScript/JavaScript** | typescript-language-server | `isitsecure setup --lsp` (server + a private TypeScript 5.x runtime) | Full trace via go-to-definition |
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
# Recommended: installs the server AND the TypeScript runtime it needs
isitsecure setup --lsp

# Manual equivalent
npm install -g typescript-language-server
npm install --prefix ~/.isitsecure/lsp typescript@5
```

`npx` also works as a fallback — isitsecure uses it automatically when
`typescript-language-server` isn't on PATH — but it's slower to start.

3. **A TypeScript 5.x runtime** — the `tsserver.js` the server actually runs

This is a separate requirement, and the one that most often bites:

- `typescript-language-server` ships **no TypeScript of its own**. It resolves
  `typescript` from the *workspace* and refuses to start when it can't find
  one (`Could not find a valid TypeScript installation…`).
- isitsecure scans a **copy** of your project with `node_modules` stripped, so
  the workspace never has one — meaning a scan can't rely on your project's
  install even when your editor can.
- It must be TypeScript **5.x**. `typescript@latest` is now 7.x — the
  Go-native rewrite — which ships no `lib/tsserver.js` at all and cannot drive
  the language server.

So `isitsecure setup --lsp` provisions a private TypeScript 5.x under
`~/.isitsecure/lsp` and passes it to the server as `tsserver.path`. It never
installs or changes a global `typescript`, so your projects keep whatever
version they use.

### Where isitsecure looks for the runtime

First match wins:

1. `$ISITSECURE_TSSERVER_PATH` — an explicit path to a `tsserver.js`
2. The scanned project, then its immediate subdirectories (monorepo packages)
3. `~/.isitsecure/lsp/node_modules/typescript/lib/tsserver.js` (provisioned)
4. Next to the `typescript-language-server` binary (a global install that also
   has a global `typescript` 5.x)
5. `npm root -g` — the global node_modules root

To pin a specific TypeScript:

```bash
export ISITSECURE_TSSERVER_PATH=/path/to/node_modules/typescript/lib/tsserver.js
```

### Verification

```bash
# Reports the server AND the TypeScript runtime it will use
isitsecure setup --check

# Or check the server by hand
typescript-language-server --version
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
isitsecure setup --lsp
```

**"LSP initialize failed: … Could not find a valid TypeScript installation"**

The language server is installed and healthy, but has no TypeScript 5.x
`tsserver.js` to run. Install one:

```bash
isitsecure setup --lsp
```

Confirm with `isitsecure setup --check`, which prints the exact `tsserver.js`
that scans will use. If you keep your own TypeScript somewhere unusual, point
at it with `ISITSECURE_TSSERVER_PATH` instead.

Note that a global `npm install -g typescript` no longer helps on its own:
that installs 7.x, which has no `lib/tsserver.js`.

**"LSP initialization timed out"**

The project may have a very large `node_modules` or complex tsconfig. Try:
```bash
# Ensure node_modules is installed (LSP needs it for type resolution)
cd your-project && npm install
```

**"LSP reader stopped: ..."**

The language server sent something the client could not read, so the session is
dead and the scan falls back to regex analysis. The text after the colon is the
parse failure itself — include it if you file an issue, since it identifies the
server and the message that broke.

This is reported immediately rather than after the initialization timeout, so a
scan that prints this has not silently waited 30 seconds first.

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
   (it also needs a TypeScript 5.x runtime to start — see above)
2. **Python** — if `pylsp` or `pyright-langserver` is available
3. **Java** — if `java` runtime + `jdtls` is available
4. **NoOp** — fallback, regex-only analysis

The first available server is used. If your project is Python but you have TypeScript LSP installed, the TS LSP will be initialized — but it won't find any routes and auth flow tracing will be skipped. The regex-based Python auth detection still works regardless of which LSP is active.

To force a specific LSP, install only the server for your language.
