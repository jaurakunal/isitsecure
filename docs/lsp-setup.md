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

isitsecure picks the server that matches the language your project is written in, and uses regex-based auth detection when there isn't one (still effective, slightly higher false positive rate).

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

### When the TypeScript server is considered usable

For a project detected as TypeScript (see [How the Server Is Chosen](#how-the-server-is-chosen)),
isitsecure checks that:

1. Node.js is available (`node --version`)
2. `typescript-language-server` is on PATH, or `npx` is available as a fallback
3. A TypeScript 5.x runtime can be found (see above)

If any of those is missing you'll see the reason and the fix:

```
No typescript language server installed — auth-flow tracing is skipped for
this scan. Install one with `isitsecure setup --lsp`.
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

**Next.js inline auth — including your own helpers:**
```typescript
import { getUserFromRequest } from "@/lib/auth"   // your code, not a library

export async function PATCH(request: Request) {
  const user = getUserFromRequest(request)
  // LSP traces: getUserFromRequest → lib/auth.ts → verifyToken()
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
}
```

No pattern list can name `getUserFromRequest` — it's your project's invention —
so the tracer resolves the call and looks for the terminal in **that function's
own body**, not the whole module. Scoping matters: helpers cluster, so a login
route importing `signToken` from the file that also defines `verifyToken` would
otherwise look authenticated.

**Router-wide Express middleware:**
```typescript
import { ensureMember } from "../auth/membership"   // your name, not a convention
router.use(ensureMember)                            // guards every route below
router.get('/team/:id', handler)
```

Middleware applied without a path guards the whole router, so it settles every
route in the file. It's found by **where it's applied** — a path-less `.use()`
— not by a list of names: a list can only recognise vocabulary someone thought
of in advance, and `ensureMember` is your project's word.

**Centrally-mounted Express routes, per route:**
```typescript
app.use('/api/BasketItems', security.isAuthorized())   // traced → verified
app.post('/api/Challenges', security.denyAll())        // traced → verified
app.get('/api/Products', ...)                          // no guard → not verified
```

A single `server.ts` can mount a hundred routes of which a handful are guarded,
so each route is answered from **its own mount line**. One verdict for the whole
file would either miss every guard or vouch for every unguarded neighbour —
and vouching is the dangerous direction, because a suppressed finding is a
vulnerability the report no longer mentions.

Middleware that delegates to a library counts as the terminal, because tracing
deliberately will not follow into `node_modules`: `expressJwt` (express-jwt),
`requiresAuth` (express-openid-connect), `ensureLoggedIn` (connect-ensure-login),
alongside the direct `jwt.verify` / `getUser` / `getServerSession` forms.

### Performance Impact

LSP adds ~2-5 seconds to the scan for initialization and ~0.5s per route traced. For a typical project with 20 routes, this adds ~12 seconds total. The accuracy improvement (fewer false positives) is worth the time.

### Troubleshooting

**"No &lt;language&gt; language server installed"**

Your project was detected as that language, but its server isn't installed.
Install it:

```bash
isitsecure setup --lsp
```

isitsecure deliberately won't substitute a server for a different language —
one that can't read your code would report no findings, which is worse than
saying it didn't look.

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

## How the Server Is Chosen

The choice is made **per scan, from your code** — not from what happens to be
installed. Once your project has been ingested, isitsecure counts its source
files and picks the server for whichever language most of it is written in:

| Language | Counted extensions | Server |
|---|---|---|
| TypeScript / JavaScript | `.ts` `.tsx` `.js` `.jsx` `.mjs` `.cjs` | typescript-language-server |
| Python | `.py` `.pyi` | pylsp or pyright-langserver |
| Java / Kotlin | `.java` `.kt` `.kts` | jdtls |

Vendored and generated directories (`node_modules`, `.venv`, `dist`, `target`,
and hidden directories) don't count toward the total, so a Python service with
a bundled JavaScript dependency is still scanned as Python. If two languages
tie, the order in the table wins, so repeated scans of the same repo always
choose the same server.

**If the matching server isn't installed, no server is used** — isitsecure says
which one it wanted and falls back to regex-only auth detection. It will not
start a server for a different language: one that doesn't understand your code
finds nothing, which reads as "no problems here" rather than "not checked".

```
No python language server installed — auth-flow tracing is skipped for this
scan. Install one with `isitsecure setup --lsp`.
```

To see what a scan chose, run with `-v` and look for `Project language:` and
`LSP: using ...`.
