# IDOR Scanner

**Type:** DAST (Special) | **Severity:** High–Critical | **Category:** IDOR

## What It Does

Tests for Insecure Direct Object References by swapping resource identifiers in API requests and checking if the server returns another user's data.

Four test types:

1. **Unauthenticated Access** — Sends requests without any auth headers. If the endpoint returns data, it's publicly accessible when it shouldn't be. "Returns data" means the JSON body actually carries a value: an endpoint that answers an anonymous request with an empty envelope like `{"user":{}}` is telling you *nobody*, not leaking a record, and is not flagged. The check is structural (any non-empty scalar, anywhere) so it doesn't depend on recognising `data`/`result`/`user` envelope keys.

2. **Path Parameter Swapping** — Changes `/api/tasks/USER-A-TASK-ID` to `/api/tasks/USER-B-TASK-ID` and compares the response to the original id's. Different data means the id is a real object reference; identical means it's ignored. Unauthenticated this is only a lead (see risk levels) — confirming an ownership violation needs the cross-user pass.

3. **Query Parameter Swapping** — Changes `?user_id=USER-A` to `?user_id=USER-B`. Targets ID-bearing query parameters.

4. **Sequential ID Enumeration** — For numeric IDs, tries `id+1`, `id-1`, `id+100` to check if sequential enumeration works.

In **authenticated mode** with two sets of credentials, the scanner performs **cross-user IDOR testing** (broken object-level authorization, BOLA):
- Log in as User A and User B — via the browser login helper, or via a generic REST login (`RestLoginAuthProvider`) for frontend-less APIs
- **Harvest User A's real object IDs** from parent collections (e.g. `GET /api/tasks` yields task IDs), instead of guessing. Both **numeric** and **UUID** id shapes are handled; when harvested IDs are all numeric the candidate set is filtered to numeric IDs so UUIDs aren't wasted
- Try to access User A's harvested resources as User B (read, write, delete)
- **Anonymous-access guard**: each resource is first probed with no auth at all — if it's simply public, the cross-user finding is suppressed as a false positive
- **Content-match guard**: a hit is only reported when User B's response actually contains User A's data, not an empty or generic body
- **Mutation read-back**: for PUT/PATCH IDOR, a 2xx only proves the write was *accepted*. The probe writes a canary into one existing, non-sensitive field (never a money/auth/PII field), re-reads it, and restores the original value. Confirmed persistence → CRITICAL; genuinely unconfirmable → a downgraded HIGH lead. A write-open, read-gated endpoint (the GET returns 401 but the PUT echoes the object) is still confirmed, from the write response. Each endpoint yields one finding — self-swaps (id→same id) are skipped and probing stops at the first accepted swap. The SPA catch-all (200 text/html for unknown routes) is rejected before any of this, so an app-shell response is never a write.
- Test if User B can do a full-table `SELECT *` via Supabase REST API

Risk levels: **CONFIRMED** is reserved for the **cross-user** path (below) — it proves user B can read user A's object. An **unauthenticated** probe cannot reach CONFIRMED or LIKELY: a public catalogue (`/api/Products/{id}`) and a private record (`/api/Recycles/{id}`) both return a different object per id with no auth, and only ownership intent — invisible without credentials — separates them. So an unauthenticated swap that returns *different* data per id is at most **POSSIBLE** (a lead to verify), and an id that returns the *same* response however you change it is **SAFE** (the id is not a real object reference). Real read-IDOR comes from the authenticated cross-user pass.

## Why It Matters

IDOR is the #1 most common vulnerability in modern web APIs. It lets attackers:

- **Read other users' private data** — messages, documents, medical records, financial information
- **Modify other users' data** — change settings, delete files, alter records
- **Escalate privileges** — access admin-only resources by guessing admin user IDs
- **Mass data theft** — enumerate all records by iterating through IDs

Unlike SQL injection, IDOR doesn't require any special payload. It's just changing a number in a URL. This makes it trivial to exploit and devastating in impact.

## Real-World Breaches

**First American Financial (2019)** — 885 million mortgage documents (Social Security numbers, bank statements, tax records) were exposed because document URLs used sequential record numbers with no authorization check. Changing the ID in the URL returned any customer's documents.

**Parler (2021)** — After the platform was deplatformed, researchers scraped all posts (including deleted content and GPS metadata) because the API used sequential post IDs with no access control.

## What Vulnerable Code Looks Like

```typescript
// BAD: No ownership check — any authenticated user can access any task
export async function GET(request, { params }) {
  const task = await db.getById("tasks", params.id)
  return NextResponse.json(task)
}

// BAD: User ID comes from request body, not from auth token
export async function GET(request) {
  const { userId } = await request.json()
  const profile = await db.getById("profiles", userId)
  return NextResponse.json(profile)
}
```

## How to Fix

```typescript
// GOOD: Verify the resource belongs to the authenticated user
export async function GET(request, { params }) {
  const user = await getAuthUser(request)
  const task = await db.query("tasks", `id = '${params.id}' AND user_id = '${user.id}'`)

  if (!task.length) {
    return NextResponse.json({ error: "Not found" }, { status: 404 })
  }
  return NextResponse.json(task[0])
}

// GOOD: Use Supabase RLS instead of application-level checks
// In your migration:
// CREATE POLICY "Users can view own tasks" ON tasks
//   FOR SELECT USING (auth.uid() = user_id);
```
