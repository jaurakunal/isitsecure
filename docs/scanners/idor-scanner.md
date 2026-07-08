# IDOR Scanner

**Type:** DAST (Special) | **Severity:** High–Critical | **Category:** IDOR

## What It Does

Tests for Insecure Direct Object References by swapping resource identifiers in API requests and checking if the server returns another user's data.

Four test types:

1. **Unauthenticated Access** — Sends requests without any auth headers. If the endpoint returns data, it's publicly accessible when it shouldn't be.

2. **Path Parameter Swapping** — Changes `/api/tasks/USER-A-TASK-ID` to `/api/tasks/USER-B-TASK-ID`. If data is returned, there's no ownership check.

3. **Query Parameter Swapping** — Changes `?user_id=USER-A` to `?user_id=USER-B`. Targets ID-bearing query parameters.

4. **Sequential ID Enumeration** — For numeric IDs, tries `id+1`, `id-1`, `id+100` to check if sequential enumeration works.

In **authenticated mode** with two sets of credentials, the scanner performs **cross-user IDOR testing** (broken object-level authorization, BOLA):
- Log in as User A and User B — via the browser login helper, or via a generic REST login (`RestLoginAuthProvider`) for frontend-less APIs
- **Harvest User A's real object IDs** from parent collections (e.g. `GET /api/tasks` yields task IDs), instead of guessing. Both **numeric** and **UUID** id shapes are handled; when harvested IDs are all numeric the candidate set is filtered to numeric IDs so UUIDs aren't wasted
- Try to access User A's harvested resources as User B (read, write, delete)
- **Anonymous-access guard**: each resource is first probed with no auth at all — if it's simply public, the cross-user finding is suppressed as a false positive
- **Content-match guard**: a hit is only reported when User B's response actually contains User A's data, not an empty or generic body
- Test if User B can do a full-table `SELECT *` via Supabase REST API

Risk levels: **CONFIRMED** (data returned), **LIKELY** (200 status but different response), **POSSIBLE** (suspicious behavior), **SAFE**.

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
