# Privilege Escalation Scanner

**Type:** DAST (Special) | **Severity:** Medium to Critical | **Category:** Privilege Escalation

## What It Does

Runs 8 automated tests, in this order, to check if a regular user can gain admin-level access. Admin-route and authenticated-endpoint probes reject HTML responses unless an anonymous request to the same URL is refused, so a single-page app that answers 200 with its shell for every path is not reported. Differential requests clear the shared cookie jar between identities so one identity's `Set-Cookie` never reaches the other:

1. **Admin table access** — regular user reads tables whose name looks administrative (High)
2. **Role self-elevation** — only on tables whose name contains `role` or `permission`: five PATCH bodies against the user's own row, one field each (`role=admin`, `is_admin`, `is_verified`, `plan=enterprise`, `permissions=all`); Critical only when the PATCH (sent with `Prefer: return=representation`) returns the updated row; PostgREST answers 204 when RLS filtered the row out, so a bare 200/204 or an empty `[]` is not reported
3. **Admin route access** — regular user requests `/admin/*` and similar admin-looking endpoints (High)
4. **Authenticated endpoint access** — other login-protected endpoints requested with the regular user's token (Medium, a hint only)
5. **Differential responses** — fetches the same URL as an admin and as a regular user; reported only when the admin body is more than 1.5x larger and holds more records (High). The session passed as admin is assumed to be one; it is not verified
6. **Mutation replay** — replays up to 20 POST/PUT/PATCH writes captured during the crawl with the regular user token. Runs only when a distinct admin identity exists (with one credential set the replay would just re-run the crawl user's own writes); DELETE is never replayed. High on admin-looking paths, Medium elsewhere ("any user may write here")
7. **Object-level write** — regular user sends an empty PATCH (`Prefer: return=representation`) to another user's rows, up to 15; Critical only when rows are returned
8. **RPC function access** — POSTs `{}` to `/rest/v1/rpc/{name}` for functions found in the JavaScript, using the regular user's token plus the anon key (High)

Tests 1, 2, 7 and 8 need the Supabase URL and anon key. Nothing reads the data back to confirm a change.

## Why It Matters

Privilege escalation turns a $0 account into full admin access. Attackers can:

- **Access all user data** — admin endpoints typically return all records
- **Modify system configuration** — change app settings, disable security features
- **Delete anything** — admin-level delete permissions on all resources
- **Create backdoors** — create new admin accounts for persistent access

## Real-World Breaches

**Microsoft Exchange / ProxyLogon (2021)** — CVE-2021-26855 allowed attackers to authenticate as the Exchange server, escalate to admin, and install web shells. Impacted tens of thousands of organizations worldwide.

## How to Fix

```typescript
// GOOD: Check role on every admin endpoint
export async function GET(request: Request) {
  const user = await getAuthUser(request)
  if (!user || user.role !== "admin") {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 })
  }
  // ... admin logic
}

// GOOD: Use Supabase RLS for role-based access
CREATE POLICY "Admins only" ON admin_settings
  FOR ALL USING (
    auth.uid() IN (SELECT id FROM profiles WHERE role = 'admin')
  );
```
