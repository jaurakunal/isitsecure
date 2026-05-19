# Privilege Escalation Scanner

**Type:** DAST (Special) | **Severity:** Critical | **Category:** Privilege Escalation

## What It Does

Runs 8 automated tests to check if a regular user can gain admin-level access:

1. **Admin table access** — regular user tries to read admin-only tables
2. **Role self-elevation** — PATCH own profile with `{"is_admin": true, "role": "admin"}`
3. **Admin route access** — regular user requests `/admin/*` endpoints
4. **Differential responses** — compares admin vs regular user responses for extra data
5. **Mutation replay** — replays admin-created requests with regular user token
6. **Object-level write** — regular user tries to PATCH another user's resource
7. **RPC function access** — unauthenticated calls to Supabase RPC functions
8. **Authenticated endpoint access** — access protected endpoints without intended permissions

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
