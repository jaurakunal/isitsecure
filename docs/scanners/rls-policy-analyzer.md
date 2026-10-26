# RLS Policy Analyzer

**Type:** SAST | **Severity:** Critical–Medium | **Category:** RLS Misconfiguration

## What It Does

Scans Supabase migration SQL files for Row Level Security gaps:

1. **Missing RLS** (Critical) — Tables with `CREATE TABLE` but no `ALTER TABLE ... ENABLE ROW LEVEL SECURITY` are flagged. Without RLS, the Supabase anon key grants read/write access to every row.

2. **RLS Enabled but No Policies** (High) — Tables where RLS is enabled but no `CREATE POLICY` statements exist. RLS without policies blocks all access (or allows all, depending on Supabase config).

3. **Overly Permissive Policies** (High) — Policies using `USING (true)` (or `1 = 1`) that effectively disable RLS for that operation. Policies that only target server-side roles (`TO service_role`, `postgres`, `supabase_admin`...) are not reported: those roles bypass RLS anyway and the policy is not reachable with the anon key.

4. **Policy never references `auth.uid()`** (Medium) — A policy whose `USING` / `WITH CHECK` expressions never call `auth.uid()` may allow cross-user access. Policies already flagged as permissive are not reported twice.

`ALTER TABLE ONLY public.t ENABLE ROW LEVEL SECURITY` (and `IF EXISTS`) counts as enabling RLS. An unterminated `/*` comments out the rest of the file: statements before it are still analysed, nothing after it is.

The scanner parses `.sql` files whose path contains "migration" (typically `supabase/migrations/`) **and that are Supabase SQL**: the repo's backend is Supabase, the path contains `supabase`, or the SQL uses Supabase constructs (`auth.uid()`, `auth.users`, `TO anon/authenticated/service_role`, `service_role`). Prisma, Rails or Flyway `migrations/` folders are skipped, so their tables are not reported as missing RLS. It replays the statements in file order (files sorted by path): `CREATE TABLE`, `ENABLE`/`DISABLE ROW LEVEL SECURITY`, `CREATE POLICY` and `DROP POLICY` / `DROP TABLE`, so a later `DISABLE` makes the table unprotected again and a dropped policy is no longer reported. Quoted policy names may contain spaces (`"Enable read access for all users"`). It stops at the first problem per table: a table with no RLS gets only the missing-RLS finding, and a table with RLS but no policies gets only the no-policies finding.

## Why It Matters

In Supabase, the **anon key is public** — it's embedded in your frontend JavaScript. If a table doesn't have RLS:

- **Anyone can read all data** — `SELECT * FROM users` via the anon key returns everything
- **Anyone can write data** — `INSERT`, `UPDATE`, `DELETE` all work without authentication
- **Service role key bypass** — even if you use the service role key server-side, forgetting RLS means the client-side anon key is a backdoor

RLS is the **only** access control between the public internet and your Supabase database. Without it, your database is effectively public.

## Real-World Context

**Supabase's own documentation** warns: "If you have RLS disabled on any table, the anon key gives full read/write access to that table." This is the most common security issue in Supabase apps — developers create tables and forget to enable RLS.

**Facebook (2013)** — While not Supabase, a similar broken access control bug allowed any user to delete any photo by manipulating the photo ID in the Graph API. The server did not verify ownership — the same pattern that missing RLS creates.

## What Vulnerable Code Looks Like

```sql
-- BAD: No RLS on a table with sensitive data
CREATE TABLE profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL,
  role TEXT DEFAULT 'user'
);
-- Missing: ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
-- Missing: CREATE POLICY ...

-- BAD: RLS enabled but policy is too permissive
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Anyone can read" ON tasks FOR SELECT USING (true);
```

## How to Fix

```sql
-- GOOD: Enable RLS and create proper policies
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

-- Users can only read their own profile
CREATE POLICY "Users view own profile" ON profiles
  FOR SELECT USING (auth.uid() = id);

-- Users can only update their own profile
CREATE POLICY "Users update own profile" ON profiles
  FOR UPDATE USING (auth.uid() = id);

-- GOOD: Deny all by default, allow specific operations
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users view own tasks" ON tasks
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users create own tasks" ON tasks
  FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users update own tasks" ON tasks
  FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users delete own tasks" ON tasks
  FOR DELETE USING (auth.uid() = user_id);
```
