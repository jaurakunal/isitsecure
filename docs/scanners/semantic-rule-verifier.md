# Semantic Rule Verifier

**Type:** LLM-Powered | **Severity:** Critical–High | **Category:** RLS Misconfiguration

## What It Does

Uses AI to analyze Supabase RLS policies and Firebase security rules for **logical errors** that structural analyzers cannot detect:

- **Wrong column reference** — policy checks `auth.uid() = id` instead of `auth.uid() = user_id` (the `id` column is the row's primary key, not the owner's user ID)
- **Privilege escalation paths** — a combination of policies that allows escalation (e.g., users can update their own role)
- **Inconsistent operation coverage** — SELECT policy exists but UPDATE/DELETE policies are missing
- **Tenant isolation errors** — multi-tenant policies that don't properly scope queries to the tenant

The structural RLS Policy Analyzer checks *if* policies exist. This scanner checks *if the logic is correct*.

## Why It Matters

An RLS policy that looks correct but references the wrong column is worse than no policy — it gives false confidence while being completely bypassable. For example:

```sql
-- LOOKS correct but IS wrong:
CREATE POLICY "Users view own tasks" ON tasks
  FOR SELECT USING (auth.uid() = id);
--                                ^^
-- This compares the user's UUID to the TASK's UUID (primary key)
-- It should be: auth.uid() = user_id (the foreign key to profiles)
-- Result: nobody can see any tasks (UUIDs never match)
-- OR: policy is bypassed entirely depending on Postgres behavior
```

A regex-based scanner would see "RLS policy exists" and report no issues. The LLM reads the SQL, understands the schema, and catches the column mismatch.

## Configuration

Requires an LLM API key. Runs automatically as part of the SAST phase when RLS policies or Firebase rules files are detected.
