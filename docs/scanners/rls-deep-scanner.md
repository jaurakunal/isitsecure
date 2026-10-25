# RLS Deep Scanner

**Type:** DAST (Special) | **Severity:** High to Critical | **Category:** RLS Misconfiguration

## What It Does

Supabase-specific scanner that tests Row Level Security at runtime:

1. **Tier 1: Anon access** — queries each discovered table using the anon key via Supabase REST API. If data is returned, the table is publicly readable without authentication (Critical when a sensitive column is present, otherwise High). Tier 1 also tries an anonymous insert with a harmless body: a 200/201 is a confirmed anonymous write (Critical, 0.98), and a 400 carrying a column-constraint error rather than an RLS denial is reported as an inferred write (Critical, 0.90).

2. **Tier 3: Cross-user access** — authenticates as User B and tries to read User A's rows. If User B can see User A's data, the RLS policy is misconfigured or missing (Critical). Tier 2 (a single user) is not a separate step; it is covered implicitly by comparing the anon and authenticated results.

3. **RPC testing** — POSTs an empty body to `/rest/v1/rpc/{name}` without a user token, for each function name found in the JavaScript via `.rpc()` (these are Postgres functions, not `/functions/v1/` edge functions). A 200 is reported as an exposed function (High).

This scanner requires the Supabase URL and anon key (discovered from JS bundles by the endpoint discovery scanner).

## Why It Matters

In Supabase, the anon key is **public** — it's in your frontend JavaScript. RLS is the only barrier between the public internet and your database. If it's misconfigured:

- **Anyone can read all data** — user profiles, messages, medical records, financial data
- **Anyone can write data** — create fake accounts, modify records, delete data
- **Cross-user data access** — users can see each other's private data

## Real-World Context

**Clubhouse (2021)** — Broken access controls (functionally equivalent to missing RLS) allowed bulk scraping of 1.3 million user profiles. In Supabase apps, missing RLS is the most common path to the same outcome — the anon key is public, and without RLS policies, the entire database is exposed.

## How to Fix

See [RLS Policy Analyzer](./rls-policy-analyzer.md) for detailed fix examples with proper Supabase RLS policies.
