# RLS Deep Scanner

**Type:** DAST (Special) | **Severity:** Critical | **Category:** RLS Misconfiguration

## What It Does

Supabase-specific scanner that tests Row Level Security at runtime:

1. **Tier 1: Anon access** — queries each discovered table using the anon key via Supabase REST API. If data is returned, the table is publicly readable without authentication.

2. **Tier 3: Cross-user access** — authenticates as User B and tries to read User A's rows. If User B can see User A's data, the RLS policy is misconfigured or missing.

3. **RPC testing** — calls Supabase edge functions without authentication to check if they're exposed.

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
