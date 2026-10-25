# Prisma Schema Analyzer

**Type:** SAST | **Severity:** Low–High | **Category:** Various

## What It Does

Analyzes Prisma `model` blocks (any indexed file containing `model Name {`, scalar-typed fields only) with the same four checks as the Drizzle Schema Analyzer:

1. **Plaintext secrets** — fields whose name contains `secret`, `api_key`, `password`, `access_token` and similar, with no `_encrypted`/`_hash`/`_hashed` twin (High, 0.90)
2. **PII without a protected twin** — `email`, `phone`, `ssn`, `address` and similar with no `_encrypted`/`_hash`/`_hashed` field (Medium, 0.80)
3. **Missing tenant scope** — in a schema that has a `Tenant`/`Organization`/`Org`/`Workspace`/`Company` model, models such as users, orders or invoices without a `tenant_id` field (Medium, 0.75)
4. **Payment provider IDs** — `stripe_customer_id`-style fields stored as plain strings (Low, 0.70)

Not covered today: `isAdmin`/`role` mass-assignment targets, missing `createdAt`/`updatedAt`, and missing `deletedAt`.

This scanner activates when Prisma is detected as the ORM.

## Why It Matters

Same as the Drizzle Schema Analyzer — schema design directly impacts security:
- `isAdmin Boolean @default(false)` on the User model is a mass assignment target
- PII stored in plaintext becomes a liability when (not if) the database leaks

## Real-World Context

**GitHub (2012)** — Mass assignment exploited through a model field that shouldn't have been writable. Schema-level protections would have prevented it.

## How to Fix

```prisma
// BAD: isAdmin on User model
model User {
  id      String  @id @default(uuid())
  email   String  @unique
  isAdmin Boolean @default(false)  // Mass assignment target!
}

// GOOD: Separate Role model
model User {
  id    String @id @default(uuid())
  email String @unique
  roles Role[]
}

model Role {
  id     String @id @default(uuid())
  name   String // "admin", "user", "moderator"
  userId String
  user   User   @relation(fields: [userId], references: [id])
}
```
