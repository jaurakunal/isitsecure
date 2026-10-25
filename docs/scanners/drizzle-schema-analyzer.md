# Drizzle Schema Analyzer

**Type:** SAST | **Severity:** Low–High | **Category:** Various

## What It Does

Analyzes Drizzle ORM schema definitions (files calling `pgTable`, `mysqlTable` or `sqliteTable` with a quoted table name; the quoted column name is what is checked) for:

1. **Plaintext secrets** — columns whose name contains `secret`, `api_key`, `password`, `access_token` and similar, with no `_encrypted`/`_hash`/`_hashed` twin (High, 0.90)
2. **PII without a protected twin** — `email`, `phone`, `ssn`, `address` and similar columns with no `_encrypted`/`_hash`/`_hashed` column (Medium, 0.80)
3. **Missing tenant scope** — when a `tenants`/`organizations`/`orgs`/`workspaces`/`companies` table exists, tables such as users, orders or invoices without a `tenant_id` column (Medium, 0.75)
4. **Payment provider IDs** — `stripe_customer_id`-style columns stored as plain text (Low, 0.70)

Not covered today: `isAdmin`/`role`/`permissions` mass-assignment columns, missing `deleted_at` (soft delete) and missing `created_at`/`updated_at` audit columns.

## Why It Matters

Schema design decisions have security implications:
- An `isAdmin` boolean column is a mass assignment target — if the API accepts all fields, users can promote themselves
- PII stored in plaintext is a breach liability — if the database leaks, all personal data is immediately readable
- Hard deletes without audit trails make incident response impossible

## Real-World Context

**GitHub (2012)** — A mass assignment vulnerability in Rails allowed an attacker to add his SSH key to the Rails core repository by exploiting a `user_id` field that was directly on the model (not a separate association table). Schema design directly enabled the attack.

## How to Fix

```typescript
// GOOD: Separate role/permission tables (not columns on user table)
export const userRoles = pgTable("user_roles", {
  userId: uuid("user_id").references(() => users.id),
  role: text("role").notNull(),
  grantedBy: uuid("granted_by").references(() => users.id),
  grantedAt: timestamp("granted_at").defaultNow(),
})

// GOOD: Encrypt PII at rest
// Use pgcrypto or application-level encryption for sensitive fields
```
