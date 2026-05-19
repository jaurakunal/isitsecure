# Drizzle Schema Analyzer

**Type:** SAST | **Severity:** Medium | **Category:** Various

## What It Does

Analyzes Drizzle ORM schema definitions for:

1. **Sensitive fields exposed** — `isAdmin`, `role`, `permissions` columns that could be targets for mass assignment
2. **PII without encryption** — `email`, `phone`, `ssn` columns stored as plain text without encryption markers
3. **No soft delete** — tables without `deleted_at` column (hard deletes are irreversible)
4. **Missing audit fields** — tables without `created_at`, `updated_at` timestamps

## Why It Matters

Schema design decisions have security implications:
- An `isAdmin` boolean column is a mass assignment target — if the API accepts all fields, users can promote themselves
- PII stored in plaintext is a breach liability — if the database leaks, all personal data is immediately readable
- Hard deletes without audit trails make incident response impossible

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
