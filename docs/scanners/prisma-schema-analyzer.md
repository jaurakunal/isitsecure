# Prisma Schema Analyzer

**Type:** SAST | **Severity:** Medium | **Category:** Various

## What It Does

Analyzes Prisma schema definitions (`schema.prisma`) for the same issues as the Drizzle Schema Analyzer:

1. **Sensitive fields exposed** — `isAdmin`, `role`, `permissions` fields that are mass assignment targets
2. **PII without encryption markers** — `email`, `phone`, `ssn` stored as plain `String` type
3. **Missing audit fields** — models without `createdAt` / `updatedAt` timestamps
4. **No soft delete pattern** — models without a `deletedAt` field

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
