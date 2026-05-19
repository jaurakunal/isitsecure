# Race Condition Scanner

**Type:** DAST (Special) | **Severity:** High–Critical | **Category:** Business Logic

## What It Does

Tests for Time-of-Check-to-Time-of-Use (TOCTOU) vulnerabilities by sending multiple identical mutation requests concurrently and checking if more than one succeeds.

Technique:
1. Identifies state-changing endpoints (POST, PUT, PATCH, DELETE)
2. Fires N concurrent copies of the same request using a shared HTTP connection (maximizing timing overlap)
3. If 2+ requests return success (200/201/204), the endpoint likely has a race condition

The scanner targets endpoints that involve:
- Balance deductions (credits, wallet, gift cards)
- Coupon/code redemption (one-time use)
- Voting / rating (one vote per user)
- Account creation (unique constraints)

## Why It Matters

Race conditions let attackers exploit the gap between "check" and "update":

```
Request A: Read balance (100) → Check: 100 >= 50 ✓ → Deduct: 100 - 50 = 50
Request B: Read balance (100) → Check: 100 >= 50 ✓ → Deduct: 100 - 50 = 50
                                                                    ↑
                                          Both read 100 before either writes
                                          Result: spent 100, got 2x the value
```

This enables:
- **Double-spend** — redeem credits/gift cards twice
- **Free purchases** — exploit payment flows to get products without paying
- **Bypass limits** — vote multiple times, create duplicate accounts
- **Data corruption** — concurrent writes leave the database in an inconsistent state

## Real-World Breaches

**Starbucks (2015)** — Researchers demonstrated a race condition in Starbucks' gift card system that allowed duplicating gift card balances by simultaneously transferring the same balance to multiple cards.

**Docker runc CVE-2019-5736 (2019)** — A TOCTOU race condition in runc allowed a malicious container to overwrite the host runc binary, gaining root-level access on the host system.

## What Vulnerable Code Looks Like

```typescript
// BAD: Check-then-act without locking
export async function POST(request: Request) {
  const { amount } = await request.json()

  // Read current balance
  const credits = await db.query("credits", `user_id = '${userId}'`)
  const balance = credits[0].balance

  // Check
  if (balance < amount) return error("Insufficient")

  // GAP: Another request can read the same balance here

  // Act
  await db.update("credits", { balance: balance - amount })
  return success({ redeemed: amount })
}
```

## How to Fix

```typescript
// GOOD: Use a database transaction with row-level locking
export async function POST(request: Request) {
  const { amount } = await request.json()

  const result = await db.transaction(async (tx) => {
    // SELECT ... FOR UPDATE locks the row
    const credits = await tx.query(
      `SELECT * FROM credits WHERE user_id = $1 FOR UPDATE`, [userId]
    )

    if (credits[0].balance < amount) {
      throw new Error("Insufficient")
    }

    await tx.query(
      `UPDATE credits SET balance = balance - $1 WHERE user_id = $2`,
      [amount, userId]
    )

    return { redeemed: amount }
  })

  return NextResponse.json(result)
}

// GOOD: Use atomic operations
await db.query(
  `UPDATE credits SET balance = balance - $1
   WHERE user_id = $2 AND balance >= $1
   RETURNING balance`,
  [amount, userId]
)
// If balance < amount, zero rows updated — no race possible
```
