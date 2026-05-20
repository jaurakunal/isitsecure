# LLM Code Reviewer

**Type:** LLM-Powered | **Severity:** Varies | **Category:** Business Logic

## What It Does

Uses Claude or Gemini to analyze code for **business logic vulnerabilities** that pattern matchers cannot detect. The LLM reads route source code and identifies:

- **Missing ownership checks** — authentication is present but authorization is not (the user is logged in, but the code doesn't check if they *own* the resource)
- **Race conditions in payment flows** — check-then-act patterns without locking or atomic operations
- **Price manipulation** — accepting price/amount from client request body instead of looking it up server-side
- **Incorrect RLS policy logic** — policy checks `auth.uid() = id` instead of `auth.uid() = user_id` (wrong column)
- **Auth bypass through alternative code paths** — the happy path is protected but error/edge paths skip auth
- **Business rule violations** — coupons applied after payment, negative quantities, self-referrals

**Not every route gets reviewed.** Five review triggers select high-priority routes to stay within token budget:

| Trigger | Priority | What It Selects |
|---|---|---|
| Financial Operation | 0 (always) | Payment, checkout, billing, subscription routes |
| Cross-Scanner Flagged | 1 | Routes flagged by 2+ SAST scanners |
| State Mutation | 2 | POST/PUT/PATCH/DELETE routes |
| Risk Indicator | 3 | Routes with eval, exec, raw SQL patterns |
| Import Graph Centrality | 4 | Shared helpers imported by many risky routes |

Each trigger type gets a **specialized system prompt** tuned for that vulnerability class.

## Why It Matters

Business logic bugs are the most impactful and hardest to detect:

- **Pattern matchers can't find them** — there's no regex for "this payment flow doesn't have idempotency"
- **They're specific to your app** — unlike SQL injection which is universal, business logic bugs depend on what your app does
- **They often involve multiple steps** — the vulnerability only appears when you understand the sequence of operations

## Example

The LLM reviewer reads this route:

```typescript
export async function POST(request: Request) {
  const user = getAuthUser(request)
  const { plan, price } = await request.json()

  const order = await db.insert("orders", {
    user_id: user.id,
    plan: plan,
    amount: price,    // ← LLM catches this: client-controlled price
    status: "paid"
  })

  return NextResponse.json({ order })
}
```

And produces:

> **CRITICAL: Price manipulation vulnerability.** The `price` field is accepted from the client request body and directly used as the order amount. An attacker can submit `{"plan": "enterprise", "price": 0.01}` to purchase the enterprise plan for $0.01. The price should be looked up server-side based on the selected plan, not accepted from the client.

No pattern matcher would flag `amount: price` as a vulnerability. The LLM understands that in a checkout flow, prices should be server-authoritative.

## Real-World Context

**Starbucks (2015)** — A race condition in the gift card balance transfer flow allowed double-spending. This is exactly the type of business logic flaw that only reasoning about the code can detect — there's no regex for "this balance check isn't atomic."

**Multiple e-commerce platforms** — Price manipulation via client-controlled price fields is a common finding in bug bounty programs. The pattern is always the same: the API accepts `price` from the request body instead of looking it up server-side.

## How to Fix

Business logic fixes are app-specific, but common patterns:

```typescript
// FIX: Price manipulation — look up price server-side
const PLAN_PRICES = { starter: 9, pro: 29, enterprise: 99 }
const amount = PLAN_PRICES[plan]
if (!amount) return error("Invalid plan")

// FIX: Race condition — use atomic database operations
await db.query(
  `UPDATE credits SET balance = balance - $1
   WHERE user_id = $2 AND balance >= $1 RETURNING balance`,
  [amount, userId]
)

// FIX: Missing ownership — always filter by authenticated user
const task = await db.query(
  `SELECT * FROM tasks WHERE id = $1 AND user_id = $2`, [taskId, userId]
)
```

## Configuration

Requires an LLM API key:

```bash
# Set via environment
export ANTHROPIC_API_KEY=sk-ant-...

# Or use Google
export GOOGLE_API_KEY=...
isitsecure scan --llm google ...

# Disable LLM review (free, but reduced accuracy)
isitsecure scan --llm none ...
```

Estimated cost: $5–8 per code-only scan, depending on number of routes and file sizes.
