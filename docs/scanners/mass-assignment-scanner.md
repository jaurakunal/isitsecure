# Mass Assignment Scanner

**Type:** DAST | **Severity:** High–Critical | **Category:** Privilege Escalation

## What It Does

Sends POST/PATCH requests with extra fields that shouldn't be accepted — `is_admin`, `role`, `price`, `balance`, `permissions` — and checks if the server accepts them (returns 2xx with the field present in the response).

Also tests Supabase-specific escalation fields via the REST API.

### Where it looks in the response

The injected field is searched for **anywhere in the response body**, not just at the top level. Most APIs wrap the object they just created in an envelope — `{"status": "success", "data": {...}}`, `{"result": {...}}`, JSON:API's `{"data": {"attributes": {...}}}` — and a top-level-only check reads every one of those as "not reflected". That is how a confirmed, reproducible mass assignment reports as clean.

The value still has to match: finding `role` nested somewhere proves nothing if it came back as `customer`.

### What it does not do yet

The probe sends the escalation field **on its own**, with no valid base payload. An endpoint that validates its required fields rejects that request outright, so the escalation never gets evaluated. This is the reason Juice Shop's `feedbackChallenge` (a `POST /api/Feedbacks` that also demands a captcha) is out of reach while `registerAdminChallenge` (a `POST /api/Users` that accepts a bare body) is not.

## Why It Matters

If your API blindly accepts all fields from the request body, attackers can:

- **Promote themselves to admin** — send `{"role": "admin"}` or `{"is_admin": true}`
- **Manipulate prices** — send `{"price": 0.01}` on an order update
- **Modify other users' data** — send `{"user_id": "other-user"}` to change ownership
- **Bypass payment** — set `{"status": "paid"}` without actually paying

## Real-World Breaches

**GitHub (2012)** — Egor Homakov exploited a Rails mass assignment vulnerability to add his SSH key to the Rails core repository by manipulating the `user_id` attribute, gaining commit access to one of the most important open source projects.

**HackerOne (2015)** — A mass assignment flaw allowed adding yourself as a member of any bug bounty program by manipulating group membership parameters.

## How to Fix

```typescript
// BAD: Accept all fields from request body
const body = await request.json()
await db.update("profiles", userId, body)  // Whatever the client sends gets written

// GOOD: Explicitly pick allowed fields
const body = await request.json()
const allowedUpdate = {
  display_name: body.display_name,
  avatar_url: body.avatar_url,
  // role and is_admin are NOT included
}
await db.update("profiles", userId, allowedUpdate)
```
