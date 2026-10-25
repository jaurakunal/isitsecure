# Mass Assignment Scanner

**Type:** DAST | **Severity:** High | **Category:** Privilege Escalation

## What It Does

Sends POST/PUT/PATCH requests to every discovered state-changing endpoint, one extra field per request, from a list of seven: `role=admin`, `is_admin=true`, `is_verified=true`, `email_verified=true`, `plan=enterprise`, `credits=99999`, `permissions=all`. It checks if the server accepts them (2xx with the field present in the response). Every finding is High (confidence 0.85); the severity does not vary by field.

When the URL contains `supabase` or `rest/v1`, the list is replaced by three fields: `role`, `is_admin` and `stripe_customer_id`.

### Where it looks in the response

The injected field is searched for **anywhere in the response body**, not just at the top level. Most APIs wrap the object they just created in an envelope — `{"status": "success", "data": {...}}`, `{"result": {...}}`, JSON:API's `{"data": {"attributes": {...}}}` — and a top-level-only check reads every one of those as "not reflected". That is how a confirmed, reproducible mass assignment reports as clean.

The value still has to match: finding `role` nested somewhere proves nothing if it came back as `customer`. The search goes up to 8 levels deep, and a string `"true"` does not match a boolean `true`. The scanner does not read the record back afterwards to confirm it was stored; reflection in the reply is the only evidence.

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
