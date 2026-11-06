# Mass Assignment Scanner

**Type:** DAST | **Severity:** Low to High | **Category:** Privilege Escalation

## What It Does

Sends POST/PUT/PATCH requests to every discovered state-changing endpoint, one extra field per request, from a list of seven: `role=admin`, `is_admin=true`, `is_verified=true`, `email_verified=true`, `plan=enterprise`, `credits=99999`, `permissions=all`. It checks if the server accepts them (2xx with the field present in a JSON response). Every confirmed finding is High (confidence 0.85); the severity does not vary by field. Non-JSON responses (HTML catch-all pages) are never evidence. Before the fields are sent, a control request with a made-up field is made: if the endpoint echoes that too, it is a pure echo endpoint and reflection proves nothing about persistence, so the scanner reads the object back: each reflected field is re-sent with a unique marker field and the written object is fetched (Location header, `/<id>`, or the endpoint itself) and must carry both the marker and the privileged field. Fields that persist stay High (a schemaless endpoint that stores any field and returns it is a real mass assignment); if nothing persists, or no read-back is possible, the reflected fields collapse into a single Low "Endpoint echoes request fields (mass assignment not confirmed)" note (0.30) instead of one High per field. If the control request itself fails (transient error), the findings are not dropped: reflected fields are reported High with reduced confidence (0.55).

When the URL contains `supabase` or `rest/v1`, the list is replaced by three fields: `role`, `is_admin` and `stripe_customer_id`.

### Where it looks in the response

The injected field is searched for **anywhere in the response body**, not just at the top level. Most APIs wrap the object they just created in an envelope — `{"status": "success", "data": {...}}`, `{"result": {...}}`, JSON:API's `{"data": {"attributes": {...}}}` — and a top-level-only check reads every one of those as "not reflected". That is how a confirmed, reproducible mass assignment reports as clean.

The value still has to match: finding `role` nested somewhere proves nothing if it came back as `customer`. The search goes up to 8 levels deep, and a string `"true"` does not match a boolean `true`. The scanner does not read the record back afterwards to confirm it was stored; reflection in the reply is the only evidence.

### Strict APIs: request contracts

The probe sends the escalation field on its own, so an endpoint that validates its required fields answers 400/422 before the handler runs. The scanner reads that rejection (FastAPI/Pydantic, DRF, Rails, Laravel, Zod, Spring, ASP.NET, Joi and similar; see `engine/shared/request_contract.py`), learns which sibling fields the endpoint requires, and re-sends the probe with them filled in (at most 2 retries per probe and 6 per endpoint; once learned, later probes are repaired up front at no extra cost). A 415 switches the body to form encoding. A rejection that names no field the request failed to satisfy (for example "bad request") is treated as the application's answer and is not retried.

If a field is still rejected after repair (for example the server pins `role` to a closed set that excludes `admin`), the probe never reached the handler. The scanner then adds one Info finding, "Injection probes blocked by request validation (not tested)", naming the fields and the learned contract, instead of returning nothing. It is a coverage note, not a vulnerability, and an absent finding on such a field is not evidence of safety. Contracts that need a value the scanner cannot guess (a captcha, a signature) remain out of reach; Juice Shop's `feedbackChallenge` is one.

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
