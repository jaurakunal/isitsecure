# BOLA Forge Scanner

**Type:** DAST (Special, authenticated, opt-in) | **Severity:** Medium to High | **Category:** IDOR

## What It Does

Detects broken object-level authorization where the **owner identity is in the request body, not the URL**. Many create endpoints take the owner/author/account id from the body (`POST /api/feedbacks {"UserId": 7, "message": "..."}`). If the server stores that field as sent instead of deriving it from the session, any logged-in user can create objects in someone else's name. The IDOR scanner swaps ids in URLs, so it can never reach this.

It runs only when **both** are true: the scan is authenticated (it replays creates captured during the authenticated crawl) **and** `--probe-writes` is on, because it writes to the target. Without `--probe-writes` it sends nothing.

For each captured, successful JSON `POST` (one per path, at most 5 endpoints):

0. **Scope and safety filters (no request is sent for a skipped endpoint).**
   - *Origin:* only the scan target's origin (scheme, host, port) is ever contacted. Captured requests to other hosts (analytics, payment SDKs) are ignored, and our credentials are never attached to any other origin. If the target is unknown the scanner does nothing.
   - *Dangerous paths:* a path with any of these tokens (whole segment or a token inside a hyphen/underscore/camelCase segment) is never replayed: checkout, pay, payment(s), charge, purchase, refund, send, email, mail, sms, notify, notification(s), invite, subscribe, webhook(s), transfer, withdraw, delete, remove, reset, password, login, logout, signin, signup, register, token, otp, verify, auth, oauth, session, 2fa, mfa, **order, orders**. `order(s)` is skipped on purpose: it is a plain resource in some apps and a purchase in others, and a wrong guess spends money. The cost is that a genuine forged-owner bug on an orders endpoint is not tested by this scanner.
   - *Payment-looking bodies:* a body with a key such as card, cvv, cvc, iban, expiry, routing, swift, or both amount and currency is never replayed.
1. **Find our identity field by value.** The key whose value equals one of our own ids. Matching the session user id or email is "strong" and may be a short number (`UserId: 7`). Any other JWT claim value only counts if it is distinctive (an opaque id of 8+ chars, a 9+ digit number, or an email). Claims such as `sub`, `iss`, `aud`, `role`, `scope`, `exp`, `iat`, `nbf`, `jti`, `typ`, `alg` are never used (so `{"role": "user"}` or `{"iss": ...}` coincidences are ignored). If several body keys share one short id (`{"rating": 1, "UserId": 1}`) the owner field is unclear and the endpoint is skipped. No field-name vocabulary otherwise: `UserId`, `owner`, `zzz` are all found the same way.
2. **Verified read endpoint, before any write.** A GET of the same collection (captured GETs on the same path, then the path itself) must already return 200 JSON containing a record of ours with the identity field set to our id. If none does, the result is INCONCLUSIVE and **nothing is written**.
3. **Control.** Replay the body unchanged, with a unique `isitsecure-probe-ctl-<hex>` marker appended to a safe free-text field (never a password, token, key, URL or email-like value; a field that already holds prose with a space is preferred; no safe field means INCONCLUSIVE and zero writes). Re-read and require the marker record to come back **attributed to us** in the identity field.
4. **Treatment.** Resend with the identity field forged and an `isitsecure-probe-frg-<hex>` marker. Re-read the collection (as us and, with two accounts, as the victim) and require the marked record to carry the **forged owner**.

The write response is never used as proof. A response that echoes the forged owner while the stored record keeps the real one (reflection) is not reported, and a pre-existing victim record cannot match because it has no marker.

Read endpoints tried (at most 3): captured `GET`s on the same path and the path itself, all on the target origin. A scan sends at most 9 requests per endpoint (3 verification reads, 2 writes, 4 re-reads), with no loops or retries. Because a record of ours must already be visible, an app whose crawl never showed a listing of our own records is reported as not tested rather than guessed at.

## Modes: what each can and cannot prove

| Mode | Needs | Forged value | Reported when | Severity / confidence |
|---|---|---|---|---|
| **Two identities, owner-scoped read** | `--auth-email-b` | user B's matching claim | the marked record shows up in **B's** listing, which did **not** show our control record, with the field set to B | High / 0.92 |
| **Two identities, shared listing** | `--auth-email-b` | user B's matching claim | the listing shows everyone's records (the control record was visible to B) and the forged value is distinctive: opaque id of 8+ chars or numeric id of 9+ digits | High / 0.80 |
| **One identity** | login only | a random, same-shaped id that belongs to nobody (UUID, email, opaque string) | a fresh read returns the marked record with that synthetic owner | Medium / 0.60 |

What the modes **cannot** prove:

- *Shared listing with short numeric ids* (`UserId: 2`): the scanner cannot tell an owner field from an unrelated numeric field that happens to equal the id, so the result is INCONCLUSIVE and nothing is reported.
- *One identity* proves only that the server trusts a client-chosen owner value. It does not prove that another real user can be impersonated (the server may check that the owner exists), and an owner-scoped listing hides the forged record from us, so a vulnerable app can be missed. Numeric or very short ids are never forged (any number could be a real user), so those scans stay INCONCLUSIVE.
- Updates are out of scope: only `POST` creates are replayed, never `PUT`/`PATCH`/`DELETE`. The scanner has no knowledge of business rules beyond what the re-read shows.

Anything unclear (no identity field, no free-text field for the marker, no usable read endpoint, rejected control write) is INCONCLUSIVE and produces no finding. A forged write the server rejects (for example 403) is a clean result.

## Side Effects

This scanner mutates data. Each tested endpoint (up to 5) gets **two new records** (control and forged), both containing `isitsecure-probe` in a text field. **They are not cleaned up: delete them manually** after the scan. Nothing is updated or deleted by the scanner.

In two-identity mode the forged record is created **under the second configured test account** (`--auth-email-b`), which is an operator-provided account by design; it never targets a third party. In one-identity mode the owner is a synthetic id that belongs to nobody. Use it only on an app you own or are authorized to test.

## What Vulnerable Code Looks Like

```typescript
// BAD: the owner comes from the body
app.post("/api/feedbacks", auth, (req, res) =>
  res.json(db.feedbacks.create({ ...req.body })))   // UserId is client-controlled

// GOOD: the owner comes from the session
app.post("/api/feedbacks", auth, (req, res) =>
  res.json(db.feedbacks.create({ ...req.body, UserId: req.user.id })))
```

Fix by deriving the owner from the authenticated session and ignoring (or rejecting) a body-supplied owner.
