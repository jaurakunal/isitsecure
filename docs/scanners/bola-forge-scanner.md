# BOLA Forge Scanner

**Type:** DAST (Special, authenticated, opt-in) | **Severity:** Medium to High | **Category:** IDOR

## What It Does

Detects broken object-level authorization where the **owner identity is in the request body, not the URL**. Many create endpoints take the owner/author/account id from the body (`POST /api/feedbacks {"UserId": 7, "message": "..."}`). If the server stores that field as sent instead of deriving it from the session, any logged-in user can create objects in someone else's name. The IDOR scanner swaps ids in URLs, so it can never reach this.

It runs only when **both** are true: the scan is authenticated (it replays creates captured during the authenticated crawl) **and** `--probe-writes` is on, because it writes to the target. Without `--probe-writes` it sends nothing.

For each captured, successful JSON `POST` (one per path, at most 5 endpoints):

1. **Find our identity field by value.** The key whose value equals one of our own ids (session user id, email, and every JWT claim value, excluding `exp`/`iat`/`nbf`/`auth_time`). No field-name vocabulary: `UserId`, `owner`, `zzz` are all found the same way.
2. **Control.** Replay the body unchanged, with a unique `isitsecure-probe-ctl-<hex>` marker appended to the longest free-text field. Re-read the collection and require the marker record to come back **attributed to us** in that field. If no read endpoint shows our records, the result is INCONCLUSIVE and the forged write is never sent.
3. **Treatment.** Resend with the identity field forged and an `isitsecure-probe-frg-<hex>` marker. Re-read the collection (as us and, with two accounts, as the victim) and require the marked record to carry the **forged owner**.

The write response is never used as proof. A response that echoes the forged owner while the stored record keeps the real one (reflection) is not reported, and a pre-existing victim record cannot match because it has no marker.

Read endpoints tried (at most 3): captured `GET`s on the same path, the write URL itself, the `Location` header, and `/<id>` from the create response. A scan sends at most 8 requests per endpoint, with no loops or retries.

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

This scanner mutates data. Each tested endpoint gets two new records (control and forged), both containing `isitsecure-probe` in a text field so they can be found and deleted. Nothing is updated or deleted, and with two accounts a forged record appears under the second test account, never a third party. Use it only on an app you own or are authorized to test.

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
