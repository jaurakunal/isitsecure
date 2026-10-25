# Firebase Rules Analyzer

**Type:** SAST | **Severity:** Critical–Medium | **Category:** Auth Weakness

## What It Does

Analyzes Firebase security rules files (`firestore.rules`, `storage.rules`, `database.rules.json`, also under `firebase/`) as text for:

1. **Wide-open rules** — `allow read, write: if true` grants all access to anyone without authentication (Critical); `allow read: if true` or `allow write: if true` alone is High
2. **Allow rules with no auth test** — an `allow read|write|create|update|delete:` line with no `request.auth != null` or `request.auth.uid` on that line or the two after it (High)
3. **Broad wildcards** — `match /{document=**}` style catch-all matches (Medium)
4. **Realtime Database open rules** — `".read": true` and `".write": true` in `database.rules.json` (Critical each)

Only the literal `if true` form is treated as open, and multi-operation lines such as `allow read, write: if <expr>` are caught only when the expression is exactly `true`. Any mention of `request.auth != null` counts as auth: ownership is not checked.

Not covered today: collections with no rule, `request.auth != null` with no ownership check, and missing data-validation rules.

This scanner activates when Firebase is detected as the backend.

## Why It Matters

Firebase security rules are the **only** access control for Firestore, Realtime Database, and Storage. Unlike server-side APIs, Firebase clients talk directly to the database. If rules are permissive:

- **Anyone can read all data** — user profiles, messages, private documents
- **Anyone can write data** — create fake accounts, modify other users' data, delete records
- **No server-side protection** — there is no backend API to add auth checks to; rules ARE the auth

## Real-World Context

Multiple security researchers have published scans finding thousands of Firebase databases with open rules. In 2020, a study by Comparitech found 24,000 Android apps with misconfigured Firebase databases leaking user data including emails, passwords, and health data.

## How to Fix

```
// BAD: Wide open
match /users/{userId} {
  allow read, write: if true;
}

// GOOD: Owner-only access
match /users/{userId} {
  allow read: if request.auth != null && request.auth.uid == userId;
  allow write: if request.auth != null && request.auth.uid == userId;
}

// GOOD: Validate data on write
match /posts/{postId} {
  allow create: if request.auth != null
    && request.resource.data.authorId == request.auth.uid
    && request.resource.data.title is string
    && request.resource.data.title.size() <= 200;
}
```
