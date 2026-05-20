# Firebase Rules Analyzer

**Type:** SAST | **Severity:** Critical–High | **Category:** Auth Weakness

## What It Does

Analyzes Firebase security rules files (`firestore.rules`, `database.rules.json`, `storage.rules`) for:

1. **Wide-open rules** — `allow read, write: if true` grants all access to anyone without authentication
2. **Missing rules for collections** — Firestore collections without explicit rules default to denied, but developers often add `if true` to "fix" access errors
3. **Overly permissive conditions** — `if request.auth != null` allows ANY authenticated user to read/write ANY document (no ownership check)
4. **Missing validation rules** — write rules that don't validate data structure or field types

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
