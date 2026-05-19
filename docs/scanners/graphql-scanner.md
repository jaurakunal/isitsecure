# GraphQL Scanner

**Type:** DAST | **Severity:** Medium–High | **Category:** Info Disclosure / API Exposure

## What It Does

Tests GraphQL endpoints for three issues:

1. **Introspection enabled** — sends `__schema` query. If the full schema is returned, attackers can see every type, field, query, and mutation — a complete map of your API.

2. **No depth limit** — sends deeply nested queries (100+ levels). Without limits, attackers can craft queries that consume exponential server resources (DoS).

3. **Batch query support** — sends arrays of queries in a single POST. Batch queries can bypass rate limiting (1 HTTP request = 1000 queries).

## Real-World Breaches

**GitLab (2019)** — GraphQL introspection was enabled by default, allowing researchers to enumerate private project information and user data. GitLab subsequently restricted introspection in production.

## How to Fix

```typescript
// GOOD: Disable introspection in production
const yoga = createYoga({
  schema,
  graphiql: false,  // Disable playground
  maskedErrors: true,
  plugins: [
    useDisableIntrospection(),  // Block __schema queries
    useDepthLimit({ maxDepth: 10 }),
    useRateLimiter({ max: 100, window: "1m" })
  ]
})
```
