# OpenAPI Scanner

**Type:** SAST | **Severity:** Medium–High | **Category:** API Exposure

## What It Does

Scans OpenAPI/Swagger specification files (`openapi.yaml`, `openapi.json`, `swagger.json`) for:

1. **Internal endpoints exposed** — admin, debug, or internal endpoints listed in the public spec
2. **Missing authentication requirements** — endpoints without `security` field defined
3. **Sensitive data in examples** — real API keys, tokens, or PII in example values
4. **Overly broad parameters** — endpoints accepting freeform objects without schema validation

## Why It Matters

OpenAPI specs are often served at `/docs`, `/swagger`, or `/api-docs` in production. They provide attackers with:

- **Complete API map** — every endpoint, parameter, and response schema
- **Auth requirements** — which endpoints need auth and which don't
- **Internal endpoints** — admin routes that shouldn't be public knowledge
- **Data structure** — exact field names and types for crafting payloads

## Real-World Context

Exposed Swagger/OpenAPI documentation is a common finding in bug bounty programs. Attackers routinely check `/api-docs`, `/swagger.json`, and `/openapi.yaml` as their first reconnaissance step, using the spec to identify the most promising attack targets.

## How to Fix

```yaml
# GOOD: Don't serve OpenAPI spec in production
# Only enable in development:
if (process.env.NODE_ENV === "development") {
  app.use("/api-docs", swaggerUi.serve)
}

# GOOD: If you must serve it, add auth
app.use("/api-docs", authMiddleware, swaggerUi.serve)

# GOOD: Remove internal endpoints from the public spec
# Keep a separate internal-api.yaml for internal documentation
```
