# OpenAPI Scanner

**Type:** SAST | **Severity:** Medium–High | **Category:** API Exposure

## What It Does

Scans OpenAPI/Swagger specification files for six regex-based checks. Any `.yaml`, `.yml` or `.json` file in the repo whose text contains an `openapi:` or `swagger:` marker is treated as a spec, whatever its file name:

1. **No global security** — no `securitySchemes`/`securityDefinitions`, or no top-level `security:` line (High)
2. **Sensitive paths without auth** — `/admin`, `/users`, `/payment(s)`, `/billing`, `/token(s)`, `/auth` or `/secret(s)` paths in a spec with no top-level `security:` (High)
3. **Endpoints that disable security** — an operation with `security: []` (Medium)
4. **HTTP server URLs** — `url: http://...` outside localhost/127.0.0.1/0.0.0.0 (Medium)
5. **HTTP Basic auth scheme** (Medium)
6. **API key in a query parameter** (Medium)

Not covered today: sensitive data inside example values and freeform object parameters.

> **Note:** This is the *static* scanner that analyzes OpenAPI/Swagger spec **files in your repo**. It is separate from the *runtime* OpenAPI discovery the DAST engine performs — that probes a live target for served specs (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, …) and turns them into testable endpoints. See the "Cross-Referencing + Guided DAST" section of the main README.

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
