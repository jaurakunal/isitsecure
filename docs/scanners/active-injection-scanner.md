# Active Injection Scanner

**Type:** DAST | **Severity:** Critical | **Category:** Injection Risk

## What It Does

Tests for server-side injection vulnerabilities by sending payloads to API endpoints and analyzing the responses. Covers six injection types:

1. **Error-based SQL Injection** — Sends `' OR '1'='1`, `1; SELECT 1--`, `1 UNION SELECT NULL--` and `' AND 1=CONVERT(int, @@version)--` and checks for SQL error patterns in the response. Recognizes database error signatures such as MySQL (`SQL syntax`), PostgreSQL (`syntax error at or near`), SQLite (`SQLITE_ERROR`, `unrecognized token`), Oracle (`ORA-…`), MSSQL (`Unclosed quotation mark`), PDO (`SQLSTATE[`), and ORM error types (`OperationalError`, `ProgrammingError`), so injections surface even behind an ORM layer. Bare library names (`sqlalchemy`, `psycopg2`) are deliberately not matched, and neither is `IntegrityError`, so a benign constraint violation is not reported as injection.

2. **Time-based Blind SQL Injection** — Runs at deep depth only (it is skipped at quick depth) and only on a parameter where error-based injection found nothing. Measures baseline response time, then sends `WAITFOR DELAY '0:0:3'` (MSSQL), `SLEEP(3)` (MySQL) and `pg_sleep(3)` (PostgreSQL) payloads. If the response is 2.5+ seconds slower than the baseline, it **re-measures independently to confirm**: the delay must reproduce on a second request before the finding is reported. This kills false positives from one-off timing noise (GC pauses, load spikes, network jitter).

3. **Command Injection** — Injects `; echo xss_cmd_test`, `| echo xss_cmd_test`, `$(echo xss_cmd_test)` and `` `echo xss_cmd_test` `` and checks that the canary appears in the response without the un-executed `echo <canary>` text, so a page that merely reflects the payload is not reported.

4. **NoSQL Injection** — Uses a differential oracle. A control request sets the parameter to an exact sentinel value that should not exist, then MongoDB operators (`param[$ne]=…`, `param[$regex]=.*`, `param[$gt]=`, plus JSON-body operators on POST endpoints) are sent. The finding is raised only when the operator response is a 2xx, non-empty, differs from the control and is broader than it (the control was empty or denied, or the operator body is more than 20 bytes larger). A leaked `MongoError`, `CastError` or `MongoServerError` also counts. A backend that treats the operator as a literal returns the control body and is not flagged.

5. **XXE (XML External Entity)** — Injects `<!ENTITY xx SYSTEM "/etc/passwd">` and checks for file content indicators in the response. Delivered **two ways**, because an endpoint that accepts XML as a *file* rejects it as a request body:

   - as the request body, on endpoints that advertise an XML content type or are POST;
   - as an **uploaded file** (`.xml`, `.svg`) on upload-shaped paths — SVG, DOCX and XLSX are zipped XML, and SAML assertions and sitemap imports arrive as attachments, so an XXE probe that only posts raw bodies misses the whole class.

   The upload delivery is not gated on the recorded HTTP method: discovery records most endpoints as GET, and an upload endpoint is worth probing either way.

6. **SSTI (Server-Side Template Injection)** — Sends `{{99991*7}}` and checks that the product `699937` appears in the response, indicating template evaluation. The same expression is sent in other engines' syntax (`${...}`, `{...}`, `<%= ... %>`, `#{...}`, and a Velocity `#set`). The large operands make an accidental match on a normal page very unlikely, and the finding is dropped if the payload is merely echoed back or the product also appears for a benign value.

Each payload is injected into **path parameters** (templated `{id}`-style segments), **query parameters**, and **JSON body fields** — not just the query string — so injection in REST-style path components is covered. Endpoints are ranked by a shared prioritizer so the most likely-injectable ones are tested first within the scanner's time budget. File-upload endpoints rank high despite having no parameters at all: their payload is the file, which is where XXE and traversal filenames arrive.

A login-shaped endpoint (found by crawling, or tried from a short list of conventional login paths) is also tested for authentication-bypass SQL injection: a benign invalid credential must be rejected while a SQL tautology must return a valid session token or cookie. All findings from this scanner are Critical.

All payloads are **read-only** — no data modification or exfiltration is attempted.

## Why It Matters

Injection vulnerabilities allow attackers to:

- **Read your entire database** — SQL injection can dump all tables, including user credentials and payment data
- **Execute system commands** — Command injection gives full shell access to your server
- **Read server files** — XXE can read `/etc/passwd`, environment variables, AWS credentials
- **Bypass authentication** — `' OR '1'='1' --` as a password bypasses login forms with SQL injection

Injection is #1 on the OWASP Top 10 for a reason. It's the most impactful vulnerability class.

## Real-World Breaches

**Heartland Payment Systems (2008)** — SQL injection led to the theft of 130 million credit/debit card numbers. One of the largest data breaches in history at the time.

**Sony Pictures (2011)** — LulzSec exploited SQL injection in Sony's websites, compromising over 1 million user accounts including plaintext passwords.

## What Vulnerable Code Looks Like

```typescript
// BAD: String concatenation in SQL query
const filter = `status = '${userInput}'`
const result = await sql.unsafe(`SELECT * FROM tasks WHERE ${filter}`)

// BAD: Template literal with user input in SQL
const result = await sql`SELECT * FROM users WHERE name = '${name}'`

// BAD: Command execution with user input
const output = execSync(`convert ${uploadedFile} output.png`)
```

## How to Fix

```typescript
// GOOD: Parameterized queries
const result = await sql`SELECT * FROM tasks WHERE status = ${userInput}`
// Note: tagged template literals in postgres.js are parameterized automatically

// GOOD: Use an ORM
const tasks = await db.select().from(tasks).where(eq(tasks.status, userInput))

// GOOD: Whitelist allowed values
const ALLOWED_STATUSES = ["pending", "in_progress", "done"]
if (!ALLOWED_STATUSES.includes(userInput)) throw new Error("Invalid status")
```
