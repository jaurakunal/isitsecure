# Active Injection Scanner

**Type:** DAST | **Severity:** Critical | **Category:** Injection Risk

## What It Does

Tests for server-side injection vulnerabilities by sending payloads to API endpoints and analyzing the responses. Covers six injection types:

1. **Error-based SQL Injection** — Sends `'` and `"1"="2"` characters and checks for SQL error patterns in the response (PostgreSQL, MySQL, SQLite error messages).

2. **Time-based Blind SQL Injection** — Measures baseline response time, then sends `SLEEP(5)` / `pg_sleep(5)` payloads. If the response takes 5+ seconds longer, the injection is confirmed.

3. **Command Injection** — Injects shell metacharacters (`;`, `|`, `` ` ``) with canary output detection. Checks if the command output appears in the response.

4. **NoSQL Injection** — Sends MongoDB operator payloads (`[$ne]=null`) and checks for response size inflation, indicating the query returned more data than intended.

5. **XXE (XML External Entity)** — For endpoints accepting XML, injects `<!ENTITY xx SYSTEM "/etc/passwd">` and checks for file content indicators in the response.

6. **SSTI (Server-Side Template Injection)** — Sends `{{7*7}}` and checks if `49` appears in the response, indicating template evaluation.

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
