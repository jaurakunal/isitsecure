# AI Fix Generator

**Type:** LLM-Powered | **Severity:** N/A | **Category:** Remediation

## What It Does

Generates code patches for security findings using LLM. For each critical and high finding that has a source code location:

1. Reads the full source file
2. Sends the finding details + file content to the LLM with a security-aware system prompt
3. Parses the LLM response to extract the fixed code
4. Generates a unified diff between original and fixed code
5. Includes an explanation of what changed and why

Output is a Markdown fix plan with diffs that can be:
- **Pasted into Cursor/Claude Code** — "Apply all the security fixes in this document"
- **Applied manually** — `git apply fix.patch`
- **Reviewed in PRs** — each diff is a standalone change

## Why It Matters

Finding vulnerabilities is only half the problem. Most developers (especially vibe coders) don't know how to fix:
- SQL injection → parameterized queries
- Missing RLS → correct policy with right column references
- Race condition → database transactions with row locking
- IDOR → ownership verification in the query

The fix generator closes the **find → fix loop**. No other open-source security scanner generates LLM-powered code patches.

## How It Works

The system prompt includes common fix patterns:

| Vulnerability | Fix Pattern |
|---|---|
| SQL injection | Parameterized queries / tagged template literals |
| XSS | HTML escaping, textContent, CSP headers |
| Missing auth | Add getUserFromRequest() check |
| IDOR | Add WHERE user_id = $userId to queries |
| Mass assignment | Explicitly pick allowed fields |
| Race condition | Database transactions with SELECT ... FOR UPDATE |
| Weak JWT | Restrict algorithms, strong secret, add expiration |

## Usage

```bash
# Generate fixes for all critical/high findings
isitsecure scan --repo ./my-app --output fixes -f fixes.md

# Paste into Cursor
# "Apply all the security fixes in this document"
```

## Configuration

Requires an LLM API key. Uses the same provider configured for the scan (`--llm anthropic` or `--llm google`).

Estimated cost: ~$1-3 per fix plan (depends on number of findings and file sizes).
