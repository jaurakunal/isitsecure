# AI Fix Generator

**Type:** LLM-Powered | **Severity:** N/A | **Category:** Remediation

## What It Does

Generates code patches for security findings using LLM. For each critical and high finding that has a source code location:

1. Reads the full source file
2. Sends the finding details + file content to the LLM with a security-aware system prompt
3. Parses the LLM response to extract the fixed code
4. Generates a unified diff between original and fixed code
5. Includes an explanation of what changed and why

Fixes are delivered three ways:
- **Markdown fix plan** (`scan --output fixes`) — diffs + explanations to paste
  into Cursor/Claude Code, `git apply`, or review manually.
- **Local apply + verify** (`fix --repo <path>`) — writes fixes in place
  (git-free), after backing up the working tree, then **re-scans to confirm each
  finding is resolved** and reports a plain-language summary.
- **Remote clone → per-category PRs** (`fix --repo <github-url>`) — clones,
  fixes, and opens one pull request per finding category (one commit per
  finding) onto feature branches.

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
# 1. Just give me a plan (Markdown, paste into Cursor / Claude Code)
isitsecure scan --repo ./my-app --output fixes -f fixes.md

# 2. Apply fixes in place on a local repo (git-free; auto-backup + re-scan verify)
isitsecure fix --repo ./my-app
isitsecure fix --repo ./my-app --dry-run          # preview without writing
isitsecure fix --repo ./my-app --severity critical
isitsecure fix --repo ./my-app --technical         # show git/backup details

# 3. Fix a remote GitHub repo → open per-category pull requests
isitsecure fix --repo https://github.com/you/your-app --github-token $GITHUB_TOKEN
isitsecure fix --repo <github-url> --pr-strategy per-file --max-prs 5
```

The local apply flow backs up the working tree first, then re-scans to verify
findings are resolved and prints how many were fixed / need review / couldn't be
fixed. The remote flow never pushes to the default branch — fixes land on
feature branches as pull requests; `--max-prs` caps the count (default 8) and
excess low-severity categories batch into one PR. The GitHub token is used only
for the push + PR and is never stored or logged.

## Configuration

Requires an LLM API key. Uses the same provider configured for the scan (`--llm anthropic` or `--llm google`).

Estimated cost: ~$1-3 per fix plan (depends on number of findings and file sizes).
