# Git Secret Scanner

**Type:** SAST | **Severity:** Critical–High | **Category:** Exposed Secrets

## What It Does

Scans your entire git history — not just the current files — for accidentally committed secrets. Checks every commit diff for patterns matching:

- **API keys**: Stripe (sk_live/sk_test), AWS (AKIA...), Firebase, Supabase (service role key), SendGrid, Twilio
- **Tokens**: GitHub (ghp_/gho_), GitLab, OAuth tokens
- **Database credentials**: PostgreSQL/MySQL connection strings with passwords
- **Private keys**: RSA/EC private key file contents (-----BEGIN PRIVATE KEY-----)
- **Generic secrets**: High-entropy strings in variable assignments matching `SECRET`, `KEY`, `TOKEN`, `PASSWORD`

The scanner checks **both HEAD (current files) and git history**. This matters because developers often commit secrets, then remove them in a later commit — but the secret is still in the git history and accessible to anyone who clones the repo.

## Why It Matters

Exposed secrets are the fastest path to a full compromise:

- **Database access** — a leaked connection string gives direct read/write to all data
- **Cloud account takeover** — leaked AWS keys can spin up resources, access S3 buckets, delete infrastructure
- **Impersonate services** — leaked API keys let attackers act as your application (send emails, charge cards, access user data)
- **Bypass all security** — a Supabase service role key bypasses all Row Level Security policies

The secret doesn't need to be in the current code. If it was **ever committed**, anyone who clones your repo can run `git log -p` and find it.

## Real-World Breaches

**Uber (2016)** — Engineers committed AWS credentials to a private GitHub repo. Attackers found them, accessed an S3 bucket, and stole 57 million user and driver records. Uber paid $100K to the attackers and concealed the breach for over a year.

**Samsung (2022)** — Researchers at GitGuardian found Samsung engineers had leaked internal source code, private keys, and AWS credentials in public GitLab repositories.

## What Vulnerable Code Looks Like

```typescript
// BAD: Hardcoded secret in source code
const STRIPE_SECRET = "sk_live_51abc123def456..."

// BAD: Committed .env file
// .env
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIs...
DATABASE_URL=postgresql://user:p@ssw0rd@db.example.com/prod

// BAD: "Removed" secret (still in git history)
// git log shows: commit abc123 "add config" → commit def456 "remove secrets"
// The secret is still accessible via: git show abc123:.env
```

## How to Fix

```bash
# 1. Rotate the secret immediately (this is the ONLY real fix)
# Generate new API key in your provider's dashboard
# Update your deployment environment variables

# 2. Add .env to .gitignore
echo ".env" >> .gitignore

# 3. Use environment variables, not code
# In your app:
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)

# 4. If secret was committed to git history, use git-filter-repo to remove it
pip install git-filter-repo
git filter-repo --path .env --invert-paths

# 5. For new projects, use pre-commit hooks to prevent secret commits
# .pre-commit-config.yaml
# - repo: https://github.com/gitleaks/gitleaks
#   hooks: [{ id: gitleaks }]
```

**Important**: Removing a file from git does NOT remove it from history. You must either rewrite history (destructive) or rotate the secret (recommended).
