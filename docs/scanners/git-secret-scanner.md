# Git Secret Scanner

**Type:** SAST | **Severity:** Critical–High | **Category:** Exposed Secrets

## What It Does

Scans the files at HEAD, the lines added by past commits, and the names of every file ever committed, for accidentally committed secrets. The history pass runs `git log --all --diff-filter=A -p` (last 500 non-merge commits), so it reads the diffs of commits that **add files**. Each added line is checked against these patterns:

- **API keys**: Stripe live secret keys (`sk_live_`) and restricted keys (`rk_live_`), AWS access key IDs (AKIA...), Firebase/Google (`AIza...`), SendGrid, Twilio, OpenAI (`sk-` and `sk-proj-` / `sk-svcacct-` / `sk-admin-`), Anthropic
- **Supabase service role key**: a JWT-shaped string (`eyJ...eyJ...sig`) whose payload `role` claim decodes to `service_role` is Critical. The public Supabase **anon** (and `authenticated`) key that ships in every frontend is not reported. A JWT whose role cannot be confirmed (no `role` claim, or an unreadable payload) is kept as a Medium "JSON Web Token (role could not be confirmed)" finding rather than dropped
- **Tokens**: GitHub personal access (`ghp_`) and OAuth (`gho_`) tokens
- **Database credentials**: `postgres://`, `postgresql://`, `mysql://`, `mongodb://` and `mongodb+srv://` connection URLs that embed a `user:password@` pair (Critical). The password runs to the last `@` before the host, so an unencoded `/` or a bare `<` in it is still caught, and a `password=`/`passwd=`/`pwd=` query parameter with a value is treated the same way. URLs with no password, or with a templated one (`${DB_PASS}`, a whole `<password>` placeholder), are not reported; an obvious placeholder password (`password`, `changeme`, `example`, `xxx`...) is kept at Medium
- **Private keys**: `-----BEGIN [RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP ]PRIVATE KEY[ BLOCK]-----` headers
- **Sensitive file names**: `.env` (and `.local`/`.production`/`.staging`), `.pem`, `.key`, `credentials.json`, service-account JSON, reported as High even if no pattern matches inside

Matches shorter than 8 or longer than 500 characters are dropped. Symlinked files and symlinked `.env*` files are skipped, and git subprocesses that outlive their timeout are killed. There is no entropy-based or variable-name-based generic secret detection, no Stripe `sk_test_` pattern and no GitLab token pattern.

The scanner checks **both HEAD (current files) and git history**. This matters because developers often commit secrets, then remove them in a later commit, but the secret is still in the git history and accessible to anyone who clones the repo. A history finding is tagged "currently in the codebase" when the file path still exists in the HEAD index (the file, not the secret value).

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
