# Shell Script Scanner

**Type:** SAST | **Severity:** Low–High | **Category:** Injection Risk

## What It Does

Scans shell scripts (`.sh`, `.bash`) in the repository with line-level regular expressions for:

1. **Command injection via eval** — `eval "$USER_INPUT"`: `eval` followed by a `$` on the same line (Medium)
2. **Curl piped to shell** — `curl url | sh` executes remote code without verification (High)
3. **Hardcoded credentials** — passwords, tokens, and keys assigned to named variables such as `*PASSWORD`, `*API_KEY`, `*SECRET`, `AWS_SECRET_ACCESS_KEY`, `DATABASE_URL` (High, one finding per secret type per file).
4. **Hardcoded AWS account IDs** — a 12-digit ID in an ECR image URL (Low)
5. **Permissive chmod** — `chmod 777`, `666` or `a+rwx` (Medium)
6. **Missing error handling** — no `set -e`, `-u` or `-o` text anywhere in the file (Low)
7. **Secrets echoed to output** — `echo` of a password, secret, token or key followed by `:` or `=` (Medium)
8. **TLS verification disabled** — `curl -k` or `--insecure` (Medium)

Not covered today: unquoted variables (`rm -rf $DIR`) and predictable `/tmp` paths.

## Why It Matters

Shell scripts often run with elevated privileges (CI/CD, deployment, cron jobs):

- **`eval` with user input** — full remote code execution on your server
- **Unquoted variables** — word splitting can cause `rm -rf /` if a variable is empty
- **Curl pipe to shell** — if the remote URL is compromised, your server runs the attacker's code

## Real-World Context

**SolarWinds (2020)** — While the attack vector was different (supply chain), the principle is the same: build/deploy scripts that execute remote or dynamic content without verification are high-risk targets.

## How to Fix

```bash
# BAD: eval with variable
eval "$USER_INPUT"

# GOOD: Use arrays and explicit commands
allowed_commands=("list" "status" "restart")
if [[ " ${allowed_commands[*]} " =~ " ${1} " ]]; then
  systemctl "$1" myservice
fi

# BAD: Unquoted variable
rm -rf $DEPLOY_DIR

# GOOD: Always quote variables
rm -rf "$DEPLOY_DIR"

# BAD: Curl pipe to shell
curl -fsSL https://example.com/install.sh | sh

# GOOD: Download, inspect, then execute
curl -fsSL https://example.com/install.sh -o install.sh
# Review install.sh
bash install.sh
```
