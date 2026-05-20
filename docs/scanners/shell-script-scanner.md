# Shell Script Scanner

**Type:** SAST | **Severity:** High | **Category:** Injection Risk

## What It Does

Scans shell scripts (`.sh`, `.bash`) in the repository for:

1. **Command injection via eval** — `eval "$USER_INPUT"` allows arbitrary command execution
2. **Unquoted variables** — `rm -rf $DIR` instead of `rm -rf "$DIR"` breaks on paths with spaces and can be exploited
3. **Curl piped to shell** — `curl url | sh` executes remote code without verification
4. **Hardcoded credentials** — passwords, tokens, and keys in script variables
5. **Insecure temp files** — using predictable `/tmp/myapp` paths (symlink attacks)

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
