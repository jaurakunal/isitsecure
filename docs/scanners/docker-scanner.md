# Docker Scanner

**Type:** SAST | **Severity:** Medium–Low | **Category:** Infrastructure Misconfiguration

## What It Does

Analyzes Dockerfiles for security best practices:

1. **Running as root** — No `USER` directive means the container runs as root. If the container is compromised, the attacker has root access.

2. **Unpinned base image** — Using `FROM node:latest` instead of `FROM node:20.11-alpine`. The `:latest` tag can change unexpectedly, introducing vulnerabilities or breaking changes.

3. **Sensitive files copied** — `COPY . .` or `COPY .env .env` copies secrets into the image. Anyone who pulls the image can extract them.

4. **Exposed sensitive ports** — `EXPOSE 5432` (PostgreSQL) or `EXPOSE 6379` (Redis) suggests the database runs in the same container, which is an anti-pattern.

5. **No HEALTHCHECK** — Without a health check, orchestrators can't detect when the container is unhealthy.

## Why It Matters

Docker misconfigurations can:

- **Give attackers root** — container escape + root = full host compromise
- **Leak secrets** — anyone who pulls your Docker image gets your .env file
- **Break builds** — unpinned tags change without notice
- **Expose databases** — databases should not be in application containers

## Real-World Breaches

**Tesla (2018)** — Attackers found an unsecured Kubernetes dashboard (running as root, no auth) on Tesla's AWS infrastructure, used it to access AWS credentials, and deployed cryptocurrency miners.

**Alpine Linux Docker images CVE-2019-5021 (2019)** — Official Alpine Docker images shipped with a blank root password for three years, allowing anyone with container console access to log in as root.

## What Vulnerable Code Looks Like

```dockerfile
# BAD: Every common mistake
FROM node:latest           # Unpinned
WORKDIR /app
COPY . .                   # Copies .env, secrets, node_modules
COPY .env .env             # Explicit secret copy
RUN npm install
EXPOSE 3000
EXPOSE 5432                # Database in same container?
CMD ["npm", "start"]       # Runs as root, no healthcheck
```

## How to Fix

```dockerfile
# GOOD: Secure Dockerfile
FROM node:20.11-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --only=production
COPY src/ ./src/

FROM node:20.11-alpine
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=builder /app .
USER app
EXPOSE 3000
HEALTHCHECK --interval=30s CMD wget -q --spider http://localhost:3000/api/health || exit 1
CMD ["node", "dist/index.js"]

# Use .dockerignore to exclude sensitive files
# .dockerignore:
# .env
# .git
# node_modules
# *.md
```
