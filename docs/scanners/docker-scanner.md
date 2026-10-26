# Docker Scanner

**Type:** SAST | **Severity:** Low–Critical | **Category:** Infrastructure Misconfiguration

## What It Does

Analyzes Dockerfiles (`Dockerfile`, `Dockerfile.dev`/`.prod`/`.staging`) and Docker Compose files (`docker-compose[.dev|.prod].yml/.yaml`, `compose.yml/.yaml`) for security best practices. Ingestion indexes these by pattern (`Dockerfile*`, `*.Dockerfile`, `docker-compose*.y*ml`, `compose*.y*ml`), so `Dockerfile.prod` and `compose.yaml` are read; the same pattern indexing covers `requirements*.txt`, `openapi*.y*ml`, `swagger*.y*ml` and `.env.*` (template files such as `.env.example` excluded). The root-user and HEALTHCHECK checks are skipped for any path containing "dev". Dockerfile checks:

1. **Running as root** — No `USER` directive means the container runs as root. If the container is compromised, the attacker has root access.

2. **Unpinned base image** — Using `FROM node:latest` instead of `FROM node:20.11-alpine`. The `:latest` tag can change unexpectedly, introducing vulnerabilities or breaking changes.

3. **Exposed sensitive ports** — `EXPOSE 5432` (PostgreSQL) or `EXPOSE 6379` (Redis) suggests the database runs in the same container, which is an anti-pattern. Also SSH, MySQL, MongoDB, Elasticsearch, Memcached and the Docker daemon ports.

4. **No HEALTHCHECK** — Without a health check, orchestrators can't detect when the container is unhealthy.

5. **Secrets in `ENV`** — an `ENV` name containing PASSWORD, SECRET, KEY or TOKEN with a literal value is stored in the image layers (High, one finding per file).

6. **`ADD` with a remote URL** — `ADD https://...` pulls unverified bytes into the image at build time (Medium).

Docker Compose checks: default or short (8 characters or fewer) `PASSWORD`/`PASSWD` values (Medium), `privileged: true` (Critical), and database ports published to the host such as `5432:5432` (Low).

Not covered today: `COPY . .` and `COPY .env` are not flagged, so use a `.dockerignore` yourself.

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
