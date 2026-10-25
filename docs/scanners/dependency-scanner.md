# Dependency Scanner

**Type:** SAST | **Severity:** Low–Critical (High when unknown) | **Category:** Dependency Vulnerability

## What It Does

Reads `package.json` (the root and every workspace; `dependencies` and `devDependencies`) and checks each dependency version against the OSV.dev vulnerability database. Flags packages with published advisories (CVEs and GHSA entries).

How it works:
- Each version is reduced to a bare number by stripping leading `^ ~ > = <` and spaces. No lockfile is read and `npm audit` is not run, so transitive dependencies are not checked.
- Packages are sent to `https://api.osv.dev/v1/querybatch` in batches of 100 (30 s timeout), capped at 200 packages. The scan needs outbound HTTPS to api.osv.dev; offline it reports nothing.
- Each advisory returned becomes one finding (confidence 0.95).
- Severity comes from the first `severity[]` score if it is a plain number (9.0+ Critical, 7.0+ High, 4.0+ Medium, else Low), otherwise from `database_specific.severity` (CRITICAL, HIGH, MODERATE/MEDIUM, LOW). A CVSS vector string is not decoded, and anything unreadable defaults to High.

## Why It Matters

Your application is mostly other people's code. A typical Next.js app has 500–1000 transitive dependencies. A single vulnerable dependency can:

- **Allow remote code execution** — the attacker runs arbitrary code on your server
- **Bypass authentication** — a JWT library bug means forged tokens work
- **Crash your application** — denial of service via crafted input
- **Leak data** — information disclosure through error handling bugs

You don't need to have a bug in YOUR code. The bug in a dependency is your bug too.

## Real-World Breaches

**Equifax (2017)** — 147 million records stolen because of an unpatched Apache Struts dependency (CVE-2017-5638). The patch had been available for two months before the breach. Equifax paid $700 million in settlements.

**Log4Shell / Log4j (2021)** — CVE-2021-44228 in the Log4j library allowed remote code execution via crafted log messages. It affected hundreds of thousands of applications globally including services from Apple, Amazon, Cloudflare, and Steam. One of the most impactful vulnerabilities ever discovered.

## What Vulnerable Code Looks Like

```json
{
  "dependencies": {
    "next": "13.0.0",           // Multiple critical CVEs
    "jsonwebtoken": "8.5.1",    // CVE: algorithm confusion attack
    "lodash": "4.17.15",        // CVE-2019-10744: prototype pollution
    "axios": "0.21.0"           // CVE-2021-3749: ReDoS
  }
}
```

## How to Fix

```bash
# Check for vulnerabilities
npm audit

# Update to patched versions
npm update

# For major version updates (breaking changes)
npx npm-check-updates -u
npm install

# Automate with Dependabot or Renovate in CI
# .github/dependabot.yml
# version: 2
# updates:
#   - package-ecosystem: npm
#     directory: /
#     schedule: { interval: weekly }
```
