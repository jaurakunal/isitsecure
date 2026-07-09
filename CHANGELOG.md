# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- OpenAPI/Swagger spec discovery — probes common spec paths and parses the spec
  into testable endpoints (finds attack surface on frontend-less APIs).
- HTML form/link endpoint discovery for server-rendered apps, wired into both
  url-only discovery and the authenticated crawler.
- Form-scoped login-field detection — logs in against apps whose identity field
  is not named `email` (e.g. `userName`).
- Authenticated cross-user IDOR / BOLA: generic REST login, `scan_cross_user_api`
  with an anonymous-access false-positive guard, and owned-resource-id
  harvesting (numeric + UUID ids). New CLI flags `--auth-email-b`,
  `--auth-password-b`, `--login-url`.
- Path-parameter injection and broader SQL-error recognition (SQLAlchemy /
  sqlite3 / psycopg); time-based SQLi confirmation to remove timing-noise FPs.
- Stored XSS detection via inject-then-retrieve.
- Allowlist-bypass open-redirect detection; OSV dependency scanner.
- A repeatable benchmark harness (`benchmarks/`) with recall + false-positive
  scorecards and a per-instance scorer (`benchmarks/score.py`).

### Security
- Hardened `git clone` against argument-injection RCE (scheme allow-list, `--`
  separator, `GIT_ALLOW_PROTOCOL`); scrub the GitHub token from git stderr.
- Contained the AI-fix apply path to the repository (no arbitrary file write).
- Replaced the web server's wildcard CORS with a loopback-only origin policy.
- API-key config file is now written `0600`.
- Credentials are no longer replayed on cross-origin redirects.

### Changed
- Scrubbed leaked private-product identifiers from generic scanner logic.

## [0.1.0]

- Initial pre-release: SAST + DAST + LLM code review, ~40 rule-based scanners,
  SAST→DAST feedback loop, and AI fix generation.
