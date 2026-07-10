# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-10

First public release — an AI-powered SAST + DAST + LLM security scanner for
modern web apps, run from a single command.

### Added

**Scanning**
- 40 rule-based scanners by default (44 with `--depth deep`): SAST, DAST, and
  special DAST scanners, plus optional LLM code review, triage, and AI fixes.
- SAST → DAST feedback loop: static findings generate targeted live tests.
- Scan depth (`--depth quick|deep`, default `quick`): quick runs the fast
  structural + error-based scanners in seconds; deep adds time-based (blind)
  SQL injection, active XSS, auth-bypass timing, rate-limit bursts, and
  password-reset probes.
- Live Supabase RLS testing with the anon key in url-only mode: flags tables
  readable/writable without authentication, escalates to CRITICAL when a
  sensitive column (email, etc.) is exposed, and infers anon-INSERT exposure
  from the PostgREST error code.
- Backend / infrastructure fingerprinting (Cloudflare, Vercel, Netlify, … plus
  Supabase).
- Snapshot scanners: source-map leak (verified, not just present), mixed
  content, Subresource Integrity, and client-side exposure (Supabase
  `service_role` keys, internal URLs, unreplaced env placeholders).
- Endpoint discovery: OpenAPI/Swagger probing, HTML form/link extraction,
  `/{id}` variant generation, and external API-base probing.
- Authenticated cross-user IDOR / BOLA with owned-resource-id harvesting
  (`--auth-email-b`, `--auth-password-b`, `--login-url`).
- Injection: path-parameter injection, broad SQL-error recognition
  (SQLAlchemy / sqlite3 / psycopg), time-based SQLi confirmation, and SSTI.
- Stored XSS via inject-then-retrieve; allowlist-bypass open-redirect
  detection; OSV.dev dependency scanning.

**Experience**
- Live scan narration: every phase and every scanner reports progress (with
  per-item sub-events) as a scrolling log, so long scans never look stuck —
  routed to stderr so piped `--output json`/`sarif` stays clean.
- Auto-generated HTML report led by a plain-English "what this means for you"
  risk summary and action plan.
- Security badge (SVG), SARIF export for GitHub code scanning, and a local web
  UI (`isitsecure launch`).
- Framed, animated welcome banner.

**Setup & onboarding**
- One-command installers — `install.sh` (macOS/Linux) and `install.ps1`
  (Windows): verify Python 3.11+/git, clone, create a virtual environment,
  install, and run first-time setup.
- `isitsecure setup` installs the DAST browser and language servers, with
  `--lsp` / `--check` sub-flows; `isitsecure launch` also offers language-server
  setup. LSP install is cross-platform (pip / npm / Homebrew) with per-OS
  guidance for anything it can't install directly.

**Project**
- Repeatable benchmark harness (`benchmarks/`) with recall + false-positive
  scorecards and a per-instance scorer.
- CI (GitHub Actions): test gate on Python 3.11 and 3.12.

### Security
- Hardened `git clone` against argument-injection RCE (scheme allow-list, `--`
  separator, `GIT_ALLOW_PROTOCOL`); scrub the GitHub token from git stderr.
- Contained the AI-fix apply path to the repository (no arbitrary file write).
- Loopback-only CORS on the web server (no wildcard origins).
- API-key config file written `0600`; credentials no longer replayed on
  cross-origin redirects.
- Scrubbed leaked private-product identifiers from generic scanner logic.

### Fixed
- Per-resource findings (e.g. per-table RLS) were collapsed by fuzzy
  deduplication — now kept distinct.
- Confirmed SSTI findings were silently discarded (swallowed `NameError`).
- `scan --output json` produced invalid JSON when piped/redirected (Rich
  word-wrapping mid-string); now written raw so it always parses.
- Cross-user REST IDOR now runs regardless of crawler-harvested resource ids.

[Unreleased]: https://github.com/jaurakunal/isitsecure/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jaurakunal/isitsecure/releases/tag/v0.1.0
