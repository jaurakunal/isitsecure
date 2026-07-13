# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1](https://github.com/jaurakunal/isitsecure/compare/v0.2.0...v0.2.1) (2026-07-12)


### Bug Fixes

* **dast:** detect authentication-bypass SQLi via login-path probing (closes [#2](https://github.com/jaurakunal/isitsecure/issues/2)) ([6cef112](https://github.com/jaurakunal/isitsecure/commit/6cef112f0b49cecf5b1eb03d195a41eff4e4c4f4))


### Documentation

* **benchmarks:** Juice Shop url-only recall 36% -&gt; 44% after auth-bypass SQLi ([855a7c4](https://github.com/jaurakunal/isitsecure/commit/855a7c4be4b9b8b3ee0bcef10b2eb7bee54ea32e))

## [0.2.0](https://github.com/jaurakunal/isitsecure/compare/v0.1.2...v0.2.0) (2026-07-12)


### Features

* **dast:** interactive DOM/reflected XSS oracle (closes [#3](https://github.com/jaurakunal/isitsecure/issues/3)) ([de6e483](https://github.com/jaurakunal/isitsecure/commit/de6e483022b978f807185207d950ed27084251c5))


### Bug Fixes

* **dast:** return DOM XSS findings on timeout instead of discarding them ([3c979ad](https://github.com/jaurakunal/isitsecure/commit/3c979adc7c7574498036e4adbb1891158e3bc8da))
* **dast:** tighten NoSQL oracle to kill false positives ([#5](https://github.com/jaurakunal/isitsecure/issues/5)) ([f899664](https://github.com/jaurakunal/isitsecure/commit/f899664ab28d1b249ffcd38df341e2da3e3b0f9a))


### Documentation

* **benchmarks:** document the must-detect regression guard ([d8e1150](https://github.com/jaurakunal/isitsecure/commit/d8e11509e0b8886a3cbafbf0bb66973abb8ec153))
* **benchmarks:** Juice Shop url-only recall 33% -&gt; 36% after XSS fix ([4b8b16a](https://github.com/jaurakunal/isitsecure/commit/4b8b16afab06f7d56dfc79723eb89efbced5e099))
* **benchmarks:** make OWASP Juice Shop reproducible + correct the numbers ([be9af0f](https://github.com/jaurakunal/isitsecure/commit/be9af0f695123cb27c77c6ef5b5f85e02f342f9e))
* flag NoSQL injection as a known false-positive-prone class ([#5](https://github.com/jaurakunal/isitsecure/issues/5)) ([c334c3e](https://github.com/jaurakunal/isitsecure/commit/c334c3e0e8a0dca7a4952737663582af2bfcfdff))


### Reverts

* NoSQL oracle tightening — restore prior detection ([#5](https://github.com/jaurakunal/isitsecure/issues/5)) ([f60d7fb](https://github.com/jaurakunal/isitsecure/commit/f60d7fbd36f78e75a2d30bed045fafab86d3730a))

## [0.1.2](https://github.com/jaurakunal/isitsecure/compare/v0.1.1...v0.1.2) (2026-07-11)


### Dependencies

* Bump actions/checkout from 4 to 7 ([#23](https://github.com/jaurakunal/isitsecure/issues/23)) ([fdb7c75](https://github.com/jaurakunal/isitsecure/commit/fdb7c75bf2c32801c3c32c45e0b40fd3026fd7d8))
* Bump actions/setup-python from 5 to 6 ([#24](https://github.com/jaurakunal/isitsecure/issues/24)) ([368849d](https://github.com/jaurakunal/isitsecure/commit/368849d79bad4c9cd5e34595880bf3fb2837f245))
* Bump eslint-config-next from 16.2.6 to 16.2.10 in /ui ([#31](https://github.com/jaurakunal/isitsecure/issues/31)) ([7edb854](https://github.com/jaurakunal/isitsecure/commit/7edb85402950c51c63f4755e277bfbc09807a9e1))
* Bump github/codeql-action from 3 to 4 ([#21](https://github.com/jaurakunal/isitsecure/issues/21)) ([90bbdd3](https://github.com/jaurakunal/isitsecure/commit/90bbdd330de32ddcb0d030ffe899d53c77563fea))
* Bump googleapis/release-please-action from 4 to 5 ([#22](https://github.com/jaurakunal/isitsecure/issues/22)) ([ea448dc](https://github.com/jaurakunal/isitsecure/commit/ea448dcc80b01c2e44e52bddd1e18c0ac9f72b8b))
* Update cryptography requirement from &gt;=42.0 to &gt;=49.0.0 ([#27](https://github.com/jaurakunal/isitsecure/issues/27)) ([df22a1c](https://github.com/jaurakunal/isitsecure/commit/df22a1ccbd793f7303c8981e86e7466f443e032b))
* Update fastapi requirement from &gt;=0.111 to &gt;=0.139.0 ([#28](https://github.com/jaurakunal/isitsecure/issues/28)) ([052e253](https://github.com/jaurakunal/isitsecure/commit/052e2530df92331c159c6047edbdc8e16849af0a))
* Update pytest-cov requirement from &gt;=5.0 to &gt;=7.1.0 ([#26](https://github.com/jaurakunal/isitsecure/issues/26)) ([c7016f9](https://github.com/jaurakunal/isitsecure/commit/c7016f92ecfeb5c904d0de401dfcbc1598394f79))
* Update ruff requirement from &gt;=0.5 to &gt;=0.15.21 ([#29](https://github.com/jaurakunal/isitsecure/issues/29)) ([ad83a4a](https://github.com/jaurakunal/isitsecure/commit/ad83a4a6c898a7fe53d79ddcc9bea48ee2249b9a))
* Update typer requirement from &gt;=0.12 to &gt;=0.26.8 ([#25](https://github.com/jaurakunal/isitsecure/issues/25)) ([db27c0d](https://github.com/jaurakunal/isitsecure/commit/db27c0da1d875466227700466cca34d0ab32533d))

## [0.1.1](https://github.com/jaurakunal/isitsecure/compare/v0.1.0...v0.1.1) (2026-07-11)


### Bug Fixes

* **ci:** repair slack-notify YAML — multiline strings broke block scalar ([955ac67](https://github.com/jaurakunal/isitsecure/commit/955ac6764436eede8d7124378e9e4bbafb94258b))
* **security:** resolve CodeQL alerts — scope analysis to product code ([39727f9](https://github.com/jaurakunal/isitsecure/commit/39727f9eddf4b5bd5ee97d3a01847e6ad1d9a905))


### Dependencies

* **deps:** Bump @types/node from 20.19.43 to 26.1.1 in /ui ([#14](https://github.com/jaurakunal/isitsecure/issues/14)) ([c2c275d](https://github.com/jaurakunal/isitsecure/commit/c2c275d2838a9e511b4cf203b5ca3662b3b67147))
* **deps:** Bump eslint from 9.39.5 to 10.7.0 in /ui ([#16](https://github.com/jaurakunal/isitsecure/issues/16)) ([4494869](https://github.com/jaurakunal/isitsecure/commit/449486932e0a5de52cca838aafa8fbf63c7a496e))
* **deps:** Bump next from 16.2.6 to 16.2.10 in /ui ([#15](https://github.com/jaurakunal/isitsecure/issues/15)) ([528077c](https://github.com/jaurakunal/isitsecure/commit/528077cfdcdbb5f864a74adbd32d0cbad553f734))
* **deps:** Bump react from 19.2.4 to 19.2.7 in /ui ([#13](https://github.com/jaurakunal/isitsecure/issues/13)) ([027075c](https://github.com/jaurakunal/isitsecure/commit/027075c76617d4406db1839575c0987967349b0a))
* **deps:** Bump react-dom from 19.2.4 to 19.2.7 in /ui ([#17](https://github.com/jaurakunal/isitsecure/issues/17)) ([a26da11](https://github.com/jaurakunal/isitsecure/commit/a26da11a4710458e3d0c836194e75a7044d51f15))
* **deps:** Update anthropic requirement from &gt;=0.40 to &gt;=0.116.0 ([#7](https://github.com/jaurakunal/isitsecure/issues/7)) ([70707c7](https://github.com/jaurakunal/isitsecure/commit/70707c713523f6ea92cc33ae826fd96454a21186))
* **deps:** Update google-genai requirement from &gt;=1.0 to &gt;=2.11.0 ([#8](https://github.com/jaurakunal/isitsecure/issues/8)) ([e1aa575](https://github.com/jaurakunal/isitsecure/commit/e1aa57526f6538fa20b3f706fc3b239c08c5eec0))
* **deps:** Update playwright requirement from &gt;=1.40 to &gt;=1.61.0 ([#6](https://github.com/jaurakunal/isitsecure/issues/6)) ([71c9d1e](https://github.com/jaurakunal/isitsecure/commit/71c9d1ec2c51d4d73c943c41d70240d230355c32))
* **deps:** Update pydantic requirement ([#12](https://github.com/jaurakunal/isitsecure/issues/12)) ([ff76243](https://github.com/jaurakunal/isitsecure/commit/ff76243e76b1302c03b475e1cbe591f9df8e0a91))
* **deps:** Update uvicorn requirement from &gt;=0.30 to &gt;=0.51.0 ([#9](https://github.com/jaurakunal/isitsecure/issues/9)) ([451dcbe](https://github.com/jaurakunal/isitsecure/commit/451dcbecfe03a0643e01f86679210bd24335b0c7))
* launch hygiene — badges, Dependabot, CodeQL ([aa8fbf2](https://github.com/jaurakunal/isitsecure/commit/aa8fbf2abec3f01c560e498ce1b9da5ba45c7912))
* **release-please:** clean v-tags (no component prefix) + manual dispatch ([8f36b63](https://github.com/jaurakunal/isitsecure/commit/8f36b633a470584a18b234eb2000da7c2a72c3e1))


### Documentation

* add Demo section + VHS tape to render the demo GIF ([5b88549](https://github.com/jaurakunal/isitsecure/commit/5b885499e594121a085042c34c82fd0efe6a75c3))
* add static terminal-screenshot placeholder (docs/demo.svg) ([44cdbff](https://github.com/jaurakunal/isitsecure/commit/44cdbff998247a3ddcf526cc435651fe8ac1f185))
* **demo:** add reliable banner.tape + note scan.tape's slow-tail caveat ([2ae1b9c](https://github.com/jaurakunal/isitsecure/commit/2ae1b9ce072833006e861ec8832f904c6491a48e))

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
