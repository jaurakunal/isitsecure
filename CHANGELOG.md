# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.21.0](https://github.com/jaurakunal/isitsecure/compare/v0.20.0...v0.21.0) (2026-08-14)


### Features

* **trust:** baseline mode — surface only findings new since an accepted baseline ([#52](https://github.com/jaurakunal/isitsecure/issues/52)) ([#134](https://github.com/jaurakunal/isitsecure/issues/134)) ([8e67035](https://github.com/jaurakunal/isitsecure/commit/8e67035a2d4f9b6aef17592fcc0b3831673da042))

## [0.20.0](https://github.com/jaurakunal/isitsecure/compare/v0.19.1...v0.20.0) (2026-08-14)


### Features

* **trust:** stable finding fingerprint + .isitsecureignore suppression ([#51](https://github.com/jaurakunal/isitsecure/issues/51)) ([#132](https://github.com/jaurakunal/isitsecure/issues/132)) ([1eeacf3](https://github.com/jaurakunal/isitsecure/commit/1eeacf3054d0bbfbbb6f46be1f40c8ac8fc9349d))

## [0.19.1](https://github.com/jaurakunal/isitsecure/compare/v0.19.0...v0.19.1) (2026-08-14)


### Bug Fixes

* **dast:** stop matching bare ORM/driver names as SQL errors ([#125](https://github.com/jaurakunal/isitsecure/issues/125)) ([#130](https://github.com/jaurakunal/isitsecure/issues/130)) ([fd523d1](https://github.com/jaurakunal/isitsecure/commit/fd523d1519699d95c667a8b45c4cfad75ca25e5e))

## [0.19.0](https://github.com/jaurakunal/isitsecure/compare/v0.18.0...v0.19.0) (2026-08-14)


### Features

* **dast:** give error-based SQLi findings a baseline for the adjudicator ([#125](https://github.com/jaurakunal/isitsecure/issues/125)) ([#128](https://github.com/jaurakunal/isitsecure/issues/128)) ([f408688](https://github.com/jaurakunal/isitsecure/commit/f4086886be1bba7c099d5015f1289b88631c408d))


### Documentation

* architecture Phase 9.4 + models field comment updated. ([f408688](https://github.com/jaurakunal/isitsecure/commit/f4086886be1bba7c099d5015f1289b88631c408d))

## [0.18.0](https://github.com/jaurakunal/isitsecure/compare/v0.17.0...v0.18.0) (2026-08-14)


### Features

* **triage:** LLM injection false-positive adjudicator ([#5](https://github.com/jaurakunal/isitsecure/issues/5)) ([#126](https://github.com/jaurakunal/isitsecure/issues/126)) ([0ea8a4e](https://github.com/jaurakunal/isitsecure/commit/0ea8a4e832b75843b0bee22fdab01adac659a44b))

## [0.17.0](https://github.com/jaurakunal/isitsecure/compare/v0.16.0...v0.17.0) (2026-08-11)


### Features

* **dast:** carry the session into the deep-only rate-limit + reset scanners ([#119](https://github.com/jaurakunal/isitsecure/issues/119)) ([#123](https://github.com/jaurakunal/isitsecure/issues/123)) ([bd06bf8](https://github.com/jaurakunal/isitsecure/commit/bd06bf84bbb865e62c140c8516d1d691af8f07f1))

## [0.16.0](https://github.com/jaurakunal/isitsecure/compare/v0.15.0...v0.16.0) (2026-08-11)


### Features

* **dast:** run a lightweight reflected XSS pass at quick depth ([#118](https://github.com/jaurakunal/isitsecure/issues/118)) ([#121](https://github.com/jaurakunal/isitsecure/issues/121)) ([f91bb10](https://github.com/jaurakunal/isitsecure/commit/f91bb1073fb4fdec8d80f7dfa1460c47d9a7e53e))

## [0.15.0](https://github.com/jaurakunal/isitsecure/compare/v0.14.0...v0.15.0) (2026-08-08)


### Features

* **dast:** auth-aware mixin so quick-depth HTTP scanners probe authenticated ([#115](https://github.com/jaurakunal/isitsecure/issues/115)) ([#117](https://github.com/jaurakunal/isitsecure/issues/117)) ([d4a1ebf](https://github.com/jaurakunal/isitsecure/commit/d4a1ebf7f50704cf7fbc7bdd71724676a76cfe3c))

## [0.14.0](https://github.com/jaurakunal/isitsecure/compare/v0.13.0...v0.14.0) (2026-08-07)


### Features

* **dast:** capture + propagate session-cookie auth to DAST scanners ([#111](https://github.com/jaurakunal/isitsecure/issues/111)) ([#114](https://github.com/jaurakunal/isitsecure/issues/114)) ([4601b3c](https://github.com/jaurakunal/isitsecure/commit/4601b3c4e83c920cc9dcdc74d34b5b596bd2e581))

## [0.13.0](https://github.com/jaurakunal/isitsecure/compare/v0.12.0...v0.13.0) (2026-08-05)


### Features

* **dast:** POST-body XSS uses the form's real fields + form/JSON transports ([#109](https://github.com/jaurakunal/isitsecure/issues/109)) ([#110](https://github.com/jaurakunal/isitsecure/issues/110)) ([c2215a9](https://github.com/jaurakunal/isitsecure/commit/c2215a932e5762f97faf39ca3328113814c48baa))

## [0.12.0](https://github.com/jaurakunal/isitsecure/compare/v0.11.0...v0.12.0) (2026-07-30)


### Features

* **sast:** Kotlin/Spring taint/injection rule pack for the Semgrep layer ([#104](https://github.com/jaurakunal/isitsecure/issues/104)) ([#105](https://github.com/jaurakunal/isitsecure/issues/105)) ([573563f](https://github.com/jaurakunal/isitsecure/commit/573563f0bdd7de497c4513f29936ed50d83f80b3))

## [0.11.0](https://github.com/jaurakunal/isitsecure/compare/v0.10.0...v0.11.0) (2026-07-30)


### Features

* **sast:** Java/Spring taint/injection rule pack for the Semgrep layer ([#102](https://github.com/jaurakunal/isitsecure/issues/102)) ([#103](https://github.com/jaurakunal/isitsecure/issues/103)) ([085263c](https://github.com/jaurakunal/isitsecure/commit/085263c0255ebd22e4fb4b122630f7fd508c4a97))


### Documentation

* **taint:** fill remaining JS/TS-only gaps left by the Python pack ([#93](https://github.com/jaurakunal/isitsecure/issues/93)) ([#100](https://github.com/jaurakunal/isitsecure/issues/100)) ([06b845e](https://github.com/jaurakunal/isitsecure/commit/06b845eb1c5e2584818238d31d6ccedc73b29cac))

## [0.10.0](https://github.com/jaurakunal/isitsecure/compare/v0.9.0...v0.10.0) (2026-07-30)


### Features

* **sast:** auto-select taint rule packs by repo language ([#94](https://github.com/jaurakunal/isitsecure/issues/94)) ([#99](https://github.com/jaurakunal/isitsecure/issues/99)) ([fbc422f](https://github.com/jaurakunal/isitsecure/commit/fbc422fd08de776abbacc02ba917b7ff56d5370e))
* **sast:** Python taint/injection rule pack for the Semgrep layer ([#93](https://github.com/jaurakunal/isitsecure/issues/93)) ([#97](https://github.com/jaurakunal/isitsecure/issues/97)) ([eba40a5](https://github.com/jaurakunal/isitsecure/commit/eba40a55b0d88035aa8a7c7b3853b26e07a299d7))

## [0.9.0](https://github.com/jaurakunal/isitsecure/compare/v0.8.0...v0.9.0) (2026-07-29)


### Features

* **sast:** deterministic Semgrep taint/injection floor for JS/TS ([#4](https://github.com/jaurakunal/isitsecure/issues/4)) ([#95](https://github.com/jaurakunal/isitsecure/issues/95)) ([ed239aa](https://github.com/jaurakunal/isitsecure/commit/ed239aa295fabd8f7a67635d5846f3cf262ab5e8))


### Documentation

* taint-analysis design ([#4](https://github.com/jaurakunal/isitsecure/issues/4)) — layered Semgrep + LLM injection detection ([e6cc3e7](https://github.com/jaurakunal/isitsecure/commit/e6cc3e789afa3ebc3913552966949bcfdc4dee34))

## [0.8.0](https://github.com/jaurakunal/isitsecure/compare/v0.7.0...v0.8.0) (2026-07-29)


### Features

* **mcp:** DAST over MCP via job handle ([#60](https://github.com/jaurakunal/isitsecure/issues/60)) — scan_url + scan_status ([d33fae1](https://github.com/jaurakunal/isitsecure/commit/d33fae193639cbbfc2c6c93e8c5838440aefc31c))

## [0.7.0](https://github.com/jaurakunal/isitsecure/compare/v0.6.0...v0.7.0) (2026-07-28)


### Features

* **mcp:** export tool ([#88](https://github.com/jaurakunal/isitsecure/issues/88)) — render a cached scan, host writes it ([2d94add](https://github.com/jaurakunal/isitsecure/commit/2d94add35d777e1244793ecc5be83769efc027d8))
* **mcp:** fix tool ([#59](https://github.com/jaurakunal/isitsecure/issues/59)) — propose a patch, host LLM applies ([e5882fc](https://github.com/jaurakunal/isitsecure/commit/e5882fcf3777f16358418fe332f582e0c15b3d73))
* **mcp:** verify tool ([#71](https://github.com/jaurakunal/isitsecure/issues/71)) — re-scan, report what cleared + grade movement ([f88fe28](https://github.com/jaurakunal/isitsecure/commit/f88fe281b41debbebdd0f5de9f85621c79f2174f))


### Bug Fixes

* **mcp:** pin mcp&lt;2 — 2.0.0 removed mcp.server.fastmcp (broke CI) ([5ee596f](https://github.com/jaurakunal/isitsecure/commit/5ee596f106026a2adbb8ccfe7dd8cd8c69d25030))

## [0.6.0](https://github.com/jaurakunal/isitsecure/compare/v0.5.1...v0.6.0) (2026-07-28)


### Features

* **mcp:** explain tool ([#70](https://github.com/jaurakunal/isitsecure/issues/70)) + BUSINESS_LOGIC category & classifier fixes ([#64](https://github.com/jaurakunal/isitsecure/issues/64)) ([18af523](https://github.com/jaurakunal/isitsecure/commit/18af523bd1d031f35f334406b9110cb714d55f41))
* **mcp:** make scan self-advertise so agents auto-invoke it ([30d2b2e](https://github.com/jaurakunal/isitsecure/commit/30d2b2ef10d4a4565eb3044cb465a69959f15bd1))

## [0.5.1](https://github.com/jaurakunal/isitsecure/compare/v0.5.0...v0.5.1) (2026-07-28)


### Dependencies

* Bump actions/setup-python from 6 to 7 ([#77](https://github.com/jaurakunal/isitsecure/issues/77)) ([93d153f](https://github.com/jaurakunal/isitsecure/commit/93d153f68b9adfaed506f2c3c83e7055ba2781f2))
* Bump react from 19.2.7 to 19.2.8 in /ui ([#80](https://github.com/jaurakunal/isitsecure/issues/80)) ([8778270](https://github.com/jaurakunal/isitsecure/commit/87782708602640578620fe39ec01fa3c4ea20142))
* Bump react-dom from 19.2.7 to 19.2.8 in /ui ([#78](https://github.com/jaurakunal/isitsecure/issues/78)) ([caa90ce](https://github.com/jaurakunal/isitsecure/commit/caa90ce99725b8b78d54c47d42ca5fb9432fef5f))
* Update httpx requirement from &gt;=0.25 to &gt;=0.28.1 ([#73](https://github.com/jaurakunal/isitsecure/issues/73)) ([e0efae4](https://github.com/jaurakunal/isitsecure/commit/e0efae474dbe02bc75ca48846f9cdc52b6b7c80d))
* Update mcp requirement from &gt;=1.2 to &gt;=1.28.1 ([#76](https://github.com/jaurakunal/isitsecure/issues/76)) ([aa59068](https://github.com/jaurakunal/isitsecure/commit/aa5906826207ded1b1bb1697b745c2c575273a4e))
* Update pytest-asyncio requirement from &gt;=0.23 to &gt;=1.4.0 ([#72](https://github.com/jaurakunal/isitsecure/issues/72)) ([aa95c0f](https://github.com/jaurakunal/isitsecure/commit/aa95c0f4125ea55205dcaaa510fad9d27723d181))
* Update rich requirement from &gt;=13.0 to &gt;=15.0.0 ([#75](https://github.com/jaurakunal/isitsecure/issues/75)) ([79c6ef6](https://github.com/jaurakunal/isitsecure/commit/79c6ef679c7a9d33c344d77e5b52c9119b188c9d))
* Update ruff requirement from &gt;=0.15.21 to &gt;=0.15.22 ([#74](https://github.com/jaurakunal/isitsecure/issues/74)) ([3a6b08a](https://github.com/jaurakunal/isitsecure/commit/3a6b08a34003c4404cf6280acf328d79bbee49ba))


### Documentation

* **mcp:** record the fix design — host LLM applies, MCP verifies ([433edfc](https://github.com/jaurakunal/isitsecure/commit/433edfcafeed4c28d70e70b1ba179882691c6910))

## [0.5.0](https://github.com/jaurakunal/isitsecure/compare/v0.4.1...v0.5.0) (2026-07-15)


### Features

* **mcp:** local stdio MCP server exposing `scan` ([#58](https://github.com/jaurakunal/isitsecure/issues/58)) ([39b6cce](https://github.com/jaurakunal/isitsecure/commit/39b6cce2ae801dcea545822c43ab413b291d0784))


### Bug Fixes

* **mcp:** use typing_extensions.TypedDict (Py3.11 CI) + widen CI matrix ([c339dd7](https://github.com/jaurakunal/isitsecure/commit/c339dd79bb88cc3b9a269cdececc66478dfedca4))


### Documentation

* **mcp:** add MCP design doc — the scan → understand → plan → fix journey ([abf9dad](https://github.com/jaurakunal/isitsecure/commit/abf9dad9cbd1d21e9107450d7173b9e2683bbc73))

## [0.4.1](https://github.com/jaurakunal/isitsecure/compare/v0.4.0...v0.4.1) (2026-07-14)


### Documentation

* document Wave 2 fix→PR flow, new CLI commands, and remediation pipeline ([aedbd8f](https://github.com/jaurakunal/isitsecure/commit/aedbd8f70b554795eb140ed5ecf2a159ddce7691))

## [0.4.0](https://github.com/jaurakunal/isitsecure/compare/v0.3.0...v0.4.0) (2026-07-14)


### Features

* **fixes:** remote-repo fix → per-category pull requests ([#62](https://github.com/jaurakunal/isitsecure/issues/62)) ([c551f52](https://github.com/jaurakunal/isitsecure/commit/c551f527d00ea1e6c5a8398da5db38f40cc3f130))
* **fix:** git-free fix & verify flow with plain-language results ([#50](https://github.com/jaurakunal/isitsecure/issues/50)) ([adf3f88](https://github.com/jaurakunal/isitsecure/commit/adf3f88bf48af1b49d3ed2873c4c34bd9bf1130a))
* **remediation:** framework-aware remediation for DAST findings ([#48](https://github.com/jaurakunal/isitsecure/issues/48)) ([cd152db](https://github.com/jaurakunal/isitsecure/commit/cd152db618f97cbdf0e1df2f6df473ca1bc4e67d))
* **remediation:** specific fix guidance for all 18 categories ([#47](https://github.com/jaurakunal/isitsecure/issues/47)) ([f67ade4](https://github.com/jaurakunal/isitsecure/commit/f67ade4e3432a1e4aac7daa692c314b959c59071))
* **remediation:** step-by-step walkthroughs for the top-4 fixes ([#49](https://github.com/jaurakunal/isitsecure/issues/49)) ([acb1927](https://github.com/jaurakunal/isitsecure/commit/acb1927bbf0223b83920f268fadf2043d29cabde))


### Bug Fixes

* **fixes:** capture uncommitted work in git safety net + add restore round-trip tests ([469103d](https://github.com/jaurakunal/isitsecure/commit/469103d9f7d38bcb5494b3692e90664f827b0f09))


### Documentation

* **fixes,triage:** correct safety-net docstring and surface copy-mode restore ([8e5a41b](https://github.com/jaurakunal/isitsecure/commit/8e5a41bf7d0f9b2230bd6fc5176b48dcc4865e34))

## [0.3.0](https://github.com/jaurakunal/isitsecure/compare/v0.2.1...v0.3.0) (2026-07-13)


### Features

* **cli:** friendlier first-run — pre-flight checks, human errors, smart mode ([ab864d6](https://github.com/jaurakunal/isitsecure/commit/ab864d63f15b86a01b331e0d7728f9b160f2f2d4))
* **cli:** lead scan results with launch verdict + plain-English framing ([c1b0efa](https://github.com/jaurakunal/isitsecure/commit/c1b0efabcc6575d53040b2a389419b7dbc5cc7a6))
* **reporting:** add rule-based plain-English framing layer (no LLM) ([3732422](https://github.com/jaurakunal/isitsecure/commit/373242280b1ad0e39ed7acdedd72cded590c9301))
* **reporting:** wire plain-English layer into report + HTML output ([2f40003](https://github.com/jaurakunal/isitsecure/commit/2f40003c4a1e9d25fa02c0a636ab78dbf6dbe773))
* **server,ui:** surface Wave 1 plain-English layer in the web report ([876cb1e](https://github.com/jaurakunal/isitsecure/commit/876cb1e0e413eb8b67ce266cd497cd28381dfbc1))

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
