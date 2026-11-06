# isitsecure MCP — Design

Status: **living design doc.** Implemented so far: `scan` (#58 + #68 enrichment),
the scan-cache/identity layer (#69), `explain` (#70), `fix` (#59, propose mode),
`verify` (#71), and `export` (#88) — the scan → understand → plan → fix → verify
loop is complete, and `scan_url`/`scan_status` add DAST (#60). Still proposed:
`fix`'s optional `apply=true` fallback.
This doc is the contract we build to — argue it here before writing code.

## Goal: the remediation journey, inside the user's AI coding tool

`isitsecure` ships a local [MCP](https://modelcontextprotocol.io) server so an AI
coding tool (Cursor, Claude Code, Claude Desktop) can drive security work in the
loop where the user already writes code. The bar we hold ourselves to — we don't
call it "the isitsecure MCP" until it can do **all four**, or a beginner hits a
dead end after the scan:

1. **Scan** the repo and give a report.
2. **Converse** about what the report means — priority, what matters most, why.
3. **Plan** the fixes together.
4. **Run** individual fixes.

## Core principle: the MCP supplies data + verbs; the host LLM supplies judgment

An MCP server exposes **tools** (functions). Needs **2 (converse)** and **3
(plan)** are *not* functions you call — that is the host LLM (Claude in the AI
tool) reasoning and talking. The MCP cannot *be* the conversation; its job is to
make the host LLM's conversation and planning **grounded instead of guessed.**

> The MCP provides self-describing data and action verbs.
> The host LLM provides the conversation, judgment, and adaptation to skill level.

Trying to build "conversation" or "planning" as tools fights the grain. Instead
we make the **scan** and **fix** verbs excellent, and make the **payload rich
enough** that the LLM nails the conversation and the plan on its own.

Concrete failure this prevents: asked "what gets me to a C grade?", an agent gave
a perfect answer — but only because it could read `plain_english.py`'s grader.
A real user's agent, scanning their own repo, has no access to our internals and
would guess the thresholds. The fix is not a "grading tool" — it is putting the
**grade model into the scan payload** so the LLM never has to guess.

### Responsibility split

| # | Need | Who does it | What the MCP must provide |
|---|---|---|---|
| 1 | Scan → report | MCP tool (`scan`) | findings + grade + counts |
| 2 | Converse about meaning / priority | **Host LLM** | payload it can reason over without guessing: plain **and** technical register, priority rationale, **grade model + path-to-grade**, root-cause themes |
| 3 | Plan the fixes | **Host LLM** | per-finding remediation + walkthroughs + fix ordering / dependency hints |
| 4 | Run individual fixes | MCP tools (`explain`, `fix`, `verify`) | deep-dive text, a fix brief (host writes + applies the patch), and re-scan verification |

## Discoverability: the agent must invoke it on its own

Real users don't say "call the isitsecure scan tool." They say *"run a security
audit"*, *"scan for vulnerabilities"*, or *"is this safe to ship?"* and expect
the agent to reach for the tool unprompted. Whether that happens is driven by the
metadata the server advertises, in priority order:

1. **Server `instructions`** (surfaced in the MCP initialize response) — a
   when-to-use / when-not-to-use blurb telling the host LLM to use `scan` for any
   security-audit/vulnerability/"safe to ship" request, even when isitsecure
   isn't named. Set via `FastMCP("isitsecure", instructions=...)`.
2. **Tool description** — leads with "Security audit / vulnerability scan …" and
   the trigger phrases, not just "scan a repo".
3. **Tool name** — namespaced as `isitsecure/scan`.

Honest caveat: this maximizes the odds but can't *guarantee* invocation — it's
ultimately the host LLM's call and varies by client (Cursor / Claude Code /
Claude Desktop), some of which also gate tools behind user approval.

## Tool surface

```
scan(path, min_severity="medium")                      → report + grade model + themes (code-only; no mode argument)
explain(scan_id, finding_id)                           → deep dive: plain + technical + walkthrough
fix(scan_id, finding_id)                               → return a fix brief (finding + source + patterns); the HOST LLM writes + applies the patch
  (proposed, NOT implemented: an `apply=true` fallback — the tool takes no `apply` argument and never writes files)
verify(scan_id)                                        → re-scan, report findings cleared + grade movement
export(scan_id, format="markdown")                     → render html/sarif/json/markdown; the HOST writes it
scan_url(url, min_severity="medium")                   → start a DAST (live-URL) scan; returns a job_id
scan_status(job_id)                                    → poll a DAST job; the full result when done
```

- **`scan`** *(implemented, #58 + #68).* Runs a fast code-only (SAST) scan on a
  local repo. Returns a typed result: a `scan_id`, grade, launch verdict,
  severity counts, **`path_to_next_grade`** (what it takes to reach each better
  grade — so an assistant answers "what gets me to a C?" without our grader),
  root-cause **themes**, and trimmed findings each with a plain-English
  explanation (what-it-is / attacker-could / how-to-fix) and a priority. When
  part of the scan did not run (ingestion error, scanner timeout or crash, skipped
  review work) the result carries `incomplete: true` and the `coverage_gaps`;
  `safe_to_launch` is then false and the grade label is provisional. `verify`
  and the markdown `export` apply the same rule.
- **`explain`** *(implemented, #70).* `explain(scan_id, finding_id)` — deep dive
  on one finding resolved from the scan cache. Leads with the finding's **own**
  generated text (description, technical detail, evidence, the vulnerable
  snippet) so it's specific to that finding, not the category blurb the scan list
  carries; plus business impact, stack-tailored remediation, and a step-by-step
  walkthrough. The finding text and snippet are **redacted** (shared evidence
  redactor, #282; best-effort regex masking, not a DLP guarantee), as are `scan`
  titles and every `export` format. (Its per-finding accuracy relies on correct categorization —
  #64 added the `BUSINESS_LOGIC` category and tightened the classifier so
  payment/idempotency/race findings and error-disclosure land in the right
  bucket instead of the `auth`/`injection` catch-alls.)
- **`fix`** *(implemented, #59; reworked to a host-does-the-work brief).*
  `fix(scan_id, finding_id)` reads the finding's source file and returns a **fix
  brief** — the finding (title, severity, description, guidance, line), the full
  `file_content`, the common `fix_patterns` and `guidelines` — with
  `applied: false`. The brief's finding text (title, description, guidance) is
  redacted like `explain`, but **`file_content` is intentionally unredacted**: it
  is the user's own local source and the host must receive it exactly to edit the
  file. A fix the host writes may therefore echo secret-shaped strings from that
  source. The MCP makes **no LLM call**, so it needs **no API key**: the
  **host LLM writes the patch and applies it** with its own editor (see "Who
  applies the fix" below), then `verify` confirms. The CLI and web UI keep using
  `FixGenerator`. The file is read with the same strict reader as the CLI and web
  fixes: confined to the scanned repo, never `.git/`, strict UTF-8 with CRLF/LF
  newlines exactly as on disk (so `file_content` never has its line endings
  rewritten or replacement characters baked in). A file that can't be read
  faithfully (non-UTF-8, oversize, outside the repo) is refused with a clear
  reason instead of being fixed lossily. *Not built (and not on the roadmap for
  this tool):* the `apply=true` safety-net fallback described below stays a
  proposal.
- **`verify`** *(implemented, #71).* `verify(scan_id)` re-scans the same path and
  reports which findings cleared vs. still present, the grade **before → after**,
  and a fresh `scan_id` for the new state so the loop continues. Both the
  resolved/still-present counts and the grade movement reflect only *verifiable*
  rule-based SAST findings; LLM/DAST findings are counted `unverifiable` and held
  constant (a code re-scan can't reliably reproduce them), so LLM non-determinism
  can never inflate or deflate the grade. If the re-scan cannot run to completion
  (no report), `verify` errors with "Could not verify" instead of reporting anything
  as resolved. A finding whose scanner failed, timed out or did not run in the
  re-scan (for example the optional `isitsecure[taint]` Semgrep is not installed,
  or semgrep could not parse a file the fix broke) is counted `unverifiable`, never
  resolved, and held constant in the grade; a missing optional Semgrep is called
  out in the `summary` but does not by itself make the result `incomplete`, while
  any other scanner failure does. A finding that disappeared from a file that no longer parses (checked by `fixes/parse_check.py`, since the scanners skip such files silently) is unverifiable too. A finding whose code now appears in another file
  is reported under `possibly_moved` (also unverifiable). `verify`, `isitsecure
  verify` and the `fix` re-check share one classifier. A malformed report gives a
  "Could not compare the scans" error. The visible reward that closes the loop.
- **`export`** *(implemented, #88).* `export(scan_id, format)` renders a **cached**
  scan (no re-scan) as `html` | `sarif` | `json` | `markdown` and **returns the
  content** for the host to save — the MCP does not write files (same stance as
  `fix`). Reuses the engine's HTML/SARIF renderers; SARIF feeds GitHub code
  scanning. Every format is redacted first (shared evidence redactor, #282), so
  an export never carries raw emails, SSNs, tokens or credential values from
  finding evidence. Rendering from the cache is why this lives in the MCP and not only the
  stateless CLI.
- **`scan_url` / `scan_status`** *(implemented, #60).* DAST (live-URL) scanning
  takes minutes, so it uses a **job handle** rather than one long blocking call:
  `scan_url(url)` starts a background url-only DAST scan and returns a `job_id`
  immediately; `scan_status(job_id)` returns `running | done | error` with a 0–1
  `progress`, and — once done — the full result (same shape as `scan`, whose
  `scan_id` works with `explain`/`export`). The URL must be reachable from the
  machine running the server.

## State & identity: the scan cache

The conversational loop assumes the user can say *"explain the SQLi one"* or
*"fix #3"* across turns. That requires **stable finding IDs that persist across
the conversation**, and `explain`/`fix`/`verify` must resolve a finding from a
**prior** scan.

**Implemented (#69):** `scan` returns a `scan_id` and caches the full report in
the spawned server process, bounded to the most recent scans. `get_finding(scan_id,
finding_id)` resolves a finding from a prior scan — the foundation the
`explain`/`fix`/`verify` tools build on. (On-disk persistence under
`~/.isitsecure/scans/<scan_id>.json` to survive a restart is a possible later
add; in-process is enough for a single session's scan → fix loop.)

## Who applies the fix (the central decision)

Need 4 mutates the user's code — the riskiest capability here. **In the MCP
context, `fix` returns a brief (finding + source + patterns) and the *host LLM*
writes and applies the patch. The MCP neither calls an LLM nor writes files.** Reasoning:

1. **The host tool already has world-class edit UX** (Cursor, Claude Code) —
   diff review, apply, undo, approval gates. Writing files ourselves bypasses all
   of it and fights the environment the user chose.
2. **Single writer = coherence.** If the agent applies the change, its context
   still matches disk. If we silently rewrite files, the agent's mental model
   drifts and its later advice goes wrong.
3. **Less scary.** "Here's the fix, want me to apply it?" in the user's normal
   review flow beats "the security tool rewrote 5 of your files." Matches the
   Wave 2 dry-run-by-default philosophy.
4. **A fix applied *with understanding* beats a blind patch.** Applying with our
   metadata (the vuln, the fix pattern, framework context, constraints), the host
   LLM adapts imports/style to the surrounding code — often better-integrated
   than pasting our diff verbatim.

**The host writes the patch; we supply the grounding.** `fix` returns the finding
metadata (`finding_id`, `file`, `line`, `title`, `category`, `severity`,
`description`, `guidance`), the full `file_content`, the common `fix_patterns`
and `guidelines`, and `applied: false`. No diff is generated: the host LLM, which
already has the user's model and context, adapts the fix to the surrounding code.
This is also why `fix` needs no API key over MCP. *Planned:* an explicit
fix-pattern label, constraints (e.g. "preserve the public API"), and a confidence
score.

**Quality is preserved by `verify`, not by applying.** Whoever holds the pen,
`verify(scan_id)` re-scans and confirms the finding is actually gone **for
rule-based findings** (LLM/DAST findings are reported `unverifiable`), and reports
grade movement (F → D) attributable to that verified change. This **decouples the
quality gate from who does the
writing**, which is exactly what makes "let the host apply" safe. No assuming
success.

### Why this differs from the CLI

`isitsecure fix` on the CLI has **no host LLM**, so it *must* generate and apply the fix
itself (`FixGenerator` + safety-net backup → write → re-scan verify; needs an LLM
key). The MCP **always** has a capable agent, so it defers both the patch and the
write. Same product, opposite right-answer per context —
recorded here so the divergence is intentional, not an inconsistency.

### `apply=true` — the optional fallback (proposal only, not implemented)

For headless/non-agent callers, or a user who explicitly wants us to do it,
`fix(..., apply=true)` *would* write via our Wave 2 pipeline: **back up the file about to
change (safety net) → write one finding's fix → re-scan to verify**. If the
re-scan cannot run, the result says so and nothing is reported as resolved. Still one finding at
a time; never a "fix everything" over MCP.

## Skill-level adaptation

Different users are at different levels — but the MCP does **not** adapt tone; the
host LLM does that naturally. Our job is to keep **both registers in the
payload** (plain-English *and* technical detail), which Wave 1/2 already do, so
the LLM can pitch a nervous beginner or a senior engineer from the same data. An
optional `audience`/`min_severity` hint can keep a beginner from being shown 68
findings at once.

## Sequencing & definition of done

- **Done:** `scan` thin slice (#58).
- **MVP that satisfies all four needs:** `scan` (enriched with the grade model +
  themes) + `explain` + `fix` + `verify` + the **scan-cache/identity** layer.
- Ship incrementally on branches; only present the MCP as "complete" once the MVP
  above works end-to-end for all four needs.

## Out of scope (for now)

- **Hosted / multi-user MCP** — this is a local stdio server, spawned per user by
  their own tool. Nothing is hosted.
- **Authenticated / full DAST over MCP** — `scan_url` does *url-only* DAST;
  authenticated crawls (credentials) and full SAST+DAST runs stay CLI-side for now.

## Open questions

- **Scan-cache lifetime** — in-process only (simplest; lost on restart) vs.
  on-disk under `~/.isitsecure/scans/` (survives, but needs cleanup/expiry).
- **`verify` cost** — a full re-scan with LLM review is slow; can we scope
  verification to changed files or run rule-based-only for speed?
- **Multi-file fixes** — some findings (e.g. add RLS across tables) span files;
  how does `fix` present and apply those safely under the one-finding-at-a-time rule?
- **Grade-path shape** — exact schema of the `path_to_next_grade` field the LLM
  reads to answer "what gets me to a C?".
