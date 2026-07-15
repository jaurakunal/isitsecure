# isitsecure MCP — Design

Status: **living design doc.** The `scan` tool (thin slice, #58) is implemented;
everything past it is proposed and subject to change. This doc is the contract we
build to — argue it here before writing code.

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
| 4 | Run individual fixes | MCP tools (`explain`, `fix`, `verify`) | deep-dive text, a proposed/applied diff, and re-scan verification |

## Tool surface

```
scan(path, mode="code-only", min_severity="medium")   → report + grade model + themes
explain(scan_id, finding_id)                           → deep dive: plain + technical + walkthrough
fix(scan_id, finding_id)                               → return a diff + metadata; the HOST LLM applies it
fix(scan_id, finding_id, apply=true)                   → (optional fallback) apply via our safety-net pipeline
verify(scan_id)                                        → re-scan, report findings cleared + grade movement
```

- **`scan`** *(implemented, #58 — to be enriched).* Runs a fast code-only (SAST)
  scan on a local repo. Returns a typed result: grade, launch verdict, severity
  counts, and trimmed findings, each with a plain-English explanation
  (what-it-is / attacker-could / how-to-fix). **To add:** the grade model +
  path-to-next-grade, root-cause themes, and per-finding priority rationale, so
  needs 2–3 are grounded.
- **`explain`** *(proposed, #59).* Deep dive on one finding: full plain-English +
  technical detail + step-by-step walkthrough + framework-aware remediation
  (Wave 2 already produces all of this — the tool surfaces it per finding).
- **`fix`** *(proposed, #59).* Generates a fix for one finding and **returns a
  diff + the metadata to apply it well** — the host LLM does the writing (see
  "Who applies the fix" below). An optional `apply=true` is a fallback that
  applies via our own safety-net pipeline.
- **`verify`** *(proposed, #53/#50).* Re-scans and reports which findings are now
  resolved and how the grade moved — the visible reward that closes the loop.

## State & identity: the scan cache

The conversational loop assumes the user can say *"explain the SQLi one"* or
*"fix #3"* across turns. That requires **stable finding IDs that persist across
the conversation**, and `explain`/`fix`/`verify` must resolve a finding from a
**prior** scan. Today `scan` returns fresh UUIDs each call with no memory.

**Design:** `scan` persists its result under a `scan_id` (in the spawned server
process for the session; optionally `~/.isitsecure/scans/<scan_id>.json` to
survive a restart). `explain`/`fix`/`verify` take `(scan_id, finding_id)` and look
findings up. Without this layer, the loop breaks the moment the user references
"that one." This is the single biggest new piece beyond the thin slice.

## Who applies the fix (the central decision)

Need 4 mutates the user's code — the riskiest capability here. **In the MCP
context, `fix` returns a diff + metadata and the *host LLM* applies it. The MCP
does not write files by default.** Reasoning:

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

**The diff is a reference implementation, not a mandate.** `fix` therefore returns:
a unified diff, the full fixed-file content (so the agent *can* apply verbatim),
the vulnerability explanation, the fix pattern, constraints (e.g. "preserve the
public API"), the `finding_id`, and a confidence score.

**Quality is preserved by `verify`, not by applying.** Whoever holds the pen,
`verify(scan_id)` re-scans and confirms the finding is actually gone and reports
grade movement (F → D). This **decouples the quality gate from who does the
writing**, which is exactly what makes "let the host apply" safe. No assuming
success.

### Why this differs from the CLI

`isitsecure fix` on the CLI has **no host LLM**, so it *must* apply the fix itself
(safety-net backup → write → re-scan verify). The MCP **always** has a capable
agent, so it defers the write. Same product, opposite right-answer per context —
recorded here so the divergence is intentional, not an inconsistency.

### `apply=true` — the optional fallback

For headless/non-agent callers, or a user who explicitly wants us to do it,
`fix(..., apply=true)` writes via our Wave 2 pipeline: **back up the working tree
(safety net) → write one finding's fix → re-scan to verify**. Still one finding at
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

- **DAST over MCP** (live-URL scanning with progress streaming) — tracked
  separately (#60); code-only SAST is the fast, natural fit for the coding loop.
- **Hosted / multi-user MCP** — this is a local stdio server, spawned per user by
  their own tool. Nothing is hosted.

## Open questions

- **Scan-cache lifetime** — in-process only (simplest; lost on restart) vs.
  on-disk under `~/.isitsecure/scans/` (survives, but needs cleanup/expiry).
- **`verify` cost** — a full re-scan with LLM review is slow; can we scope
  verification to changed files or run rule-based-only for speed?
- **Multi-file fixes** — some findings (e.g. add RLS across tables) span files;
  how does `fix` present and apply those safely under the one-finding-at-a-time rule?
- **Grade-path shape** — exact schema of the `path_to_next_grade` field the LLM
  reads to answer "what gets me to a C?".
