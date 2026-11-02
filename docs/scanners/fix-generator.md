# AI Fix Generator

**Type:** LLM-Powered | **Severity:** N/A | **Category:** Remediation

## What It Does

Generates code patches for security findings using LLM. For each critical and high finding that has a source code location (the `fix` command's `--severity` can add medium):

1. Reads the full source file (files over 50,000 bytes are skipped)
2. Sends the finding details + file content to the LLM with a security-aware system prompt
3. Parses the LLM response to extract the fixed code
4. Generates a unified diff between original and fixed code
5. Includes an explanation of what changed and why

Fixes are delivered three ways:
- **Markdown fix plan** (`scan --output fixes`) — diffs + explanations to paste
  into Cursor/Claude Code, `git apply`, or review manually.
- **Local apply + verify** (`fix --repo <path>`) — writes fixes in place
  (git-free), after backing up the files it will change, then **re-scans to confirm each
  finding is resolved** and reports a plain-language summary.
- **Remote clone → per-category PRs** (`fix --repo <github-url>`) — clones,
  fixes, and opens one pull request per finding category (one commit per
  finding) onto feature branches.

## Why It Matters

Finding vulnerabilities is only half the problem. Most developers (especially vibe coders) don't know how to fix:
- SQL injection → parameterized queries
- Missing RLS → correct policy with right column references
- Race condition → database transactions with row locking
- IDOR → ownership verification in the query

The fix generator closes the **find → fix loop**. No other open-source security scanner generates LLM-powered code patches.

## How It Works

The system prompt includes common fix patterns:

| Vulnerability | Fix Pattern |
|---|---|
| SQL injection | Parameterized queries / tagged template literals |
| XSS | HTML escaping, textContent, CSP headers |
| Missing auth | Add getUserFromRequest() check |
| IDOR | Add WHERE user_id = $userId to queries |
| Mass assignment | Explicitly pick allowed fields |
| Race condition | Database transactions with SELECT ... FOR UPDATE |
| Weak JWT | Restrict algorithms, strong secret, add expiration |

## Usage

```bash
# 1. Just give me a plan (Markdown, paste into Cursor / Claude Code)
isitsecure scan --repo ./my-app --output fixes -f fixes.md

# 2. Apply fixes in place on a local repo (git-free; auto-backup + re-scan verify)
isitsecure fix --repo ./my-app
isitsecure fix --repo ./my-app --dry-run          # preview without writing
isitsecure fix --repo ./my-app --severity critical
isitsecure fix --repo ./my-app --technical         # show git/backup details

# 3. Fix a remote GitHub repo → open per-category pull requests
isitsecure fix --repo https://github.com/you/your-app --github-token $GITHUB_TOKEN
isitsecure fix --repo <github-url> --pr-strategy per-file --max-prs 5
```

The local apply flow backs up the files it is about to overwrite first (a git
backup ref when every target is a plain tracked file; otherwise a file-copy backup
kept outside the repo under `~/.isitsecure/backups/<repo>-<hash>/<stamp>`, or
`$ISITSECURE_BACKUP_DIR`; it stops without changing anything if no backup could be
made), writes each file once and atomically (a file you edited since it was read is
left alone, and earlier writes are rolled back if a later one fails), then re-scans to verify findings are resolved and prints how many were
fixed / need review / couldn't be fixed. If the re-scan itself cannot run (for
example the repository cannot be read), nothing is counted as confirmed fixed
and the output says the re-check did not run. If a re-scan scanner fails or
times out, findings from that scanner are reported as could-not-verify, never as
resolved. The `fix` command exits non-zero on any failed write, unfixed finding or
skipped re-check (see the README for the codes). The server Fix All flow follows
the same file rules but works on a clean git tree, commits to a new
`isitsecure/fixes[-N]` branch and restores your branch without `--force` (see
`docs/architecture.md`, section b2, for the caps, cancel and plan fallback). Fixes keep each file's newline
style, trailing newline and UTF-8 BOM; files that are not valid UTF-8, finding paths
outside the repo, and anything under `.git/` are skipped; a reply that is
truncated, ambiguous about its code fences, or identical to the input is
rejected rather than written. The same bracket/string-balance check (JS/TS, Java, Kotlin, Go; Python and JSON are parsed) rejects a reply that is cut off or garbled when the original was fine, and the verification step uses it again on the written file. A reply under 60% of the original length (for
files of 400 characters or more) is treated as truncated, a reply that elides
code with a placeholder (`# ... rest of file unchanged ...`, `// existing code`,
a bare `...`) is rejected, and for Python and JSON files a reply that no longer
parses is rejected (other languages have no cheap checker and are not checked).
A reply cut off by the model's output limit (an unclosed code fence) fails with
an explicit "too large to rewrite whole" message. Findings chained in one file
drop their scan-time line numbers once an earlier fix changed the content.
`FixResult.diff` is a real unified diff that `git apply --check` accepts
(CRLF files and files without a trailing newline included). The verification
re-scan matches a finding on any of its fingerprints, so changing the flagged
line without removing the bug is reported as still present, and a finding whose
equivalent now appears in another file is reported as *possibly moved*
(unverifiable), not resolved. Files with mixed
CRLF/LF line endings are not auto-fixed; CRLF files stay CRLF. `--api-key` applies to the selected `--llm`
provider only; the environment/config key is looked up per provider. The remote flow never pushes to the default branch — fixes land on
feature branches as pull requests; `--max-prs` caps the count (default 8) and
excess low-severity categories batch into one PR. The GitHub token is used only
for the clone, push and PR and is never stored or logged; it is passed to git
through the process environment, never in the clone URL, a command line or
`.git/config`, and the temp clone is a `0700` directory removed afterwards.

Remote-flow behavior worth knowing:

- PRs target the branch the scan ran on (the report's `repo_branch`); with none
  recorded, the default branch is looked up and a failure (401/403/404, a
  renamed repo, a network error) is reported instead of falling back to `main`.
- Branch names are `isitsecure/fix-<slug>-<hash>` for per-file and per-finding
  strategies, so paths that slug alike (`a_b.py`, `a-b.py`) get distinct branches.
- Retries are safe: each planned branch is looked up with `git ls-remote` before
  any LLM call. A branch from an earlier run is never overwritten (no
  force-push); with an open PR it is noted as skipped, without one it is an
  error telling you to open a PR from it or delete it. A branch pushed but whose
  PR could not be opened is listed in the result's `orphaned_branches`.
- Only a genuine non-fast-forward rejection is reported as "branch already
  exists"; any other push rejection (pre-receive hook, protected branch, push
  protection, token scope) shows git's own message with secrets scrubbed.
- Commits are authored as `isitsecure[bot]` with hooks and gpg signing disabled.
  Finding titles/paths in commit messages and PR text are flattened to one
  line, redacted for secret-looking values, and escaped (`@mentions`, images,
  backticks, `#123`). A failed commit is rolled back; a fix that changes nothing
  or targets a symlink is skipped.
- Every git command has a timeout (120 s, clone 300 s) and is killed, with its
  child processes, on timeout or cancellation.

## Configuration

Requires an LLM API key. Uses the same provider configured for the scan (`--llm anthropic` or `--llm google`).

Estimated cost: ~$1-3 per fix plan (depends on number of findings and file sizes).
