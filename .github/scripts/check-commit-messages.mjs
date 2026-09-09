#!/usr/bin/env node
// Fails when a commit message cannot be parsed as a Conventional Commit.
//
// release-please reads every commit on main to build the release. A message
// it cannot parse is not an error there — it is skipped, silently, and the
// workflow still reports success. The only trace is a `commit could not be
// parsed` line in the run log, so the first sign of trouble is a release that
// never appears. That has cost this repo two releases.
//
// The parser here is the one release-please itself uses, pinned to the same
// version, rather than a rule of thumb about what breaks it: the failure is
// subtle enough that it was mis-derived twice from examples before anyone
// tried the parser. A line *beginning* with a token that contains nested
// parentheses is the shape that bites — indenting it, or putting a word in
// front of it, is enough — but knowing that is not needed to use this.
//
// Usage: node check-commit-messages.mjs <git-range>

import { parser } from '@conventional-commits/parser'
import { execFileSync } from 'node:child_process'

const range = process.argv[2]
if (!range) {
  console.error('usage: check-commit-messages.mjs <git-range>')
  process.exit(2)
}

const git = (...args) => execFileSync('git', args, { encoding: 'utf8' })
// `--no-merges`: on a pull_request event actions/checkout builds a synthetic
// "Merge <head> into <base>" commit. It is not a Conventional Commit, nobody
// wrote it, and it cannot be reworded — and it never reaches main, since
// pull requests here are squashed.
const shas = git('rev-list', '--no-merges', range).trim().split('\n').filter(Boolean)

if (shas.length === 0) {
  console.log('No commits in range — nothing to check.')
  process.exit(0)
}

let failed = 0

for (const sha of shas) {
  const message = git('log', '-1', '--format=%B', sha)
  const subject = message.split('\n', 1)[0]

  try {
    parser(message)
    console.log(`  ok    ${sha.slice(0, 8)}  ${subject.slice(0, 72)}`)
  } catch (error) {
    failed++
    const detail = String(error.message).split('\n')[0]
    console.error(`  FAIL  ${sha.slice(0, 8)}  ${subject.slice(0, 72)}`)
    console.error(`        ${detail}`)

    // The parser reports "at LINE:COLUMN" against the whole message, so the
    // offending line can be shown rather than described.
    const at = detail.match(/at (\d+):(\d+)/)
    if (at) {
      const line = message.split('\n')[Number(at[1]) - 1]
      if (line !== undefined) {
        const prefix = `        line ${at[1]}: `
        console.error(`${prefix}${line}`)
        console.error(`${' '.repeat(prefix.length + Number(at[2]) - 1)}^`)
      }
    }
    console.error(
      '        Fix: indent the line by four spaces, or put a word before the\n' +
      '        code. See "Commit messages" in CONTRIBUTING.md.'
    )
  }
}

if (failed) {
  console.error(
    `\n${failed} commit message(s) release-please would silently skip.\n` +
    'Reword with `git commit --amend` or `git rebase -i`, then force-push.'
  )
  process.exit(1)
}

console.log(`\n${shas.length} commit message(s) parse cleanly.`)
