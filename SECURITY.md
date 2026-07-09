# Security Policy

isitsecure is a security tool, so we take the security of the tool itself
seriously — including the ways it handles your source code, API keys, and the
targets it scans.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately using **GitHub's private vulnerability reporting**:
[Security → Report a vulnerability](https://github.com/jaurakunal/isitsecure/security/advisories/new).
If that is unavailable, email the maintainer at **kunaljaura@gmail.com** with
`[SECURITY]` in the subject.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal proof of concept if possible),
- affected version / commit, and
- any suggested remediation.

## What to expect

- **Acknowledgement** within 3 business days.
- An initial assessment and severity within 7 days.
- We will keep you updated on remediation progress and coordinate a disclosure
  timeline with you. We aim to fix high-severity issues promptly and will credit
  reporters who wish to be named.

## Scope

In scope — vulnerabilities in isitsecure itself, for example:

- code execution or file access via a crafted repo URL, scan target, LLM
  response, or fix-apply path;
- leakage of API keys, tokens, or scanned source code;
- authentication/authorization flaws in the local web server (`isitsecure launch`).

Out of scope — findings that the tool *reports* about a third-party app you
scan (those belong to that app's maintainers), and issues in dependencies
(report those upstream, though we welcome a heads-up).

## Supported versions

isitsecure is pre-1.0 (`0.x`). Only the latest release / `main` receives
security fixes.
