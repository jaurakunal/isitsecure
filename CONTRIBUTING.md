# Contributing to isitsecure

Thanks for your interest in improving isitsecure! This guide covers local setup,
tests, and how to add a scanner.

## Development setup

Requires Python 3.11+ and `git`.

```bash
git clone https://github.com/jaurakunal/isitsecure.git
cd isitsecure
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[all]"            # all scanners + browser + LLM extras
isitsecure setup                   # installs the Chromium browser for DAST
```

## Running the checks

```bash
pytest                 # the full test suite (~1600 tests)
ruff check isitsecure  # lint
```

Please make sure `pytest` and `ruff check` are green before opening a PR, and
add tests for any behavior you change — the suite is the project's safety net.
Some DAST/browser tests need the `[browser]` extra (Chromium) installed.

## Adding a scanner

Scanners implement a small protocol (`isitsecure/engine/scanners/protocols.py`)
and are registered in `isitsecure/engine/factory.py`. In brief:

1. Add a scanner class with an async `scan(...)` method returning
   `list[DeepFinding]`.
2. Keep detection logic **generic** — no app-specific route names, domains, or
   product identifiers baked into "generic" logic (these are a correctness bug
   and a leak; see the git history for why).
3. Register it in the factory's DAST/SAST list.
4. Add tests with true-positive **and** true-negative fixtures — a scanner that
   only ever fires is as useless as one that never does.

There is a repeatable benchmark harness under `benchmarks/` for measuring recall
and false-positive rates against public vulnerable apps; new detection work is
much more convincing with a benchmark number behind it.

## Pull requests

- Keep PRs focused; one logical change per PR.
- Write a clear description of *what* and *why*.
- Match the surrounding code's style (the repo uses `ruff`).
- By contributing, you agree your work is licensed under Apache-2.0.

## Reporting bugs / security issues

- Non-security bugs and feature requests: open a GitHub issue (templates
  provided).
- Security vulnerabilities: **do not** open a public issue — see
  [SECURITY.md](SECURITY.md).
