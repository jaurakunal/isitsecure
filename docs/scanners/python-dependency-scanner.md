# Python Dependency Scanner

**Type:** SAST | **Severity:** Critical–Low | **Category:** Dependency Vulnerability

## What It Does

Scans Python dependency files for known vulnerable packages:

- **requirements.txt** (and files whose name starts with `requirements` and ends in `.txt`, like requirements-dev.txt; files in a `requirements/` folder such as `requirements/base.txt` are not read)
- **pyproject.toml** dependencies, only when the array opens on its own line as `dependencies = [` or sits under `[project.dependencies]`, with double-quoted entries (single-quoted entries and one-line arrays are skipped)
- Checks 13 common packages against a built-in CVE database (High 0.85 confidence). Severity per entry runs from Critical to Medium
- Flags unpinned requirements.txt dependencies (no version specifier) as Low severity, confidence 0.60; pyproject.toml entries are not checked for pinning

The version comparison uses the first version number on the line and ignores the operator, so `django>=4.2.8` is treated like `django==4.2.8`. A version that falls in two ranges of one package (for example old Django) yields one finding per range.

Known vulnerability database includes: Django, Flask, FastAPI, PyJWT, cryptography, SQLAlchemy, Jinja2, Werkzeug, Pillow, urllib3, Paramiko, PyYAML, Requests.

## Why It Matters

Python's ecosystem has the same dependency vulnerability problems as npm:

- **Unpatched Django** — CVE-2023-46695 (DoS), CVE-2023-41164 (DoS via URI validation)
- **PyJWT < 2.4.0** — CVE-2022-29217: Algorithm confusion attack allows token forgery
- **PyYAML < 6.0.1** — Arbitrary code execution via `yaml.load()`

## Real-World Breaches

**Log4Shell pattern in Python**: While Log4Shell was Java-specific, the same class of vulnerability (RCE via deserialization) exists in Python packages like PyYAML and Pickle. Unpatched dependencies are the most common attack vector across all languages.

## How to Fix

```bash
# Check for vulnerabilities
pip audit

# Upgrade to safe versions
pip install --upgrade django flask pyjwt

# Pin all dependencies
pip freeze > requirements.txt

# Use Dependabot or Renovate for automated updates
```
