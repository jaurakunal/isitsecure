# Python Dependency Scanner

**Type:** SAST | **Severity:** Critical–Medium | **Category:** Dependency Vulnerability

## What It Does

Scans Python dependency files for known vulnerable packages:

- **requirements.txt** (and variants like requirements-dev.txt)
- **pyproject.toml** `[project.dependencies]`
- Checks 13 common packages against a built-in CVE database
- Flags unpinned dependencies (no version specifier)

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
