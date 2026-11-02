"""Cheap, dependency-free "does this file still parse?" checks.

Used on both sides of a fix: before writing an LLM reply (a truncated or garbled
reply must not be applied) and after (a finding in a file that no longer parses
is not "fixed" just because the scanners now see nothing -- semgrep's
tree-sitter parsers recover from syntax errors silently, exit 0 and report no
error, so an unparseable file looks clean).

Python and JSON are parsed for real. For the brace languages the scanners cover
(JS/TS, Java, Kotlin, Go) a full parser is out of scope, so we check what
truncation and garbling actually break: balanced ``() [] {}`` and terminated
strings/comments/templates. A file this check rejects is reported as *could not
verify*, never as fixed; one it accepts is merely not known to be broken.
"""

from __future__ import annotations

import ast
import json
import os

_BRACE_EXTS = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt", ".kts", ".go"})
_JS_EXTS = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"})
_TEXT_BLOCK_EXTS = frozenset({".java", ".kt", ".kts"})
_OPEN = {"(": ")", "[": "]", "{": "}"}
_CLOSE = {v: k for k, v in _OPEN.items()}
# A '/' after one of these starts a regex literal rather than a division.
_REGEX_PRECEDERS = frozenset("(,=:[!&|?{};+-*%<>~^")


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _balance_problem(text: str, ext: str) -> str | None:
    """Why the brackets/strings in brace-language ``text`` cannot be balanced."""
    js = ext in _JS_EXTS
    go = ext == ".go"
    n = len(text)
    # Entries are (bracket, opened_at, is_template_expr). A template expression
    # (`${ ... }` inside a JS template literal) resumes the template when closed.
    stack: list[tuple[str, int, bool]] = []
    in_template = [False]  # innermost template-literal body is being read
    i = 0
    prev = ""  # previous significant character of code

    while i < n:
        if in_template[-1]:
            c = text[i]
            if c == "\\":
                i += 2
            elif c == "`":
                in_template.pop()
                prev = "`"
                i += 1
            elif text.startswith("${", i):
                stack.append(("{", i, True))
                in_template.append(False)
                i += 2
            else:
                i += 1
            continue

        c = text[i]
        two = text[i:i + 2]
        if c.isspace():
            i += 1
        elif two == "//":
            nl = text.find("\n", i)
            i = n if nl < 0 else nl
        elif two == "/*":
            end = text.find("*/", i + 2)
            if end < 0:
                return f"unterminated comment opened at line {_line_of(text, i)}"
            i = end + 2
        elif ext in _TEXT_BLOCK_EXTS and text.startswith('"""', i):
            end = text.find('"""', i + 3)
            if end < 0:
                return f"unterminated text block opened at line {_line_of(text, i)}"
            i, prev = end + 3, '"'
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                if text[j] == "\\":
                    j += 1
                elif text[j] == "\n":
                    break
                j += 1
            if j >= n or text[j] != c:
                if c == "'" and ext in (".jsx", ".tsx"):
                    i += 1  # an apostrophe in JSX text ("Don't"), not a string
                    continue
                return f"unterminated string opened at line {_line_of(text, i)}"
            i, prev = j + 1, c
        elif c == "`":
            if go:  # raw string
                end = text.find("`", i + 1)
                if end < 0:
                    return f"unterminated raw string opened at line {_line_of(text, i)}"
                i, prev = end + 1, "`"
            elif js:
                in_template.append(True)
                i += 1
            else:
                i += 1
        elif c == "/" and js and (prev == "" or prev in _REGEX_PRECEDERS):
            j, in_class = i + 1, False
            while j < n and text[j] != "\n":
                ch = text[j]
                if ch == "\\":
                    j += 1
                elif ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    break
                j += 1
            if j < n and text[j] == "/":
                i, prev = j + 1, "/"
            else:  # not a regex literal after all: a division
                i, prev = i + 1, "/"
        elif c in _OPEN:
            stack.append((c, i, False))
            i, prev = i + 1, c
        elif c in _CLOSE:
            if not stack or stack[-1][0] != _CLOSE[c]:
                return f"unexpected {c!r} at line {_line_of(text, i)}"
            _opener, _at, template_expr = stack.pop()
            if template_expr:
                in_template.pop()
            i, prev = i + 1, c
        else:
            i, prev = i + 1, c

    if len(in_template) > 1 or in_template[-1]:
        return "unterminated template literal"
    if stack:
        opener, at, _ = stack[-1]
        return f"{opener!r} opened at line {_line_of(text, at)} is never closed"
    return None


def syntax_problem(file_path: str, text: str) -> str | None:
    """Why ``text`` is not a valid ``file_path`` (by extension), or None.

    None means "no problem found", which is not a guarantee: languages without a
    checker here (and anything subtler than bracket/string structure) pass.
    """
    ext = os.path.splitext(file_path)[1].lower()
    if ext in (".py", ".pyi"):
        try:
            ast.parse(text)
        except (SyntaxError, ValueError) as exc:
            return str(exc)
        return None
    if ext == ".json":
        try:
            json.loads(text)
        except ValueError as exc:
            return str(exc)
        return None
    if ext in _BRACE_EXTS:
        return _balance_problem(text, ext)
    return None


def introduced_syntax_problem(file_path: str, original: str, fixed: str) -> str | None:
    """A problem in ``fixed`` that ``original`` did not have, or None.

    If the original is already broken (or trips the heuristic, e.g. an exotic
    regex literal) nothing is claimed about the fix.
    """
    if syntax_problem(file_path, original) is not None:
        return None
    return syntax_problem(file_path, fixed)


def unparseable_files(repo_path: str, rel_paths) -> dict[str, str]:
    """``{rel_path: reason}`` for files under ``repo_path`` that no longer parse.

    Missing or unreadable files are skipped: that is a different failure and is
    not this check's to judge.
    """
    problems: dict[str, str] = {}
    for rel in dict.fromkeys(p for p in rel_paths if p):
        try:
            with open(os.path.join(repo_path, rel), "rb") as fh:
                text = fh.read().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        reason = syntax_problem(rel, text)
        if reason is not None:
            problems[rel] = reason
    return problems
