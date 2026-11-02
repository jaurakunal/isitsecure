"""parse_check: the "does it still parse?" gate used before writing and after fixing."""

from __future__ import annotations

from pathlib import Path

import pytest

from isitsecure.engine.fixes.parse_check import (
    introduced_syntax_problem,
    syntax_problem,
    unparseable_files,
)

FIXTURES = Path(__file__).resolve().parents[2] / "benchmarks" / "fixtures" / "sast-injection"


@pytest.mark.parametrize("path", sorted(p for p in FIXTURES.rglob("*") if p.is_file()),
                         ids=lambda p: p.name)
def test_real_benchmark_sources_all_pass(path: Path) -> None:
    assert syntax_problem(path.name, path.read_text()) is None


@pytest.mark.parametrize("path", sorted(p for p in (FIXTURES / "vulnerable").rglob("*") if p.is_file()),
                         ids=lambda p: p.name)
def test_truncated_real_sources_are_caught(path: Path) -> None:
    text = path.read_text()
    # A reply cut off at an output limit: drop everything after the first opening
    # brace's body begins, leaving something unclosed.
    cut = text[: text.rindex("}")] if "}" in text else text
    if path.suffix == ".py":
        cut = text.rstrip() + "\nx = (1,\n"
    assert syntax_problem(path.name, cut) is not None


@pytest.mark.parametrize("name,text", [
    ("a.ts", "function f() { if (x) { run(); }\n"),
    ("a.ts", "const s = `abc ${x\n"),
    ("a.js", "const a = [1, 2;\n"),
    ("a.js", "const a = 'oops\n"),
    ("A.java", "class A { void f() { call(; } }\n"),
    ("a.go", "func f() {\n"),
    ("a.kt", "fun f() { val s = \"\"\"abc\n"),
    ("a.ts", "/* never closed\nconst a = 1;\n"),
    ("a.py", "def f(:\n"),
    ("a.json", "{\"a\": }"),
])
def test_broken_sources_are_rejected(name: str, text: str) -> None:
    assert syntax_problem(name, text)


@pytest.mark.parametrize("name,text", [
    ("a.ts", "const re = /[(\\]]+/g; const x = a / b / c; const t = `a ${f(`b ${1}`)} c`;\n"),
    ("a.js", "const s = \"it's (fine\"; // a comment with ( brace\n/* and { another */\n"),
    ("a.tsx", "const el = <p>Don't panic</p>;\n"),
    ("a.go", "var s = `raw ( string`\nvar r = '('\n"),
    ("A.java", "String s = \"\"\"\n  a ( b\n  \"\"\";\nchar c = '{';\n"),
    ("a.rb", "def broken(\n"),  # no checker for this language: nothing claimed
])
def test_valid_sources_pass(name: str, text: str) -> None:
    assert syntax_problem(name, text) is None


def test_only_problems_introduced_by_the_fix_count() -> None:
    assert introduced_syntax_problem("a.ts", "f(1);\n", "f(1;\n")
    assert introduced_syntax_problem("a.ts", "f(1;\n", "f(1;\n") is None  # already broken
    assert introduced_syntax_problem("a.ts", "f(1);\n", "f(2);\n") is None


def test_unparseable_files_reports_only_broken_readable_files(tmp_path) -> None:
    (tmp_path / "ok.ts").write_text("f();\n")
    (tmp_path / "bad.ts").write_text("f(\n")
    (tmp_path / "binary.ts").write_bytes(b"\xff\xfe\x00")
    res = unparseable_files(str(tmp_path), ["ok.ts", "bad.ts", "binary.ts", "missing.ts", "ok.ts"])
    assert list(res) == ["bad.ts"]
