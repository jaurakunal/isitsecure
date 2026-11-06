"""Real-semgrep checks for the JS/TS SQL-injection taint rule.

The rule must flag user input reaching the query STRING, and must not flag the
parameterized form where user input is only a bound value. Runs the actual rule
pack, so it is skipped when the optional `semgrep` binary isn't installed.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys

import pytest

RULES = (
    pathlib.Path(__file__).parents[2]
    / "isitsecure/engine/code_analysis/semgrep_rules/injection-js.yaml"
)


def _semgrep() -> str | None:
    found = shutil.which("semgrep")
    if found:
        return found
    sibling = pathlib.Path(sys.executable).with_name("semgrep")
    return str(sibling) if sibling.exists() else None


pytestmark = pytest.mark.skipif(_semgrep() is None, reason="semgrep not installed")


def _sqli_lines(tmp_path, source: str) -> set[int]:
    target = tmp_path / "app.js"
    target.write_text(source)
    out = subprocess.run(
        [_semgrep(), "--metrics=off", "--json", "--config", str(RULES), str(target)],
        capture_output=True, text=True, check=False,
    )
    return {
        r["start"]["line"]
        for r in json.loads(out.stdout)["results"]
        if r["check_id"].endswith("isitsecure-sqli-taint")
    }


@pytest.mark.parametrize("line", [
    "db.query(\"SELECT * FROM u WHERE id = '\" + req.query.id + \"'\", cb);",
    "db.query(`SELECT * FROM u WHERE id = ${req.params.id}`);",
    "const q = req.query.q; db.query(q);",
    "prisma.$queryRawUnsafe('SELECT ' + req.query.c);",
])
def test_flags_user_input_in_query_string(tmp_path, line):
    assert _sqli_lines(tmp_path, line + "\n") == {1}


@pytest.mark.parametrize("line", [
    "db.query('SELECT * FROM u WHERE id = ?', [req.query.id], cb);",
    "db.query('SELECT * FROM u WHERE id = $1', [req.body.id]);",
    "knex.raw('select * from u where id = ?', [req.query.id]);",
])
def test_ignores_user_input_as_bound_parameter(tmp_path, line):
    assert _sqli_lines(tmp_path, line + "\n") == set()
