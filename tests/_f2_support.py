"""Shared helpers for the F2 "no data loss" fix tests: a real temp git repo, real
findings, and a stub LLM (the ONLY thing faked -- reading, generating, applying,
committing and restoring all run for real)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.models import CodeLocation, DeepFinding, FindingSource


def git(repo, *args, check=True) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise AssertionError(f"git {args} failed: {r.stderr}")
    return r.stdout.strip()


def make_repo(tmp_path: Path, files: dict[str, bytes], name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "t@example.com")
    git(repo, "config", "user.name", "t")
    git(repo, "config", "commit.gpgsign", "false")
    git(repo, "config", "core.autocrlf", "false")
    for rel, data in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "init")
    return repo


def make_finding(path: str, *, title: str = "SQLi", severity=SeverityLevel.HIGH,
                 line: int = 1, snippet: str = "") -> DeepFinding:
    return DeepFinding(
        source=FindingSource.SAST_CODE, category=FindingCategory.INJECTION_RISK,
        severity=severity, title=title, description="d", confidence=0.9,
        scanner_name="semgrep_taint",
        code_location=CodeLocation(file_path=path, line_number=line, code_snippet=snippet),
    )


def report_for(repo, findings: list[DeepFinding]) -> dict:
    return {"repo_url": str(repo), "findings": [f.model_dump(mode="json") for f in findings]}


class StubLLM:
    """Replies to the fix prompt with the prompt's own file, BAD -> GOOD.

    ``on_call`` (sync callable) runs before each reply, to simulate things that
    happen while the model is "thinking" (e.g. the user editing a file).
    """

    def __init__(self, on_call=None, reply=None):
        self.calls = 0
        self.prompts: list[str] = []
        self.on_call = on_call
        self.reply = reply

    async def generate_with_system(self, system_prompt, user_prompt, max_tokens=0, **kw):
        self.calls += 1
        self.prompts.append(user_prompt)
        if self.on_call:
            self.on_call(self.calls)
        if self.reply is not None:
            return self.reply
        head, _, rest = user_prompt.partition("Source File:")
        body = rest.split("```\n", 1)[1]
        body = body[: body.rindex("\n```")]
        fixed = body.replace("BAD", "GOOD")
        return f"Replaced the unsafe call.\n```python\n{fixed}\n```"
