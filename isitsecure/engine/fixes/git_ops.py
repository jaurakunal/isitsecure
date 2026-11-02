"""Git process boundary for the remote fix → PR flow.

``GitRunner`` runs one git command at a time with a hard timeout, no prompts and
no interactive credential/gpg helpers, and kills + reaps the child on timeout or
task cancellation.

TOKEN HANDLING: the GitHub token is never placed in a URL, in argv or in
``.git/config``. It reaches git only through environment variables
(``GIT_CONFIG_COUNT``/``GIT_CONFIG_KEY_n``/``GIT_CONFIG_VALUE_n``) that install
an ``http.<github>.extraheader`` Authorization header for that one process, so
nothing token-bearing persists in the clone.

The same environment pins a bot commit identity and disables hooks and gpg
signing, so commits made in the temp clone never depend on (or leak) the
operator's global git configuration.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import signal

logger = logging.getLogger(__name__)

# Per-command ceiling (checkout/add/commit/push/ls-remote). Clone has its own
# larger one. Module constants so deployments/tests can tune them.
GIT_COMMAND_TIMEOUT_SECONDS = 120.0
GIT_CLONE_TIMEOUT_SECONDS = 300.0

# Restrict git to safe transports (ext::/fd:: run commands; file:// reads local).
DEFAULT_ALLOW_PROTOCOL = "https:http:ssh:git"

# Bot identity for commits made in the temp clone.
BOT_NAME = "isitsecure[bot]"
BOT_EMAIL = "isitsecure-bot@users.noreply.github.com"

_GITHUB_EXTRAHEADER_KEY = "http.https://github.com/.extraheader"


class GitError(RuntimeError):
    """A git command failed. The message is already token-scrubbed."""


class GitTimeoutError(GitError):
    """A git command exceeded its timeout and was killed."""


def is_non_fast_forward(git_error: str) -> bool:
    """True only when a push was refused because the remote branch has diverged.

    Git words that rejection ``(non-fast-forward)`` or ``(fetch first)`` (or
    ``(stale info)`` for leased pushes). Every other ``[remote rejected]``
    reason (pre-receive hook, protected branch, push protection, missing token
    scope, size limits) is a different problem and must surface its real
    message rather than be mislabelled as "branch already exists".
    """
    lowered = git_error.lower()
    return any(
        marker in lowered
        for marker in ("non-fast-forward", "fetch first", "stale info")
    )


def _config_pairs(token: str | None) -> list[tuple[str, str]]:
    pairs = [
        ("core.hooksPath", os.devnull),
        ("commit.gpgsign", "false"),
        ("tag.gpgsign", "false"),
        ("credential.helper", ""),
    ]
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        pairs.append((_GITHUB_EXTRAHEADER_KEY, f"AUTHORIZATION: basic {basic}"))
    return pairs


def build_git_env(
    token: str | None,
    *,
    allow_protocol: str = DEFAULT_ALLOW_PROTOCOL,
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """Environment for a git child process (see module docstring)."""
    env = dict(os.environ if base is None else base)
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": allow_protocol,
            "GCM_INTERACTIVE": "never",
            "GIT_ASKPASS": "true",
            "SSH_ASKPASS": "true",
            "GIT_SSH_COMMAND": "ssh -o BatchMode=yes",
            "GIT_AUTHOR_NAME": BOT_NAME,
            "GIT_AUTHOR_EMAIL": BOT_EMAIL,
            "GIT_COMMITTER_NAME": BOT_NAME,
            "GIT_COMMITTER_EMAIL": BOT_EMAIL,
        }
    )
    try:
        start = int(env.get("GIT_CONFIG_COUNT", "0"))
    except ValueError:
        start = 0
    pairs = _config_pairs(token)
    for offset, (key, value) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{start + offset}"] = key
        env[f"GIT_CONFIG_VALUE_{start + offset}"] = value
    env["GIT_CONFIG_COUNT"] = str(start + len(pairs))
    return env


class GitRunner:
    """Runs git commands in a working tree. Token is scrubbed from any output."""

    def __init__(
        self,
        token: str | None = None,
        *,
        timeout: float | None = None,
        allow_protocol: str = DEFAULT_ALLOW_PROTOCOL,
    ) -> None:
        self._token = token
        self._timeout = timeout
        self._allow_protocol = allow_protocol

    def _scrub(self, text: str) -> str:
        if not self._token:
            return text
        basic = base64.b64encode(f"x-access-token:{self._token}".encode()).decode()
        for secret in (self._token, basic):
            text = text.replace(secret, "***")
        return text

    async def run(self, cwd: str, *args: str, timeout: float | None = None) -> str:
        limit = timeout or self._timeout or GIT_COMMAND_TIMEOUT_SECONDS
        proc = await asyncio.create_subprocess_exec(
            "git", "-C", cwd, *args,
            stdin=asyncio.subprocess.DEVNULL,
            # Own process group, so a timeout/cancel can kill git AND whatever it
            # spawned (ssh, credential helper, gpg, hooks) rather than orphan it.
            start_new_session=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=build_git_env(self._token, allow_protocol=self._allow_protocol),
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=limit)
        except asyncio.TimeoutError:
            await _kill_and_reap(proc)
            raise GitTimeoutError(
                f"git {args[0] if args else ''} timed out after {limit:g}s"
            ) from None
        except asyncio.CancelledError:
            await _kill_and_reap(proc)
            raise
        stdout = out.decode(errors="replace").strip()
        stderr = err.decode(errors="replace").strip()
        if proc.returncode != 0:
            raise GitError(self._scrub(stderr or stdout or "git failed"))
        return self._scrub(stdout)


async def _kill_and_reap(proc: asyncio.subprocess.Process) -> None:
    """SIGKILL the child's whole process group, then wait for it to exit."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        try:
            proc.kill()
        except ProcessLookupError:
            return

    async def _reap() -> None:
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:  # noqa: BLE001 — best effort
            pass

    # Shield: the reap must finish even while the caller is being cancelled.
    await asyncio.shield(_reap())


async def remote_branches(
    git: GitRunner, cwd: str, branches: list[str]
) -> set[str]:
    """Which of ``branches`` already exist on ``origin`` (one ``ls-remote``)."""
    if not branches:
        return set()
    wanted = {f"refs/heads/{b}" for b in branches}
    out = await git.run(cwd, "ls-remote", "--heads", "origin", *sorted(wanted))
    found: set[str] = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] in wanted:
            found.add(parts[1][len("refs/heads/"):])
    return found


_SAFE_BRANCH = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]*$")


def is_valid_branch_name(name: str) -> bool:
    """Conservative branch-name check (no option-injection, no odd ref syntax)."""
    return (
        bool(name)
        and len(name.encode()) <= 200
        and bool(_SAFE_BRANCH.match(name))
        and ".." not in name
        and "//" not in name
        and not name.endswith((".lock", "/", "."))
    )


async def clone_repo(
    repo_url: str,
    branch: str,
    dest: str,
    token: str | None,
    *,
    allow_protocol: str = DEFAULT_ALLOW_PROTOCOL,
) -> None:
    """Clone ``repo_url`` (full history) into the existing, empty ``dest`` dir.

    The URL stays token-free; auth rides on the environment (see module doc).
    """
    from isitsecure.engine.code_analysis.repo_ingestion import RepoIngestionService
    from isitsecure.engine.constants import RepoIngestionConfig

    # Same arg-injection / unsafe-transport guard the scanner clone uses.
    RepoIngestionService._validate_remote(repo_url, branch)  # noqa: SLF001
    runner = GitRunner(token, timeout=GIT_CLONE_TIMEOUT_SECONDS,
                       allow_protocol=allow_protocol)
    try:
        await runner.run(
            os.path.dirname(dest) or ".",
            "clone", "--branch", branch, "--", repo_url, dest,
        )
    except GitTimeoutError:
        raise RuntimeError(
            RepoIngestionConfig.ERROR_CLONE_TIMEOUT.format(
                timeout=GIT_CLONE_TIMEOUT_SECONDS
            )
        ) from None
    except GitError as exc:
        lowered = str(exc).lower()
        if "remote branch" in lowered and "not found" in lowered:
            raise RuntimeError(
                RepoIngestionConfig.ERROR_BRANCH_NOT_FOUND.format(branch=branch)
            ) from None
        if "repository not found" in lowered:
            raise RuntimeError(
                RepoIngestionConfig.ERROR_REPO_NOT_FOUND.format(repo_url=repo_url)
            ) from None
        raise RuntimeError(
            RepoIngestionConfig.ERROR_CLONE_FAILED.format(error=exc)
        ) from None
