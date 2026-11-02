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
signing, and points ``GIT_CONFIG_GLOBAL`` at the null device with
``GIT_CONFIG_NOSYSTEM=1``: the operator's global/system git config (identity,
hooks, gpg, and above all ``url.<x>.insteadOf`` rewrites that could send the
clone/push over ssh and around the token) is never consulted. Proxy settings
must therefore come from the standard ``HTTPS_PROXY``/``NO_PROXY`` environment
variables, not from ``~/.gitconfig``.

POSIX gets a fresh process group per command so a timeout/cancel kills git and
its children. Windows has no process groups here: ``taskkill /T`` (or a plain
``kill``) is used instead.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import signal
import subprocess

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


# Git's own status line for a refused ref: `` ! [rejected] HEAD -> x (non-fast-forward)``.
# Anchored at the line start, so hook output (always prefixed ``remote:``) that
# merely quotes those words can never match.
_NFF_STATUS_LINE = re.compile(
    r"^\s*!\s*\[(?:remote )?rejected\][^\n]*\((?:non-fast-forward|fetch first|stale info)\)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def is_non_fast_forward(git_error: str) -> bool:
    """True only when git itself reports the push refused because the branch diverged.

    Matches git's ``! [rejected] ... (non-fast-forward | fetch first | stale
    info)`` status lines only. Every other rejection (pre-receive hook,
    protected branch, push protection, missing token scope, size limits), and
    any hook message that happens to quote those words, is a different problem
    and must surface its real message rather than be mislabelled as "branch
    already exists".
    """
    return bool(_NFF_STATUS_LINE.search(git_error))


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
    allow_protocol: str | None = None,
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """Environment for a git child process (see module docstring)."""
    env = dict(os.environ if base is None else base)
    env.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": allow_protocol or DEFAULT_ALLOW_PROTOCOL,
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
        allow_protocol: str | None = None,
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
            # Own process group (POSIX), so a timeout/cancel can kill git AND
            # whatever it spawned (ssh, credential helper, gpg, hooks).
            start_new_session=_process_groups_supported(),
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


def _process_groups_supported() -> bool:
    return os.name == "posix" and hasattr(os, "killpg") and hasattr(signal, "SIGKILL")


def _kill_tree(proc: asyncio.subprocess.Process) -> None:
    """Kill ``proc`` and, where the platform allows, everything it spawned."""
    if _process_groups_supported():
        try:
            os.killpg(proc.pid, signal.SIGKILL)
            return
        except (OSError, AttributeError):
            pass
    elif os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                capture_output=True, timeout=10, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        proc.kill()
    except (ProcessLookupError, OSError):
        pass


async def _kill_and_reap(proc: asyncio.subprocess.Process) -> None:
    """Kill the child (tree) and wait for it to exit."""
    _kill_tree(proc)

    async def _reap() -> None:
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:  # noqa: BLE001 — best effort, but never silent
            logger.debug("git child %s was not reaped within 5s", proc.pid, exc_info=True)

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


def is_valid_branch_name(name: str) -> bool:
    """True when ``name`` is a safe, git-valid branch name.

    Defers to ``git check-ref-format --branch`` (so ``rel/v1.0+b``,
    ``dep/foo@1.2`` and ``feature/é`` pass while ``a/.b`` and ``x.lock/y`` do
    not) and additionally refuses option-like names, ``refs/...`` spellings and
    reflog syntax.
    """
    if (
        not name
        or len(name.encode("utf-8", "replace")) > 200
        or name.startswith(("-", "refs/"))
        or "@{" in name
        or name == "@"
        or "\x00" in name
    ):
        return False
    try:
        proc = subprocess.run(
            ["git", "check-ref-format", "--branch", name],
            capture_output=True, timeout=10, check=False,
            env=build_git_env(None),
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0 and proc.stdout.decode("utf-8", "replace").strip() == name


async def clone_repo(
    repo_url: str,
    branch: str,
    dest: str,
    token: str | None,
    *,
    allow_protocol: str | None = None,
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
