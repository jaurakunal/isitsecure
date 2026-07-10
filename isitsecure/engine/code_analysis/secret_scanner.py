"""Git history secret scanner.

Scans the full git history for leaked secrets — API keys, tokens,
credentials, and .env files that were committed and later removed.
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
from pathlib import Path

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import SecretScannerConfig
from isitsecure.engine.shared.code_utils import find_line_number
from isitsecure.engine.shared.progress import emit
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class GitSecretScanner:
    """Scans git history for leaked secrets.

    Two-pass approach:
    1. Scan current HEAD files for secrets (fast)
    2. Scan git history diffs for secrets that were committed and removed (thorough)

    Also detects sensitive files (.env, .pem, credentials.json) in history.
    """

    # Git log format: commit hash followed by subject on the same line
    _GIT_LOG_COMMIT_PREFIX = "commit "
    _GIT_LOG_DIFF_FILE_PREFIX = "+++ b/"
    _GIT_LOG_ADDED_LINE_PREFIX = "+"

    @property
    def scanner_name(self) -> str:
        return SecretScannerConfig.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Scan repository for secrets in current files and git history."""
        findings: list[CodeFinding] = []

        # Pass 1: Scan current HEAD files
        emit("secrets: scanning working tree")
        findings.extend(self._scan_current_files(repo))

        # Pass 2: Scan git history
        emit("secrets: scanning git history")
        history_findings = await self._scan_git_history(repo)
        findings.extend(history_findings)

        # Pass 3: Check for sensitive files committed
        emit("secrets: checking history for sensitive files")
        findings.extend(await self._scan_sensitive_files(repo))

        logger.info("GitSecretScanner: found %d findings", len(findings))
        return findings

    def _scan_current_files(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Scan indexed files at HEAD for secrets."""
        findings: list[CodeFinding] = []
        for file_path, content in repo.file_index.items():
            if self._should_skip_file(file_path):
                continue
            file_findings = self._scan_content_for_secrets(
                content, file_path, is_in_current_head=True
            )
            findings.extend(file_findings)
        return findings

    async def _scan_git_history(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Scan git log diffs for secrets in past commits."""
        findings: list[CodeFinding] = []
        clone_path = repo.clone_path

        try:
            proc = await asyncio.create_subprocess_exec(
                "git",
                "log",
                "--all",
                "--diff-filter=A",
                "-p",
                f"--max-count={SecretScannerConfig.MAX_COMMITS_TO_SCAN}",
                "--no-merges",
                "--format=commit %H %s",
                cwd=clone_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=SecretScannerConfig.GIT_LOG_TIMEOUT_SECONDS,
            )

            output = stdout.decode("utf-8", errors="replace")
            findings.extend(self._parse_git_log_output(output, repo))

        except asyncio.TimeoutError:
            logger.warning(
                SecretScannerConfig.ERROR_GIT_LOG_TIMEOUT.format(
                    timeout=SecretScannerConfig.GIT_LOG_TIMEOUT_SECONDS
                )
            )
        except Exception as e:
            logger.error(
                SecretScannerConfig.ERROR_GIT_LOG_FAILED.format(error=str(e))
            )

        return findings

    def _parse_git_log_output(
        self, output: str, repo: RepoSnapshot
    ) -> list[CodeFinding]:
        """Parse git log -p output and scan diffs for secrets."""
        findings: list[CodeFinding] = []
        current_commit: str | None = None
        current_file: str | None = None
        diff_lines: list[str] = []

        for line in output.splitlines():
            # Detect commit boundary
            if line.startswith(self._GIT_LOG_COMMIT_PREFIX):
                # Flush previous file diff
                if current_file and diff_lines:
                    findings.extend(
                        self._scan_diff_lines(
                            diff_lines, current_file, current_commit, repo
                        )
                    )
                    diff_lines = []
                    current_file = None

                parts = line.split(maxsplit=2)
                current_commit = parts[1] if len(parts) > 1 else None
                continue

            # Detect file in diff
            if line.startswith(self._GIT_LOG_DIFF_FILE_PREFIX):
                # Flush previous file diff
                if current_file and diff_lines:
                    findings.extend(
                        self._scan_diff_lines(
                            diff_lines, current_file, current_commit, repo
                        )
                    )
                    diff_lines = []

                current_file = line[len(self._GIT_LOG_DIFF_FILE_PREFIX) :]
                continue

            # Collect added lines only (lines starting with +, not +++)
            if line.startswith(self._GIT_LOG_ADDED_LINE_PREFIX) and not line.startswith(
                "+++"
            ):
                diff_lines.append(line[1:])  # Strip the leading +

        # Flush last file
        if current_file and diff_lines:
            findings.extend(
                self._scan_diff_lines(
                    diff_lines, current_file, current_commit, repo
                )
            )

        return findings

    def _scan_diff_lines(
        self,
        lines: list[str],
        file_path: str,
        commit_hash: str | None,
        repo: RepoSnapshot,
    ) -> list[CodeFinding]:
        """Scan accumulated diff added-lines for secrets."""
        if self._should_skip_file(file_path):
            return []

        content = "\n".join(lines)

        # Enforce max diff size
        if len(content.encode("utf-8")) > SecretScannerConfig.MAX_DIFF_SIZE_BYTES:
            return []

        is_in_head = file_path in repo.file_index
        return self._scan_content_for_secrets(
            content, file_path, is_in_current_head=is_in_head, commit_hash=commit_hash
        )

    async def _scan_sensitive_files(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Check if sensitive files (.env, .pem) exist in git history."""
        findings: list[CodeFinding] = []
        clone_path = repo.clone_path

        try:
            proc = await asyncio.create_subprocess_exec(
                "git",
                "log",
                "--all",
                "--diff-filter=A",
                "--name-only",
                "--format=",
                f"--max-count={SecretScannerConfig.MAX_COMMITS_TO_SCAN}",
                cwd=clone_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(),
                timeout=SecretScannerConfig.GIT_LOG_TIMEOUT_SECONDS,
            )

            filenames = stdout.decode("utf-8", errors="replace").strip().split("\n")
            seen: set[str] = set()

            for filename in filenames:
                filename = filename.strip()
                if not filename or filename in seen:
                    continue
                seen.add(filename)

                for pattern in SecretScannerConfig.SENSITIVE_FILE_PATTERNS:
                    if re.search(pattern, filename):
                        is_in_head = filename in repo.file_index or Path(
                            clone_path, filename
                        ).exists()

                        findings.append(
                            CodeFinding(
                                scanner_name=SecretScannerConfig.SCANNER_NAME,
                                severity=SeverityLevel.HIGH,
                                category=FindingCategory.EXPOSED_SECRETS,
                                title=SecretScannerConfig.TITLE_SENSITIVE_FILE.format(
                                    filename=filename
                                ),
                                description=SecretScannerConfig.DESC_SENSITIVE_FILE.format(
                                    filename=filename
                                ),
                                file_path=filename,
                                confidence=SecretScannerConfig.CONFIDENCE_SENSITIVE_FILE,
                                is_in_current_head=is_in_head,
                            )
                        )
                        break  # One finding per file

        except Exception as e:
            logger.error(
                SecretScannerConfig.ERROR_GIT_LOG_FAILED.format(error=str(e))
            )

        return findings

    def _scan_content_for_secrets(
        self,
        content: str,
        file_path: str,
        is_in_current_head: bool = True,
        commit_hash: str | None = None,
    ) -> list[CodeFinding]:
        """Scan a string for secret patterns."""
        findings: list[CodeFinding] = []

        for _secret_name, config in SecretScannerConfig.SECRET_PATTERNS.items():
            pattern = config["pattern"]
            severity_str = config["severity"]
            description = config["description"]

            severity = SeverityLevel(severity_str)

            for match in re.finditer(pattern, content):
                secret_value = match.group(0)

                # Skip if too short or too long
                if len(secret_value) < SecretScannerConfig.MIN_SECRET_LENGTH:
                    continue
                if len(secret_value) > SecretScannerConfig.MAX_SECRET_LENGTH:
                    continue

                # Find line number
                line_num = find_line_number(content, match.start())

                # Mask the secret for evidence
                masked = self._mask_secret(secret_value)

                if is_in_current_head:
                    detail = SecretScannerConfig.DETAIL_SECRET_IN_HEAD
                else:
                    detail = SecretScannerConfig.DETAIL_SECRET_IN_HISTORY

                findings.append(
                    CodeFinding(
                        scanner_name=SecretScannerConfig.SCANNER_NAME,
                        severity=severity,
                        category=FindingCategory.EXPOSED_SECRETS,
                        title=f"{description} found in {file_path}",
                        description=(
                            f"A {description.lower()} was found in "
                            f"'{file_path}'. {detail}"
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=masked,
                        confidence=SecretScannerConfig.CONFIDENCE_SECRET_MATCH,
                        commit_hash=commit_hash,
                        is_in_current_head=is_in_current_head,
                    )
                )

        return findings

    def _mask_secret(self, secret_value: str) -> str:
        """Mask the middle of a secret, preserving prefix and suffix."""
        if len(secret_value) <= SecretScannerConfig.MASK_MIN_LENGTH:
            return secret_value[:SecretScannerConfig.MASK_PREFIX_LENGTH] + "***"
        return (
            secret_value[:SecretScannerConfig.MASK_FULL_PREFIX_LENGTH]
            + "***"
            + secret_value[-SecretScannerConfig.MASK_SUFFIX_LENGTH:]
        )

    def _should_skip_file(self, file_path: str) -> bool:
        """Check if a file should be skipped (lock files, minified, etc.)."""
        for pattern in SecretScannerConfig.SKIP_FILE_PATTERNS:
            if re.search(pattern, file_path):
                return True
        return False

    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        freq: dict[str, int] = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )
