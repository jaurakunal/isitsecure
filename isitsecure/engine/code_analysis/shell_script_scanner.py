"""Shell script security scanner.

SRP: This scanner is responsible ONLY for analyzing shell scripts
     (.sh, .bash) for security issues.  It does not analyze other
     file types or runtime behavior.

OCP: Implements ``CodeScannerProtocol`` — added to the sast_scanners
     list without modifying the agent or factory.

DIP: Depends on ``RepoSnapshot`` and ``CodeScannerProtocol``
     (abstractions), never on concrete implementations.
"""

from __future__ import annotations

import logging
import re

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import ShellScriptScannerConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class ShellScriptScanner:
    """Scans shell scripts for security issues.

    Checks performed:
    1. Hardcoded secrets (API keys, passwords, tokens)
    2. Hardcoded AWS account IDs
    3. curl piped to shell (supply chain risk)
    4. Overly permissive chmod (777, 666)
    5. eval with variable expansion (injection risk)
    6. Missing set -e error handling
    7. Secrets printed to stdout
    8. curl with --insecure (TLS bypass)

    Implements ``CodeScannerProtocol``.
    """

    @property
    def scanner_name(self) -> str:
        return ShellScriptScannerConfig.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Analyze shell scripts for security issues."""
        findings: list[CodeFinding] = []

        shell_files = self._find_shell_files(repo)

        if not shell_files:
            return findings

        for file_path, content in shell_files.items():
            try:
                findings.extend(self._scan_file(content, file_path))
            except Exception as e:
                logger.warning(
                    ShellScriptScannerConfig.ERROR_ANALYSIS_FAILED.format(
                        file=file_path, error=e
                    )
                )

        logger.info(
            "ShellScriptScanner: %d files scanned, %d findings",
            len(shell_files),
            len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # File discovery
    # ------------------------------------------------------------------

    @staticmethod
    def _find_shell_files(repo: RepoSnapshot) -> dict[str, str]:
        """Find shell script files in the file index."""
        return {
            path: content
            for path, content in repo.file_index.items()
            if any(
                path.endswith(ext)
                for ext in ShellScriptScannerConfig.SHELL_EXTENSIONS
            )
        }

    # ------------------------------------------------------------------
    # Per-file scanning
    # ------------------------------------------------------------------

    def _scan_file(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Run all checks on a single shell script."""
        findings: list[CodeFinding] = []

        findings.extend(self._check_hardcoded_secrets(content, file_path))
        findings.extend(self._check_aws_account_ids(content, file_path))
        findings.extend(self._check_curl_pipe(content, file_path))
        findings.extend(self._check_chmod_permissive(content, file_path))
        findings.extend(self._check_eval_variable(content, file_path))
        findings.extend(self._check_set_e(content, file_path))
        findings.extend(self._check_echo_secrets(content, file_path))
        findings.extend(self._check_curl_insecure(content, file_path))

        return findings

    # ------------------------------------------------------------------
    # 1. Hardcoded secrets
    # ------------------------------------------------------------------

    def _check_hardcoded_secrets(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Find hardcoded secrets in shell scripts."""
        findings: list[CodeFinding] = []

        for pattern, secret_type in ShellScriptScannerConfig.HARDCODED_SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.MULTILINE):
                value = match.group(1)

                # Skip variable references and placeholders
                if self._is_placeholder(value):
                    continue

                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.HIGH,
                        category=FindingCategory.EXPOSED_SECRETS,
                        title=ShellScriptScannerConfig.TITLE_HARDCODED_SECRET.format(
                            secret_type=secret_type
                        ),
                        description=ShellScriptScannerConfig.DESC_HARDCODED_SECRET.format(
                            file=file_path, secret_type=secret_type
                        ),
                        file_path=file_path,
                        confidence=ShellScriptScannerConfig.CONFIDENCE_HARDCODED_SECRET,
                    )
                )
                # One finding per secret type per file
                break

        return findings

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        """Check if a value is a variable reference or placeholder."""
        # Use search for patterns like '/' that may appear anywhere
        # Use match for patterns anchored to start (^$, ^your, etc.)
        for pattern in ShellScriptScannerConfig.SECRET_SKIP_PATTERNS:
            if pattern.startswith("^") or pattern.startswith(r"\$"):
                if re.match(pattern, value, re.IGNORECASE):
                    return True
            else:
                if re.search(pattern, value, re.IGNORECASE):
                    return True
        return False

    # ------------------------------------------------------------------
    # 2. AWS account IDs
    # ------------------------------------------------------------------

    def _check_aws_account_ids(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Find hardcoded AWS account IDs."""
        findings: list[CodeFinding] = []
        seen: set[str] = set()

        for match in re.finditer(
            ShellScriptScannerConfig.AWS_ACCOUNT_ID_PATTERN, content
        ):
            account_id = match.group(1)
            if account_id in seen:
                continue
            seen.add(account_id)

            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.LOW,
                    category=FindingCategory.INFO_DISCLOSURE,
                    title=ShellScriptScannerConfig.TITLE_AWS_ACCOUNT_ID,
                    description=ShellScriptScannerConfig.DESC_AWS_ACCOUNT_ID.format(
                        file=file_path, account_id=account_id
                    ),
                    file_path=file_path,
                    confidence=ShellScriptScannerConfig.CONFIDENCE_AWS_ACCOUNT_ID,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # 3. curl | bash
    # ------------------------------------------------------------------

    def _check_curl_pipe(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for curl output piped to shell."""
        if re.search(
            ShellScriptScannerConfig.CURL_PIPE_BASH_PATTERN, content
        ):
            return [
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.HIGH,
                    category=FindingCategory.DEPENDENCY_VULNERABILITY,
                    title=ShellScriptScannerConfig.TITLE_CURL_PIPE,
                    description=ShellScriptScannerConfig.DESC_CURL_PIPE.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=ShellScriptScannerConfig.CONFIDENCE_CURL_PIPE,
                )
            ]
        return []

    # ------------------------------------------------------------------
    # 4. chmod 777
    # ------------------------------------------------------------------

    def _check_chmod_permissive(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for overly permissive chmod commands."""
        if re.search(
            ShellScriptScannerConfig.CHMOD_PERMISSIVE_PATTERN, content
        ):
            return [
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.MEDIUM,
                    category=FindingCategory.AUTH_WEAKNESS,
                    title=ShellScriptScannerConfig.TITLE_CHMOD_PERMISSIVE,
                    description=ShellScriptScannerConfig.DESC_CHMOD_PERMISSIVE.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=ShellScriptScannerConfig.CONFIDENCE_CHMOD_PERMISSIVE,
                )
            ]
        return []

    # ------------------------------------------------------------------
    # 5. eval with variables
    # ------------------------------------------------------------------

    def _check_eval_variable(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for eval with variable expansion."""
        if re.search(
            ShellScriptScannerConfig.EVAL_VARIABLE_PATTERN, content
        ):
            return [
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.MEDIUM,
                    category=FindingCategory.INJECTION_RISK,
                    title=ShellScriptScannerConfig.TITLE_EVAL_VARIABLE,
                    description=ShellScriptScannerConfig.DESC_EVAL_VARIABLE.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=ShellScriptScannerConfig.CONFIDENCE_EVAL_VARIABLE,
                )
            ]
        return []

    # ------------------------------------------------------------------
    # 6. Missing set -e
    # ------------------------------------------------------------------

    def _check_set_e(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for missing set -e error handling."""
        if re.search(
            ShellScriptScannerConfig.SET_E_PATTERN, content
        ):
            return []

        return [
            CodeFinding(
                scanner_name=self.scanner_name,
                severity=SeverityLevel.LOW,
                category=FindingCategory.INFO_DISCLOSURE,
                title=ShellScriptScannerConfig.TITLE_NO_SET_E,
                description=ShellScriptScannerConfig.DESC_NO_SET_E.format(
                    file=file_path
                ),
                file_path=file_path,
                confidence=ShellScriptScannerConfig.CONFIDENCE_NO_SET_E,
            )
        ]

    # ------------------------------------------------------------------
    # 7. Secrets in echo
    # ------------------------------------------------------------------

    def _check_echo_secrets(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for secrets being printed to stdout."""
        if re.search(
            ShellScriptScannerConfig.ECHO_SECRET_PATTERN,
            content,
            re.IGNORECASE,
        ):
            return [
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.MEDIUM,
                    category=FindingCategory.INFO_DISCLOSURE,
                    title=ShellScriptScannerConfig.TITLE_ECHO_SECRET,
                    description=ShellScriptScannerConfig.DESC_ECHO_SECRET.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=ShellScriptScannerConfig.CONFIDENCE_ECHO_SECRET,
                )
            ]
        return []

    # ------------------------------------------------------------------
    # 8. curl --insecure
    # ------------------------------------------------------------------

    def _check_curl_insecure(
        self, content: str, file_path: str
    ) -> list[CodeFinding]:
        """Check for curl with disabled TLS verification."""
        if re.search(
            ShellScriptScannerConfig.CURL_INSECURE_PATTERN, content
        ):
            return [
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.MEDIUM,
                    category=FindingCategory.AUTH_WEAKNESS,
                    title=ShellScriptScannerConfig.TITLE_CURL_INSECURE,
                    description=ShellScriptScannerConfig.DESC_CURL_INSECURE.format(
                        file=file_path
                    ),
                    file_path=file_path,
                    confidence=ShellScriptScannerConfig.CONFIDENCE_CURL_INSECURE,
                )
            ]
        return []
