"""Firebase security rules analyzer.

Analyzes Firebase configuration files for security misconfigurations:
1. Firestore rules (firestore.rules)
2. Realtime Database rules (database.rules.json)
3. Storage rules (storage.rules)

Detects: open rules, missing auth checks, broad wildcards.
"""

from __future__ import annotations

import json
import logging
import re
from enum import Enum

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import FirebaseRulesConfig
from isitsecure.engine.shared.code_context import CodeContextExtractor
from isitsecure.engine.shared.code_utils import find_line_number
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class FirebaseServiceType(str, Enum):
    """Type of Firebase service being analyzed."""

    FIRESTORE = "Firestore"
    REALTIME_DB = "Realtime Database"
    STORAGE = "Storage"


class FirebaseRulesAnalyzer:
    """Analyzes Firebase security rules for misconfigurations.

    Implements CodeScannerProtocol.
    """

    @property
    def scanner_name(self) -> str:
        return FirebaseRulesConfig.SCANNER_NAME

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Scan Firebase rules files for security issues.

        Args:
            repo: Repository snapshot with file_index.

        Returns:
            List of code findings for Firebase rules misconfigurations.
        """
        findings: list[CodeFinding] = []

        for file_path, content in repo.file_index.items():
            if not self._is_rules_file(file_path):
                continue

            try:
                file_findings = self._analyze_rules_file(file_path, content)
                findings.extend(file_findings)
            except Exception as exc:
                logger.debug(
                    FirebaseRulesConfig.ERROR_RULES_PARSE_FAILED.format(
                        file=file_path, error=str(exc)
                    )
                )

        logger.info(
            "FirebaseRulesAnalyzer: %d findings from rules files",
            len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # File classification
    # ------------------------------------------------------------------

    @staticmethod
    def _is_rules_file(file_path: str) -> bool:
        """Check if a file path matches known Firebase rules locations."""
        normalized = file_path.replace("\\", "/")
        for rules_name in FirebaseRulesConfig.RULES_FILE_NAMES:
            if normalized.endswith(rules_name):
                return True
        return False

    @staticmethod
    def _detect_service_type(file_path: str, content: str) -> FirebaseServiceType:
        """Detect which Firebase service the rules file is for."""
        if file_path.endswith(".json"):
            return FirebaseServiceType.REALTIME_DB

        if FirebaseRulesConfig.STORAGE_INDICATOR in content:
            return FirebaseServiceType.STORAGE

        if FirebaseRulesConfig.FIRESTORE_INDICATOR in content:
            return FirebaseServiceType.FIRESTORE

        # Default based on filename
        if "storage" in file_path.lower():
            return FirebaseServiceType.STORAGE

        return FirebaseServiceType.FIRESTORE

    # ------------------------------------------------------------------
    # Analysis dispatch
    # ------------------------------------------------------------------

    def _analyze_rules_file(
        self, file_path: str, content: str
    ) -> list[CodeFinding]:
        """Analyze a single rules file, dispatching by type."""
        service_type = self._detect_service_type(file_path, content)

        if service_type == FirebaseServiceType.REALTIME_DB:
            return self._analyze_rtdb_rules(file_path, content, service_type)

        return self._analyze_firestore_style_rules(
            file_path, content, service_type
        )

    # ------------------------------------------------------------------
    # Firestore / Storage rules analysis
    # ------------------------------------------------------------------

    def _analyze_firestore_style_rules(
        self,
        file_path: str,
        content: str,
        service_type: FirebaseServiceType,
    ) -> list[CodeFinding]:
        """Analyze Firestore or Storage security rules."""
        findings: list[CodeFinding] = []
        type_name = service_type.value

        # Check for open read/write rules
        if re.search(FirebaseRulesConfig.OPEN_READ_WRITE, content):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.CRITICAL,
                    category=FindingCategory.AUTH_WEAKNESS,
                    title=FirebaseRulesConfig.TITLE_OPEN_RULES.format(
                        type=type_name
                    ),
                    description=FirebaseRulesConfig.DESC_OPEN_RULES.format(
                        type=type_name, file=file_path
                    ),
                    file_path=file_path,
                    line_number=self._find_line_number(
                        content, FirebaseRulesConfig.OPEN_READ_WRITE
                    ),
                    confidence=FirebaseRulesConfig.CONFIDENCE_OPEN_RULES,
                )
            )

        # Check individual open read or write
        for pattern, operation in (
            (FirebaseRulesConfig.OPEN_READ, "read"),
            (FirebaseRulesConfig.OPEN_WRITE, "write"),
        ):
            if re.search(pattern, content):
                findings.append(
                    CodeFinding(
                        scanner_name=self.scanner_name,
                        severity=SeverityLevel.HIGH,
                        category=FindingCategory.AUTH_WEAKNESS,
                        title=FirebaseRulesConfig.TITLE_OPEN_RULES.format(
                            type=type_name
                        ),
                        description=FirebaseRulesConfig.DESC_OPEN_RULES.format(
                            type=type_name, file=file_path
                        ),
                        file_path=file_path,
                        line_number=self._find_line_number(content, pattern),
                        confidence=FirebaseRulesConfig.CONFIDENCE_OPEN_RULES,
                    )
                )

        # Check for allow statements missing auth check
        findings.extend(
            self._check_missing_auth(content, file_path, type_name)
        )

        # Check for broad wildcards
        findings.extend(
            self._check_wildcards(content, file_path, type_name)
        )

        return findings

    def _check_missing_auth(
        self,
        content: str,
        file_path: str,
        type_name: str,
    ) -> list[CodeFinding]:
        """Check for allow statements without auth checks."""
        findings: list[CodeFinding] = []
        lines = content.splitlines()

        for line_number, line in enumerate(lines, start=1):
            allow_match = re.search(
                FirebaseRulesConfig.MISSING_AUTH_CHECK, line
            )
            if not allow_match:
                continue

            # Check if auth is present in the same rule block
            # Look at this line and a few following lines for auth check
            rule_context = "\n".join(
                lines[line_number - 1: min(line_number + 2, len(lines))]
            )

            has_auth = re.search(
                FirebaseRulesConfig.AUTH_CHECK_PATTERN, rule_context
            )
            if has_auth:
                continue

            # Skip if this line was already caught as fully open
            if re.search(FirebaseRulesConfig.OPEN_READ_WRITE, line):
                continue
            if re.search(FirebaseRulesConfig.OPEN_READ, line):
                continue
            if re.search(FirebaseRulesConfig.OPEN_WRITE, line):
                continue

            # Extract operation from the allow statement
            op_match = re.search(FirebaseRulesConfig.ALLOW_OPERATION_PATTERN, line)
            operation = op_match.group(1) if op_match else "access"

            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.HIGH,
                    category=FindingCategory.AUTH_WEAKNESS,
                    title=FirebaseRulesConfig.TITLE_MISSING_AUTH.format(
                        type=type_name
                    ),
                    description=FirebaseRulesConfig.DESC_MISSING_AUTH.format(
                        type=type_name,
                        path=file_path,
                        operation=operation,
                    ),
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=CodeContextExtractor.extract(
                        content, line_number
                    ),
                    confidence=FirebaseRulesConfig.CONFIDENCE_MISSING_AUTH,
                )
            )

        return findings

    def _check_wildcards(
        self,
        content: str,
        file_path: str,
        type_name: str,
    ) -> list[CodeFinding]:
        """Check for broad wildcard match patterns."""
        findings: list[CodeFinding] = []

        for match in re.finditer(
            FirebaseRulesConfig.WILDCARD_COLLECTION_PATTERN, content
        ):
            wildcard_path = match.group(0)
            line_number = find_line_number(content, match.start())

            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.MEDIUM,
                    category=FindingCategory.AUTH_WEAKNESS,
                    title=FirebaseRulesConfig.TITLE_WILDCARD_COLLECTION.format(
                        type=type_name
                    ),
                    description=FirebaseRulesConfig.DESC_WILDCARD_COLLECTION.format(
                        type=type_name, path=wildcard_path
                    ),
                    file_path=file_path,
                    line_number=line_number,
                    code_snippet=CodeContextExtractor.extract(
                        content, line_number
                    ),
                    confidence=FirebaseRulesConfig.CONFIDENCE_WILDCARD,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Realtime Database rules analysis
    # ------------------------------------------------------------------

    def _analyze_rtdb_rules(
        self,
        file_path: str,
        content: str,
        service_type: FirebaseServiceType,
    ) -> list[CodeFinding]:
        """Analyze Realtime Database JSON rules."""
        findings: list[CodeFinding] = []
        type_name = service_type.value

        # Check for open read
        if re.search(FirebaseRulesConfig.RTDB_OPEN_READ, content):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.CRITICAL,
                    category=FindingCategory.AUTH_WEAKNESS,
                    title=FirebaseRulesConfig.TITLE_OPEN_RULES.format(
                        type=type_name
                    ),
                    description=FirebaseRulesConfig.DESC_OPEN_RULES.format(
                        type=type_name, file=file_path
                    ),
                    file_path=file_path,
                    line_number=self._find_line_number(
                        content, FirebaseRulesConfig.RTDB_OPEN_READ
                    ),
                    confidence=FirebaseRulesConfig.CONFIDENCE_OPEN_RULES,
                )
            )

        # Check for open write
        if re.search(FirebaseRulesConfig.RTDB_OPEN_WRITE, content):
            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=SeverityLevel.CRITICAL,
                    category=FindingCategory.AUTH_WEAKNESS,
                    title=FirebaseRulesConfig.TITLE_OPEN_RULES.format(
                        type=type_name
                    ),
                    description=FirebaseRulesConfig.DESC_OPEN_RULES.format(
                        type=type_name, file=file_path
                    ),
                    file_path=file_path,
                    line_number=self._find_line_number(
                        content, FirebaseRulesConfig.RTDB_OPEN_WRITE
                    ),
                    confidence=FirebaseRulesConfig.CONFIDENCE_OPEN_RULES,
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_line_number(content: str, pattern: str) -> int | None:
        """Find the line number of the first regex match in content."""
        match = re.search(pattern, content)
        if not match:
            return None
        return find_line_number(content, match.start())
