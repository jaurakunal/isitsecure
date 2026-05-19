"""LLM-powered semantic verifier for security rules (RLS and Firebase).

Analyzes security rules for LOGICAL flaws that structural analyzers
cannot detect -- wrong column references, privilege escalation paths,
inconsistent operation coverage, and tenant isolation errors.

SRP: This class handles LLM interaction and response parsing for
     rule semantics only.  Structural checks (missing policies, open
     rules) are handled by ``RLSPolicyAnalyzer`` and
     ``FirebaseRulesAnalyzer``.

OCP: Implements ``CodeScannerProtocol`` so it can be added to the
     scanner list without modifying existing scanners or the agent.

DIP: Depends on ``LLMClientProtocol`` (abstraction) for LLM calls,
     not on any concrete LLM implementation.
"""

from __future__ import annotations

import json
import logging
import re

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot
from isitsecure.engine.constants import SemanticRuleVerifierConfig
from isitsecure.llm.protocol import LLMClientProtocol
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class SemanticRuleVerifier:
    """LLM-powered semantic verifier for RLS policies and Firebase rules.

    Implements CodeScannerProtocol.
    Depends on LLMClientProtocol (DIP).
    """

    SEVERITY_MAP = {
        "CRITICAL": SeverityLevel.CRITICAL,
        "HIGH": SeverityLevel.HIGH,
        "MEDIUM": SeverityLevel.MEDIUM,
        "LOW": SeverityLevel.LOW,
    }

    def __init__(self, llm_client: LLMClientProtocol) -> None:
        self._llm = llm_client
        self._total_tokens_used = 0

    @property
    def scanner_name(self) -> str:
        return SemanticRuleVerifierConfig.SCANNER_NAME

    # ------------------------------------------------------------------
    # Main scan entry point
    # ------------------------------------------------------------------

    async def scan(self, repo: RepoSnapshot) -> list[CodeFinding]:
        """Analyze security rules for semantic/logic flaws.

        Args:
            repo: Repository snapshot with file_index.

        Returns:
            List of code findings for logical rule flaws.
        """
        findings: list[CodeFinding] = []

        # Phase 1: Firebase rules
        firebase_rules = self._collect_firebase_rules(repo)
        for file_path, content in firebase_rules.items():
            file_findings = await self._review_firebase_rules(
                file_path, content
            )
            findings.extend(file_findings)

        # Phase 2: RLS policies from migration SQL
        rls_sql = self._collect_rls_sql(repo)
        for file_path, content in rls_sql.items():
            file_findings = await self._review_rls_policies(
                file_path, content
            )
            findings.extend(file_findings)

        logger.info(
            "SemanticRuleVerifier: %d findings, ~%d tokens used",
            len(findings),
            self._total_tokens_used,
        )
        return findings

    # ------------------------------------------------------------------
    # File collection
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_firebase_rules(repo: RepoSnapshot) -> dict[str, str]:
        """Collect Firebase rules files from the repository file index."""
        rules: dict[str, str] = {}
        for file_path, content in repo.file_index.items():
            normalized = file_path.replace("\\", "/")
            for rules_name in SemanticRuleVerifierConfig.FIREBASE_RULES_FILES:
                if normalized.endswith(rules_name):
                    rules[file_path] = content
                    break
        return rules

    @staticmethod
    def _collect_rls_sql(repo: RepoSnapshot) -> dict[str, str]:
        """Collect SQL migration files containing RLS policy definitions."""
        rls_files: dict[str, str] = {}
        for file_path, content in repo.file_index.items():
            if not file_path.endswith(".sql"):
                continue
            content_upper = content.upper()
            has_policy = any(
                indicator in content_upper
                for indicator in SemanticRuleVerifierConfig.RLS_SQL_INDICATORS
            )
            if has_policy:
                rls_files[file_path] = content
        return rls_files

    # ------------------------------------------------------------------
    # LLM review: Firebase rules
    # ------------------------------------------------------------------

    async def _review_firebase_rules(
        self, file_path: str, content: str
    ) -> list[CodeFinding]:
        """Send Firebase rules to LLM for semantic analysis."""
        truncated = content[: SemanticRuleVerifierConfig.MAX_RULE_SIZE_CHARS]
        user_prompt = SemanticRuleVerifierConfig.FIREBASE_USER_PROMPT.format(
            file_path=file_path,
            rules_content=truncated,
        )

        return await self._send_to_llm(
            system_prompt=SemanticRuleVerifierConfig.FIREBASE_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            file_path=file_path,
            content=content,
        )

    # ------------------------------------------------------------------
    # LLM review: RLS policies
    # ------------------------------------------------------------------

    async def _review_rls_policies(
        self, file_path: str, content: str
    ) -> list[CodeFinding]:
        """Send RLS policies to LLM for semantic analysis."""
        truncated = content[: SemanticRuleVerifierConfig.MAX_RULE_SIZE_CHARS]
        user_prompt = SemanticRuleVerifierConfig.RLS_USER_PROMPT.format(
            file_path=file_path,
            sql_content=truncated,
        )

        return await self._send_to_llm(
            system_prompt=SemanticRuleVerifierConfig.RLS_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            file_path=file_path,
            content=content,
        )

    # ------------------------------------------------------------------
    # Shared LLM interaction
    # ------------------------------------------------------------------

    async def _send_to_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        file_path: str,
        content: str,
    ) -> list[CodeFinding]:
        """Send a prompt to the LLM and parse the response into findings."""
        self._total_tokens_used += (
            len(user_prompt)
            // SemanticRuleVerifierConfig.CHARS_PER_TOKEN_ESTIMATE
        )

        try:
            response = await self._llm.generate_with_system(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=SemanticRuleVerifierConfig.MAX_TOKENS_PER_REVIEW,
            )

            self._total_tokens_used += (
                len(response)
                // SemanticRuleVerifierConfig.CHARS_PER_TOKEN_ESTIMATE
            )
            return self._parse_llm_findings(response, file_path, content)

        except Exception as e:
            logger.warning(
                SemanticRuleVerifierConfig.ERROR_LLM_REVIEW_FAILED.format(
                    file=file_path, error=str(e)
                )
            )
            return []

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_llm_findings(
        self, response: str, file_path: str, content: str
    ) -> list[CodeFinding]:
        """Parse LLM JSON response into CodeFinding objects."""
        findings: list[CodeFinding] = []

        # Extract JSON array from response (may be wrapped in code block)
        json_match = re.search(r"\[.*\]", response, re.DOTALL)
        if not json_match:
            return findings

        try:
            items = json.loads(json_match.group(0))
        except json.JSONDecodeError as e:
            logger.debug(
                SemanticRuleVerifierConfig.ERROR_PARSE_RESPONSE.format(
                    error=str(e)
                )
            )
            return findings

        for item in items[: SemanticRuleVerifierConfig.MAX_FINDINGS_PER_FILE]:
            if not isinstance(item, dict):
                continue

            severity_str = item.get("severity", "MEDIUM").upper()
            severity = self.SEVERITY_MAP.get(
                severity_str, SeverityLevel.MEDIUM
            )

            line_number = item.get("line_number")

            findings.append(
                CodeFinding(
                    scanner_name=self.scanner_name,
                    severity=severity,
                    category=FindingCategory.RLS_MISCONFIGURATION,
                    title=item.get(
                        "title",
                        SemanticRuleVerifierConfig.FALLBACK_FINDING_TITLE,
                    ),
                    description=item.get("description", ""),
                    file_path=file_path,
                    line_number=line_number,
                    confidence=SemanticRuleVerifierConfig.CONFIDENCE_LLM_FINDING,
                )
            )

        return findings
