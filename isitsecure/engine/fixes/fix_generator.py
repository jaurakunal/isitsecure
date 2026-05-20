"""LLM-powered fix generator for security findings.

Takes a finding + the source file content, asks the LLM to generate
a fixed version, and returns a unified diff.

SRP: This class generates fixes. It does not run scans, read files
     from disk, or apply patches.

DIP: Depends on LLMClientProtocol, not any concrete LLM implementation.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from difflib import unified_diff

from isitsecure.engine.fixes.prompts import FixPrompts
from isitsecure.engine.models import DeepFinding
from isitsecure.llm.protocol import LLMClientProtocol

logger = logging.getLogger(__name__)


@dataclass
class FixResult:
    """Result of a fix generation attempt."""

    finding_id: str
    file_path: str
    success: bool
    original_code: str = ""
    fixed_code: str = ""
    diff: str = ""
    explanation: str = ""
    error: str = ""


@dataclass
class FixPlan:
    """Collection of fixes for an entire scan."""

    fixes: list[FixResult] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    total_findings: int = 0

    @property
    def fixed_count(self) -> int:
        return sum(1 for f in self.fixes if f.success)

    @property
    def failed_count(self) -> int:
        return sum(1 for f in self.fixes if not f.success)


class FixGenerator:
    """Generates code fixes for security findings using LLM.

    Implements the find→fix loop:
    1. Read the finding (what's wrong, where, what severity)
    2. Read the source file content
    3. Ask the LLM to generate a fixed version
    4. Parse the response and produce a unified diff

    Args:
        llm_client: LLM client implementing LLMClientProtocol (DIP).
    """

    MAX_FILE_SIZE = 50_000  # Skip files larger than 50KB
    MAX_CONCURRENT_FIXES = 3

    def __init__(self, llm_client: LLMClientProtocol) -> None:
        self._llm = llm_client

    async def generate_fix(
        self,
        finding: DeepFinding,
        file_content: str,
    ) -> FixResult:
        """Generate a fix for a single finding.

        Args:
            finding: The security finding to fix.
            file_content: Full content of the source file.

        Returns:
            FixResult with diff and explanation.
        """
        file_path = finding.code_location.file_path if finding.code_location else ""

        if not file_path or not file_content:
            return FixResult(
                finding_id=finding.id,
                file_path=file_path,
                success=False,
                error="No source file available for this finding",
            )

        if len(file_content) > self.MAX_FILE_SIZE:
            return FixResult(
                finding_id=finding.id,
                file_path=file_path,
                success=False,
                error=f"File too large ({len(file_content)} bytes)",
            )

        try:
            system_prompt = FixPrompts.SYSTEM_PROMPT
            user_prompt = FixPrompts.build_fix_prompt(finding, file_content)

            response = await self._llm.generate_with_system(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=8192,
            )

            return self._parse_response(finding, file_path, file_content, response)

        except Exception as e:
            logger.warning("Fix generation failed for %s: %s", finding.id, e)
            return FixResult(
                finding_id=finding.id,
                file_path=file_path,
                success=False,
                error=str(e),
            )

    async def generate_fix_plan(
        self,
        findings: list[DeepFinding],
        file_contents: dict[str, str],
    ) -> FixPlan:
        """Generate fixes for multiple findings.

        Args:
            findings: List of findings to fix (typically critical + high).
            file_contents: Mapping of file_path → content.

        Returns:
            FixPlan with all fix results.
        """
        import asyncio

        plan = FixPlan(total_findings=len(findings))
        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_FIXES)

        async def _fix_one(finding: DeepFinding) -> FixResult | None:
            file_path = finding.code_location.file_path if finding.code_location else ""
            content = file_contents.get(file_path, "")

            if not file_path or not content:
                plan.skipped.append(
                    f"{finding.title} — no source file (DAST-only finding)"
                )
                return None

            async with semaphore:
                return await self.generate_fix(finding, content)

        tasks = [_fix_one(f) for f in findings]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, FixResult):
                plan.fixes.append(result)
            elif isinstance(result, Exception):
                logger.warning("Fix generation error: %s", result)

        return plan

    def _parse_response(
        self,
        finding: DeepFinding,
        file_path: str,
        original_content: str,
        response: str,
    ) -> FixResult:
        """Parse LLM response to extract fixed code and explanation."""
        # Extract code block from response
        fixed_code = self._extract_code_block(response)
        explanation = self._extract_explanation(response)

        if not fixed_code:
            return FixResult(
                finding_id=finding.id,
                file_path=file_path,
                success=False,
                original_code=original_content,
                explanation=explanation,
                error="Could not extract fixed code from LLM response",
            )

        # Generate unified diff
        diff = self._generate_diff(file_path, original_content, fixed_code)

        if not diff:
            return FixResult(
                finding_id=finding.id,
                file_path=file_path,
                success=False,
                original_code=original_content,
                fixed_code=fixed_code,
                explanation=explanation,
                error="Fix produced no changes (code unchanged)",
            )

        return FixResult(
            finding_id=finding.id,
            file_path=file_path,
            success=True,
            original_code=original_content,
            fixed_code=fixed_code,
            diff=diff,
            explanation=explanation,
        )

    @staticmethod
    def _extract_code_block(response: str) -> str:
        """Extract the first fenced code block from the response."""
        # Match ```language\n...code...\n```
        pattern = r"```(?:\w+)?\s*\n(.*?)```"
        match = re.search(pattern, response, re.DOTALL)
        if match:
            return match.group(1).strip()

        # Fallback: look for FIXED_CODE markers
        pattern2 = r"FIXED_CODE_START\n(.*?)FIXED_CODE_END"
        match2 = re.search(pattern2, response, re.DOTALL)
        if match2:
            return match2.group(1).strip()

        return ""

    @staticmethod
    def _extract_explanation(response: str) -> str:
        """Extract explanation text from before/after the code block."""
        # Take everything before the first code block
        parts = re.split(r"```", response)
        if parts:
            explanation = parts[0].strip()
            # Also check for text after the last code block
            if len(parts) >= 3:
                after = parts[-1].strip()
                if after:
                    explanation = f"{explanation}\n\n{after}" if explanation else after
            return explanation
        return ""

    @staticmethod
    def _generate_diff(file_path: str, original: str, fixed: str) -> str:
        """Generate a unified diff between original and fixed code."""
        original_lines = original.splitlines(keepends=True)
        fixed_lines = fixed.splitlines(keepends=True)

        diff_lines = list(unified_diff(
            original_lines,
            fixed_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="",
        ))

        if not diff_lines:
            return ""

        return "\n".join(diff_lines)
