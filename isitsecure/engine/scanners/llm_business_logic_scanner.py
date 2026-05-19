"""LLM-driven business logic attack engine.

Uses an LLM to read source code, understand business logic flows,
generate targeted attack plans, execute them against the live app,
and analyze whether attacks succeeded.

This catches vulnerabilities that no automated scanner can find:
- Authorization bypass through alternative code paths
- State machine violations (skipping steps in workflows)
- Price/amount manipulation via client-controlled values
- Cross-tenant data access from missing scoping
- Webhook replay/forgery

All LLM calls go through the shared LLM client so token usage
is tracked automatically for cost reporting.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from urllib.parse import urlparse

import httpx

from isitsecure.engine.auth.protocols import AuthSession
from isitsecure.engine.constants import (
    LLMBusinessLogicConfig,
    SharedPatterns,
)
from isitsecure.engine.models import (
    CodeLocation,
    DeepFinding,
    DiscoveredEndpoint,
    FindingSource,
)
from isitsecure.engine.enums import FindingCategory, SeverityLevel

logger = logging.getLogger(__name__)


class LLMBusinessLogicScanner:
    """Reads source code, plans attacks, executes them, analyzes results.

    Uses the shared LLM client for all calls so token usage is
    automatically tracked via ``_track_usage`` in the client.
    """

    _SEVERITY_MAP = {
        "CRITICAL": SeverityLevel.CRITICAL,
        "HIGH": SeverityLevel.HIGH,
        "MEDIUM": SeverityLevel.MEDIUM,
        "LOW": SeverityLevel.LOW,
    }

    def __init__(
        self,
        llm_client: object,
        judgment_llm_client: object | None = None,
    ) -> None:
        """Initialize with LLM clients for planning and judgment.

        Args:
            llm_client: Primary LLM for code analysis and attack planning.
                Should be the most capable model (e.g., Opus).
            judgment_llm_client: Optional cheaper/faster LLM for result
                judgment. Falls back to llm_client if not provided.
        """
        self._llm = llm_client
        self._judgment_llm = judgment_llm_client or llm_client

    @property
    def scanner_name(self) -> str:
        return LLMBusinessLogicConfig.SCANNER_NAME

    async def scan(
        self,
        repo_files: dict[str, str],
        endpoints: list[DiscoveredEndpoint],
        admin_session: AuthSession,
        regular_session: AuthSession,
        target_url: str,
    ) -> list[DeepFinding]:
        """Full attack pipeline: analyze → plan → execute → judge.

        Args:
            repo_files: Dict of {file_path: file_content} from repo snapshot.
            endpoints: Discovered API endpoints (from crawl + static analysis).
            admin_session: User A (admin/owner) session.
            regular_session: User B (regular/attacker) session.
            target_url: Base URL of the target application.

        Returns:
            List of confirmed vulnerability findings.
        """
        findings: list[DeepFinding] = []

        # Phase 1: Select business-logic-heavy files
        selected_files = self._select_files(repo_files)
        if not selected_files:
            logger.info("LLM Business Logic: no relevant source files found")
            return findings

        # Phase 2: LLM analyzes code and generates attack plans
        attack_plans = await self._generate_attack_plans(
            selected_files, endpoints, target_url,
        )
        if not attack_plans:
            logger.info("LLM Business Logic: no attack plans generated")
            return findings

        logger.info(
            LLMBusinessLogicConfig.LOG_ANALYSIS_COMPLETE,
            len(selected_files), len(attack_plans),
        )

        # Phase 3: Execute attack plans and analyze results
        sessions = {
            "admin_user": admin_session,
            "regular_user": regular_session,
        }

        for plan in attack_plans[: LLMBusinessLogicConfig.MAX_ATTACK_PLANS]:
            finding = await self._execute_and_analyze_plan(
                plan, sessions, target_url,
            )
            if finding:
                findings.append(finding)

        logger.info(
            LLMBusinessLogicConfig.LOG_EXECUTION_COMPLETE,
            len(findings), len(attack_plans),
        )
        return findings

    # ------------------------------------------------------------------
    # Phase 1: File Selection
    # ------------------------------------------------------------------

    @staticmethod
    def _select_files(repo_files: dict[str, str]) -> dict[str, str]:
        """Select files likely to contain business logic."""
        selected: dict[str, str] = {}

        for path, content in repo_files.items():
            # Skip non-code files
            if not any(
                path.endswith(ext)
                for ext in LLMBusinessLogicConfig.CODE_EXTENSIONS
            ):
                continue

            # Skip test files, node_modules, etc.
            if any(
                skip in path
                for skip in LLMBusinessLogicConfig.FILE_SKIP_PATTERNS
            ):
                continue

            path_lower = path.lower()
            if any(
                pattern in path_lower
                for pattern in LLMBusinessLogicConfig.BUSINESS_LOGIC_FILE_PATTERNS
            ):
                max_chars = LLMBusinessLogicConfig.MAX_FILE_CHARS
                selected[path] = content if not max_chars else content[:max_chars]

            if len(selected) >= LLMBusinessLogicConfig.MAX_FILES_FOR_ANALYSIS:
                break

        return selected

    # ------------------------------------------------------------------
    # Phase 2: LLM Attack Plan Generation
    # ------------------------------------------------------------------

    async def _generate_attack_plans(
        self,
        files: dict[str, str],
        endpoints: list[DiscoveredEndpoint],
        target_url: str,
    ) -> list[dict]:
        """Use the LLM to analyze code and generate attack plans."""
        # Format code files for the prompt
        code_section = ""
        for path, content in files.items():
            code_section += f"\n--- {path} ---\n```\n{content}\n```\n"

        # Format discovered endpoints
        endpoint_section = "\n".join(
            f"- {ep.method.value} {ep.url}"
            for ep in endpoints[: LLMBusinessLogicConfig.MAX_ENDPOINTS_IN_PROMPT]
        )

        framework = self._detect_framework(files)

        user_prompt = LLMBusinessLogicConfig.ANALYSIS_USER_PROMPT.format(
            framework=framework,
            endpoints=endpoint_section,
            code_files=code_section,
            max_plans=LLMBusinessLogicConfig.MAX_ATTACK_PLANS,
            max_steps=LLMBusinessLogicConfig.MAX_STEPS_PER_PLAN,
        )

        try:
            response = await self._llm.generate_with_system(
                system_prompt=LLMBusinessLogicConfig.ANALYSIS_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                max_tokens=LLMBusinessLogicConfig.MAX_TOKENS_ANALYSIS,
            )
            return self._parse_attack_plans(response)
        except Exception as exc:
            logger.error(
                LLMBusinessLogicConfig.ERROR_ANALYSIS_FAILED.format(
                    error=str(exc)
                )
            )
            return []

    # ------------------------------------------------------------------
    # Phase 3: Execute and Analyze
    # ------------------------------------------------------------------

    async def _execute_and_analyze_plan(
        self,
        plan: dict,
        sessions: dict[str, AuthSession],
        target_url: str,
    ) -> DeepFinding | None:
        """Execute an attack plan step by step, then ask LLM if it worked."""
        plan_title = plan.get("title", "Unknown")
        steps = plan.get("steps", [])
        if not steps:
            return None

        step_results: list[dict] = []

        async with httpx.AsyncClient(
            timeout=LLMBusinessLogicConfig.HTTP_TIMEOUT_SECONDS,
            follow_redirects=True,
        ) as client:
            for i, step in enumerate(
                steps[: LLMBusinessLogicConfig.MAX_STEPS_PER_PLAN]
            ):
                result = await self._execute_step(
                    client, step, sessions, target_url,
                )
                step_results.append({
                    "step": i + 1,
                    "description": step.get("description", ""),
                    "method": step.get("method", "GET"),
                    "url": step.get("url", ""),
                    "expected": step.get("expect", ""),
                    "actual_status": result.get("status", 0),
                    "actual_body_preview": result.get("body", "")[
                        : LLMBusinessLogicConfig.RESPONSE_PREVIEW_LENGTH
                    ],
                })

        # Ask LLM to analyze the results
        return await self._analyze_results(plan, step_results)

    async def _execute_step(
        self,
        client: httpx.AsyncClient,
        step: dict,
        sessions: dict[str, AuthSession],
        target_url: str,
    ) -> dict:
        """Execute a single attack step."""
        method = step.get("method", "GET").upper()
        url = step.get("url", "")
        body = step.get("body")
        user = step.get("user", "regular_user")

        # Build headers with auth
        headers: dict[str, str] = {
            SharedPatterns.HEADER_CONTENT_TYPE: SharedPatterns.CONTENT_TYPE_JSON,
        }
        session = sessions.get(user)
        if session:
            headers[SharedPatterns.HEADER_AUTHORIZATION] = (
                f"{SharedPatterns.BEARER_PREFIX}{session.access_token}"
            )
        elif user == "no_auth":
            pass  # No auth header

        try:
            kwargs: dict = {"headers": headers}
            if body and method in ("POST", "PUT", "PATCH"):
                kwargs["content"] = json.dumps(body) if isinstance(body, dict) else str(body)

            resp = await client.request(method, url, **kwargs)
            return {
                "status": resp.status_code,
                "body": resp.text,
            }
        except Exception as exc:
            return {
                "status": 0,
                "body": f"Request failed: {exc}",
            }

    async def _analyze_results(
        self,
        plan: dict,
        step_results: list[dict],
    ) -> DeepFinding | None:
        """Ask the LLM if the attack succeeded based on the responses."""
        results_text = json.dumps(step_results, indent=2)

        user_prompt = LLMBusinessLogicConfig.RESULT_ANALYSIS_USER_PROMPT.format(
            plan_title=plan.get("title", ""),
            plan_description=plan.get("description", ""),
            success_criteria=plan.get("success_criteria", ""),
            step_results=results_text,
        )

        try:
            response = await self._judgment_llm.generate_with_system(
                system_prompt=LLMBusinessLogicConfig.RESULT_ANALYSIS_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                max_tokens=LLMBusinessLogicConfig.MAX_TOKENS_RESULT,
            )
            verdict = self._parse_json_response(response)
            if not verdict:
                return None

            if not verdict.get("confirmed", False):
                return None

            severity = self._SEVERITY_MAP.get(
                verdict.get("severity", "MEDIUM"), SeverityLevel.MEDIUM,
            )

            # Build code location if the plan references a source file
            code_loc = None
            affected_file = plan.get("affected_file")
            if affected_file:
                code_loc = CodeLocation(
                    file_path=affected_file,
                    line_number=plan.get("affected_line"),
                )

            first_step = plan.get("steps", [{}])[0]
            return DeepFinding(
                source=FindingSource.SAST_GUIDED_DAST,
                category=FindingCategory.AUTH_WEAKNESS,
                severity=severity,
                title=plan.get("title", "Business logic vulnerability"),
                description=(
                    f"{plan.get('description', '')}\n\n"
                    f"**Evidence:** {verdict.get('evidence', 'N/A')}\n\n"
                    f"**Remediation:** {verdict.get('remediation', 'N/A')}"
                ),
                confidence=min(verdict.get("confidence", 0.7), 1.0),
                scanner_name=self.scanner_name,
                endpoint_url=first_step.get("url", ""),
                http_method=first_step.get("method", ""),
                code_location=code_loc,
                response_preview=verdict.get("evidence", "")[
                    : LLMBusinessLogicConfig.RESPONSE_PREVIEW_LENGTH
                ],
            )
        except Exception as exc:
            logger.warning(
                LLMBusinessLogicConfig.ERROR_RESULT_ANALYSIS_FAILED.format(
                    plan=plan.get("title", ""), error=str(exc),
                )
            )
            return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_framework(files: dict[str, str]) -> str:
        """Detect the framework from file paths using configurable rules."""
        paths = " ".join(files.keys()).lower()
        for indicators, framework in LLMBusinessLogicConfig.FRAMEWORK_PATTERNS:
            if any(ind in paths for ind in indicators):
                return framework
        return LLMBusinessLogicConfig.DEFAULT_FRAMEWORK

    @staticmethod
    def _parse_attack_plans(response: str) -> list[dict]:
        """Parse attack plans from LLM JSON response."""
        data = LLMBusinessLogicScanner._parse_json_response(response)
        if not data:
            return []
        plans = data.get("attack_plans", [])
        if not isinstance(plans, list):
            return []
        return [p for p in plans if isinstance(p, dict) and p.get("steps")]

    @staticmethod
    def _parse_json_response(response: str) -> dict | None:
        """Extract JSON from LLM response (handles markdown code blocks)."""
        # Strip markdown code fences
        text = response.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            lines = [l for l in lines if not l.strip().startswith("```")]
            text = "\n".join(lines)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to find JSON in the response
            match = re.search(r'\{[\s\S]*\}', text)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass
        return None
