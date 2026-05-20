"""Prompts for LLM-powered fix generation.

SRP: This module only defines prompts. Fix generation logic is in
     fix_generator.py.
"""

from __future__ import annotations

from isitsecure.engine.models import DeepFinding


class FixPrompts:
    """Prompts for generating security fixes."""

    SYSTEM_PROMPT = """You are a senior security engineer fixing vulnerabilities in a web application.

RULES:
1. Output the COMPLETE fixed file inside a single fenced code block (```typescript or ```sql etc.)
2. Only change what is necessary to fix the vulnerability. Do not refactor, reorganize, or "improve" unrelated code.
3. Preserve all existing functionality — the fix must not break the application.
4. Before the code block, write 1-3 sentences explaining what you changed and why.
5. After the code block, write nothing.
6. If the fix requires a new import, add it.
7. If the fix requires a new dependency, mention it in the explanation.
8. Use the same coding style as the original file (indentation, quotes, etc.)

COMMON FIX PATTERNS:
- SQL injection → parameterized queries (use tagged template literals in postgres.js, or $1/$2 placeholders)
- XSS → escape output, use textContent instead of innerHTML, add CSP headers
- Missing auth → add getUserFromRequest() check at the top of the handler
- Missing ownership → add WHERE user_id = $userId to queries
- IDOR → verify the authenticated user owns the requested resource
- Mass assignment → explicitly pick allowed fields from the request body
- RLS → add ALTER TABLE ... ENABLE ROW LEVEL SECURITY + CREATE POLICY statements
- CSRF → validate Origin header or use SameSite cookies
- Rate limiting → add rate limiter middleware
- Weak JWT → restrict algorithms, use strong secret, add expiration
- Open redirect → validate redirect URL is relative or on an allowlist
- File upload → whitelist extensions, generate random filenames
- Race condition → use database transactions with SELECT ... FOR UPDATE
- Docker → add USER directive, pin base image version, use .dockerignore"""

    @classmethod
    def build_fix_prompt(cls, finding: DeepFinding, file_content: str) -> str:
        """Build the user prompt for fix generation."""
        severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        category = finding.category.value if hasattr(finding.category, "value") else str(finding.category)
        file_path = finding.code_location.file_path if finding.code_location else "unknown"
        line = finding.code_location.line_number if finding.code_location else None

        parts = [
            f"## Vulnerability to Fix",
            f"**Severity:** {severity.upper()}",
            f"**Category:** {category}",
            f"**Scanner:** {finding.scanner_name}",
            f"**Title:** {finding.title}",
        ]

        if finding.description:
            parts.append(f"**Description:** {finding.description}")

        if finding.remediation_guidance:
            parts.append(f"**Guidance:** {finding.remediation_guidance}")

        if line:
            parts.append(f"**Location:** {file_path}:{line}")
        else:
            parts.append(f"**File:** {file_path}")

        parts.append(f"\n## Source File: {file_path}\n")
        parts.append(f"```\n{file_content}\n```")
        parts.append(f"\nGenerate the fixed version of this complete file.")

        return "\n".join(parts)
