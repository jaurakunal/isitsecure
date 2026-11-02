"""Exports a FixPlan as a Markdown document.

The output is designed to be pasted into Cursor, Claude Code, or any
AI coding assistant as a "fix all" prompt.

SRP: This module only formats FixPlan → Markdown. It does not generate
     fixes or interact with the LLM.
"""

from __future__ import annotations

import re

from isitsecure.engine.fixes.fix_generator import FixPlan

_TICKS = re.compile(r"`+")


def fence_for(content: str, minimum: int = 3) -> str:
    """A backtick fence strictly longer than any backtick run in ``content``.

    Diffs and explanations are derived from scanned (untrusted) files, which can
    contain triple backticks; a fixed ```` ``` ```` fence would let that text
    close the block early and land as live instructions in a document meant to
    be pasted into a coding agent.
    """
    longest = max((len(m.group(0)) for m in _TICKS.finditer(content)), default=0)
    return "`" * max(minimum, longest + 1)


def fenced(content: str, info: str = "") -> list[str]:
    """Markdown lines for ``content`` inside an un-escapable code fence."""
    fence = fence_for(content)
    return [f"{fence}{info}", content, fence]


def inline(text: str) -> str:
    """One safe line of repo-derived text for use OUTSIDE a fence."""
    return _TICKS.sub("'", " ".join(str(text).split()))


class FixPlanMarkdownExporter:
    """Exports a FixPlan as a Markdown fix document."""

    def export(self, plan: FixPlan) -> str:
        """Export the fix plan as a Markdown string."""
        parts = [
            "# isitsecure Fix Plan",
            "",
            f"**{plan.fixed_count} fixes generated** from {plan.total_findings} findings "
            f"({plan.failed_count} failed, {len(plan.skipped)} skipped)",
            "",
        ]

        if plan.skipped:
            parts.append("## Skipped (no source file)")
            parts.append("")
            for reason in plan.skipped:
                parts.append(f"- {inline(reason)}")
            parts.append("")

        for i, fix in enumerate(plan.fixes, 1):
            if not fix.success:
                continue

            parts.append(f"## Fix {i}: {inline(fix.file_path)}")
            parts.append("")

            if fix.explanation:
                # Model text derived from the scanned file: keep it inside a
                # fence so it cannot masquerade as instructions.
                parts.extend(fenced(fix.explanation, "text"))
                parts.append("")

            parts.extend(fenced(fix.diff, "diff"))
            parts.append("")

        # Add a "paste into Cursor" section
        parts.append("---")
        parts.append("")
        parts.append("## Apply These Fixes")
        parts.append("")
        parts.append("**Option 1: Paste into Cursor / Claude Code**")
        parts.append("")
        parts.append("Copy this entire document and paste it with the prompt:")
        parts.append("> Apply all the security fixes in this document to my codebase.")
        parts.append("")
        parts.append("**Option 2: Apply diffs manually**")
        parts.append("")
        parts.append("Save the diffs above and run:")
        parts.append("```bash")
        parts.append("# For each diff block, save as fix-N.patch and apply:")
        parts.append("git apply fix-1.patch")
        parts.append("```")
        parts.append("")
        parts.append("**Option 3: Re-scan to verify**")
        parts.append("")
        parts.append("After applying fixes, re-run the scan:")
        parts.append("```bash")
        parts.append("isitsecure scan --repo . --mode code-only --output table")
        parts.append("```")

        return "\n".join(parts)
