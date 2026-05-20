"""Exports a FixPlan as a Markdown document.

The output is designed to be pasted into Cursor, Claude Code, or any
AI coding assistant as a "fix all" prompt.

SRP: This module only formats FixPlan → Markdown. It does not generate
     fixes or interact with the LLM.
"""

from __future__ import annotations

from isitsecure.engine.fixes.fix_generator import FixPlan


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
                parts.append(f"- {reason}")
            parts.append("")

        for i, fix in enumerate(plan.fixes, 1):
            if not fix.success:
                continue

            parts.append(f"## Fix {i}: {fix.file_path}")
            parts.append("")

            if fix.explanation:
                parts.append(fix.explanation)
                parts.append("")

            parts.append("```diff")
            parts.append(fix.diff)
            parts.append("```")
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
