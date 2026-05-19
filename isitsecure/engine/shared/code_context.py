"""Code context extraction around problem lines.

SRP: This module is responsible ONLY for extracting formatted code
     snippets.  It does not detect problems, assign severity, or
     make any security judgments.

DRY: All scanners that need code context use this single utility
     instead of implementing their own substring/line extraction.
"""

from __future__ import annotations


class CodeContextExtractor:
    """Extracts formatted code context around a specific line number.

    Output format::

        248 |   // Seller onboarding
        249 |   acceptSellerTos: tenantProcedure
        250 |     .mutation(async ({ ctx }) => {
        251 |       const updated = await userRepo.update(ctx.user.id, ctx.tenantId, {
        252 |         seller_tos_accepted_at: new Date(),
        253 >>>   });
        254 |       // Immediately grants seller role — no verification
        255 |       await db.insert(userRoles).values({
        256 |         user_id: ctx.user.id,
        257 |         role: 'seller',
        258 |       });
    """

    CONTEXT_LINES_BEFORE = 8
    CONTEXT_LINES_AFTER = 8
    PROBLEM_LINE_MARKER = ">>>"
    MAX_SNIPPET_LENGTH = 2000

    @classmethod
    def extract(
        cls,
        content: str,
        line_number: int | None,
        context_before: int | None = None,
        context_after: int | None = None,
    ) -> str:
        """Extract formatted code context around a line number.

        Args:
            content: Full file content.
            line_number: 1-based line number of the problem line.
                If None or 0, returns the first 11 lines.
            context_before: Lines to show before the problem line.
                Defaults to ``CONTEXT_LINES_BEFORE``.
            context_after: Lines to show after the problem line.
                Defaults to ``CONTEXT_LINES_AFTER``.

        Returns:
            Formatted code snippet with line numbers and a ``>>>``
            marker on the problem line.
        """
        if not content:
            return ""

        lines = content.splitlines()
        total_lines = len(lines)

        before = context_before if context_before is not None else cls.CONTEXT_LINES_BEFORE
        after = context_after if context_after is not None else cls.CONTEXT_LINES_AFTER

        # Handle missing/invalid line number — show file start
        if not line_number or line_number < 1:
            end = min(before + after + 1, total_lines)
            return cls._format_lines(lines[:end], start_line=1)

        # Clamp to file bounds
        line_idx = min(line_number, total_lines)  # 1-based

        start_idx = max(0, line_idx - 1 - before)
        end_idx = min(total_lines, line_idx + after)

        selected = lines[start_idx:end_idx]
        start_line = start_idx + 1  # back to 1-based

        return cls._format_lines(
            selected,
            start_line=start_line,
            problem_line=line_number,
        )

    @classmethod
    def _format_lines(
        cls,
        lines: list[str],
        start_line: int,
        problem_line: int | None = None,
    ) -> str:
        """Format lines with line numbers and optional problem marker."""
        formatted: list[str] = []
        max_line_num = start_line + len(lines) - 1
        width = len(str(max_line_num))

        for i, line in enumerate(lines):
            line_num = start_line + i
            num_str = str(line_num).rjust(width)

            if problem_line and line_num == problem_line:
                formatted.append(
                    f"{num_str} {cls.PROBLEM_LINE_MARKER} {line}"
                )
            else:
                formatted.append(f"{num_str} | {line}")

        result = "\n".join(formatted)

        # Truncate if too long
        if len(result) > cls.MAX_SNIPPET_LENGTH:
            result = result[: cls.MAX_SNIPPET_LENGTH] + "\n... (truncated)"

        return result
