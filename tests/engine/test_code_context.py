"""Tests for CodeContextExtractor utility."""

import pytest

from isitsecure.engine.shared.code_context import CodeContextExtractor

SAMPLE_CODE = """import express from 'express';
const app = express();

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000);"""


class TestCodeContextExtractor:
    """Tests for the CodeContextExtractor class."""

    def test_empty_content_returns_empty(self) -> None:
        """Empty string content should return empty string."""
        assert CodeContextExtractor.extract("", line_number=5) == ""

    def test_none_line_number_shows_file_start(self) -> None:
        """None line_number should return the first N lines without a marker."""
        result = CodeContextExtractor.extract(SAMPLE_CODE, line_number=None)
        assert result  # non-empty
        # Should not contain the problem marker
        assert CodeContextExtractor.PROBLEM_LINE_MARKER not in result
        # Should start at line 1
        lines = result.strip().splitlines()
        assert lines[0].strip().startswith("1")

    def test_zero_line_number_shows_file_start(self) -> None:
        """line_number=0 should behave like None — show file start."""
        result_zero = CodeContextExtractor.extract(SAMPLE_CODE, line_number=0)
        result_none = CodeContextExtractor.extract(SAMPLE_CODE, line_number=None)
        assert result_zero == result_none

    def test_extracts_context_around_line(self) -> None:
        """Line 5 of 12-line content should show surrounding lines."""
        result = CodeContextExtractor.extract(SAMPLE_CODE, line_number=5)
        lines = result.strip().splitlines()
        # Should contain the problem line and surrounding context
        assert len(lines) > 1
        # Line 5 should be present with the marker
        marked = [ln for ln in lines if CodeContextExtractor.PROBLEM_LINE_MARKER in ln]
        assert len(marked) == 1

    def test_problem_line_marked_with_arrows(self) -> None:
        """The problem line should use the >>> marker."""
        result = CodeContextExtractor.extract(SAMPLE_CODE, line_number=7)
        lines = result.strip().splitlines()
        marked = [ln for ln in lines if CodeContextExtractor.PROBLEM_LINE_MARKER in ln]
        assert len(marked) == 1
        # The marked line should contain "7" as the line number
        assert "7" in marked[0]

    def test_non_problem_lines_have_pipe(self) -> None:
        """Non-problem lines should use | separator."""
        result = CodeContextExtractor.extract(SAMPLE_CODE, line_number=7)
        lines = result.strip().splitlines()
        pipe_lines = [ln for ln in lines if " | " in ln]
        marker_lines = [ln for ln in lines if CodeContextExtractor.PROBLEM_LINE_MARKER in ln]
        # All lines are either pipe or marker
        assert len(pipe_lines) + len(marker_lines) == len(lines)
        # There should be more pipe lines than marker lines
        assert len(pipe_lines) > len(marker_lines)

    def test_line_numbers_right_aligned(self) -> None:
        """Line numbers should be right-aligned to consistent width.

        The source uses rjust(width) so single-digit numbers in a range
        that includes double-digit numbers should be space-padded.
        """
        # Use a 20-line file and target line 10 so the window spans
        # both single-digit (5-9) and double-digit (10-15) numbers.
        content = "\n".join(f"line {i}" for i in range(1, 21))
        result = CodeContextExtractor.extract(content, line_number=10)
        lines = result.strip().splitlines()

        # Single-digit line numbers should be space-padded (e.g., " 5")
        # while double-digit numbers should not (e.g., "10").
        has_padded_single_digit = False
        has_double_digit = False
        for line in lines:
            stripped = line.lstrip()
            if stripped[0].isdigit() and line[0] == " ":
                has_padded_single_digit = True
            if len(line) > 1 and line[0].isdigit() and line[1].isdigit():
                has_double_digit = True
        # Both types should be present in the output
        assert has_padded_single_digit, "Expected padded single-digit line numbers"
        assert has_double_digit, "Expected double-digit line numbers"

    def test_context_at_file_start(self) -> None:
        """Line 1 should have no lines before, but lines after."""
        result = CodeContextExtractor.extract(SAMPLE_CODE, line_number=1)
        lines = result.strip().splitlines()
        # First line should be the problem line (line 1)
        assert CodeContextExtractor.PROBLEM_LINE_MARKER in lines[0]
        # Should have lines after
        assert len(lines) > 1

    def test_context_at_file_end(self) -> None:
        """Last line should have lines before but no lines after."""
        content_lines = SAMPLE_CODE.splitlines()
        last_line = len(content_lines)
        result = CodeContextExtractor.extract(SAMPLE_CODE, line_number=last_line)
        lines = result.strip().splitlines()
        # Last output line should be the problem line
        assert CodeContextExtractor.PROBLEM_LINE_MARKER in lines[-1]
        # Should have lines before
        assert len(lines) > 1

    def test_custom_context_before_after(self) -> None:
        """Custom context_before and context_after should override defaults."""
        result = CodeContextExtractor.extract(
            SAMPLE_CODE,
            line_number=6,
            context_before=2,
            context_after=3,
        )
        lines = result.strip().splitlines()
        # context_before=2 + problem line + context_after=3 = 6 lines max
        assert len(lines) <= 6
        # Problem line should be present
        marked = [ln for ln in lines if CodeContextExtractor.PROBLEM_LINE_MARKER in ln]
        assert len(marked) == 1

    def test_truncates_long_output(self) -> None:
        """Content exceeding MAX_SNIPPET_LENGTH should be truncated."""
        # Create content with 1000 lines, each ~300 chars to guarantee
        # the 11-line window exceeds MAX_SNIPPET_LENGTH (2000).
        padding = "x" * 280
        long_content = "\n".join(
            f"const v_{i} = '{padding}';"
            for i in range(1000)
        )
        result = CodeContextExtractor.extract(long_content, line_number=500)
        assert result.endswith("... (truncated)")
        # Total length should not wildly exceed the limit
        assert len(result) <= CodeContextExtractor.MAX_SNIPPET_LENGTH + len(
            "\n... (truncated)"
        )

    def test_single_line_file(self) -> None:
        """A file with a single line should still produce output."""
        result = CodeContextExtractor.extract("console.log('hello');", line_number=1)
        lines = result.strip().splitlines()
        assert len(lines) == 1
        assert CodeContextExtractor.PROBLEM_LINE_MARKER in lines[0]
        assert "console.log" in lines[0]
