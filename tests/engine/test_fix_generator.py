"""Tests for FixGenerator."""

import pytest
from unittest.mock import AsyncMock

from isitsecure.engine.fixes.fix_generator import FixGenerator, FixResult, FixPlan
from isitsecure.engine.fixes.prompts import FixPrompts
from isitsecure.engine.fixes.markdown_exporter import FixPlanMarkdownExporter
from isitsecure.engine.models import DeepFinding, FindingSource, CodeLocation
from isitsecure.engine.enums import FindingCategory, SeverityLevel


def _make_finding(file_path="src/db.ts", line=10, title="SQL injection"):
    return DeepFinding(
        source=FindingSource.SAST_CODE,
        category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.CRITICAL,
        title=title,
        description="Raw SQL concatenation",
        scanner_name="active_injection_scanner",
        confidence=0.9,
        code_location=CodeLocation(
            file_path=file_path,
            line_number=line,
            code_snippet="return sql.unsafe(query)",
        ),
    )


class TestFixGenerator:
    @pytest.mark.asyncio
    async def test_generates_fix_with_diff(self):
        mock_llm = AsyncMock()
        mock_llm.generate_with_system.return_value = (
            "Fixed the SQL injection by using parameterized queries.\n\n"
            "```typescript\n"
            "return sql`SELECT * FROM ${table}`\n"
            "```"
        )

        generator = FixGenerator(mock_llm)
        finding = _make_finding()
        result = await generator.generate_fix(finding, "return sql.unsafe(query)")

        assert result.success is True
        assert result.diff != ""
        assert "sql`SELECT" in result.fixed_code
        assert "parameterized" in result.explanation.lower()

    @pytest.mark.asyncio
    async def test_returns_error_when_no_file(self):
        mock_llm = AsyncMock()
        generator = FixGenerator(mock_llm)

        finding = DeepFinding(
            source=FindingSource.DAST_URL,
            category=FindingCategory.INJECTION_RISK,
            severity=SeverityLevel.HIGH,
            title="XSS",
            description="Reflected XSS",
            scanner_name="xss_scanner",
            confidence=0.8,
        )
        result = await generator.generate_fix(finding, "")

        assert result.success is False
        assert "No source file" in result.error

    @pytest.mark.asyncio
    async def test_returns_error_on_large_file(self):
        mock_llm = AsyncMock()
        generator = FixGenerator(mock_llm)

        finding = _make_finding()
        large_content = "x" * 60_000
        result = await generator.generate_fix(finding, large_content)

        assert result.success is False
        assert "too large" in result.error.lower()

    @pytest.mark.asyncio
    async def test_returns_error_when_no_code_block(self):
        mock_llm = AsyncMock()
        mock_llm.generate_with_system.return_value = "I can't fix this."

        generator = FixGenerator(mock_llm)
        finding = _make_finding()
        result = await generator.generate_fix(finding, "original code")

        assert result.success is False
        assert "Could not extract" in result.error

    @pytest.mark.asyncio
    async def test_returns_error_when_code_unchanged(self):
        mock_llm = AsyncMock()
        mock_llm.generate_with_system.return_value = (
            "No changes needed.\n\n```typescript\noriginal code\n```"
        )

        generator = FixGenerator(mock_llm)
        finding = _make_finding()
        result = await generator.generate_fix(finding, "original code")

        assert result.success is False
        assert "no changes" in result.error.lower()


class TestExtractCodeBlock:
    def test_extracts_typescript_block(self):
        response = "Here:\n```typescript\nconst x = 1\n```\n"
        assert FixGenerator._extract_code_block(response) == "const x = 1"

    def test_extracts_generic_block(self):
        response = "Fix:\n```\ncode here\n```"
        assert FixGenerator._extract_code_block(response) == "code here"

    def test_returns_empty_for_no_block(self):
        assert FixGenerator._extract_code_block("no code here") == ""

    def test_extracts_first_block_only(self):
        response = "```python\nfirst\n```\nand\n```python\nsecond\n```"
        assert FixGenerator._extract_code_block(response) == "first"


class TestExtractExplanation:
    def test_extracts_text_before_code(self):
        response = "Fixed the bug.\n\n```\ncode\n```"
        assert "Fixed the bug" in FixGenerator._extract_explanation(response)

    def test_empty_for_no_text(self):
        response = "```\ncode\n```"
        assert FixGenerator._extract_explanation(response) == ""


class TestGenerateDiff:
    def test_produces_unified_diff(self):
        diff = FixGenerator._generate_diff("test.py", "old line\n", "new line\n")
        assert "--- a/test.py" in diff
        assert "+++ b/test.py" in diff
        assert "-old line" in diff
        assert "+new line" in diff

    def test_empty_when_no_changes(self):
        diff = FixGenerator._generate_diff("test.py", "same\n", "same\n")
        assert diff == ""


class TestFixPrompts:
    def test_build_includes_severity(self):
        finding = _make_finding()
        prompt = FixPrompts.build_fix_prompt(finding, "code here")
        assert "CRITICAL" in prompt

    def test_build_includes_file_content(self):
        finding = _make_finding()
        prompt = FixPrompts.build_fix_prompt(finding, "const sql = postgres(url)")
        assert "const sql = postgres(url)" in prompt

    def test_build_includes_file_path(self):
        finding = _make_finding(file_path="src/lib/db.ts")
        prompt = FixPrompts.build_fix_prompt(finding, "code")
        assert "src/lib/db.ts" in prompt


class TestFixPlan:
    def test_counts(self):
        plan = FixPlan(
            total_findings=5,
            fixes=[
                FixResult(finding_id="1", file_path="a.ts", success=True),
                FixResult(finding_id="2", file_path="b.ts", success=False, error="x"),
                FixResult(finding_id="3", file_path="c.ts", success=True),
            ],
        )
        assert plan.fixed_count == 2
        assert plan.failed_count == 1


class TestMarkdownExporter:
    def test_exports_fixes(self):
        plan = FixPlan(
            total_findings=2,
            fixes=[
                FixResult(
                    finding_id="1",
                    file_path="test.py",
                    success=True,
                    diff="--- a/test.py\n+++ b/test.py\n-old\n+new",
                    explanation="Fixed it.",
                ),
            ],
        )
        exporter = FixPlanMarkdownExporter()
        md = exporter.export(plan)

        assert "# isitsecure Fix Plan" in md
        assert "1 fixes generated" in md
        assert "test.py" in md
        assert "Fixed it." in md
        assert "```diff" in md
        assert "Cursor" in md

    def test_exports_skipped(self):
        plan = FixPlan(
            total_findings=1,
            skipped=["XSS — no source file"],
        )
        exporter = FixPlanMarkdownExporter()
        md = exporter.export(plan)
        assert "Skipped" in md
        assert "XSS" in md
