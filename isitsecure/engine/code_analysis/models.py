"""Data models for code analysis findings."""

from __future__ import annotations

from uuid import uuid4

from pydantic import BaseModel, Field

from isitsecure.engine.enums import FindingCategory, SeverityLevel


class CodeFinding(BaseModel):
    """A security finding from static code analysis."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    scanner_name: str
    severity: SeverityLevel
    category: FindingCategory
    title: str
    description: str
    file_path: str
    line_number: int | None = None
    line_end: int | None = None
    code_snippet: str = ""
    fix_suggestion: str = ""
    fix_code: str = ""
    confidence: float = Field(ge=0.0, le=1.0)
    commit_hash: str | None = None
    is_in_current_head: bool = True
    github_url: str = ""
    # LSP validation (backward-compatible defaults)
    lsp_validated: bool = False
    lsp_suppressed: bool = False
