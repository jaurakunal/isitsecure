"""Triage merges need the same line (SAST) / parameter (DAST); Medium/Low need a target too."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from isitsecure.engine.enums import FindingCategory, ScanMode, SeverityLevel
from isitsecure.engine.models import CodeLocation, DeepFinding, FindingSource
from isitsecure.engine.triage.llm_triage_service import LLMTriageService


def _sast(fid: str, line: int, sev: SeverityLevel = SeverityLevel.HIGH) -> DeepFinding:
    return DeepFinding(
        id=fid, source=FindingSource.SAST_CODE, category=FindingCategory.INJECTION_RISK,
        severity=sev, title="SQL injection", description="d", confidence=0.9,
        scanner_name="llm_code_reviewer",
        code_location=CodeLocation(file_path="a.py", line_number=line),
    )


def _dast(fid: str, param: str, sev: SeverityLevel = SeverityLevel.HIGH) -> DeepFinding:
    return DeepFinding(
        id=fid, source=FindingSource.DAST_URL, category=FindingCategory.INJECTION_RISK,
        severity=sev, title="SQL injection", description="d", confidence=0.9,
        scanner_name="injection_scanner", endpoint_url="https://x/search",
        http_method="GET", request_payload=f"{param}='",
    )


async def _run(findings: list[DeepFinding], payload) -> list[str]:
    llm = AsyncMock()
    llm.generate_with_system.return_value = json.dumps(payload)
    await LLMTriageService(llm)._run_batched_dev_triage(findings, ScanMode.CODE_ONLY, "t")
    return [f.id for f in findings]


def _merge(target: str, dup: str) -> dict:
    return {"triaged_findings": [{"id": target, "merged_ids": [dup]}], "duplicate_ids": [dup]}


@pytest.mark.asyncio
async def test_distinct_sqli_at_different_lines_are_not_merged() -> None:
    assert await _run([_sast("a", 10), _sast("b", 200)], _merge("b", "a")) == ["a", "b"]


@pytest.mark.asyncio
async def test_same_line_same_file_is_merged_positive_control() -> None:
    assert await _run([_sast("a", 10), _sast("b", 10)], _merge("b", "a")) == ["b"]


@pytest.mark.asyncio
async def test_distinct_params_on_one_endpoint_are_not_merged() -> None:
    assert await _run([_dast("a", "q"), _dast("b", "sort")], _merge("b", "a")) == ["a", "b"]


@pytest.mark.asyncio
async def test_same_param_same_endpoint_is_merged_positive_control() -> None:
    assert await _run([_dast("a", "q"), _dast("b", "q")], _merge("b", "a")) == ["b"]


@pytest.mark.asyncio
async def test_medium_claimed_as_duplicate_without_valid_target_is_kept() -> None:
    a = _sast("a", 10, SeverityLevel.MEDIUM)
    b = _sast("b", 99, SeverityLevel.MEDIUM)
    assert await _run([a, b], _merge("b", "a")) == ["a", "b"]


@pytest.mark.asyncio
async def test_medium_duplicate_with_valid_target_is_merged() -> None:
    a = _sast("a", 10, SeverityLevel.MEDIUM)
    b = _sast("b", 10, SeverityLevel.MEDIUM)
    assert await _run([a, b], _merge("b", "a")) == ["b"]


@pytest.mark.asyncio
async def test_prompt_injected_reply_listing_many_mediums_keeps_them_all() -> None:
    findings = [_sast(f"m{i}", i, SeverityLevel.MEDIUM) for i in range(8)]
    ids = [f"m{i}" for i in range(8)]
    assert await _run(findings, {"triaged_findings": [], "duplicate_ids": ids}) == ids


@pytest.mark.asyncio
async def test_single_plain_false_positive_flag_still_removes_a_medium() -> None:
    findings = [_sast(f"m{i}", i, SeverityLevel.MEDIUM) for i in range(8)]
    kept = await _run(findings, {"triaged_findings": [], "duplicate_ids": ["m3"]})
    assert "m3" not in kept and len(kept) == 7
