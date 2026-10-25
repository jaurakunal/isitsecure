"""Tests for the shared LLM reply-parsing helpers and skip bookkeeping."""

from __future__ import annotations

import asyncio
import logging

import pytest

from isitsecure.engine.code_analysis import llm_code_reviewer
from isitsecure.engine.code_analysis import llm_parsing as lp
from isitsecure.engine.enums import SeverityLevel
from isitsecure.engine.scanners.llm_business_logic_scanner import (
    LLMBusinessLogicScanner,
)

SEV = {"HIGH": SeverityLevel.HIGH, "LOW": SeverityLevel.LOW}


def test_reviewer_reexports_same_objects():
    assert llm_code_reviewer.extract_json_array is lp.extract_json_array
    assert llm_code_reviewer.coerce_severity is lp.coerce_severity
    assert llm_code_reviewer.coerce_line_number is lp.coerce_line_number


@pytest.mark.parametrize(
    "reply, expected",
    [
        ('[{"a": 1}]', [{"a": 1}]),
        ('Found [2 issues]: [{"a": 1}]', [{"a": 1}]),
        ('```json\n[{"a": 1}]\n```', [{"a": 1}]),
        ('[[1, 2], [3]]', [[1, 2], [3]]),
        ('[{"a": [1, 2]}, {"b": 2}]', [{"a": [1, 2]}, {"b": 2}]),
        ('[{"a": 1}', None),
        ('no array here', None),
        ('', None),
        (None, None),
    ],
)
def test_extract_json_array(reply, expected):
    assert lp.extract_json_array(reply) == expected


def test_extract_json_array_unclosed_with_nested_returns_inner_only_if_valid():
    # The outer array never closes; the first complete array is the inner one.
    assert lp.extract_json_array('[{"a": [1, 2]}, {"b"') == [1, 2]


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("high", SeverityLevel.HIGH),
        (" LOW ", SeverityLevel.LOW),
        (None, SeverityLevel.MEDIUM),
        (3, SeverityLevel.MEDIUM),
        ("bogus", SeverityLevel.MEDIUM),
    ],
)
def test_coerce_severity(raw, expected):
    assert lp.coerce_severity(raw, SEV) is expected


@pytest.mark.parametrize(
    "raw, expected",
    [(12, 12), ("34", 34), (" 5 ", 5), (True, None), ("x", None), (None, None), (1.5, None)],
)
def test_coerce_line_number(raw, expected):
    assert lp.coerce_line_number(raw) == expected


def test_parse_finding_fields_defaults_and_coercion():
    f = lp.parse_finding_fields(
        {"severity": None, "title": None, "description": None, "line_number": "7"},
        SEV,
        "Fallback",
    )
    assert (f.severity, f.title, f.description, f.line_number) == (
        SeverityLevel.MEDIUM, "Fallback", "", 7,
    )
    g = lp.parse_finding_fields(
        {"severity": "high", "title": "T", "description": "D"}, SEV, "Fallback"
    )
    assert (g.severity, g.title, g.description, g.line_number) == (
        SeverityLevel.HIGH, "T", "D", None,
    )


def test_record_skip_appends_logs_and_emits(monkeypatch, caplog):
    emitted: list[str] = []
    monkeypatch.setattr(lp, "emit", emitted.append)
    skips: list[tuple[str, str]] = []
    with caplog.at_level(logging.WARNING, logger=lp.__name__):
        lp.record_skip(skips, "Thing incomplete for", "a.py", "boom")
    assert skips == [("a.py", "boom")]
    assert emitted == ["Thing incomplete for a.py: boom"]
    assert "a.py" in caplog.text


class _Judge:
    def __init__(self, reply):
        self.reply = reply

    async def generate_with_system(self, **kwargs):
        return self.reply


def _scanner(reply):
    s = LLMBusinessLogicScanner.__new__(LLMBusinessLogicScanner)
    s._judgment_llm = _Judge(reply)
    s.skipped_steps = []
    return s


def test_business_logic_records_skip_on_unparseable_judge_reply(monkeypatch):
    monkeypatch.setattr(lp, "emit", lambda _m: None)
    s = _scanner("totally not json")
    result = asyncio.run(s._analyze_results({"title": "P"}, []))
    assert result is None
    assert s.skipped_steps == [("P", "unparseable judge reply (no JSON object)")]


def test_business_logic_records_skip_on_plan_without_steps(monkeypatch):
    monkeypatch.setattr(lp, "emit", lambda _m: None)
    s = _scanner("{}")
    result = asyncio.run(
        s._execute_and_analyze_plan({"title": "P", "steps": []}, {}, "http://x")
    )
    assert result is None
    assert s.skipped_steps == [("P", "plan has no executable steps")]
