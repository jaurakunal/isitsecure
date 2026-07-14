"""Regression guard for DeepScanReport's scan_mode serialization.

The remote fix->PR flow once passed `scan_mode` as a plain string ("code-only")
while agent.py did `mode.value`, crashing every remote scan with
`AttributeError: 'str' object has no attribute 'value'`. Mocked tests missed it;
a real-repo run caught it. `_safe_enum_value` must tolerate enum, plain str, and
None so a stray string can never crash report construction again.
"""

from isitsecure.engine.agent import DeepSecurityScanAgent
from isitsecure.engine.enums import ScanMode

_safe = DeepSecurityScanAgent._safe_enum_value


def test_enum_member_returns_plain_string_value():
    result = _safe(ScanMode.CODE_ONLY)
    assert result == "code_only"
    assert type(result) is str  # not the StrEnum member


def test_plain_string_passes_through_unchanged():
    # This is the exact input that used to crash the remote fix flow.
    assert _safe("code-only") == "code-only"


def test_none_returns_empty_string():
    assert _safe(None) == ""


def test_non_enum_non_string_returns_empty_string():
    assert _safe(object()) == ""
