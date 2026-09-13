"""Ported differential oracles for SSTI and NoSQL (from the pentest exploiters).

SSTI: the distinctive product (99991*7=699937) must be EVALUATED, not merely
reflected. NoSQL: an operator must BROADEN the query versus an exact-match
control — the old size-ratio heuristic false-positived on naturally-variable
pages.
"""

from __future__ import annotations

from isitsecure.engine.constants import InjectionConfig, TemplateInjectionConfig
from isitsecure.engine.scanners.active_injection_scanner import ActiveInjectionScanner


class TestSstiPayloads:
    def test_product_is_distinctive_not_49(self) -> None:
        exps = {e for _, e, _ in TemplateInjectionConfig.SSTI_PAYLOADS}
        assert exps == {"699937"}  # not "49"/"7777777" which appear by chance
        assert "699937" == str(99991 * 7)

    def test_covers_the_major_engine_families(self) -> None:
        payloads = " ".join(p for p, _, _ in TemplateInjectionConfig.SSTI_PAYLOADS)
        for frag in ("{{99991*7}}", "${99991*7}", "<%= 99991*7 %>", "#{99991*7}"):
            assert frag in payloads


def _broadened(status, body, control_ok, control):
    return ActiveInjectionScanner._operator_broadened(status, body, control_ok, control)


class TestNoSqlBroadenOracle:
    def test_empty_control_then_data_is_broadening(self) -> None:
        assert _broadened(200, '[{"id":1},{"id":2}]', True, "")

    def test_tiny_container_control_needs_material_increase(self) -> None:
        # A 2-char "[]" control is not treated as empty (len<2); the ported
        # oracle then requires a materially larger attack — conservative, no FP.
        assert not _broadened(200, '[{"id":1}]', True, "[]")
        assert _broadened(200, '[' + '{"id":1},' * 40 + ']', True, "[]")

    def test_denied_control_then_data_is_broadening(self) -> None:
        # control was 401/denied -> any authorized data on the operator broadens
        assert _broadened(200, '[{"id":1}]', False, "Unauthorized")

    def test_identical_to_control_is_not_broadening(self) -> None:
        assert not _broadened(200, '{"a":1}', True, '{"a":1}')

    def test_marginally_larger_non_empty_control_is_not_broadening(self) -> None:
        # control already had data; attack only trivially larger -> not proven
        assert not _broadened(200, '{"a":1,"b":2}', True, '{"a":1}')

    def test_materially_larger_than_populated_control_broadens(self) -> None:
        assert _broadened(200, "x" * 500, True, "x" * 50)

    def test_error_status_is_never_broadening(self) -> None:
        assert not _broadened(500, "big body " * 50, True, "")

    def test_empty_attack_is_not_broadening(self) -> None:
        assert not _broadened(200, "", True, "")
