"""The unauthenticated swap path must not CONFIRM IDOR.

An unauthenticated probe cannot tell public-by-design data from a real leak --
Juice Shop's ``/api/Products/{id}`` and ``/api/Recycles/{id}`` both return a
different record per id with no auth. So the swap path caps at POSSIBLE (a lead,
not an emitted finding); CONFIRMED belongs to the cross-user path. And the swap
comparison must be real: an id that is ignored (same response for every value)
is not an object reference and must not read as "differs".
"""

from __future__ import annotations

from isitsecure.engine.enums import IDORRiskLevel, IDORTestType
from isitsecure.engine.models import IDORProbeResult
from isitsecure.engine.scanners.idor_scanner import IDORScanner, _bodies_differ


def _probe(test_type, *, data, differs, error=None) -> IDORProbeResult:
    return IDORProbeResult(
        original_url="http://t/api/x/1",
        probed_url="http://t/api/x/2",
        test_type=test_type,
        data_returned=data,
        response_differs=differs,
        error=error,
    )


class TestBodiesDiffer:
    def test_no_original_is_not_a_difference(self) -> None:
        assert not _bodies_differ("", '{"id":2}')

    def test_identical_bodies_do_not_differ(self) -> None:
        assert not _bodies_differ('{"id":1}', '{"id":1}')

    def test_whitespace_only_change_does_not_differ(self) -> None:
        assert not _bodies_differ('{"id": 1}', '{"id":1}\n')

    def test_different_content_differs(self) -> None:
        assert _bodies_differ('{"id":1}', '{"id":2}')


class TestAssessRiskDowngrade:
    def test_swap_with_differing_data_is_possible_not_confirmed(self) -> None:
        # Was CONFIRMED (0.95); an unauthenticated swap cannot confirm.
        probes = [_probe(IDORTestType.PATH_PARAM_SWAP, data=True, differs=True)]
        level, conf = IDORScanner()._assess_risk(probes)
        assert level == IDORRiskLevel.POSSIBLE
        assert conf < 0.8

    def test_unauthed_access_alone_is_safe(self) -> None:
        # A plain public read is not an IDOR; was LIKELY.
        probes = [_probe(IDORTestType.UNAUTHED_ACCESS, data=True, differs=False)]
        level, _ = IDORScanner()._assess_risk(probes)
        assert level == IDORRiskLevel.SAFE

    def test_id_ignored_swap_is_safe(self) -> None:
        # Data returned but identical to the original -> id ignored, not IDOR.
        probes = [_probe(IDORTestType.SEQUENTIAL_ID_ENUM, data=True, differs=False)]
        level, _ = IDORScanner()._assess_risk(probes)
        assert level == IDORRiskLevel.SAFE

    def test_no_data_is_safe(self) -> None:
        probes = [_probe(IDORTestType.PATH_PARAM_SWAP, data=False, differs=False)]
        assert IDORScanner()._assess_risk(probes)[0] == IDORRiskLevel.SAFE

    def test_errored_probe_does_not_confirm(self) -> None:
        probes = [_probe(IDORTestType.PATH_PARAM_SWAP, data=True, differs=True,
                         error="boom")]
        assert IDORScanner()._assess_risk(probes)[0] == IDORRiskLevel.SAFE

    def test_swap_never_reaches_the_emission_threshold(self) -> None:
        # agent.py emits only CONFIRMED/LIKELY. POSSIBLE must be the ceiling
        # for every unauthenticated read combination, so nothing is emitted.
        for tt in (IDORTestType.PATH_PARAM_SWAP,
                   IDORTestType.QUERY_PARAM_SWAP,
                   IDORTestType.SEQUENTIAL_ID_ENUM,
                   IDORTestType.UNAUTHED_ACCESS):
            level, _ = IDORScanner()._assess_risk(
                [_probe(tt, data=True, differs=True)]
            )
            assert level not in (IDORRiskLevel.CONFIRMED, IDORRiskLevel.LIKELY)
