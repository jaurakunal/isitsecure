"""Unit tests for the shared conclusive/inconclusive verdict module (#276)."""

from __future__ import annotations

import dataclasses
import json

import pytest

from isitsecure.engine.shared.verdict import (
    Outcome,
    Reply,
    Verdict,
    absolutize,
    body_signals_failure,
    evidence_gap,
    judge_difference,
    unreachable_reason,
)

CONTROL = Reply(200, '{"id": 1, "owner": "alice"}')


class TestVerdict:
    def test_proven_is_conclusive_and_vulnerable(self):
        v = Verdict.proven("x")
        assert v.conclusive and v.vulnerable

    def test_not_proven_is_conclusive_not_vulnerable(self):
        v = Verdict.not_proven("x")
        assert v.conclusive and not v.vulnerable

    def test_inconclusive_is_neither(self):
        v = Verdict.inconclusive("x")
        assert not v.conclusive and not v.vulnerable
        assert v.outcome is Outcome.INCONCLUSIVE

    def test_immutable(self):
        with pytest.raises(dataclasses.FrozenInstanceError):
            Verdict.proven("x").evidence = "y"  # type: ignore[misc]


class TestAbsolutize:
    def test_relative_without_base_is_none(self):
        assert absolutize("/api/login") is None

    def test_relative_with_base_resolves(self):
        assert absolutize("/api/login", "https://x.com/app") == "https://x.com/api/login"

    def test_absolute_kept(self):
        assert absolutize("https://x.com/a") == "https://x.com/a"

    @pytest.mark.parametrize("bad", ["", "   ", "ftp://x.com/a", "//x.com/a", "javascript:1"])
    def test_unsendable_is_none(self, bad):
        assert absolutize(bad) is None


class TestUnreachableReason:
    @pytest.mark.parametrize("status", [0, -1, 500, 503, 404, 405])
    def test_unusable_statuses(self, status):
        assert unreachable_reason(Reply(status, "x")) is not None

    def test_status_zero_names_transport_failure(self):
        assert "transport" in unreachable_reason(Reply(0))

    def test_get_html_shell_is_unreachable(self):
        assert unreachable_reason(Reply(200, "<!doctype html><html>", "GET"))

    def test_post_html_is_not_flagged(self):
        assert unreachable_reason(Reply(200, "<html>err</html>", "POST")) is None

    @pytest.mark.parametrize("status", [200, 201, 400, 401, 403, 422])
    def test_real_answers_are_usable(self, status):
        assert unreachable_reason(Reply(status, '{"a":1}', "POST")) is None


class TestJudgeDifference:
    def test_distinct_body_is_proven(self):
        v = judge_difference(Reply(200, '{"id": 2, "owner": "bob"}'), CONTROL)
        assert v.vulnerable and v.conclusive

    def test_identical_control_is_not_proven(self):
        v = judge_difference(Reply(200, CONTROL.body), CONTROL)
        assert v.conclusive and not v.vulnerable
        assert "identical" in v.evidence

    def test_status_change_alone_is_not_proof(self):
        v = judge_difference(Reply(201, CONTROL.body), Reply(403, CONTROL.body))
        assert not v.vulnerable

    def test_reflection_only_difference_is_not_proof(self):
        v = judge_difference(
            Reply(200, '{"echo": "PAYLOAD-1"}'),
            Reply(200, '{"echo": ""}'),
            probe_input="PAYLOAD-1",
        )
        assert not v.vulnerable and v.conclusive

    def test_reflection_plus_real_difference_is_proven(self):
        v = judge_difference(
            Reply(200, '{"echo": "PAYLOAD-1", "secret": "s3"}'),
            Reply(200, '{"echo": ""}'),
            probe_input="PAYLOAD-1",
        )
        assert v.vulnerable

    @pytest.mark.parametrize("bad", [Reply(0, ""), Reply(500, "boom"), Reply(404, "")])
    def test_transport_or_server_failure_treatment_is_inconclusive(self, bad):
        v = judge_difference(bad, CONTROL)
        assert not v.conclusive and not v.vulnerable

    def test_transport_failure_control_is_inconclusive(self):
        v = judge_difference(Reply(200, '{"a": 1}'), Reply(0, ""))
        assert not v.conclusive and "control" in v.evidence

    def test_validation_rejection_is_inconclusive(self):
        v = judge_difference(Reply(422, '{"detail": "bad"}'), CONTROL)
        assert not v.conclusive and "validation" in v.evidence

    def test_denial_is_not_proven(self):
        v = judge_difference(Reply(403, '{"error": "no"}'), CONTROL)
        assert v.conclusive and not v.vulnerable

    def test_empty_body_is_not_proven(self):
        v = judge_difference(Reply(200, "  "), CONTROL)
        assert v.conclusive and not v.vulnerable

    def test_get_html_shell_treatment_is_inconclusive(self):
        v = judge_difference(Reply(200, "<html><body>app</body></html>"), CONTROL)
        assert not v.conclusive and not v.vulnerable

    def test_post_html_treatment_is_not_proven(self):
        v = judge_difference(Reply(200, "<html><body>app</body></html>", "POST"), CONTROL)
        assert v.conclusive and not v.vulnerable

    def test_success_false_json_is_not_proven(self):
        v = judge_difference(Reply(200, '{"success": false}'), CONTROL)
        assert v.conclusive and not v.vulnerable

    def test_dynamic_control_is_inconclusive(self):
        v = judge_difference(
            Reply(200, '{"ts": 3}'), Reply(200, '{"ts": 1}'),
            control_repeat=Reply(200, '{"ts": 2}'),
        )
        assert not v.conclusive and "dynamic" in v.evidence

    def test_stable_control_repeat_allows_proof(self):
        v = judge_difference(
            Reply(200, '{"id": 9}'), CONTROL, control_repeat=Reply(200, CONTROL.body),
        )
        assert v.vulnerable

    def test_failed_control_repeat_is_inconclusive(self):
        v = judge_difference(
            Reply(200, '{"id": 9}'), CONTROL, control_repeat=Reply(0, ""),
        )
        assert not v.conclusive


class TestEvidenceGap:
    def test_no_replies_inconclusive(self):
        assert not evidence_gap([]).conclusive

    def test_all_transport_failures_inconclusive(self):
        v = evidence_gap([Reply(0, "Request failed"), Reply(0, "Request failed")])
        assert not v.conclusive and not v.vulnerable

    def test_all_validation_rejections_inconclusive(self):
        assert not evidence_gap([Reply(422, "{}"), Reply(400, "{}")]).conclusive

    def test_all_denials_not_proven(self):
        v = evidence_gap([Reply(403, '{"error":"x"}'), Reply(401, "")])
        assert v.conclusive and not v.vulnerable

    @pytest.mark.parametrize("status", [200, 204])
    def test_empty_success_is_not_a_gap(self, status):
        """Recall guard: an unauthorized DELETE/PATCH that succeeds has no body."""
        assert evidence_gap([Reply(status, "", "DELETE")]) is None

    def test_real_answer_leaves_no_gap(self):
        assert evidence_gap([Reply(0, "x"), Reply(200, '{"id": 1}')]) is None


# --- Review fixes 2, 3, 5, 6 ---


class TestBodySignalsFailure:
    def test_graphql_partial_data_is_not_failure(self):
        assert not body_signals_failure('{"data": {"u": {"id": 1}}, "errors": [{"m": "x"}]}')

    def test_pure_errors_is_failure(self):
        assert body_signals_failure('{"errors": [{"message": "nope"}]}')

    def test_data_null_with_errors_is_failure(self):
        assert body_signals_failure('{"data": null, "errors": [{"message": "nope"}]}')

    def test_explicit_success_false_wins_over_data(self):
        assert body_signals_failure('{"success": false, "data": {"id": 1}}')

    def test_non_json_and_lists_are_not_failure(self):
        assert not body_signals_failure("plain") and not body_signals_failure("[1]")


def test_evidence_gap_5xx_is_not_a_gap():
    assert evidence_gap([Reply(500, '{"error": "boom"}', "POST")]) is None


def test_evidence_gap_graphql_partial_is_not_a_gap():
    body = '{"data": {"users": [{"id": 1}]}, "errors": [{"message": "x"}]}'
    assert evidence_gap([Reply(200, body, "POST")]) is None


class TestProbeStripping:
    def test_short_probe_not_stripped(self):
        v = judge_difference(Reply(200, "12"), Reply(200, "21"), probe_input="1")
        assert v.vulnerable

    def test_json_escaped_reflection_is_not_proof(self):
        probe = 'a"b\\c<x>'
        v = judge_difference(
            Reply(200, '{"echo": ' + json.dumps(probe) + "}", "POST"),
            Reply(200, '{"echo": ""}', "POST"),
            probe_input=probe,
        )
        assert v.conclusive and not v.vulnerable

    def test_url_encoded_reflection_is_not_proof(self):
        v = judge_difference(
            Reply(200, '{"q": "a%20b%27%20OR%201"}', "POST"),
            Reply(200, '{"q": ""}', "POST"),
            probe_input="a b' OR 1",
        )
        assert not v.vulnerable

    def test_boundary_aware_does_not_eat_inside_words(self):
        v = judge_difference(
            Reply(200, '{"v": "xxPROBEyy"}', "POST"),
            Reply(200, '{"v": "xxyy"}', "POST"),
            probe_input="PROBE",
        )
        assert v.vulnerable


class TestCanonicalComparison:
    def test_key_order_and_whitespace_insensitive(self):
        v = judge_difference(
            Reply(200, '{"a": 1, "b": 2}', "POST"),
            Reply(200, '{\n "b":2,\n "a":1 }', "POST"),
        )
        assert v.conclusive and not v.vulnerable

    def test_distinct_json_values_still_proven(self):
        v = judge_difference(Reply(200, '{"a": 1}', "POST"), Reply(200, '{"a": 2}', "POST"))
        assert v.vulnerable

    def test_huge_bodies_are_bounded_but_length_differences_count(self):
        big = "x" * 1_000_000
        same = judge_difference(Reply(200, big, "POST"), Reply(200, big, "POST"))
        assert not same.vulnerable
        longer = judge_difference(Reply(200, big + "y", "POST"), Reply(200, big, "POST"))
        assert longer.vulnerable


class TestAbsolutizeOrigin:
    def test_protocol_relative_cannot_switch_host(self):
        assert absolutize("//evil.example/x", "https://x.com") is None

    def test_cross_origin_absolute_refused_with_base(self):
        assert absolutize("https://evil.example/x", "https://x.com") is None

    def test_port_mismatch_refused(self):
        assert absolutize("http://x.com:8080/a", "http://x.com:80") is None

    def test_default_port_equivalent(self):
        assert absolutize("https://x.com:443/a", "https://x.com/") == "https://x.com:443/a"

    def test_ipv6_same_origin_ok_and_different_refused(self):
        assert absolutize("/a", "http://[::1]:9000/") == "http://[::1]:9000/a"
        assert absolutize("http://[::2]:9000/a", "http://[::1]:9000/") is None
