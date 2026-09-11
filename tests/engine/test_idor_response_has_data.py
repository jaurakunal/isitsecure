"""What counts as "the endpoint returned data" for the IDOR scanner.

A 200 with a JSON body is not proof of a leak: an endpoint can answer an
unauthenticated request with an empty envelope (Juice Shop's
``/rest/user/whoami`` returns ``{"user":{}}``), which clears a byte-length gate
while carrying nothing. These tests pin the content check that tells the two
apart -- by structure, never by envelope key name.
"""

from __future__ import annotations

import httpx

from isitsecure.engine.scanners.idor_scanner import (
    IDORScanner,
    _has_substantive_value,
    _json_has_substantive_content,
)


def _resp(body: str, status: int = 200, ctype: str = "application/json") -> httpx.Response:
    return httpx.Response(
        status_code=status,
        headers={"content-type": ctype},
        content=body.encode(),
    )


class TestSubstantiveValue:
    def test_empty_containers_are_not_substantive(self) -> None:
        assert not _has_substantive_value({})
        assert not _has_substantive_value([])
        assert not _has_substantive_value({"user": {}})
        assert not _has_substantive_value({"a": {}, "b": [], "c": None})

    def test_blank_string_and_null_are_not_substantive(self) -> None:
        assert not _has_substantive_value("")
        assert not _has_substantive_value("   ")
        assert not _has_substantive_value(None)

    def test_zero_and_false_are_real_data(self) -> None:
        # A balance of 0 or a flag of False is a leaked value, not emptiness.
        assert _has_substantive_value(0)
        assert _has_substantive_value(False)
        assert _has_substantive_value({"balance": 0})

    def test_populated_record_is_substantive(self) -> None:
        assert _has_substantive_value({"data": [{"UserId": 2, "quantity": 800}]})

    def test_value_nested_below_empty_wrappers(self) -> None:
        assert _has_substantive_value({"a": {"b": {"c": "x"}}})
        assert not _has_substantive_value({"a": {"b": {"c": {}}}})


class TestJsonHasSubstantiveContent:
    def test_whoami_empty_envelope(self) -> None:
        assert not _json_has_substantive_content('{"user":{}}')

    def test_all_empty_containers_are_not_content(self) -> None:
        assert not _json_has_substantive_content('{"user":{},"data":[]}')

    def test_status_string_counts_as_content_by_design(self) -> None:
        # The honest limit of a key-name-agnostic check: a "success" leaf on an
        # otherwise-empty result IS a non-empty scalar, so it reads as content.
        # Recognising it as mere envelope metadata would need an envelope-key
        # allowlist -- the overfit this fix exists to avoid. Empty result sets
        # are a separate concern, addressable only by response discrimination.
        assert _json_has_substantive_content('{"status":"success","data":[]}')

    def test_populated_envelope(self) -> None:
        assert _json_has_substantive_content(
            '{"status":"success","data":[{"UserId":2}]}'
        )

    def test_undecodable_json_is_treated_as_content(self) -> None:
        # JSON-shaped but broken: don't silently drop a possible finding.
        assert _json_has_substantive_content('{"data": [unclosed')


class TestResponseHasData:
    def test_empty_envelope_is_not_data(self) -> None:
        # The regression: whoami cleared the old byte-length gate.
        assert not IDORScanner()._response_has_data(_resp('{"user":{}}'))

    def test_populated_json_is_data(self) -> None:
        assert IDORScanner()._response_has_data(
            _resp('{"status":"success","data":[{"UserId":2,"quantity":800}]}')
        )

    def test_error_status_is_never_data(self) -> None:
        assert not IDORScanner()._response_has_data(
            _resp('{"data":[{"id":1}]}', status=404)
        )

    def test_trivially_short_body_is_not_data(self) -> None:
        assert not IDORScanner()._response_has_data(_resp("{}"))

    def test_json_without_content_type_still_inspected(self) -> None:
        # A JSON array served as text/plain is still judged on content.
        assert IDORScanner()._response_has_data(
            _resp('[{"id":1,"name":"x"}]', ctype="text/plain")
        )
        assert not IDORScanner()._response_has_data(
            _resp('[{},{},{}]', ctype="text/plain")
        )

    def test_html_is_not_data(self) -> None:
        assert not IDORScanner()._response_has_data(
            _resp("<html><body>Not found</body></html>", ctype="text/html")
        )
