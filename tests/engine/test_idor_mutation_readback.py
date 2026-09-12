"""Read-back verification for mutation-IDOR findings.

A 2xx to an unauthenticated write proves it was accepted, not that the resource
changed (the probe body is an unknown field the ORM drops). These tests pin the
confirm-by-canary / fall-back-to-no-op logic and its field-selection safety.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import httpx

from isitsecure.engine.constants import IDORConfig
from isitsecure.engine.scanners.idor_scanner import (
    IDORScanner,
    _mutation_bodies_differ,
    _mutation_data_object,
    _pick_writable_field,
)


class TestDataObject:
    def test_unwraps_data_envelope(self) -> None:
        assert _mutation_data_object('{"data":{"id":1,"name":"x"}}') == {"id": 1, "name": "x"}

    def test_bare_object(self) -> None:
        assert _mutation_data_object('{"id":1}') == {"id": 1}

    def test_list_and_scalar_are_none(self) -> None:
        assert _mutation_data_object('[1,2]') is None
        assert _mutation_data_object('"x"') is None

    def test_non_json_is_none(self) -> None:
        assert _mutation_data_object('<html>') is None


class TestPickWritableField:
    def test_picks_first_safe_string(self) -> None:
        f, v = _pick_writable_field({"id": 1, "name": "Apple", "price": 1.99})
        assert (f, v) == ("name", "Apple")

    def test_skips_identifiers_and_timestamps(self) -> None:
        f, _ = _pick_writable_field(
            {"id": "u1", "UserId": "u2", "createdAt": "t", "description": "d"}
        )
        assert f == "description"

    def test_skips_sensitive_money_auth_pii(self) -> None:
        # Every writable field is sensitive -> nothing safe to canary.
        f, v = _pick_writable_field(
            {"password": "p", "email": "e", "role": "admin", "cardNumber": "4"}
        )
        assert (f, v) == (None, None)

    def test_skips_empty_and_nonstring(self) -> None:
        assert _pick_writable_field({"a": "", "b": 5, "c": None}) == (None, None)


class TestBodiesDifferIgnoringTimestamps:
    def test_timestamp_only_change_is_not_a_difference(self) -> None:
        a = '{"data":{"id":1,"name":"x","updatedAt":"T1"}}'
        b = '{"data":{"id":1,"name":"x","updatedAt":"T2"}}'
        assert not _mutation_bodies_differ(a, b)

    def test_real_field_change_differs(self) -> None:
        a = '{"data":{"id":1,"name":"x","updatedAt":"T1"}}'
        b = '{"data":{"id":1,"name":"y","updatedAt":"T2"}}'
        assert _mutation_bodies_differ(a, b)


def _resp(status=200, body="", ctype="application/json") -> httpx.Response:
    return httpx.Response(status, headers={"content-type": ctype}, content=body.encode())


class TestVerifyMutationPersists:
    async def test_canary_persists_is_confirmed_and_restores(self) -> None:
        # GET baseline, PUT canary, GET (canary present), PUT restore.
        canary_holder = {}
        async def fake_request(m, url, **kw):
            if m == "GET" and not canary_holder:
                return _resp(body='{"data":{"id":1,"name":"Apple"}}')
            if m in ("PUT", "PATCH"):
                sent = json.loads(kw["content"])
                canary_holder["name"] = sent.get("name")
                return _resp(status=200, body='{"data":{"id":1}}')
            # GET after canary write
            return _resp(body=json.dumps({"data": {"id": 1, "name": canary_holder["name"]}}))
        client = AsyncMock()
        client.request = AsyncMock(side_effect=fake_request)
        verdict, detail = await IDORScanner()._verify_mutation_persists(
            client, "http://t/api/Products/1", "PUT"
        )
        assert verdict == "persisted"
        assert detail == "name"
        # last write restored the original value
        assert canary_holder["name"] == "Apple"

    async def test_baseline_401_is_unknown(self) -> None:
        client = AsyncMock()
        client.request = AsyncMock(return_value=_resp(status=401, body="nope", ctype="text/html"))
        verdict, _ = await IDORScanner()._verify_mutation_persists(
            client, "http://t/api/Hints/1", "PUT"
        )
        assert verdict == "unknown"

    async def test_no_writable_field_falls_back_to_noop_no_effect(self) -> None:
        # Baseline has only sensitive fields -> no-op fallback, unchanged.
        body = '{"data":{"id":1,"price":1.99,"updatedAt":"T1"}}'
        async def fake_request(m, url, **kw):
            return _resp(body=body)
        client = AsyncMock()
        client.request = AsyncMock(side_effect=fake_request)
        verdict, _ = await IDORScanner()._verify_mutation_persists(
            client, "http://t/api/x/1", "PUT"
        )
        assert verdict == "no_effect"
