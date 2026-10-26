"""Verdict rules of the SAST-guided DAST runner.

A guided probe is a finding only when the response BODY shows the weakness.
Each negative test below is a live-app shape that used to be reported as a
CRITICAL/HIGH finding on a bare HTTP 200; each positive control is a genuinely
vulnerable response that must still be reported.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from isitsecure.engine.constants import GuidedDASTConfig
from isitsecure.engine.enums import FindingCategory, SeverityLevel
from isitsecure.engine.guided_dast.protocols import GuidedTestCase
from isitsecure.engine.guided_dast.runner import SASTGuidedDASTRunner
from isitsecure.engine.models import DeepFinding, FindingSource

BASE = "http://app.test"
SHELL = "<!doctype html><html><head><title>App</title></head><body><div id=root></div></body></html>"


@pytest.fixture(autouse=True)
def _no_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(GuidedDASTConfig, "PROBE_DELAY", 0)


def _tc(test_type: str, path: str = "/search", method: str = "GET",
        payload: dict | None = None, **kw) -> GuidedTestCase:
    return GuidedTestCase(
        source_finding_id="f1", source_scanner="s", test_type=test_type,
        target_url=BASE + path, http_method=method, payload=payload, **kw,
    )


async def _run(cases: list[GuidedTestCase]) -> list[DeepFinding]:
    return await SASTGuidedDASTRunner([])._execute_tests(cases)


def _html(text: str = SHELL) -> httpx.Response:
    return httpx.Response(200, text=text, headers={"content-type": "text/html"})


# --------------------------------------------------------------------------
# #2: payload placement
# --------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_get_probe_sends_payload_in_query_string_not_body() -> None:
    route = respx.get(BASE + "/search").mock(return_value=httpx.Response(200, json=[]))
    await _run([_tc(GuidedDASTConfig.TEST_TYPE_SQLI, payload={"q": "' OR '1'='1' --"})])
    req = route.calls[0].request
    assert req.url.params["q"] == "' OR '1'='1' --"
    assert req.content == b""


@pytest.mark.asyncio
@respx.mock
async def test_post_probe_still_sends_json_body() -> None:
    route = respx.post(BASE + "/items").mock(return_value=httpx.Response(200, json={}))
    await _run([_tc(GuidedDASTConfig.TEST_TYPE_MASS_ASSIGNMENT, "/items", "POST", {"role": "admin"})])
    assert route.calls[0].request.content == b'{"role":"admin"}'


# --------------------------------------------------------------------------
# #2: SQLi
# --------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_sqli_200_empty_array_is_not_a_finding() -> None:
    respx.get(BASE + "/search").mock(return_value=httpx.Response(200, json=[]))
    cases = [_tc(GuidedDASTConfig.TEST_TYPE_SQLI, payload={"q": p})
             for p in ("' OR '1'='1' --", "' UNION SELECT NULL, NULL --")]
    assert await _run(cases) == []


@pytest.mark.asyncio
@respx.mock
async def test_sqli_error_in_body_is_reported_critical() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("q") == "1":
            return httpx.Response(200, json=[{"id": 1}])
        return httpx.Response(500, text='SQLITE_ERROR: near "OR": syntax error')
    respx.get(BASE + "/search").mock(side_effect=handler)
    found = await _run([_tc(GuidedDASTConfig.TEST_TYPE_SQLI, payload={"q": "' OR '1'='1' --"})])
    assert len(found) == 1
    assert found[0].severity == SeverityLevel.CRITICAL
    assert "SQLITE_ERROR" in found[0].evidence


@pytest.mark.asyncio
@respx.mock
async def test_sqli_error_present_for_benign_value_too_is_not_reported() -> None:
    respx.get(BASE + "/search").mock(return_value=httpx.Response(500, text="SQLITE_ERROR always"))
    assert await _run([_tc(GuidedDASTConfig.TEST_TYPE_SQLI, payload={"q": "' OR 1=1"})]) == []


@pytest.mark.asyncio
@respx.mock
async def test_sqli_bare_server_error_is_lower_tier_not_critical() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[]) if request.url.params["q"] == "1" else httpx.Response(500, text="boom")
    respx.get(BASE + "/search").mock(side_effect=handler)
    found = await _run([_tc(GuidedDASTConfig.TEST_TYPE_SQLI, payload={"q": "'"})])
    assert len(found) == 1
    assert found[0].severity == SeverityLevel.MEDIUM
    assert found[0].confidence < 0.7


# --------------------------------------------------------------------------
# #2: XSS
# --------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_xss_not_reflected_is_not_a_finding() -> None:
    respx.get(BASE + "/search").mock(return_value=_html())
    assert await _run([_tc(GuidedDASTConfig.TEST_TYPE_XSS, payload={"q": "<script>alert(1)</script>"})]) == []


@pytest.mark.asyncio
@respx.mock
async def test_xss_reflected_in_json_is_not_a_finding() -> None:
    respx.get(BASE + "/search").mock(
        return_value=httpx.Response(200, json={"q": "<script>alert(1)</script>"}),
    )
    assert await _run([_tc(GuidedDASTConfig.TEST_TYPE_XSS, payload={"q": "<script>alert(1)</script>"})]) == []


@pytest.mark.asyncio
@respx.mock
async def test_xss_reflected_unescaped_in_html_is_reported() -> None:
    payload = "<script>alert(1)</script>"
    respx.get(BASE + "/search").mock(return_value=_html(f"<p>You searched {payload}</p>"))
    found = await _run([_tc(GuidedDASTConfig.TEST_TYPE_XSS, payload={"q": payload})])
    assert [f.severity for f in found] == [SeverityLevel.HIGH]


# --------------------------------------------------------------------------
# #2: RLS bypass
# --------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_rls_empty_array_means_rls_is_working() -> None:
    respx.get(url__regex=r"http://db\.test/rest/v1/users.*").mock(return_value=httpx.Response(200, json=[]))
    tc = GuidedTestCase(source_finding_id="f", source_scanner="s",
                        test_type=GuidedDASTConfig.TEST_TYPE_RLS_BYPASS,
                        target_url="http://db.test/rest/v1/users?select=*", http_method="GET")
    assert await _run([tc]) == []


@pytest.mark.asyncio
@respx.mock
async def test_rls_rows_returned_to_anon_key_is_critical() -> None:
    respx.get(url__regex=r"http://db\.test/rest/v1/users.*").mock(
        return_value=httpx.Response(200, json=[{"id": 1, "email": "a@b.c"}]),
    )
    tc = GuidedTestCase(source_finding_id="f", source_scanner="s",
                        test_type=GuidedDASTConfig.TEST_TYPE_RLS_BYPASS,
                        target_url="http://db.test/rest/v1/users?select=*", http_method="GET")
    found = await _run([tc])
    assert [f.severity for f in found] == [SeverityLevel.CRITICAL]
    assert found[0].category == FindingCategory.RLS_MISCONFIGURATION


# --------------------------------------------------------------------------
# #2: auth bypass
# --------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_auth_bypass_on_catch_all_spa_shell_is_not_a_finding() -> None:
    respx.get(url__regex=r"http://app\.test/.*").mock(return_value=_html())
    assert await _run([_tc(GuidedDASTConfig.TEST_TYPE_AUTH_BYPASS, "/admin/users")]) == []


@pytest.mark.asyncio
@respx.mock
async def test_auth_bypass_unauthenticated_data_is_critical() -> None:
    respx.get(BASE + "/admin/users").mock(return_value=httpx.Response(200, json=[{"id": 1, "email": "x@y.z"}]))
    respx.get(url__regex=r"http://app\.test/isitsecure-no-such.*").mock(return_value=httpx.Response(404, text="nf"))
    found = await _run([_tc(GuidedDASTConfig.TEST_TYPE_AUTH_BYPASS, "/admin/users")])
    assert [f.severity for f in found] == [SeverityLevel.CRITICAL]


@pytest.mark.asyncio
@respx.mock
async def test_auth_bypass_distinct_html_page_is_lower_tier_not_critical() -> None:
    respx.get(BASE + "/admin").mock(return_value=_html("<html><body>Admin dashboard, 3 users</body></html>"))
    respx.get(url__regex=r"http://app\.test/isitsecure-no-such.*").mock(return_value=httpx.Response(404, text="nf"))
    found = await _run([_tc(GuidedDASTConfig.TEST_TYPE_AUTH_BYPASS, "/admin")])
    assert len(found) == 1
    assert found[0].severity == SeverityLevel.MEDIUM


# --------------------------------------------------------------------------
# #2: IDOR / mass assignment / race
# --------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_idor_html_shell_is_not_a_finding() -> None:
    respx.get(BASE + "/api/orders/1").mock(return_value=_html())
    assert await _run([_tc(GuidedDASTConfig.TEST_TYPE_IDOR, "/api/orders/1", payload={"id": "0-1"})]) == []


@pytest.mark.asyncio
@respx.mock
async def test_idor_object_returned_for_arbitrary_id_is_reported_medium() -> None:
    respx.get(BASE + "/api/orders/1").mock(
        side_effect=lambda r: httpx.Response(200, json={"id": r.url.params["id"], "email": "victim@x.io"}),
    )
    found = await _run([_tc(GuidedDASTConfig.TEST_TYPE_IDOR, "/api/orders/1",
                            payload={"id": "00000000-0000-0000-0000-000000000001"})])
    assert [f.severity for f in found] == [SeverityLevel.MEDIUM]


@pytest.mark.asyncio
@respx.mock
async def test_mass_assignment_plain_ack_is_low_not_high() -> None:
    respx.route(method__in=["POST", "PUT", "PATCH"], url=BASE + "/profile").mock(
        return_value=httpx.Response(200, json={"ok": True}),
    )
    found = await _run([_tc(GuidedDASTConfig.TEST_TYPE_MASS_ASSIGNMENT, "/profile", "PATCH", {"role": "admin"})])
    assert [f.severity for f in found] == [SeverityLevel.LOW]


@pytest.mark.asyncio
@respx.mock
async def test_mass_assignment_html_shell_is_not_a_finding() -> None:
    respx.route(url=BASE + "/profile").mock(return_value=_html())
    assert await _run([_tc(GuidedDASTConfig.TEST_TYPE_MASS_ASSIGNMENT, "/profile", "PATCH", {"role": "admin"})]) == []


@pytest.mark.asyncio
@respx.mock
async def test_mass_assignment_field_echoed_back_is_high() -> None:
    respx.route(url=BASE + "/profile").mock(
        return_value=httpx.Response(200, json={"user": {"id": 1, "role": "admin"}}),
    )
    found = await _run([_tc(GuidedDASTConfig.TEST_TYPE_MASS_ASSIGNMENT, "/profile", "PATCH", {"role": "admin"})])
    assert [f.severity for f in found] == [SeverityLevel.HIGH]


def _race_cases(n: int = 5) -> list[GuidedTestCase]:
    return [_tc(GuidedDASTConfig.TEST_TYPE_RACE_CONDITION, "/redeem", "POST", {"_race_batch": i})
            for i in range(n)]


@pytest.mark.asyncio
@respx.mock
async def test_race_on_html_shell_is_not_a_finding() -> None:
    respx.post(BASE + "/redeem").mock(return_value=_html())
    assert await _run(_race_cases()) == []


@pytest.mark.asyncio
@respx.mock
async def test_race_identical_ack_is_low_confidence_only() -> None:
    respx.post(BASE + "/redeem").mock(return_value=httpx.Response(200, json={"ok": True}))
    found = await _run(_race_cases())
    assert len(found) == 1
    assert found[0].severity == SeverityLevel.LOW


@pytest.mark.asyncio
@respx.mock
async def test_race_distinct_results_is_medium() -> None:
    counter = iter(range(100))
    respx.post(BASE + "/redeem").mock(side_effect=lambda r: httpx.Response(200, json={"redeemed": next(counter)}))
    found = await _run(_race_cases())
    assert [f.severity for f in found] == [SeverityLevel.MEDIUM]


# --------------------------------------------------------------------------
# #10: dedup
# --------------------------------------------------------------------------


def test_race_batch_survives_dedup() -> None:
    assert len(SASTGuidedDASTRunner._deduplicate(_race_cases(), [])) == 5


def test_existing_finding_dedups_matching_test_type_via_category() -> None:
    existing = DeepFinding(
        source=FindingSource.DAST_URL, category=FindingCategory.INJECTION_RISK,
        severity=SeverityLevel.HIGH, title="SQLi", description="d", evidence="e",
        confidence=0.9, scanner_name="x", endpoint_url=BASE + "/search?q=1",
    )
    cases = [
        _tc(GuidedDASTConfig.TEST_TYPE_SQLI, "/search", payload={"q": "'"}),
        _tc(GuidedDASTConfig.TEST_TYPE_IDOR, "/search", payload={"id": "1"}),
        _tc(GuidedDASTConfig.TEST_TYPE_SQLI, "/other", payload={"q": "'"}),
    ]
    kept = SASTGuidedDASTRunner._deduplicate(cases, [existing])
    assert [(c.test_type, c.target_url) for c in kept] == [
        (GuidedDASTConfig.TEST_TYPE_IDOR, BASE + "/search"),
        (GuidedDASTConfig.TEST_TYPE_SQLI, BASE + "/other"),
    ]
