"""Guided DAST: injection/XSS probes only use safe methods; no invented POST."""

from __future__ import annotations

import httpx
import pytest
import respx

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot, RouteEntry
from isitsecure.engine.constants import GuidedDASTConfig
from isitsecure.engine.enums import EndpointMethod, FindingCategory, SeverityLevel
from isitsecure.engine.guided_dast.protocols import GuidedTestCase
from isitsecure.engine.guided_dast.runner import SASTGuidedDASTRunner
from isitsecure.engine.guided_dast.strategies.injection_targeted import InjectionTargetedStrategy
from isitsecure.engine.guided_dast.strategies.mass_assignment import MassAssignmentSchemaStrategy
from isitsecure.engine.models import DiscoveredEndpoint


def _snap(*routes: RouteEntry) -> RepoSnapshot:
    return RepoSnapshot(
        repo_url="r", branch="main", clone_path="/tmp/r",
        route_map=list(routes), file_index={},
    )


def _finding(scanner: str, title: str, file_path: str, desc: str = "", snippet: str = "") -> CodeFinding:
    return CodeFinding(
        scanner_name=scanner, severity=SeverityLevel.HIGH,
        category=FindingCategory.INJECTION_RISK, title=title, description=desc,
        file_path=file_path, code_snippet=snippet, confidence=0.9,
    )


def _ep(url: str, method: EndpointMethod) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(url=url, method=method)


_INJ = ("injection_pattern_trigger", "SQL injection", "routes/items.ts",
        "Unsanitized user input in parameter 'name'")


def test_injection_never_uses_unsafe_method_when_route_has_only_delete() -> None:
    snap = _snap(RouteEntry(file_path="routes/items.ts", route_pattern="/api/items/:id",
                            http_methods=["DELETE"]))
    st = InjectionTargetedStrategy()
    cases = st.generate_tests(
        [_finding(*_INJ)], [_ep("https://t.example/api/items/7", EndpointMethod.DELETE)], snap,
    )
    assert cases == []
    assert st.skipped_notes and "DELETE" in st.skipped_notes[0]


@pytest.mark.parametrize("method", [EndpointMethod.PUT, EndpointMethod.PATCH, EndpointMethod.POST])
def test_injection_unsafe_endpoint_probed_with_get_when_route_declares_get(method) -> None:
    snap = _snap(RouteEntry(file_path="routes/items.ts", route_pattern="/api/items",
                            http_methods=["GET", method.value]))
    cases = InjectionTargetedStrategy().generate_tests(
        [_finding(*_INJ)], [_ep("https://t.example/api/items", method)], snap,
    )
    assert cases and {c.http_method for c in cases} == {"GET"}


def test_injection_positive_control_get_endpoint_still_probed() -> None:
    snap = _snap(RouteEntry(file_path="routes/items.ts", route_pattern="/api/items",
                            http_methods=["GET"]))
    cases = InjectionTargetedStrategy().generate_tests(
        [_finding(*_INJ)], [_ep("https://t.example/api/items", EndpointMethod.GET)], snap,
    )
    types = {c.test_type for c in cases}
    assert GuidedDASTConfig.TEST_TYPE_SQLI in types and GuidedDASTConfig.TEST_TYPE_XSS in types
    assert {c.http_method for c in cases} == {"GET"}


def test_no_boolean_false_twin_payload() -> None:
    assert not any("'2'" in p for p in InjectionTargetedStrategy._SQLI_PAYLOADS)


def test_mass_assignment_does_not_invent_post_without_route_info() -> None:
    cases = MassAssignmentSchemaStrategy().generate_tests(
        [_finding("drizzle_schema_analyzer", "role column", "routes/p.ts",
                  snippet="role: text('role')")],
        [_ep("https://t.example/api/profile", EndpointMethod.GET)],
        _snap(RouteEntry(file_path="routes/p.ts", route_pattern="/api/profile",
                         http_methods=[])),
    )
    assert cases == []


def test_mass_assignment_positive_control_discovered_post_kept() -> None:
    cases = MassAssignmentSchemaStrategy().generate_tests(
        [_finding("drizzle_schema_analyzer", "role column", "routes/p.ts",
                  snippet="role: text('role')")],
        [_ep("https://t.example/api/profile", EndpointMethod.POST)],
        _snap(RouteEntry(file_path="routes/p.ts", route_pattern="/api/profile",
                         http_methods=[])),
    )
    assert {c.http_method for c in cases} == {"POST"}


@pytest.mark.asyncio
@respx.mock
async def test_runner_refuses_injection_with_unsafe_method(monkeypatch) -> None:
    monkeypatch.setattr(GuidedDASTConfig, "PROBE_DELAY", 0)
    route = respx.delete("http://app.test/api/items/7").mock(return_value=httpx.Response(200))
    tc = GuidedTestCase(
        source_finding_id="f", source_scanner="injection_pattern_trigger",
        test_type=GuidedDASTConfig.TEST_TYPE_SQLI, target_url="http://app.test/api/items/7",
        http_method="DELETE", payload={"name": "' OR '1'='1' --"},
    )
    out = await SASTGuidedDASTRunner([])._execute_tests([tc])
    assert out == [] and not route.called


def test_auth_bypass_route_pattern_is_anchored_at_path_start() -> None:
    from isitsecure.engine.guided_dast.strategies.auth_bypass import AuthBypassGuidedStrategy

    snap = _snap(RouteEntry(file_path="routes/api.ts", route_pattern="/api",
                            http_methods=["GET"]))
    # /foo/api must not inherit the methods of the unrelated /api route
    assert AuthBypassGuidedStrategy._get_methods_for_endpoint(
        _ep("https://t.example/foo/api", EndpointMethod.POST), snap, "routes/api.ts",
    ) == []
    # positive control: the real /api route still resolves
    assert AuthBypassGuidedStrategy._get_methods_for_endpoint(
        _ep("https://t.example/api", EndpointMethod.POST), snap, "routes/api.ts",
    ) == ["GET"]
