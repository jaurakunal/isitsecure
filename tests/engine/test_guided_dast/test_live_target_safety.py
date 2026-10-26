"""Guided DAST must not send destructive payloads or wrong methods (#3)."""

from __future__ import annotations

from isitsecure.engine.code_analysis.models import CodeFinding
from isitsecure.engine.code_analysis.protocols import RepoSnapshot, RouteEntry
from isitsecure.engine.enums import EndpointMethod, FindingCategory, SeverityLevel
from isitsecure.engine.guided_dast.route_endpoint_matcher import RouteEndpointMatcher
from isitsecure.engine.guided_dast.strategies.auth_bypass import AuthBypassGuidedStrategy
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
        category=FindingCategory.AUTH_WEAKNESS, title=title, description=desc,
        file_path=file_path, code_snippet=snippet, confidence=0.9,
    )


def _ep(url: str, method: EndpointMethod = EndpointMethod.GET) -> DiscoveredEndpoint:
    return DiscoveredEndpoint(url=url, method=method)


def test_injection_payloads_never_include_destructive_statements() -> None:
    for payload in InjectionTargetedStrategy._SQLI_PAYLOADS:
        assert "DROP" not in payload.upper()
        assert ";" not in payload


def test_injection_still_generates_boolean_and_union_probes() -> None:
    payloads = InjectionTargetedStrategy._SQLI_PAYLOADS
    assert any("OR" in p for p in payloads)
    assert any("UNION" in p for p in payloads)


def test_auth_bypass_never_sends_unsafe_methods() -> None:
    snap = _snap(RouteEntry(
        file_path="routes/users.ts", route_pattern="/api/users/:id",
        http_methods=["GET", "DELETE", "POST"],
    ))
    cases = AuthBypassGuidedStrategy().generate_tests(
        [_finding("route_auth_analyzer", "Missing authentication", "routes/users.ts")],
        [_ep("https://t.example/api/users/7")], snap,
    )
    assert {c.http_method for c in cases} == {"GET"}


def test_auth_bypass_route_pattern_prefix_does_not_claim_unrelated_endpoint() -> None:
    snap = _snap(
        RouteEntry(file_path="routes/root.ts", route_pattern="/api", http_methods=["DELETE"]),
        RouteEntry(file_path="routes/health.ts", route_pattern="/api/health", http_methods=["GET"]),
    )
    methods = AuthBypassGuidedStrategy._get_methods_for_endpoint(
        _ep("https://t.example/api/health"), snap, "routes/health.ts",
    )
    assert methods == ["GET"]


def test_auth_bypass_without_route_info_probes_a_get_endpoint() -> None:
    methods = AuthBypassGuidedStrategy._get_methods_for_endpoint(
        _ep("https://t.example/x"), _snap(), "",
    )
    assert methods == ["GET"]


def test_auth_bypass_does_not_probe_a_discovered_delete_endpoint() -> None:
    methods = AuthBypassGuidedStrategy._get_methods_for_endpoint(
        _ep("https://t.example/x", EndpointMethod.DELETE), _snap(), "",
    )
    assert methods == []


def test_mass_assignment_only_declared_method() -> None:
    snap = _snap(RouteEntry(
        file_path="routes/profile.ts", route_pattern="/api/profile", http_methods=["PATCH"],
    ))
    cases = MassAssignmentSchemaStrategy().generate_tests(
        [_finding("drizzle_schema_analyzer", "role column", "routes/profile.ts",
                  snippet="role: text('role')")],
        [_ep("https://t.example/api/profile")], snap,
    )
    assert {c.http_method for c in cases} == {"PATCH"}


def test_empty_route_file_path_matches_no_finding() -> None:
    snap = _snap(RouteEntry(file_path="", route_pattern="/api/x", http_methods=["GET"]))
    out = RouteEndpointMatcher().find_endpoints_for_file(
        "routes/any.ts", snap.route_map, [_ep("https://t.example/api/x")],
    )
    assert out == []


def test_file_suffix_match_is_segment_aware() -> None:
    m = RouteEndpointMatcher._file_matches_route
    assert m("src/routes/users.ts", "routes/users.ts")
    assert not m("src/myroutes/users.ts", "routes/users.ts")


def test_bracket_route_pattern_matches_live_id_path() -> None:
    out = RouteEndpointMatcher().match_pattern_to_endpoints(
        "/api/posts/[id]",
        [_ep("https://t.example/api/posts/42"), _ep("https://t.example/api/other/42")],
    )
    assert [e.url for e in out] == ["https://t.example/api/posts/42"]
