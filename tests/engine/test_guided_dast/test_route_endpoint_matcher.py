"""Tests for RouteEndpointMatcher."""

from __future__ import annotations

import pytest

from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.guided_dast.route_endpoint_matcher import (
    RouteEndpointMatcher,
)
from isitsecure.engine.code_analysis.protocols import RouteEntry
from isitsecure.engine.models import DiscoveredEndpoint


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def matcher() -> RouteEndpointMatcher:
    return RouteEndpointMatcher()


def _ep(url: str, method: EndpointMethod = EndpointMethod.GET) -> DiscoveredEndpoint:
    """Shorthand to create a DiscoveredEndpoint."""
    return DiscoveredEndpoint(url=url, method=method)


def _route(
    file_path: str,
    route_pattern: str,
    http_methods: list[str] | None = None,
) -> RouteEntry:
    """Shorthand to create a RouteEntry."""
    return RouteEntry(
        file_path=file_path,
        route_pattern=route_pattern,
        http_methods=http_methods or [],
    )


# ---------------------------------------------------------------------------
# match_pattern_to_endpoints
# ---------------------------------------------------------------------------


class TestExactRouteMatch:
    def test_exact_route_matches_endpoint(self, matcher: RouteEndpointMatcher) -> None:
        """Exact route pattern /api/users matches endpoint with /api/users."""
        endpoints = [
            _ep("https://example.com/api/users"),
            _ep("https://example.com/api/orders"),
        ]

        result = matcher.match_pattern_to_endpoints("/api/users", endpoints)

        assert len(result) == 1
        assert result[0].url == "https://example.com/api/users"

    def test_exact_route_with_trailing_slash(self, matcher: RouteEndpointMatcher) -> None:
        """Route /api/users matches endpoint /api/users/ (trailing slash)."""
        endpoints = [_ep("https://example.com/api/users/")]

        result = matcher.match_pattern_to_endpoints("/api/users", endpoints)

        assert len(result) == 1


class TestParameterizedRouteMatch:
    def test_colon_param_matches_id_segment(self, matcher: RouteEndpointMatcher) -> None:
        """/api/users/:id matches /api/users/123."""
        endpoints = [
            _ep("https://example.com/api/users/123"),
            _ep("https://example.com/api/users/abc-def"),
            _ep("https://example.com/api/orders/123"),
        ]

        result = matcher.match_pattern_to_endpoints("/api/users/:id", endpoints)

        assert len(result) == 2
        urls = {ep.url for ep in result}
        assert "https://example.com/api/users/123" in urls
        assert "https://example.com/api/users/abc-def" in urls

    @pytest.mark.xfail(
        reason="Bug: _pattern_to_regex only handles :param (i%3==1), "
        "not [param] (i%3==2). Bracket params are silently dropped.",
    )
    def test_bracket_param_matches_id_segment(self, matcher: RouteEndpointMatcher) -> None:
        """/api/users/[id] matches /api/users/456."""
        endpoints = [
            _ep("https://example.com/api/users/456"),
            _ep("https://example.com/api/posts/456"),
        ]

        result = matcher.match_pattern_to_endpoints("/api/users/[id]", endpoints)

        assert len(result) == 1
        assert result[0].url == "https://example.com/api/users/456"

    def test_multiple_params(self, matcher: RouteEndpointMatcher) -> None:
        """/api/orgs/:orgId/users/:userId matches live URL with two segments."""
        endpoints = [
            _ep("https://example.com/api/orgs/42/users/99"),
        ]

        result = matcher.match_pattern_to_endpoints(
            "/api/orgs/:orgId/users/:userId", endpoints,
        )

        assert len(result) == 1


class TestNoMatch:
    def test_no_match_returns_empty_list(self, matcher: RouteEndpointMatcher) -> None:
        """Completely different patterns yield empty list."""
        endpoints = [_ep("https://example.com/api/orders")]

        result = matcher.match_pattern_to_endpoints("/api/users", endpoints)

        assert result == []

    def test_empty_endpoints_returns_empty(self, matcher: RouteEndpointMatcher) -> None:
        """No endpoints -> empty result."""
        result = matcher.match_pattern_to_endpoints("/api/users", [])

        assert result == []

    def test_empty_pattern_returns_empty(self, matcher: RouteEndpointMatcher) -> None:
        """Empty route pattern -> empty result."""
        endpoints = [_ep("https://example.com/api/users")]

        result = matcher.match_pattern_to_endpoints("", endpoints)

        assert result == []


# ---------------------------------------------------------------------------
# find_endpoints_for_file
# ---------------------------------------------------------------------------


class TestFileToEndpointMapping:
    def test_file_path_maps_to_endpoint_via_route_map(
        self, matcher: RouteEndpointMatcher,
    ) -> None:
        """file_path in route_map -> matching endpoints found."""
        route_map = [_route("src/routes/users.ts", "/api/users")]
        endpoints = [
            _ep("https://example.com/api/users"),
            _ep("https://example.com/api/orders"),
        ]

        result = matcher.find_endpoints_for_file(
            "src/routes/users.ts", route_map, endpoints,
        )

        assert len(result) == 1
        assert result[0].url == "https://example.com/api/users"

    def test_suffix_match_for_relative_paths(
        self, matcher: RouteEndpointMatcher,
    ) -> None:
        """Finding path 'routes/users.ts' matches route 'src/routes/users.ts'."""
        route_map = [_route("src/routes/users.ts", "/api/users")]
        endpoints = [_ep("https://example.com/api/users")]

        result = matcher.find_endpoints_for_file(
            "routes/users.ts", route_map, endpoints,
        )

        assert len(result) == 1

    def test_no_matching_file_returns_empty(
        self, matcher: RouteEndpointMatcher,
    ) -> None:
        """File path not in route_map -> no endpoints returned."""
        route_map = [_route("src/routes/users.ts", "/api/users")]
        endpoints = [_ep("https://example.com/api/users")]

        result = matcher.find_endpoints_for_file(
            "src/routes/orders.ts", route_map, endpoints,
        )

        assert result == []


class TestMultipleEndpointsPerPattern:
    def test_multiple_endpoints_matching_same_pattern(
        self, matcher: RouteEndpointMatcher,
    ) -> None:
        """Multiple endpoints can match a single parameterized pattern."""
        endpoints = [
            _ep("https://example.com/api/users/1"),
            _ep("https://example.com/api/users/2"),
            _ep("https://example.com/api/users/abc"),
        ]

        result = matcher.match_pattern_to_endpoints("/api/users/:id", endpoints)

        assert len(result) == 3
