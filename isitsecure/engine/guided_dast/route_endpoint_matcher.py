"""Maps SAST code findings to live discovered endpoints.

Bridges the gap between static analysis (file paths, route patterns)
and dynamic testing (live URLs) by matching RouteEntry patterns to
DiscoveredEndpoint URLs.

SRP: This module is responsible ONLY for the mapping logic between
     code-level routes and live endpoints.
"""

from __future__ import annotations

import re

from isitsecure.engine.code_analysis.protocols import RouteEntry
from isitsecure.engine.models import DiscoveredEndpoint


class RouteEndpointMatcher:
    """Maps code-level file paths and route patterns to live endpoints."""

    # Regex for Express/Next.js path parameters like :id, [id], [slug]
    _PARAM_PATTERN = re.compile(r":(\w+)|\[(\w+)\]")

    def find_endpoints_for_file(
        self,
        file_path: str,
        route_map: list[RouteEntry],
        endpoints: list[DiscoveredEndpoint],
    ) -> list[DiscoveredEndpoint]:
        """Find live endpoints that correspond to a code file.

        Looks up the file_path in the route_map to find the route pattern,
        then matches that pattern against discovered endpoints.

        Args:
            file_path: Path of the source file from a CodeFinding.
            route_map: Route map from the RepoSnapshot.
            endpoints: Live discovered endpoints.

        Returns:
            List of matching DiscoveredEndpoints.
        """
        matched_endpoints: list[DiscoveredEndpoint] = []

        for route in route_map:
            if self._file_matches_route(file_path, route.file_path):
                matched = self.match_pattern_to_endpoints(
                    route.route_pattern, endpoints,
                )
                matched_endpoints.extend(matched)

        return matched_endpoints

    def match_pattern_to_endpoints(
        self,
        route_pattern: str,
        endpoints: list[DiscoveredEndpoint],
    ) -> list[DiscoveredEndpoint]:
        """Match a route pattern (e.g. /api/users/:id) to live endpoint URLs.

        Converts path parameter placeholders to regex wildcards and matches
        against endpoint URLs.

        Args:
            route_pattern: Route pattern from code (e.g. /api/users/:id).
            endpoints: Live discovered endpoints.

        Returns:
            List of endpoints whose URL paths match the pattern.
        """
        regex = self._pattern_to_regex(route_pattern)
        if not regex:
            return []

        matched: list[DiscoveredEndpoint] = []
        for ep in endpoints:
            # Extract path from full URL for matching
            path = self._extract_path(ep.url)
            if regex.search(path):
                matched.append(ep)

        return matched

    def _pattern_to_regex(self, route_pattern: str) -> re.Pattern | None:
        """Convert a route pattern to a regex for matching endpoint URLs.

        /api/users/:id  -> /api/users/[^/]+
        /api/posts/[id] -> /api/posts/[^/]+
        """
        if not route_pattern:
            return None

        # Replace :param and [param] with wildcard
        escaped = re.escape(route_pattern)
        # re.escape will escape : and [ ] so we need to handle the original
        regex_str = self._PARAM_PATTERN.sub(r"[^/]+", route_pattern)
        # Escape the non-param parts properly
        parts = self._PARAM_PATTERN.split(route_pattern)
        regex_str = ""
        for i, part in enumerate(parts):
            if part is None:
                continue
            if i % 3 == 0:
                # Literal part — escape it
                regex_str += re.escape(part)
            else:
                # Parameter name — already handled, add wildcard once per group
                if i % 3 == 1:
                    regex_str += "[^/]+"

        return re.compile(regex_str + r"/?$")

    @staticmethod
    def _file_matches_route(finding_file: str, route_file: str) -> bool:
        """Check if a finding's file path matches a route entry's file path.

        Handles relative vs absolute path mismatches by comparing suffixes.
        """
        # Normalize separators
        finding_norm = finding_file.replace("\\", "/").rstrip("/")
        route_norm = route_file.replace("\\", "/").rstrip("/")

        return (
            finding_norm == route_norm
            or finding_norm.endswith(route_norm)
            or route_norm.endswith(finding_norm)
        )

    @staticmethod
    def _extract_path(url: str) -> str:
        """Extract the path component from a full URL."""
        from urllib.parse import urlparse

        return urlparse(url).path
