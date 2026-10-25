"""D1 / B1 #12: Location classification and evidence string."""

from __future__ import annotations

import pytest

from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.open_redirect_scanner import OpenRedirectScanner


@pytest.mark.parametrize(
    "location",
    ["//evil.com", "https://evil.com", "https://evil.com/x", "/\\/evil.com",
     "///evil.com", "\\\\evil.com", "//evil.com/path"],
)
def test_attacker_locations_are_external(location: str) -> None:
    assert OpenRedirectScanner()._is_external_redirect(location) is True


@pytest.mark.parametrize(
    "location",
    ["//127.0.0.1:8000/home", "//app.example.com/path", "/home", "/\\/app.example.com",
     "https://app.example.com/x", ""],
)
def test_same_origin_locations_are_not_external(location: str) -> None:
    assert OpenRedirectScanner()._is_external_redirect(location) is False


def test_evidence_does_not_duplicate_existing_query() -> None:
    ep = DiscoveredEndpoint(
        url="https://app.example.com/redir?redirect=x", method=EndpointMethod.GET,
    )
    f = OpenRedirectScanner()._check_redirect_header(
        ep, "redirect", "https://evil.com", "absolute_url", 302, "https://evil.com",
    )
    assert f is not None
    assert "redirect=x?redirect" not in f.evidence
    assert f.evidence.startswith("GET https://app.example.com/redir?redirect=https")
