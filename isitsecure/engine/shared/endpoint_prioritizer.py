"""Shared, dimension-aware endpoint prioritization for DAST scanners.

DAST scanners are bounded by per-scanner endpoint caps and timeouts, so on
large apps the *order* endpoints are tested in decides what actually gets
covered before the budget runs out. Testing "the first N in discovery order"
(regex-match order in a JS bundle) is effectively random — the endpoints most
likely to carry a given vulnerability class must be tested first.

This module is the single place that ranks endpoints, replacing the ad-hoc
per-scanner ordering. Every signal it scores on is a generic web/REST
convention (parameters, HTTP method, semantic category, common path words) —
there are deliberately no app-specific strings here.
"""

from __future__ import annotations

from enum import Enum
from urllib.parse import urlparse

from isitsecure.engine.enums import EndpointCategory
from isitsecure.engine.models import DiscoveredEndpoint


class PriorityDimension(str, Enum):
    """The vulnerability class a scanner is prioritizing for."""

    INJECTION = "injection"   # SQLi/NoSQL/command/SSTI/XXE
    IDOR = "idor"             # object-level access control
    XSS = "xss"               # reflected / stored cross-site scripting
    CSRF = "csrf"             # state-changing request forgery
    AUTH = "auth"             # authentication / login weaknesses


# --- generic signals (not app-specific) ---
_QUERY_HINTS = ("search", "query", "find", "filter", "lookup", "list")
_AUTH_HINTS = ("auth", "login", "signin", "signup", "oauth", "token", "session", "password", "2fa")
_STATE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_HIGH_VALUE_CATEGORIES = frozenset({
    EndpointCategory.ADMIN,
    EndpointCategory.USER_DATA,
    EndpointCategory.PAYMENT,
    EndpointCategory.FILE_ACCESS,
})


def _path(ep: DiscoveredEndpoint) -> str:
    return urlparse(ep.url).path.lower()


def _has_query(ep: DiscoveredEndpoint) -> bool:
    return bool(ep.query_param_names) or bool(urlparse(ep.url).query)


def _method(ep: DiscoveredEndpoint) -> str:
    return ep.method.value if hasattr(ep.method, "value") else str(ep.method)


def score(ep: DiscoveredEndpoint, dimension: PriorityDimension) -> int:
    """Score one endpoint for one dimension — higher = test sooner."""
    path = _path(ep)
    method = _method(ep)
    s = 0

    if dimension is PriorityDimension.INJECTION:
        # Injection lives in parameters; query/search routes and body-capable
        # methods are the richest surface.
        if _has_query(ep):
            s += 3
        if ep.has_path_params:
            s += 2
        if any(h in path for h in _QUERY_HINTS):
            s += 3
        if method in _STATE_METHODS:
            s += 1  # body injection surface

    elif dimension is PriorityDimension.IDOR:
        # Object-level access control needs an object id and matters most on
        # sensitive resources.
        if ep.has_id_params:
            s += 4
        if ep.category in _HIGH_VALUE_CATEGORIES:
            s += 3
        if ep.requires_auth:
            s += 2

    elif dimension is PriorityDimension.XSS:
        # Reflected XSS needs a reflected parameter; stored XSS rides POST bodies.
        if _has_query(ep):
            s += 3
        if any(h in path for h in _QUERY_HINTS):
            s += 2
        if method == "GET":
            s += 1  # reflective surface
        elif method in _STATE_METHODS:
            s += 1  # stored-via-body surface

    elif dimension is PriorityDimension.CSRF:
        # CSRF only applies to state-changing, auth'd actions.
        if method in _STATE_METHODS:
            s += 4
        if ep.requires_auth:
            s += 2
        if ep.category in _HIGH_VALUE_CATEGORIES:
            s += 1

    elif dimension is PriorityDimension.AUTH:
        if any(h in path for h in _AUTH_HINTS):
            s += 4
        if ep.category is EndpointCategory.AUTH:
            s += 3

    return s


def rank(
    endpoints: list[DiscoveredEndpoint],
    dimension: PriorityDimension,
) -> list[DiscoveredEndpoint]:
    """Return endpoints ordered most-likely-vulnerable first.

    Stable: endpoints with equal scores keep their original (discovery) order.
    """
    return sorted(endpoints, key=lambda ep: score(ep, dimension), reverse=True)
