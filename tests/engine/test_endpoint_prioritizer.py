"""Tests for the shared endpoint prioritizer used by DAST scanners."""

from isitsecure.engine.enums import EndpointCategory, EndpointMethod
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.shared.endpoint_prioritizer import (
    PriorityDimension,
    rank,
    score,
)


def _ep(url, method="GET", query_params=None, path_params=False,
        category=EndpointCategory.UNKNOWN, requires_auth=None):
    return DiscoveredEndpoint(
        url=url,
        method=EndpointMethod(method),
        query_param_names=query_params or [],
        has_path_params=path_params,
        path_param_names=(["id"] if path_params else []),
        category=category,
        requires_auth=requires_auth,
    )


class TestInjectionDimension:
    def test_search_and_param_endpoints_rank_above_bare_collections(self):
        eps = [
            _ep("http://x/api/Products"),
            _ep("http://x/rest/products/search"),
            _ep("http://x/api/Items?id=1"),
        ]
        ordered = rank(eps, PriorityDimension.INJECTION)
        # the bare collection must not be first
        assert ordered[0].url != "http://x/api/Products"
        assert ordered[-1].url == "http://x/api/Products"

    def test_known_injectable_lands_in_top_of_large_set(self):
        # 40 boring collections + 1 search route buried in the middle
        eps = [_ep(f"http://x/api/Coll{i}") for i in range(40)]
        eps.insert(23, _ep("http://x/rest/products/search"))
        ordered = rank(eps, PriorityDimension.INJECTION)
        top = [e.url for e in ordered[:5]]
        assert "http://x/rest/products/search" in top


class TestIdorDimension:
    def test_id_bearing_sensitive_resource_ranks_first(self):
        eps = [
            _ep("http://x/api/Products"),
            _ep("http://x/api/Users/1", path_params=True,
                category=EndpointCategory.USER_DATA, requires_auth=True),
            _ep("http://x/api/Cards", category=EndpointCategory.PAYMENT),
        ]
        assert rank(eps, PriorityDimension.IDOR)[0].url.endswith("/Users/1")


class TestCsrfDimension:
    def test_state_changing_ranks_above_read(self):
        eps = [
            _ep("http://x/api/read"),
            _ep("http://x/api/transfer", method="POST",
                requires_auth=True, category=EndpointCategory.PAYMENT),
        ]
        assert rank(eps, PriorityDimension.CSRF)[0].url.endswith("/transfer")


class TestAuthDimension:
    def test_login_path_ranks_first(self):
        eps = [_ep("http://x/api/products"), _ep("http://x/rest/user/login")]
        assert rank(eps, PriorityDimension.AUTH)[0].url.endswith("/login")


class TestXssDimension:
    def test_query_endpoint_ranks_above_paramless(self):
        eps = [_ep("http://x/api/Static"), _ep("http://x/api/search?q=1")]
        assert rank(eps, PriorityDimension.XSS)[0].url.endswith("?q=1")


class TestStability:
    def test_equal_scores_preserve_input_order(self):
        eps = [_ep("http://x/a"), _ep("http://x/b"), _ep("http://x/c")]
        assert [e.url for e in rank(eps, PriorityDimension.INJECTION)] == [
            e.url for e in eps
        ]

    def test_score_is_nonnegative(self):
        ep = _ep("http://x/api/thing")
        for dim in PriorityDimension:
            assert score(ep, dim) >= 0
