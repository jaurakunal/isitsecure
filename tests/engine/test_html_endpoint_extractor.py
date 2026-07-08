"""Tests for server-rendered HTML endpoint extraction."""

from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.shared.html_endpoint_extractor import (
    collect_same_origin_links,
    extract_html_endpoints,
)

BASE = "http://app.local/home"


def _by_url(endpoints):
    return {(e.method.value, e.url): e for e in endpoints}


class TestForms:
    def test_post_form_fields_become_params(self):
        html = ('<form action="/login" method="post">'
                '<input name="email"><input name="password" type="password">'
                '<input type="submit"></form>')
        ep = _by_url(extract_html_endpoints(html, BASE))[("POST", "http://app.local/login")]
        assert ep.method == EndpointMethod.POST
        assert ep.query_param_names == ["email", "password"]
        assert ep.source_pattern == "html_form"

    def test_get_form_default_method(self):
        html = '<form action="/search"><input name="q"></form>'
        ep = _by_url(extract_html_endpoints(html, BASE))[("GET", "http://app.local/search")]
        assert ep.query_param_names == ["q"]

    def test_hidden_and_submit_inputs_skipped(self):
        html = ('<form action="/x" method="post"><input name="real">'
                '<input type="hidden" name="_csrf"><input type="submit" name="go">'
                '</form>')
        ep = _by_url(extract_html_endpoints(html, BASE))[("POST", "http://app.local/x")]
        assert ep.query_param_names == ["real"]

    def test_empty_action_resolves_to_page(self):
        html = '<form method="post"><input name="a"></form>'
        eps = extract_html_endpoints(html, BASE)
        assert any(e.url == BASE and e.method == EndpointMethod.POST for e in eps)

    def test_unclosed_form_still_captured(self):
        html = '<form action="/x" method="post"><input name="a">'  # no </form>
        ep = _by_url(extract_html_endpoints(html, BASE))[("POST", "http://app.local/x")]
        assert ep.query_param_names == ["a"]


class TestLinks:
    def test_query_link_becomes_endpoint(self):
        html = '<a href="/profile?userId=5&tab=x">p</a>'
        ep = _by_url(extract_html_endpoints(html, BASE))[
            ("GET", "http://app.local/profile?userId=5&tab=x")]
        assert set(ep.query_param_names) == {"userId", "tab"}
        assert ep.source_pattern == "html_link"

    def test_paramless_link_ignored(self):
        assert extract_html_endpoints('<a href="/about">a</a>', BASE) == []

    def test_external_and_scheme_links_ignored(self):
        html = ('<a href="https://evil.com/x?a=1">e</a>'
                '<a href="javascript:void(0)">j</a><a href="mailto:x@y.z">m</a>')
        assert extract_html_endpoints(html, BASE) == []


class TestCollectLinks:
    def test_collects_same_origin_only(self):
        html = ('<a href="/one">1</a><a href="/two?x=1">2</a>'
                '<a href="https://other.com/z">z</a><a href="#frag">f</a>')
        links = collect_same_origin_links(html, BASE)
        assert "http://app.local/one" in links
        assert "http://app.local/two?x=1" in links
        assert not any("other.com" in u for u in links)

    def test_empty_html(self):
        assert collect_same_origin_links("", BASE) == []
        assert extract_html_endpoints("", BASE) == []
