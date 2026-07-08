"""Extract testable endpoints from server-rendered HTML.

JS-bundle discovery and the authenticated crawler both find endpoints by
looking at what the JavaScript *calls* (fetch/XHR). Server-rendered apps
(classic Rails/Django/Express+templates) expose their attack surface in the
HTML instead — ``<form action=... method=...>`` with named inputs, and
``<a href=...?q=>`` links carrying query parameters. This module reads that
surface and turns it into DiscoveredEndpoints.

Pure standard library (``html.parser``) — no new dependency, and it works on
a raw HTML string whether that came from a plain HTTP GET or ``page.content()``
inside the Playwright crawler.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

from isitsecure.engine.enums import EndpointMethod
from isitsecure.engine.models import DiscoveredEndpoint

# Input types that are not user-controllable parameters worth testing.
_SKIP_INPUT_TYPES = {"submit", "button", "reset", "image", "hidden"}


class _FormLinkParser(HTMLParser):
    """Collects ``<form>`` definitions and ``<a href>`` links from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.links: list[str] = []
        self._form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower(),
                "fields": [],
            }
        elif tag in ("input", "select", "textarea") and self._form is not None:
            name = a.get("name")
            if name and a.get("type", "").lower() not in _SKIP_INPUT_TYPES:
                self._form["fields"].append(name)
        elif tag == "a":
            href = a.get("href")
            if href:
                self.links.append(href)

    def handle_startendtag(self, tag, attrs):  # <input .../>
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def close(self) -> None:  # flush an unclosed trailing <form>
        super().close()
        if self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _same_origin(url: str, origin_netloc: str) -> bool:
    netloc = urlparse(url).netloc
    return not netloc or netloc == origin_netloc


def extract_html_endpoints(html: str, base_url: str) -> list[DiscoveredEndpoint]:
    """Return same-origin endpoints declared in a page's HTML.

    - ``<form>`` -> an endpoint at its (resolved) action with the input names
      as parameters; GET forms and POST forms are distinguished by method.
    - ``<a href=...?param=>`` -> a GET endpoint carrying those query params.
    """
    if not html:
        return []
    parser = _FormLinkParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass

    origin = urlparse(base_url).netloc
    endpoints: dict[tuple[str, str], DiscoveredEndpoint] = {}

    for form in parser.forms:
        url = urljoin(base_url, form["action"] or base_url).split("#")[0]
        if not _same_origin(url, origin):
            continue
        method = EndpointMethod.POST if form["method"] == "post" else EndpointMethod.GET
        fields = list(dict.fromkeys(form["fields"]))
        key = (method.value, url)
        if key in endpoints:
            continue
        endpoints[key] = DiscoveredEndpoint(
            url=url,
            method=method,
            source_pattern="html_form",
            query_param_names=fields,
        )

    for href in parser.links:
        if href.startswith(("javascript:", "#", "mailto:", "tel:")):
            continue
        url = urljoin(base_url, href).split("#")[0]
        if not _same_origin(url, origin):
            continue
        query = parse_qs(urlparse(url).query)
        if not query:  # only links that carry parameters are testable endpoints
            continue
        key = (EndpointMethod.GET.value, url)
        if key in endpoints:
            continue
        endpoints[key] = DiscoveredEndpoint(
            url=url,
            method=EndpointMethod.GET,
            source_pattern="html_link",
            query_param_names=list(query.keys()),
        )

    return list(endpoints.values())


def collect_same_origin_links(html: str, base_url: str) -> list[str]:
    """Return same-origin, navigable page links for a lightweight HTML crawl."""
    if not html:
        return []
    parser = _FormLinkParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        pass
    origin = urlparse(base_url).netloc
    out: list[str] = []
    seen: set[str] = set()
    for href in parser.links:
        if href.startswith(("javascript:", "#", "mailto:", "tel:")):
            continue
        url = urljoin(base_url, href).split("#")[0]
        if _same_origin(url, origin) and url not in seen:
            seen.add(url)
            out.append(url)
    return out
