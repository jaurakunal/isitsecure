"""Which JavaScript a page actually ships, as opposed to which it <script>s."""

from __future__ import annotations

from isitsecure.engine.ingestion.constants import ScanConfig
from isitsecure.engine.ingestion.url_ingestion import URLIngestionService


class TestJavaScriptURLExtraction:
    def test_script_src_is_collected(self) -> None:
        html = '<script src="/main.js"></script>'
        assert URLIngestionService()._javascript_urls(html) == ["/main.js"]

    def test_modulepreload_chunks_are_collected(self) -> None:
        """Code-split chunks reach the page as <link>, not <script>.

        Missing them costs the whole lazy-loaded route surface -- which on a
        typical SPA is where most of the API calls live.
        """
        html = (
            '<link rel="modulepreload" href="chunk-ABC.js">'
            '<script src="main.js"></script>'
        )
        urls = URLIngestionService()._javascript_urls(html)
        assert urls == ["chunk-ABC.js", "main.js"]

    def test_order_follows_the_document_not_the_tag_type(self) -> None:
        """The cap truncates the tail, so ordering decides what gets dropped.

        Gathering every <script> before any <link> would let a script-heavy
        page starve out the chunks -- the half carrying the lazy API surface.
        """
        html = (
            '<script src="a.js"></script>'
            '<link rel="modulepreload" href="b.js">'
            '<script src="c.js"></script>'
            '<link rel="modulepreload" href="d.js">'
        )
        assert URLIngestionService()._javascript_urls(html) == [
            "a.js",
            "b.js",
            "c.js",
            "d.js",
        ]

    def test_preload_and_prefetch_and_mjs(self) -> None:
        html = (
            '<link rel="preload" as="script" href="/a.js">'
            "<link rel='prefetch' href='/b.mjs'>"
            '<link rel="modulepreload" href="/c.js?v=2">'
        )
        assert URLIngestionService()._javascript_urls(html) == [
            "/a.js",
            "/b.mjs",
            "/c.js?v=2",
        ]

    def test_stylesheet_links_are_ignored(self) -> None:
        html = '<link rel="stylesheet" href="/styles.css">'
        assert URLIngestionService()._javascript_urls(html) == []

    def test_a_chunk_both_preloaded_and_scripted_is_fetched_once(self) -> None:
        html = (
            '<link rel="modulepreload" href="main.js">'
            '<script src="main.js"></script>'
        )
        assert URLIngestionService()._javascript_urls(html) == ["main.js"]

    def test_cap_applies_across_both_sources(self) -> None:
        """The cap bounds total fetches, not each tag type separately."""
        html = "".join(
            f'<link rel="modulepreload" href="c{i}.js">'
            for i in range(ScanConfig.MAX_ASSETS_TO_FETCH + 20)
        )
        urls = URLIngestionService()._javascript_urls(html)
        assert len(urls) == ScanConfig.MAX_ASSETS_TO_FETCH
