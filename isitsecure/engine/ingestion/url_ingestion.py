"""URL-based ingestion service for capturing web application snapshots."""

import logging
import re
import time
from typing import Optional
from urllib.parse import urljoin

import httpx
from playwright.async_api import async_playwright

from isitsecure.engine.ingestion.constants import ScanConfig
from isitsecure.engine.ingestion.snapshot import (
    AssetType,
    CodebaseSnapshot,
    HTTPHeadersData,
    PageAsset,
)

logger = logging.getLogger(__name__)


class URLIngestionService:
    """Ingests a web application by URL using Playwright + httpx.

    Captures HTML, JS bundles, HTTP headers, source maps, and probes
    common sensitive file paths.
    """

    SCRIPT_SRC_PATTERN = re.compile(
        r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE
    )
    SOURCE_MAP_COMMENT_PATTERN = re.compile(
        r"//[#@]\s*sourceMappingURL=(\S+)"
    )
    INLINE_SCRIPT_PATTERN = re.compile(
        r"<script(?:\s[^>]*)?>(.+?)</script>", re.DOTALL | re.IGNORECASE
    )

    async def ingest(self, url: str) -> CodebaseSnapshot:
        """Ingest a web application from its URL."""
        start_time = time.monotonic()

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await browser.new_context(
                    viewport={
                        "width": ScanConfig.DEFAULT_VIEWPORT_WIDTH,
                        "height": ScanConfig.DEFAULT_VIEWPORT_HEIGHT,
                    },
                    user_agent=ScanConfig.USER_AGENT,
                )
                page = await context.new_page()

                logger.info(f"Navigating to {url}")
                response = await page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=ScanConfig.PAGE_LOAD_TIMEOUT_MS,
                )
                try:
                    await page.wait_for_load_state("networkidle", timeout=15000)
                except Exception:
                    logger.debug("networkidle timeout - proceeding with domcontentloaded")

                html_content = await page.content()
                headers_data = self._extract_headers(response)
                assets = await self._extract_and_fetch_assets(html_content, url)
                source_maps = self._find_source_maps(assets, url)
                await page.close()
            finally:
                await browser.close()

        probe_results = await self._probe_common_paths(url)

        duration = time.monotonic() - start_time
        logger.info(
            f"Ingestion complete for {url}: "
            f"{len(assets)} assets, "
            f"{len(source_maps)} source maps, "
            f"{duration:.1f}s"
        )

        return CodebaseSnapshot(
            url=url,
            html_content=html_content,
            assets=assets,
            headers=headers_data,
            source_maps_found=source_maps,
            probe_results=probe_results,
            capture_duration_seconds=round(duration, 2),
        )

    def _extract_headers(self, response) -> HTTPHeadersData:
        """Extract HTTP headers from the Playwright response."""
        if not response:
            return HTTPHeadersData(raw_headers={}, status_code=0)

        raw = {k: v for k, v in response.headers.items()}
        return HTTPHeadersData(
            raw_headers=raw,
            status_code=response.status,
            server=raw.get("server"),
        )

    async def _extract_and_fetch_assets(
        self, html_content: str, base_url: str
    ) -> list[PageAsset]:
        """Extract script URLs from HTML and fetch their content."""
        assets: list[PageAsset] = []

        script_urls = self.SCRIPT_SRC_PATTERN.findall(html_content)
        script_urls = script_urls[: ScanConfig.MAX_ASSETS_TO_FETCH]

        inline_scripts = self.INLINE_SCRIPT_PATTERN.findall(html_content)
        for i, content in enumerate(inline_scripts):
            content = content.strip()
            if len(content) > ScanConfig.MIN_INLINE_SCRIPT_LENGTH:
                assets.append(
                    PageAsset(
                        url=f"inline-script-{i}",
                        asset_type=AssetType.JAVASCRIPT,
                        content=content,
                        size_bytes=len(content.encode()),
                        is_external=False,
                    )
                )

        async with httpx.AsyncClient(
            timeout=ScanConfig.ASSET_FETCH_TIMEOUT_SECONDS,
            follow_redirects=True,
        ) as client:
            for src in script_urls:
                absolute_url = urljoin(base_url, src)
                asset = await self._fetch_single_asset(
                    client, absolute_url, AssetType.JAVASCRIPT
                )
                if asset:
                    assets.append(asset)

        return assets

    async def _fetch_single_asset(
        self,
        client: httpx.AsyncClient,
        url: str,
        asset_type: AssetType,
    ) -> Optional[PageAsset]:
        """Fetch a single external asset."""
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None

            content = resp.text
            size = len(content.encode())

            if size > ScanConfig.MAX_JS_BUNDLE_SIZE_BYTES:
                logger.warning(f"Skipping oversized asset {url} ({size} bytes)")
                return None

            return PageAsset(
                url=url,
                asset_type=asset_type,
                content=content,
                size_bytes=size,
                is_external=True,
            )
        except httpx.HTTPError as e:
            logger.debug(f"Failed to fetch asset {url}: {e}")
            return None

    def _find_source_maps(
        self, assets: list[PageAsset], base_url: str
    ) -> list[str]:
        """Check JS assets for sourceMappingURL references."""
        source_maps: list[str] = []
        for asset in assets:
            if asset.asset_type != AssetType.JAVASCRIPT:
                continue
            match = self.SOURCE_MAP_COMMENT_PATTERN.search(asset.content)
            if match:
                map_url = match.group(1)
                absolute = urljoin(asset.url or base_url, map_url)
                source_maps.append(absolute)
        return source_maps

    async def _probe_common_paths(
        self, base_url: str
    ) -> dict[str, Optional[str]]:
        """Probe common sensitive file paths."""
        results: dict[str, Optional[str]] = {}

        async with httpx.AsyncClient(
            timeout=ScanConfig.ASSET_FETCH_TIMEOUT_SECONDS,
            follow_redirects=True,
        ) as client:
            for path in ScanConfig.PROBE_PATHS:
                probe_url = urljoin(base_url, path)
                try:
                    resp = await client.get(probe_url)
                    if resp.status_code == 200 and len(resp.text) > 0:
                        content = resp.text[:ScanConfig.MAX_PROBE_CONTENT_LENGTH]
                        results[path] = content
                        logger.info(f"Probe hit: {path} ({resp.status_code})")
                    else:
                        results[path] = None
                except httpx.HTTPError:
                    results[path] = None

        return results
