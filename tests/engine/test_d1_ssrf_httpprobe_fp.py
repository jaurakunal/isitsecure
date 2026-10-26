"""Regression + positive-control tests for B1 #5 (SSRF), #6 (.env/robots), #7 (Host header)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from isitsecure.engine.constants import HTTPProbeConfig, SSRFConfig
from isitsecure.engine.enums import EndpointMethod, SeverityLevel
from isitsecure.engine.models import DiscoveredEndpoint
from isitsecure.engine.scanners.http_probe_scanner import HTTPProbeScanner
from isitsecure.engine.scanners.ssrf_scanner import SSRFScanner


def _resp(body: str, content_type: str = "text/html") -> httpx.Response:
    return httpx.Response(200, headers={"content-type": content_type}, text=body)


async def _ssrf_scan(mock_get) -> list:
    ep = DiscoveredEndpoint(
        url="https://example.com/api/fetch?url=https://google.com",
        method=EndpointMethod.GET,
    )
    with patch("isitsecure.engine.scanners.ssrf_scanner.RateLimitedClient") as M:
        client = AsyncMock()
        client.get = mock_get
        M.return_value.__aenter__ = AsyncMock(return_value=client)
        M.return_value.__aexit__ = AsyncMock(return_value=False)
        return await SSRFScanner().scan([ep])


class TestSSRFFalsePositives:
    """B1 #5: ordinary pages must not read as SSRF."""

    @pytest.mark.asyncio
    async def test_plain_html_page_is_not_ssrf(self) -> None:
        async def get(url, **kw):
            return _resp("<!DOCTYPE html><html>home</html>")

        assert await _ssrf_scan(get) == []

    @pytest.mark.asyncio
    async def test_iam_and_meta_data_substrings_are_not_ssrf(self) -> None:
        async def get(url, **kw):
            return _resp("see william/ premium/ and the meta-data docs")

        assert await _ssrf_scan(get) == []

    @pytest.mark.asyncio
    async def test_indicator_also_in_baseline_is_not_ssrf(self) -> None:
        async def get(url, **kw):
            return _resp("docs: the instance-id field is returned")

        assert await _ssrf_scan(get) == []

    @pytest.mark.asyncio
    async def test_real_metadata_differing_from_baseline_is_flagged(self) -> None:
        """Positive control."""

        async def get(url, **kw):
            if "169.254.169.254" in url:
                return _resp(
                    "ami-id\ninstance-id\niam/security-credentials/web-role",
                    "text/plain",
                )
            return _resp("<!DOCTYPE html><html>fetch failed</html>")

        findings = await _ssrf_scan(get)
        assert len(findings) == 1
        assert findings[0].title == SSRFConfig.TITLE_SSRF


def _mock(status: int = 200, text: str = "OK", headers: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {"content-type": "text/html"}
    return r


async def _probe(get_fn) -> list:
    async def request(method, url, **kw):
        return _mock(405, headers={})

    ep = DiscoveredEndpoint(
        url="https://example.com/api/v1/users", method=EndpointMethod.GET
    )
    with patch(
        "isitsecure.engine.scanners.http_probe_scanner.RateLimitedClient"
    ) as M:
        client = AsyncMock()
        client.get = get_fn
        client.request = request
        M.return_value.__aenter__ = AsyncMock(return_value=client)
        M.return_value.__aexit__ = AsyncMock(return_value=False)
        return await HTTPProbeScanner().scan(endpoints=[ep])


class TestSensitiveFileFalsePositives:
    @pytest.mark.asyncio
    async def test_spa_catch_all_is_not_env(self) -> None:
        async def get(url, **kw):
            return _mock(
                200,
                '<html lang="en"><body class="a=b"><div id=root></div></body></html>',
                {"content-type": "text/html; charset=utf-8"},
            )

        findings = await _probe(get)
        assert not [f for f in findings if "Sensitive file" in f.title]

    @pytest.mark.asyncio
    async def test_robots_txt_is_not_reported(self) -> None:
        async def get(url, **kw):
            if url.endswith("/robots.txt"):
                return _mock(
                    200, "User-agent: *\nDisallow: /admin\n",
                    {"content-type": "text/plain"},
                )
            return _mock(404, "nf")

        findings = await _probe(get)
        assert not [f for f in findings if "robots" in f.title]

    @pytest.mark.asyncio
    async def test_real_env_file_still_flagged(self) -> None:
        """Positive control."""

        async def get(url, **kw):
            if url.endswith("/.env"):
                return _mock(
                    200, "DB_PASSWORD=hunter2\nSECRET_KEY=abc\n",
                    {"content-type": "text/plain"},
                )
            return _mock(404, "nf")

        findings = await _probe(get)
        env = [f for f in findings if "/.env" in f.title]
        assert len(env) == 1
        assert env[0].severity == SeverityLevel.HIGH


class TestHostHeaderRedirect:
    @pytest.mark.asyncio
    async def test_redirect_not_followed_and_poisoned_location_detected(self) -> None:
        seen: list[object] = []

        async def get(url, **kw):
            headers = kw.get("headers") or {}
            if not any(h in headers for h in HTTPProbeConfig.HOST_HEADERS):
                return _mock(404, "nf")
            seen.append(kw.get("follow_redirects"))
            if kw.get("follow_redirects") is not False:
                # A followed redirect lands on the forged host's final page.
                return _mock(200, "<html>login</html>")
            host = next(headers[h] for h in HTTPProbeConfig.HOST_HEADERS if h in headers)
            return _mock(302, "", {"location": f"https://{host}/login"})

        findings = await _probe(get)
        assert any("Host header injection" in f.title for f in findings)
        assert seen and all(v is False for v in seen)
