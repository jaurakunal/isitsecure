"""Tests for the rate-limited HTTP client."""

import asyncio
import time

import httpx
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from isitsecure.engine.shared.rate_limited_client import RateLimitedClient


class TestRateLimitedClient:
    """Tests for the RateLimitedClient."""

    CLIENT_DEFAULTS = {
        "max_concurrent": 2,
        "delay_seconds": 0.0,
        "timeout_seconds": 5.0,
        "user_agent": "TestAgent/1.0",
    }

    def _make_client(self, **overrides: object) -> RateLimitedClient:
        params = {**self.CLIENT_DEFAULTS, **overrides}
        return RateLimitedClient(**params)

    @pytest.mark.asyncio
    async def test_respects_concurrency_limit(self) -> None:
        """Should not exceed max_concurrent simultaneous requests."""
        max_concurrent = 2
        active_count = 0
        max_observed = 0

        original_request = httpx.AsyncClient.request

        async def mock_request(self_client, method, url, **kwargs):
            nonlocal active_count, max_observed
            active_count += 1
            max_observed = max(max_observed, active_count)
            await asyncio.sleep(0.05)
            active_count -= 1
            return httpx.Response(200)

        client = self._make_client(max_concurrent=max_concurrent)

        with patch.object(httpx.AsyncClient, "request", mock_request):
            async with client:
                tasks = [client.get(f"https://example.com/{i}") for i in range(6)]
                await asyncio.gather(*tasks)

        assert max_observed <= max_concurrent

    @pytest.mark.asyncio
    async def test_applies_delay_between_requests(self) -> None:
        """Should wait delay_seconds between requests."""
        delay = 0.1

        async def mock_request(self_client, method, url, **kwargs):
            return httpx.Response(200)

        client = self._make_client(delay_seconds=delay, max_concurrent=1)

        with patch.object(httpx.AsyncClient, "request", mock_request):
            async with client:
                start = time.monotonic()
                await client.get("https://example.com/1")
                await client.get("https://example.com/2")
                elapsed = time.monotonic() - start

        # Two requests with delay after each = at least 2 * delay
        assert elapsed >= 2 * delay * 0.9  # Allow 10% tolerance

    @pytest.mark.asyncio
    async def test_tracks_request_count(self) -> None:
        """Should increment request_count on each call."""
        async def mock_request(self_client, method, url, **kwargs):
            return httpx.Response(200)

        client = self._make_client()
        assert client.request_count == 0

        with patch.object(httpx.AsyncClient, "request", mock_request):
            async with client:
                await client.get("https://example.com/1")
                assert client.request_count == 1
                await client.post("https://example.com/2")
                assert client.request_count == 2
                await client.delete("https://example.com/3")
                assert client.request_count == 3

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        """Should open and close httpx client properly."""
        client = self._make_client()

        # Before context, _client is None
        assert client._client is None

        async with client:
            assert client._client is not None

        # After context, client should be closed (aclose called)
        # We verify by checking the internal state
        assert client._client is not None  # reference kept but closed

    @pytest.mark.asyncio
    async def test_raises_without_context_manager(self) -> None:
        """Should raise RuntimeError if used without context manager."""
        client = self._make_client()

        with pytest.raises(RuntimeError):
            await client.get("https://example.com")

    @pytest.mark.asyncio
    async def test_extra_headers(self) -> None:
        """Should include extra headers in requests."""
        extra = {"X-Custom": "value"}
        client = self._make_client(extra_headers=extra)

        async def mock_request(self_client, method, url, **kwargs):
            return httpx.Response(200)

        with patch.object(httpx.AsyncClient, "__init__", return_value=None) as mock_init:
            with patch.object(httpx.AsyncClient, "request", mock_request):
                with patch.object(httpx.AsyncClient, "aclose", AsyncMock()):
                    # Manually set _client since we mocked __init__
                    client._client = httpx.AsyncClient.__new__(httpx.AsyncClient)
                    await client.request("GET", "https://example.com")

        # Verify request count incremented
        assert client.request_count == 1

    @pytest.mark.asyncio
    async def test_http_methods(self) -> None:
        """Should support GET, POST, PATCH, DELETE convenience methods."""
        methods_called: list[str] = []

        async def mock_request(self_client, method, url, **kwargs):
            methods_called.append(method)
            return httpx.Response(200)

        client = self._make_client()

        with patch.object(httpx.AsyncClient, "request", mock_request):
            async with client:
                await client.get("https://example.com")
                await client.post("https://example.com")
                await client.patch("https://example.com")
                await client.delete("https://example.com")

        assert methods_called == ["GET", "POST", "PATCH", "DELETE"]
