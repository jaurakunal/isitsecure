"""Rate-limited HTTP client for responsible scanning."""

import asyncio
import logging

import httpx

from isitsecure.engine.constants import RateLimitedClientConfig, SharedPatterns

logger = logging.getLogger(__name__)


class RateLimitedClient:
    """httpx.AsyncClient wrapper with concurrency and rate limiting.

    Ensures we don't overwhelm the target with requests.
    Uses asyncio.Semaphore for concurrency control.
    """

    def __init__(
        self,
        max_concurrent: int,
        delay_seconds: float,
        timeout_seconds: float,
        user_agent: str,
        extra_headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> None:
        self._max_concurrent = max_concurrent
        self._delay = delay_seconds
        self._timeout = timeout_seconds
        self._user_agent = user_agent
        self._extra_headers = extra_headers or {}
        self._follow_redirects = follow_redirects
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._request_count = 0
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "RateLimitedClient":
        headers = {SharedPatterns.HEADER_USER_AGENT: self._user_agent, **self._extra_headers}
        self._client = httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=self._follow_redirects,
            headers=headers,
        )
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._client:
            await self._client.aclose()

    async def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        """Make a rate-limited HTTP request."""
        async with self._semaphore:
            if self._client is None:
                raise RuntimeError(
                    RateLimitedClientConfig.ERROR_NOT_CONTEXT_MANAGER
                )
            response = await self._client.request(method, url, **kwargs)
            self._request_count += 1
            if self._delay > 0:
                await asyncio.sleep(self._delay)
            return response

    async def get(self, url: str, **kwargs: object) -> httpx.Response:
        """Make a rate-limited GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: object) -> httpx.Response:
        """Make a rate-limited POST request."""
        return await self.request("POST", url, **kwargs)

    async def patch(self, url: str, **kwargs: object) -> httpx.Response:
        """Make a rate-limited PATCH request."""
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: object) -> httpx.Response:
        """Make a rate-limited DELETE request."""
        return await self.request("DELETE", url, **kwargs)

    @property
    def request_count(self) -> int:
        """Total number of requests made through this client."""
        return self._request_count
