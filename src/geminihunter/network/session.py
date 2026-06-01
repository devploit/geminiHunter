"""HTTP session management with proxy rotation, UA rotation, retries, and rate limiting."""

import asyncio
import logging
import os
import random
from contextlib import asynccontextmanager
from typing import AsyncIterator
from urllib.parse import urlparse

import httpx

from geminihunter.config import Config
from geminihunter.network.ratelimit import RateLimiter
from geminihunter.network.transport import TransportIssue, classify_transport_error

logger = logging.getLogger("geminihunter")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
]


class SessionManager:
    """Manages HTTP clients with OPSEC features."""

    def __init__(self, config: Config):
        self.config = config
        self.rate_limiter = RateLimiter(config.rate_limit)
        self._proxies = self._load_proxies(config.proxy)
        self._proxy_index = 0
        self._last_issues: dict[str, TransportIssue] = {}
        self._host_failures: dict[tuple[str, str], TransportIssue] = {}

    def _load_proxies(self, proxy_input: str | None) -> list[str]:
        if proxy_input is None:
            return []
        if os.path.isfile(proxy_input):
            with open(proxy_input) as f:
                return [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                ]
        return [proxy_input]

    def _next_proxy(self) -> str | None:
        if not self._proxies:
            return None
        proxy = self._proxies[self._proxy_index % len(self._proxies)]
        self._proxy_index += 1
        return proxy

    def _get_user_agent(self) -> str:
        if self.config.user_agent == "rotate":
            return random.choice(USER_AGENTS)
        return self.config.user_agent

    @asynccontextmanager
    async def client(self) -> AsyncIterator[httpx.AsyncClient]:
        """Create a configured async HTTP client."""
        proxy = self._next_proxy()
        c = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout),
            follow_redirects=True,
            http2=True,
            proxy=proxy,
            verify=not self.config.insecure,
            headers={"User-Agent": self._get_user_agent()},
            limits=httpx.Limits(
                max_connections=self.config.concurrency,
                max_keepalive_connections=max(1, self.config.concurrency),
            ),
        )
        try:
            yield c
        finally:
            await c.aclose()

    def _remember_issue(self, url: str, issue: TransportIssue) -> None:
        self._last_issues[url] = issue
        parsed = urlparse(url)
        host = parsed.hostname
        if host and not issue.retryable:
            self._host_failures[(parsed.scheme, host)] = issue

    def get_last_issue(self, url: str) -> TransportIssue | None:
        return self._last_issues.get(url)

    def should_try_http_fallback(self, url: str) -> bool:
        issue = self.get_last_issue(url)
        return bool(issue and issue.kind == "tls")

    async def fetch(
        self,
        client: httpx.AsyncClient,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        data: str | None = None,
        params: dict[str, str] | None = None,
        timeout: float | None = None,
        max_retries: int = 3,
        retry_on_429: bool = True,
    ) -> httpx.Response | None:
        """Fetch a URL with rate limiting, retries, and error handling."""
        parsed = urlparse(url)
        host = parsed.hostname
        if host and (parsed.scheme, host) in self._host_failures:
            return None
        await self.rate_limiter.acquire()

        for attempt in range(max_retries):
            try:
                if self.config.delay > 0:
                    await asyncio.sleep(self.config.delay)

                kwargs: dict = {"headers": headers or {}}
                if data is not None:
                    kwargs["content"] = data

                # Rotate UA per request if configured
                if self.config.user_agent == "rotate":
                    kwargs["headers"]["User-Agent"] = self._get_user_agent()

                resp = await client.request(
                    method,
                    url,
                    params=params,
                    timeout=timeout or self.config.timeout,
                    **kwargs,
                )

                if resp.status_code == 429:
                    if not retry_on_429:
                        return resp
                    wait = int(resp.headers.get("Retry-After", "30"))
                    logger.debug(f"Rate limited on {url}, waiting {wait}s")
                    await asyncio.sleep(wait)
                    continue

                if resp.status_code >= 500:
                    wait = 2**attempt + random.random()
                    logger.debug(
                        f"Server error {resp.status_code} on {url}, retry in {wait:.1f}s"
                    )
                    await asyncio.sleep(wait)
                    continue

                self._last_issues.pop(url, None)
                return resp

            except httpx.HTTPError as e:
                issue = classify_transport_error(e)
                self._remember_issue(url, issue)
                if not issue.retryable:
                    logger.debug(f"Non-retryable {issue.kind} error on {url}: {issue.detail}")
                    return None
                wait = 2**attempt + random.random()
                logger.debug(f"Network error on {url}: {e}, retry in {wait:.1f}s")
                await asyncio.sleep(wait)

        logger.debug(f"Failed after {max_retries} retries: {url}")
        return None
