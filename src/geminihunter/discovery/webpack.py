"""Webpack chunk discovery -- finds lazy-loaded JS chunks."""

import logging
import re

import httpx

from geminihunter.config import Config
from geminihunter.models import DiscoveredSource, SourceType

logger = logging.getLogger("geminihunter")

# Patterns to find webpack chunk URLs in JS bundles
# Pattern 1: webpackJsonp or __webpack_require__ with chunk filenames
CHUNK_FILENAME_RE = re.compile(
    r"""["'](\d+\.[a-f0-9]+\.chunk\.js)["']""",
    re.IGNORECASE,
)

# Pattern 2: Chunk map objects like {123: "abc123", 456: "def456"}
# These are typically part of __webpack_require__.e() or similar
CHUNK_MAP_RE = re.compile(
    r"""(\d+)\s*:\s*["']([a-f0-9]{6,20})["']""",
)

# Pattern 3: Static chunk pattern like "/static/js/chunk-{hash}.js"
STATIC_CHUNK_RE = re.compile(
    r"""["'](/static/js/[^"']+\.js)["']""",
    re.IGNORECASE,
)

# Pattern 4: Generic chunk URL patterns
GENERIC_CHUNK_RE = re.compile(
    r"""["']((?:chunks?|vendors?|commons?|runtime)[~./][^"']+\.js)["']""",
    re.IGNORECASE,
)


class WebpackChunkFinder:
    """Discovers webpack lazy-loaded chunk JS files."""

    def __init__(self, client: httpx.AsyncClient, config: Config):
        self.client = client
        self.config = config

    async def find_chunks(
        self, sources: list[DiscoveredSource]
    ) -> list[DiscoveredSource]:
        """
        Scan already-discovered JS sources for webpack chunk references,
        then fetch those chunks.
        """
        chunk_urls: set[str] = set()
        fetched_urls = {s.url for s in sources}

        for source in sources:
            if source.source_type != SourceType.JS_FILE:
                continue
            discovered = self._extract_chunk_urls(source.content, source.url)
            for url in discovered:
                if url not in fetched_urls:
                    chunk_urls.add(url)

        if not chunk_urls:
            return []

        logger.info(f"Webpack: found {len(chunk_urls)} chunk URLs to fetch")

        import asyncio

        domain = sources[0].target_domain if sources else ""
        sem = asyncio.Semaphore(10)

        async def _fetch_one(url: str) -> DiscoveredSource | None:
            async with sem:
                return await self._fetch_chunk(url, domain)

        fetched = await asyncio.gather(
            *[_fetch_one(u) for u in chunk_urls],
            return_exceptions=True,
        )
        return [r for r in fetched if isinstance(r, DiscoveredSource)]

    def _extract_chunk_urls(self, content: str, base_url: str) -> list[str]:
        """Extract webpack chunk URLs from JS content."""
        from urllib.parse import urljoin

        urls: list[str] = []

        # Direct chunk filename references
        for match in CHUNK_FILENAME_RE.finditer(content):
            urls.append(urljoin(base_url, match.group(1)))

        # Static chunk paths
        for match in STATIC_CHUNK_RE.finditer(content):
            urls.append(urljoin(base_url, match.group(1)))

        # Generic chunk patterns
        for match in GENERIC_CHUNK_RE.finditer(content):
            urls.append(urljoin(base_url, match.group(1)))

        return urls

    async def _fetch_chunk(
        self, url: str, domain: str
    ) -> DiscoveredSource | None:
        """Fetch a single webpack chunk."""
        try:
            resp = await self.client.get(url, timeout=self.config.timeout)
            if resp.status_code == 200:
                return DiscoveredSource(
                    url=url,
                    source_type=SourceType.WEBPACK_CHUNK,
                    target_domain=domain,
                    content=resp.text,
                )
        except (httpx.HTTPError, Exception) as e:
            logger.debug(f"Failed to fetch chunk {url}: {e}")

        return None
