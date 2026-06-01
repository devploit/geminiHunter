"""Webpack chunk discovery -- finds lazy-loaded JS chunks."""

import logging
import re
from urllib.parse import urlparse

import httpx

from geminihunter.config import Config
from geminihunter.models import DiscoveredSource, SourceType
from geminihunter.network.session import SessionManager

logger = logging.getLogger("geminihunter")

MAX_WEBPACK_CHUNKS = 64
WEBPACK_MAX_RETRIES = 1
WEBPACK_TIMEOUT_CAP = 8.0

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

    def __init__(
        self,
        client: httpx.AsyncClient,
        config: Config,
        session: SessionManager,
    ):
        self.client = client
        self.config = config
        self.session = session

    async def find_chunks(
        self, sources: list[DiscoveredSource]
    ) -> list[DiscoveredSource]:
        """
        Scan already-discovered JS sources for webpack chunk references,
        then fetch those chunks.
        """
        chunk_urls: list[str] = []
        seen_urls = {s.url for s in sources}

        for source in sources:
            if source.source_type != SourceType.JS_FILE:
                continue
            discovered = self._extract_chunk_urls(source.content, source.url)
            for url in discovered:
                if url not in seen_urls:
                    seen_urls.add(url)
                    chunk_urls.append(url)

        if not chunk_urls:
            return []

        chunk_urls = self._prioritize_chunks(chunk_urls, sources)

        logger.info(f"Webpack: found {len(chunk_urls)} chunk URLs to fetch")

        import asyncio

        domain = sources[0].target_domain if sources else ""
        sem = asyncio.Semaphore(max(1, min(self.config.concurrency, MAX_WEBPACK_CHUNKS)))

        async def _fetch_one(url: str) -> DiscoveredSource | None:
            async with sem:
                return await self._fetch_chunk(url, domain)

        fetched = await asyncio.gather(
            *[_fetch_one(u) for u in chunk_urls],
            return_exceptions=True,
        )
        return [r for r in fetched if isinstance(r, DiscoveredSource)]

    def _prioritize_chunks(
        self,
        urls: list[str],
        sources: list[DiscoveredSource],
    ) -> list[str]:
        source_hosts = {
            parsed.hostname
            for source in sources
            if source.source_type == SourceType.JS_FILE
            for parsed in [urlparse(source.url)]
            if parsed.hostname
        }

        def score(url: str) -> tuple[int, int]:
            parsed = urlparse(url)
            same_host = parsed.hostname in source_hosts
            return (0 if same_host else 1, len(parsed.path))

        return sorted(urls, key=score)[:MAX_WEBPACK_CHUNKS]

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
            resp = await self.session.fetch(
                self.client,
                url,
                timeout=min(self.config.timeout, WEBPACK_TIMEOUT_CAP),
                max_retries=WEBPACK_MAX_RETRIES,
            )
            if resp is not None and resp.status_code == 200:
                return DiscoveredSource(
                    url=url,
                    source_type=SourceType.WEBPACK_CHUNK,
                    target_domain=domain,
                    content=resp.text,
                )
        except (httpx.HTTPError, Exception) as e:
            logger.debug(f"Failed to fetch chunk {url}: {e}")

        return None
