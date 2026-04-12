"""Web crawler for discovering JS files and inline scripts."""

import asyncio
import logging
import random
import re
from urllib.parse import urljoin, urlparse

import httpx

from geminihunter.config import Config
from geminihunter.models import DiscoveredSource, SourceType

logger = logging.getLogger("geminihunter")

# Regex to extract <script src="..."> without a DOM parser
SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]+src\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# Regex to extract inline <script>...</script> content
INLINE_SCRIPT_RE = re.compile(
    r"""<script[^>]*>(.*?)</script>""",
    re.IGNORECASE | re.DOTALL,
)

# Regex to find additional JS URLs in HTML (link preload, data attributes, etc.)
JS_URL_RE = re.compile(
    r"""["']((?:https?://[^"']+|/[^"']+)\.js(?:\?[^"']*)?)["']""",
    re.IGNORECASE,
)

LINK_RE = re.compile(
    r'<a[^>]+href\s*=\s*["\'](/[^"\']+)["\']',
    re.IGNORECASE,
)

# <link rel="preload" href="..." as="script"> and <link rel="modulepreload" href="...">
PRELOAD_SCRIPT_RE = re.compile(
    r'<link[^>]+rel\s*=\s*["\'](?:preload|modulepreload)["\'][^>]+href\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
PRELOAD_SCRIPT_RE2 = re.compile(
    r'<link[^>]+href\s*=\s*["\']([^"\']+)["\'][^>]+rel\s*=\s*["\'](?:preload|modulepreload)["\']',
    re.IGNORECASE,
)

# Next.js data files: /_next/data/{buildId}/{page}.json
NEXTJS_DATA_RE = re.compile(
    r"""["'](/_next/(?:data/[^"'/]+/[^"']+\.json|static/[^"']+\.js))["\']""",
    re.IGNORECASE,
)

# Nuxt.js chunks: /_nuxt/*.js
NUXT_CHUNK_RE = re.compile(
    r"""["'](/_nuxt/[^"']+\.js)["\']""",
    re.IGNORECASE,
)

# Firebase hosting config: /__/firebase/init.json
FIREBASE_INIT_RE = re.compile(
    r"""["'](/__/firebase/[^"']+\.(?:json|js))["\']""",
    re.IGNORECASE,
)


def _normalize_url(base: str, href: str) -> str:
    """Resolve a potentially relative URL against a base."""
    if href.startswith(("http://", "https://", "//")):
        if href.startswith("//"):
            return f"https:{href}"
        return href
    return urljoin(base, href)


def _same_domain(url: str, domain: str) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host == domain or host.endswith(f".{domain}")


class Crawler:
    """Crawls targets to discover JS files and inline scripts -- fully concurrent."""

    def __init__(self, client: httpx.AsyncClient, config: Config):
        self.client = client
        self.config = config
        self._visited: set[str] = set()
        self._visited_lock = asyncio.Lock()

    async def _mark_visited(self, url: str) -> bool:
        """Mark a URL as visited. Returns True if it was new."""
        async with self._visited_lock:
            if url in self._visited:
                return False
            self._visited.add(url)
            return True

    async def crawl(self, target: str) -> list[DiscoveredSource]:
        """Crawl a target domain/URL up to configured depth."""
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        domain = urlparse(target).hostname or target
        sources: list[DiscoveredSource] = []
        sources_lock = asyncio.Lock()

        async def _add_sources(new: list[DiscoveredSource]) -> None:
            async with sources_lock:
                sources.extend(new)

        await self._crawl_page(target, domain, 0, _add_sources)
        return sources

    async def _crawl_page(
        self,
        url: str,
        domain: str,
        depth: int,
        add_sources,
    ) -> None:
        if depth > self.config.depth:
            return
        if not await self._mark_visited(url):
            return

        try:
            resp = await self.client.get(
                url,
                headers={"User-Agent": self._get_ua()},
                timeout=self.config.timeout,
            )
        except (httpx.HTTPError, Exception):
            return

        if resp.status_code != 200:
            return

        content_type = resp.headers.get("content-type", "")
        text = resp.text

        if "javascript" in content_type or url.endswith(".js"):
            await add_sources([
                DiscoveredSource(
                    url=url, source_type=SourceType.JS_FILE,
                    target_domain=domain, content=text,
                )
            ])
            return

        if "html" not in content_type:
            return

        # Extract inline scripts
        inline_sources = []
        for match in INLINE_SCRIPT_RE.finditer(text):
            script_content = match.group(1).strip()
            if script_content and len(script_content) > 10:
                inline_sources.append(
                    DiscoveredSource(
                        url=url, source_type=SourceType.HTML_INLINE,
                        target_domain=domain, content=script_content,
                    )
                )
        if inline_sources:
            await add_sources(inline_sources)

        # Collect all JS URLs
        js_urls: set[str] = set()
        for match in SCRIPT_SRC_RE.finditer(text):
            js_urls.add(_normalize_url(url, match.group(1)))
        for match in JS_URL_RE.finditer(text):
            js_urls.add(_normalize_url(url, match.group(1)))

        # Preload / modulepreload links
        for regex in (PRELOAD_SCRIPT_RE, PRELOAD_SCRIPT_RE2):
            for match in regex.finditer(text):
                href = match.group(1)
                if href.endswith((".js", ".mjs")):
                    js_urls.add(_normalize_url(url, href))

        # Framework-specific data/chunk files
        for regex in (NEXTJS_DATA_RE, NUXT_CHUNK_RE, FIREBASE_INIT_RE):
            for match in regex.finditer(text):
                js_urls.add(_normalize_url(url, match.group(1)))

        # Fetch all JS files concurrently
        js_tasks = [self._fetch_js(u, domain, add_sources) for u in js_urls]

        # Crawl deeper: find links to same-domain pages
        page_tasks = []
        if depth < self.config.depth:
            for match in LINK_RE.finditer(text):
                link = _normalize_url(url, match.group(1))
                if _same_domain(link, domain):
                    page_tasks.append(
                        self._crawl_page(link, domain, depth + 1, add_sources)
                    )

        # Run JS fetches and page crawls concurrently
        await asyncio.gather(*js_tasks, *page_tasks, return_exceptions=True)

    async def _fetch_js(
        self, url: str, domain: str, add_sources
    ) -> None:
        """Fetch a single JS file."""
        if not await self._mark_visited(url):
            return
        try:
            resp = await self.client.get(
                url,
                headers={"User-Agent": self._get_ua()},
                timeout=self.config.timeout,
            )
            if resp.status_code == 200:
                await add_sources([
                    DiscoveredSource(
                        url=url, source_type=SourceType.JS_FILE,
                        target_domain=domain, content=resp.text,
                    )
                ])
        except (httpx.HTTPError, Exception):
            pass

    def _get_ua(self) -> str:
        from geminihunter.network.session import USER_AGENTS

        if self.config.user_agent == "rotate":
            return random.choice(USER_AGENTS)
        return self.config.user_agent
