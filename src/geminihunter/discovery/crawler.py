"""Web crawler for discovering JS files and inline scripts."""

import asyncio
import logging
import random
import re
from urllib.parse import urlparse

import httpx

from geminihunter.config import Config
from geminihunter.models import DiscoveredSource, SourceType
from geminihunter.network.session import SessionManager
from geminihunter.discovery.urlfinder import (
    extract_asset_urls_from_html,
    extract_asset_urls_from_json,
    normalize_url,
)

logger = logging.getLogger("geminihunter")

MAX_ASSETS_PER_PAGE = 48
MAX_JSON_ASSETS_PER_PAGE = 10
MAX_EXTERNAL_ASSETS_PER_PAGE = 8
MAX_PAGE_LINKS = 24
DISCOVERY_MAX_RETRIES = 1
DISCOVERY_TIMEOUT_CAP = 8.0

# Regex to extract inline <script>...</script> content
INLINE_SCRIPT_RE = re.compile(
    r"""<script[^>]*>(.*?)</script>""",
    re.IGNORECASE | re.DOTALL,
)

LINK_RE = re.compile(
    r'<a[^>]+href\s*=\s*["\'](/[^"\']+)["\']',
    re.IGNORECASE,
)


def _same_domain(url: str, domain: str) -> bool:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host == domain or host.endswith(f".{domain}")


class Crawler:
    """Crawls targets to discover JS files and inline scripts -- fully concurrent."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        config: Config,
        session: SessionManager,
    ):
        self.client = client
        self.config = config
        self.session = session
        self._visited: set[str] = set()
        self._visited_lock = asyncio.Lock()
        self._fetch_sem = asyncio.Semaphore(max(1, config.concurrency))

    def _request_timeout(self) -> float:
        return min(self.config.timeout, DISCOVERY_TIMEOUT_CAP)

    async def _mark_visited(self, url: str) -> bool:
        """Mark a URL as visited. Returns True if it was new."""
        async with self._visited_lock:
            if url in self._visited:
                return False
            self._visited.add(url)
            return True

    async def crawl(self, target: str) -> list[DiscoveredSource]:
        """Crawl a target domain/URL up to configured depth."""
        original_target = target
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        domain = urlparse(target).hostname or target
        sources: list[DiscoveredSource] = []
        sources_lock = asyncio.Lock()

        async def _add_sources(new: list[DiscoveredSource]) -> None:
            async with sources_lock:
                sources.extend(new)

        await self._crawl_page(target, domain, 0, _add_sources)
        if (
            not sources
            and not original_target.startswith(("http://", "https://"))
            and self.session.should_try_http_fallback(target)
        ):
            await self._crawl_page(f"http://{original_target}", domain, 0, _add_sources)
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
            resp = await self.session.fetch(
                self.client,
                url,
                headers={"User-Agent": self._get_ua()},
                timeout=self._request_timeout(),
                max_retries=DISCOVERY_MAX_RETRIES,
            )
        except (httpx.HTTPError, Exception):
            return

        if resp is None or resp.status_code != 200:
            return

        content_type = resp.headers.get("content-type", "")
        text = resp.text

        if "javascript" in content_type or url.endswith((".js", ".mjs")):
            await add_sources([
                DiscoveredSource(
                    url=url, source_type=SourceType.JS_FILE,
                    target_domain=domain, content=text,
                )
            ])
            return

        if any(
            token in content_type
            for token in ("application/json", "application/manifest+json", "application/ld+json")
        ) or url.endswith((".json", ".webmanifest")):
            await add_sources([
                DiscoveredSource(
                    url=url,
                    source_type=SourceType.HTML_INLINE,
                    target_domain=domain,
                    content=text,
                )
            ])
            js_urls = self._prioritize_asset_urls(
                extract_asset_urls_from_json(url, text),
                domain,
            )
            await asyncio.gather(
                *[self._fetch_js(asset_url, domain, add_sources) for asset_url in js_urls],
                return_exceptions=True,
            )
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

        js_urls = self._prioritize_asset_urls(
            extract_asset_urls_from_html(url, text),
            domain,
        )

        # Fetch all JS files concurrently
        js_tasks = [self._fetch_js(u, domain, add_sources) for u in js_urls]

        # Crawl deeper: find links to same-domain pages
        page_tasks = []
        if depth < self.config.depth:
            for idx, match in enumerate(LINK_RE.finditer(text)):
                if idx >= MAX_PAGE_LINKS:
                    break
                link = normalize_url(url, match.group(1))
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
        async with self._fetch_sem:
            try:
                resp = await self.session.fetch(
                    self.client,
                    url,
                    headers={"User-Agent": self._get_ua()},
                    timeout=self._request_timeout(),
                    max_retries=DISCOVERY_MAX_RETRIES,
                )
                if resp is not None and resp.status_code == 200:
                    content_type = resp.headers.get("content-type", "")
                    source_type = (
                        SourceType.JS_FILE
                        if "javascript" in content_type or url.endswith((".js", ".mjs"))
                        else SourceType.HTML_INLINE
                    )
                    await add_sources([
                        DiscoveredSource(
                            url=url, source_type=source_type,
                            target_domain=domain, content=resp.text,
                        )
                    ])
            except (httpx.HTTPError, Exception):
                pass

    def _prioritize_asset_urls(self, urls: list[str], domain: str) -> list[str]:
        """Keep the most promising assets and cap per-page fan-out."""
        same_domain_js: list[str] = []
        same_domain_json: list[str] = []
        external_js: list[str] = []
        external_json: list[str] = []

        for url in urls:
            parsed = urlparse(url)
            same_domain = _same_domain(url, domain)
            is_js = parsed.path.endswith((".js", ".mjs"))
            is_json = parsed.path.endswith((".json", ".webmanifest"))
            looks_framework_json = any(
                marker in parsed.path
                for marker in ("/_next/", "/_nuxt/", "/_astro/", "/_app/", "/build/", "manifest", "workbox", "sw")
            )

            if same_domain and is_js:
                same_domain_js.append(url)
            elif same_domain and (is_json or looks_framework_json):
                same_domain_json.append(url)
            elif not same_domain and is_js:
                external_js.append(url)
            elif not same_domain and (is_json or looks_framework_json):
                external_json.append(url)

        prioritized = (
            same_domain_js[:MAX_ASSETS_PER_PAGE]
            + same_domain_json[:MAX_JSON_ASSETS_PER_PAGE]
            + external_js[:MAX_EXTERNAL_ASSETS_PER_PAGE]
            + external_json[: max(0, MAX_EXTERNAL_ASSETS_PER_PAGE // 2)]
        )
        return prioritized[:MAX_ASSETS_PER_PAGE]

    def _get_ua(self) -> str:
        from geminihunter.network.session import USER_AGENTS

        if self.config.user_agent == "rotate":
            return random.choice(USER_AGENTS)
        return self.config.user_agent
