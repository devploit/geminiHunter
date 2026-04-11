"""Web crawler for discovering JS files and inline scripts."""

import logging
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


def _normalize_url(base: str, href: str) -> str:
    """Resolve a potentially relative URL against a base."""
    if href.startswith(("http://", "https://", "//")):
        if href.startswith("//"):
            return f"https:{href}"
        return href
    return urljoin(base, href)


def _same_domain(url: str, domain: str) -> bool:
    """Check if a URL belongs to the same domain (or subdomain)."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return host == domain or host.endswith(f".{domain}")


class Crawler:
    """Crawls targets to discover JS files and inline scripts."""

    def __init__(self, client: httpx.AsyncClient, config: Config):
        self.client = client
        self.config = config
        self._visited: set[str] = set()

    async def crawl(self, target: str) -> list[DiscoveredSource]:
        """
        Crawl a target domain/URL up to configured depth.

        Returns all discovered sources (JS files and inline scripts).
        """
        # Normalize target to URL
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        domain = urlparse(target).hostname or target
        sources: list[DiscoveredSource] = []

        await self._crawl_recursive(target, domain, 0, sources)

        logger.info(f"Crawled {target}: {len(sources)} sources found")
        return sources

    async def _crawl_recursive(
        self,
        url: str,
        domain: str,
        depth: int,
        sources: list[DiscoveredSource],
    ) -> None:
        if depth > self.config.depth:
            return
        if url in self._visited:
            return

        self._visited.add(url)

        try:
            resp = await self.client.get(
                url,
                headers={"User-Agent": self._get_ua()},
                timeout=self.config.timeout,
            )
        except (httpx.HTTPError, Exception) as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            return

        if resp.status_code != 200:
            return

        content_type = resp.headers.get("content-type", "")
        text = resp.text

        if "javascript" in content_type or url.endswith(".js"):
            # This is a JS file
            sources.append(
                DiscoveredSource(
                    url=url,
                    source_type=SourceType.JS_FILE,
                    target_domain=domain,
                    content=text,
                )
            )
            return

        if "html" not in content_type:
            return

        # Extract inline scripts
        for match in INLINE_SCRIPT_RE.finditer(text):
            script_content = match.group(1).strip()
            if script_content and len(script_content) > 10:
                sources.append(
                    DiscoveredSource(
                        url=url,
                        source_type=SourceType.HTML_INLINE,
                        target_domain=domain,
                        content=script_content,
                    )
                )

        # Extract script src URLs
        js_urls: set[str] = set()
        for match in SCRIPT_SRC_RE.finditer(text):
            js_url = _normalize_url(url, match.group(1))
            js_urls.add(js_url)

        # Also find JS URLs in other attributes/strings
        for match in JS_URL_RE.finditer(text):
            js_url = _normalize_url(url, match.group(1))
            js_urls.add(js_url)

        # Fetch all discovered JS files
        for js_url in js_urls:
            if js_url in self._visited:
                continue
            self._visited.add(js_url)
            try:
                js_resp = await self.client.get(
                    js_url,
                    headers={"User-Agent": self._get_ua()},
                    timeout=self.config.timeout,
                )
                if js_resp.status_code == 200:
                    sources.append(
                        DiscoveredSource(
                            url=js_url,
                            source_type=SourceType.JS_FILE,
                            target_domain=domain,
                            content=js_resp.text,
                        )
                    )
            except (httpx.HTTPError, Exception) as e:
                logger.debug(f"Failed to fetch JS {js_url}: {e}")

        # Crawl deeper: find links to same-domain pages
        if depth < self.config.depth:
            link_re = re.compile(r'<a[^>]+href\s*=\s*["\'](/[^"\']+)["\']', re.IGNORECASE)
            for match in link_re.finditer(text):
                link = _normalize_url(url, match.group(1))
                if _same_domain(link, domain) and link not in self._visited:
                    await self._crawl_recursive(link, domain, depth + 1, sources)

    def _get_ua(self) -> str:
        from geminihunter.network.session import USER_AGENTS
        import random

        if self.config.user_agent == "rotate":
            return random.choice(USER_AGENTS)
        return self.config.user_agent
