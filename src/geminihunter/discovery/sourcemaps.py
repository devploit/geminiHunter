"""Source map (.js.map) discovery and content extraction."""

import json
import logging
import re
from urllib.parse import urljoin

import httpx

from geminihunter.config import Config
from geminihunter.models import DiscoveredSource, SourceType

logger = logging.getLogger("geminihunter")

# Matches //# sourceMappingURL=<url> or //@ sourceMappingURL=<url>
SOURCEMAP_COMMENT_RE = re.compile(
    r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)", re.MULTILINE
)


class SourceMapChaser:
    """Discovers and extracts source content from .js.map files."""

    def __init__(self, client: httpx.AsyncClient, config: Config):
        self.client = client
        self.config = config

    async def chase(
        self, js_url: str, js_content: str | None = None
    ) -> list[DiscoveredSource]:
        """
        Try to find and parse the source map for a JS file.

        Checks:
        1. sourceMappingURL comment in JS content (exact path)
        2. {js_url}.map (common convention)
        """
        sources: list[DiscoveredSource] = []
        tried: set[str] = set()

        # Method 1: Parse sourceMappingURL from JS content
        if js_content:
            match = SOURCEMAP_COMMENT_RE.search(js_content)
            if match:
                raw_map_url = match.group(1)
                # Skip inline data URIs
                if not raw_map_url.startswith("data:"):
                    map_url = urljoin(js_url, raw_map_url)
                    tried.add(map_url)
                    map_content = await self._fetch_map(map_url)
                    if map_content:
                        extracted = self._extract_sources_from_map(
                            map_content, map_url, js_url
                        )
                        sources.extend(extracted)
                        return sources

        # Method 2: Try the common .map extension
        map_url = f"{js_url}.map"
        if map_url not in tried:
            map_content = await self._fetch_map(map_url)
            if map_content:
                extracted = self._extract_sources_from_map(
                    map_content, map_url, js_url
                )
                sources.extend(extracted)

        return sources

    async def _fetch_map(self, url: str) -> str | None:
        """Fetch a source map file."""
        try:
            resp = await self.client.get(url, timeout=self.config.timeout)
            if resp.status_code == 200:
                ct = resp.headers.get("content-type", "")
                # Source maps are JSON
                if "json" in ct or "octet-stream" in ct or resp.text.startswith("{"):
                    return resp.text
        except (httpx.HTTPError, Exception) as e:
            logger.debug(f"Failed to fetch source map {url}: {e}")

        return None

    def _extract_sources_from_map(
        self, map_content: str, map_url: str, js_url: str
    ) -> list[DiscoveredSource]:
        """
        Parse a source map and extract all sourcesContent entries.

        Source maps have a `sourcesContent` array with the original,
        un-minified source code -- often containing API keys in plain text.
        """
        try:
            data = json.loads(map_content)
        except (json.JSONDecodeError, ValueError):
            logger.debug(f"Invalid JSON in source map: {map_url}")
            return []

        sources_content = data.get("sourcesContent", [])
        source_names = data.get("sources", [])

        if not sources_content:
            logger.debug(f"No sourcesContent in {map_url}")
            return []

        logger.info(
            f"Source map {map_url}: {len(sources_content)} source files"
        )

        from urllib.parse import urlparse as _urlparse

        domain = _urlparse(js_url).hostname or ""

        results: list[DiscoveredSource] = []
        for i, content in enumerate(sources_content):
            if not content or not isinstance(content, str):
                continue

            name = source_names[i] if i < len(source_names) else f"source_{i}"
            results.append(
                DiscoveredSource(
                    url=f"{map_url}:{name}",
                    source_type=SourceType.JS_MAP,
                    target_domain=domain,
                    content=content,
                )
            )

        return results
