"""Wayback Machine integration for discovering historical JS files."""

import logging
from urllib.parse import urlparse

import httpx

from geminihunter.config import Config
from geminihunter.models import DiscoveredSource, SourceType

logger = logging.getLogger("geminihunter")

CDX_API = "https://web.archive.org/cdx/search/cdx"
WAYBACK_RAW = "https://web.archive.org/web/{timestamp}id_/{url}"


class WaybackFetcher:
    """Fetches historical JS files from the Wayback Machine."""

    def __init__(self, client: httpx.AsyncClient, config: Config):
        self.client = client
        self.config = config

    async def fetch_historical_js(self, target: str) -> list[DiscoveredSource]:
        """
        Query Wayback CDX for JS files on the target domain,
        then fetch unique snapshots.
        """
        domain = target
        if target.startswith(("http://", "https://")):
            domain = urlparse(target).hostname or target

        # Query CDX for .js files
        js_entries = await self._query_cdx(domain)

        if not js_entries:
            logger.debug(f"No Wayback JS found for {domain}")
            return []

        logger.info(f"Wayback: found {len(js_entries)} unique JS snapshots for {domain}")

        sources: list[DiscoveredSource] = []
        for timestamp, original_url in js_entries:
            content = await self._fetch_snapshot(timestamp, original_url)
            if content:
                sources.append(
                    DiscoveredSource(
                        url=f"wayback:{timestamp}/{original_url}",
                        source_type=SourceType.WAYBACK_JS,
                        target_domain=domain,
                        content=content,
                    )
                )

        return sources

    async def _query_cdx(self, domain: str) -> list[tuple[str, str]]:
        """Query the CDX API for unique JS file snapshots."""
        params = {
            "url": f"*.{domain}/*.js",
            "output": "json",
            "fl": "timestamp,original,digest",
            "collapse": "digest",  # Dedup by content hash
            "filter": "statuscode:200",
            "limit": "500",  # Cap to avoid huge responses
        }

        try:
            resp = await self.client.get(CDX_API, params=params, timeout=30.0)
            if resp.status_code != 200:
                logger.debug(f"CDX query failed: {resp.status_code}")
                return []

            data = resp.json()
            if not data or len(data) < 2:
                return []

            # First row is header: ["timestamp", "original", "digest"]
            entries = [(row[0], row[1]) for row in data[1:]]
            return entries

        except (httpx.HTTPError, ValueError) as e:
            logger.debug(f"CDX query error for {domain}: {e}")
            return []

    async def _fetch_snapshot(self, timestamp: str, url: str) -> str | None:
        """Fetch a single Wayback snapshot."""
        snapshot_url = WAYBACK_RAW.format(timestamp=timestamp, url=url)

        try:
            resp = await self.client.get(snapshot_url, timeout=self.config.timeout)
            if resp.status_code == 200:
                return resp.text
        except (httpx.HTTPError, Exception) as e:
            logger.debug(f"Failed to fetch wayback snapshot: {e}")

        return None
