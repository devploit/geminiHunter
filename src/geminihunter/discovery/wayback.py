"""Wayback Machine integration for discovering historical JS files."""

from __future__ import annotations

import asyncio
import logging
from typing import Callable
from urllib.parse import urlparse

import httpx

from geminihunter.config import Config
from geminihunter.models import DiscoveredSource, SourceType
from geminihunter.network.session import SessionManager

logger = logging.getLogger("geminihunter")

CDX_API = "https://web.archive.org/cdx/search/cdx"
WAYBACK_RAW = "https://web.archive.org/web/{timestamp}id_/{url}"
WAYBACK_CDX_LIMIT = 25
WAYBACK_DOMAIN_CONCURRENCY = 8
WAYBACK_SNAPSHOT_CONCURRENCY = 16
WAYBACK_MAX_RETRIES = 1
WAYBACK_CDX_TIMEOUT = 15.0
WAYBACK_SNAPSHOT_TIMEOUT_CAP = 8.0


def _extract_root_domain(target: str) -> str:
    """Extract the root/parent domain from a target URL or hostname."""
    host = target
    if target.startswith(("http://", "https://")):
        host = urlparse(target).hostname or target

    # Strip leading www.
    if host.startswith("www."):
        host = host[4:]

    # For multi-part TLDs (co.uk, com.br, etc.), keep last 3 parts
    # For normal TLDs, keep last 2 parts
    parts = host.split(".")
    multi_tlds = {"co", "com", "org", "net", "gov", "ac", "edu"}
    if len(parts) >= 3 and parts[-2] in multi_tlds:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


class WaybackFetcher:
    """Fetches historical JS files from the Wayback Machine."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        config: Config,
        session: SessionManager,
    ):
        self.client = client
        self.config = config
        self.session = session

    async def fetch_for_targets(
        self,
        targets: list[str],
        on_progress: "Callable[[int, int], None] | None" = None,
    ) -> list[DiscoveredSource]:
        """
        Query Wayback for all targets, deduplicating by root domain
        so we only make one CDX query per root domain.
        on_progress(done, total) is called after each domain completes.
        """
        # Deduplicate targets by root domain
        root_domains: dict[str, str] = {}
        for t in targets:
            root = _extract_root_domain(t)
            if root not in root_domains:
                root_domains[root] = root

        total = len(root_domains)
        done = 0

        logger.info(
            f"Wayback: {len(targets)} targets -> {total} unique root domains"
        )

        if on_progress:
            on_progress(0, total)

        sem = asyncio.Semaphore(
            max(1, min(self.config.concurrency, WAYBACK_DOMAIN_CONCURRENCY))
        )

        async def _query_one(domain: str) -> list[DiscoveredSource]:
            nonlocal done
            async with sem:
                result = await self._fetch_for_domain(domain)
                done += 1
                if on_progress:
                    on_progress(done, total)
                return result

        results = await asyncio.gather(
            *[_query_one(d) for d in root_domains],
            return_exceptions=True,
        )
        all_sources: list[DiscoveredSource] = []
        for r in results:
            if isinstance(r, list):
                all_sources.extend(r)
        return all_sources

    async def fetch_historical_js(self, target: str) -> list[DiscoveredSource]:
        """Query Wayback CDX for JS files on a single target."""
        domain = target
        if target.startswith(("http://", "https://")):
            domain = urlparse(target).hostname or target
        return await self._fetch_for_domain(domain)

    async def _fetch_for_domain(self, domain: str) -> list[DiscoveredSource]:
        """Query CDX + fetch snapshots for a single domain."""
        js_entries = await self._query_cdx(domain)

        if not js_entries:
            return []

        logger.info(
            f"Wayback: found {len(js_entries)} unique JS snapshots for {domain}"
        )

        sem = asyncio.Semaphore(
            max(1, min(self.config.concurrency, WAYBACK_SNAPSHOT_CONCURRENCY))
        )

        async def _fetch_one(ts: str, orig_url: str) -> DiscoveredSource | None:
            async with sem:
                content = await self._fetch_snapshot(ts, orig_url)
                if content:
                    return DiscoveredSource(
                        url=f"wayback:{ts}/{orig_url}",
                        source_type=SourceType.WAYBACK_JS,
                        target_domain=domain,
                        content=content,
                    )
                return None

        results = await asyncio.gather(
            *[_fetch_one(ts, url) for ts, url in js_entries],
            return_exceptions=True,
        )
        return [r for r in results if isinstance(r, DiscoveredSource)]

    async def _query_cdx(self, domain: str) -> list[tuple[str, str]]:
        """Query the CDX API for unique JS file snapshots."""
        params = {
            "url": f"*.{domain}/*.js",
            "output": "json",
            "fl": "timestamp,original,digest",
            "collapse": "digest",  # Dedup by content hash
            "filter": "statuscode:200",
            "limit": str(WAYBACK_CDX_LIMIT),
        }

        try:
            resp = await self.session.fetch(
                self.client,
                CDX_API,
                params=params,
                timeout=min(self.config.timeout, WAYBACK_CDX_TIMEOUT),
                max_retries=WAYBACK_MAX_RETRIES,
            )
            if resp is None or resp.status_code != 200:
                logger.debug(
                    f"CDX query failed: {resp.status_code if resp is not None else 'no_response'}"
                )
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
            resp = await self.session.fetch(
                self.client,
                snapshot_url,
                timeout=min(self.config.timeout, WAYBACK_SNAPSHOT_TIMEOUT_CAP),
                max_retries=WAYBACK_MAX_RETRIES,
            )
            if resp is not None and resp.status_code == 200:
                return resp.text
        except (httpx.HTTPError, Exception) as e:
            logger.debug(f"Failed to fetch wayback snapshot: {e}")

        return None
