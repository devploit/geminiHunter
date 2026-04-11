"""Pipeline orchestrator -- wires all stages together."""

import logging
import time

from rich.console import Console

from geminihunter.config import Config
from geminihunter.discovery.crawler import Crawler
from geminihunter.discovery.sourcemaps import SourceMapChaser
from geminihunter.discovery.wayback import WaybackFetcher
from geminihunter.discovery.webpack import WebpackChunkFinder
from geminihunter.extraction.deobfuscator import Deobfuscator
from geminihunter.extraction.extractor import KeyExtractor
from geminihunter.intelligence.recon import KeyRecon
from geminihunter.models import (
    DiscoveredSource,
    ExtractedKey,
    KeyIntelligence,
    KeyStatus,
    ScanResult,
    SourceType,
    ValidatedKey,
)
from geminihunter.network.session import SessionManager
from geminihunter.output.console import render_table
from geminihunter.output.evidence import generate_curl_commands
from geminihunter.output.json_out import render_json
from geminihunter.validation.validator import KeyValidator

logger = logging.getLogger("geminihunter")
console = Console(stderr=True)


def _status(config: Config, msg: str) -> None:
    """Print a status line if not quiet/json."""
    if not config.quiet and not config.json_mode:
        console.print(msg)


class Pipeline:
    def __init__(self, config: Config):
        self.config = config
        self.session = SessionManager(config)

    async def execute(self) -> ScanResult:
        start = time.monotonic()

        if self.config.is_key_mode:
            extracted = self._build_keys_from_input()
            sources_crawled = 0
        else:
            sources, sources_crawled = await self._discover()
            extracted = self._extract(sources)

        if not extracted:
            _status(self.config, "  [dim]No API keys found.[/dim]")
            return self._build_result([], [], sources_crawled, start)

        _status(self.config, f"  [green]+[/green] Found [bold]{len(extracted)}[/bold] unique key(s)\n")

        validated = await self._validate(extracted)

        working = [k for k in validated if k.status in (KeyStatus.VALID, KeyStatus.BYPASSED)]
        intel = await self._gather_intel(working) if working else []

        # Add non-working keys to results for completeness
        non_working = [
            KeyIntelligence(
                key=k.key,
                status=k.status,
                target_domain=k.target_domain,
                sources=k.sources,
                bypass=k.bypass,
            )
            for k in validated
            if k.status not in (KeyStatus.VALID, KeyStatus.BYPASSED)
        ]
        all_results = intel + non_working

        if self.config.evidence:
            for r in all_results:
                r.curl_commands = generate_curl_commands(r)

        result = self._build_result(all_results, validated, sources_crawled, start)
        self._render(result)
        return result

    def _build_keys_from_input(self) -> list[ExtractedKey]:
        return [
            ExtractedKey(
                key=k,
                sources=["direct_input"],
                source_types=[SourceType.DIRECT_INPUT],
                target_domain="direct",
            )
            for k in self.config.keys
        ]

    async def _discover(self) -> tuple[list[DiscoveredSource], int]:
        import asyncio

        all_sources: list[DiscoveredSource] = []
        total_targets = len(self.config.targets)
        sem = asyncio.Semaphore(self.config.concurrency)

        async with self.session.client() as client:
            # Stage 1: Crawl all targets concurrently
            _status(self.config, f"  [cyan]>[/cyan] Crawling {total_targets} target(s)...")
            crawler = Crawler(client, self.config)

            async def _crawl_one(target: str) -> list[DiscoveredSource]:
                async with sem:
                    return await crawler.crawl(target)

            results = await asyncio.gather(
                *[_crawl_one(t) for t in self.config.targets],
                return_exceptions=True,
            )
            for r in results:
                if isinstance(r, list):
                    all_sources.extend(r)
            _status(self.config, f"    [dim]{len(all_sources)} sources found[/dim]")

            # Stage 2: Wayback Machine (all targets concurrently)
            if self.config.wayback:
                _status(self.config, f"  [cyan]>[/cyan] Fetching Wayback Machine JS...")
                before = len(all_sources)
                wayback = WaybackFetcher(client, self.config)

                async def _wayback_one(target: str) -> list[DiscoveredSource]:
                    async with sem:
                        return await wayback.fetch_historical_js(target)

                results = await asyncio.gather(
                    *[_wayback_one(t) for t in self.config.targets],
                    return_exceptions=True,
                )
                for r in results:
                    if isinstance(r, list):
                        all_sources.extend(r)
                _status(self.config, f"    [dim]{len(all_sources) - before} historical sources[/dim]")

            # Stage 3: Source maps (all JS URLs concurrently)
            if self.config.sourcemaps:
                js_urls = [s.url for s in all_sources if s.source_type == SourceType.JS_FILE]
                if js_urls:
                    _status(self.config, f"  [cyan]>[/cyan] Chasing {len(js_urls)} source map(s)...")
                    before = len(all_sources)
                    sm_chaser = SourceMapChaser(client, self.config)

                    async def _chase_one(js_url: str) -> list[DiscoveredSource]:
                        async with sem:
                            return await sm_chaser.chase(js_url)

                    results = await asyncio.gather(
                        *[_chase_one(u) for u in js_urls],
                        return_exceptions=True,
                    )
                    for r in results:
                        if isinstance(r, list):
                            all_sources.extend(r)
                    _status(self.config, f"    [dim]{len(all_sources) - before} source map files[/dim]")

            # Stage 4: Webpack chunks
            before = len(all_sources)
            webpack = WebpackChunkFinder(client, self.config)
            chunk_sources = await webpack.find_chunks(all_sources)
            all_sources.extend(chunk_sources)
            added = len(all_sources) - before
            if added:
                _status(self.config, f"    [dim]{added} webpack chunks[/dim]")

        _status(self.config, f"  [green]+[/green] Total: [bold]{len(all_sources)}[/bold] sources crawled\n")
        return all_sources, len(all_sources)

    def _extract(self, sources: list[DiscoveredSource]) -> list[ExtractedKey]:
        from concurrent.futures import ThreadPoolExecutor

        _status(self.config, f"  [cyan]>[/cyan] Extracting API keys from {len(sources)} sources...")
        deobfuscator = Deobfuscator()
        extractor = KeyExtractor()

        # Deobfuscate in parallel threads (CPU-bound)
        with ThreadPoolExecutor() as pool:
            processed = list(pool.map(deobfuscator.process, [s.content for s in sources]))

        for source, content in zip(sources, processed):
            extractor.extract_from_source(source, content)

        return extractor.all_keys

    async def _validate(self, keys: list[ExtractedKey]) -> list[ValidatedKey]:
        _status(self.config, f"  [cyan]>[/cyan] Validating {len(keys)} key(s)...")
        async with self.session.client() as client:
            validator = KeyValidator(client, self.config)
            results = await validator.validate_all(keys)

        # Print inline summary
        valid = sum(1 for r in results if r.status == KeyStatus.VALID)
        bypassed = sum(1 for r in results if r.status == KeyStatus.BYPASSED)
        forbidden = sum(1 for r in results if r.status == KeyStatus.FORBIDDEN)
        invalid = sum(1 for r in results if r.status == KeyStatus.INVALID)

        parts = []
        if valid:
            parts.append(f"[green]{valid} valid[/green]")
        if bypassed:
            parts.append(f"[yellow]{bypassed} bypassed[/yellow]")
        if forbidden:
            parts.append(f"[red]{forbidden} forbidden[/red]")
        if invalid:
            parts.append(f"[dim]{invalid} invalid[/dim]")

        _status(self.config, f"    {' / '.join(parts)}")

        if bypassed and not self.config.quiet and not self.config.json_mode:
            for r in results:
                if r.status == KeyStatus.BYPASSED and r.bypass:
                    console.print(f"    [yellow]^[/yellow] ...{r.key[-8:]} bypassed via [bold]{r.bypass.technique}[/bold]")

        _status(self.config, "")
        return results

    async def _gather_intel(self, keys: list[ValidatedKey]) -> list[KeyIntelligence]:
        _status(self.config, f"  [cyan]>[/cyan] Gathering intelligence on {len(keys)} key(s)...")
        async with self.session.client() as client:
            recon = KeyRecon(client, self.config)
            results = await recon.gather_all(keys)
        _status(self.config, "")
        return results

    def _build_result(
        self,
        results: list[KeyIntelligence],
        validated: list[ValidatedKey],
        sources_crawled: int,
        start: float,
    ) -> ScanResult:
        return ScanResult(
            targets_scanned=self.config.targets or ["direct_key_check"],
            sources_crawled=sources_crawled,
            keys_found=len(validated),
            keys_valid=sum(1 for r in results if r.status == KeyStatus.VALID),
            keys_bypassed=sum(1 for r in results if r.status == KeyStatus.BYPASSED),
            keys_forbidden=sum(1 for r in results if r.status == KeyStatus.FORBIDDEN),
            keys_invalid=sum(1 for r in results if r.status == KeyStatus.INVALID),
            duration_seconds=round(time.monotonic() - start, 2),
            results=results,
        )

    def _render(self, result: ScanResult) -> None:
        if self.config.json_mode:
            output = render_json(result)
        else:
            output = render_table(result, self.config)

        if self.config.output_path:
            with open(self.config.output_path, "w") as f:
                f.write(output if output else render_json(result))
            if not self.config.quiet:
                console.print(f"  [dim]Results written to {self.config.output_path}[/dim]")
        elif self.config.json_mode:
            click_echo = __import__("click").echo
            click_echo(output)
