"""Pipeline orchestrator -- wires all stages together."""

import logging
import time

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

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
            if not self.config.quiet:
                console.print("[yellow]No API keys found.[/yellow]")
            return self._build_result([], [], sources_crawled, start)

        if not self.config.quiet:
            console.print(f"[green]Found {len(extracted)} unique key(s)[/green]")

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
        """Build ExtractedKey objects from direct key input (skip discovery)."""
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
        """Run all discovery modules."""
        all_sources: list[DiscoveredSource] = []

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
            disable=self.config.quiet,
        )

        async with self.session.client() as client:
            with progress:
                # Stage 1: Crawl targets
                task_id = progress.add_task("Crawling targets...", total=len(self.config.targets))
                crawler = Crawler(client, self.config)
                for target in self.config.targets:
                    sources = await crawler.crawl(target)
                    all_sources.extend(sources)
                    progress.advance(task_id)

                # Stage 2: Wayback Machine
                if self.config.wayback:
                    task_id = progress.add_task("Fetching Wayback JS...", total=len(self.config.targets))
                    wayback = WaybackFetcher(client, self.config)
                    for target in self.config.targets:
                        sources = await wayback.fetch_historical_js(target)
                        all_sources.extend(sources)
                        progress.advance(task_id)

                # Stage 3: Source maps
                if self.config.sourcemaps:
                    js_urls = [s.url for s in all_sources if s.source_type == SourceType.JS_FILE]
                    if js_urls:
                        task_id = progress.add_task("Chasing source maps...", total=len(js_urls))
                        sm_chaser = SourceMapChaser(client, self.config)
                        for js_url in js_urls:
                            sources = await sm_chaser.chase(js_url)
                            all_sources.extend(sources)
                            progress.advance(task_id)

                # Stage 4: Webpack chunks
                webpack = WebpackChunkFinder(client, self.config)
                chunk_sources = await webpack.find_chunks(all_sources)
                all_sources.extend(chunk_sources)

        return all_sources, len(all_sources)

    def _extract(self, sources: list[DiscoveredSource]) -> list[ExtractedKey]:
        """Extract and deduplicate API keys from discovered sources."""
        deobfuscator = Deobfuscator()
        extractor = KeyExtractor()

        for source in sources:
            processed_content = deobfuscator.process(source.content)
            extractor.extract_from_source(source, processed_content)

        return extractor.all_keys

    async def _validate(self, keys: list[ExtractedKey]) -> list[ValidatedKey]:
        """Validate all keys against the Gemini API."""
        async with self.session.client() as client:
            validator = KeyValidator(client, self.config)
            return await validator.validate_all(keys)

    async def _gather_intel(self, keys: list[ValidatedKey]) -> list[KeyIntelligence]:
        """Gather intelligence on working keys."""
        async with self.session.client() as client:
            recon = KeyRecon(client, self.config)
            return await recon.gather_all(keys)

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
        """Render output to console/file."""
        if self.config.json_mode:
            output = render_json(result)
        else:
            output = render_table(result, self.config)

        if self.config.output_path:
            with open(self.config.output_path, "w") as f:
                f.write(output)
            if not self.config.quiet:
                console.print(f"[dim]Results written to {self.config.output_path}[/dim]")
        elif self.config.json_mode:
            # JSON to stdout for piping
            click_echo = __import__("click").echo
            click_echo(output)
