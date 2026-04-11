"""Pipeline orchestrator -- wires all stages together."""

import logging
import sys
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
        show = not self.config.quiet and not self.config.json_mode

        # Live progress (raw stderr for in-place overwrite)
        done_count = 0
        sources_count = 0

        def _progress(msg: str) -> None:
            if not show:
                return
            sys.stderr.write(f"\r  > {msg}" + " " * 20)
            sys.stderr.flush()

        def _clear_progress() -> None:
            if not show:
                return
            sys.stderr.write("\r" + " " * 100 + "\r")
            sys.stderr.flush()

        # --- Phase 1: Crawl targets ---
        async with self.session.client() as client:
            crawler = Crawler(client, self.config)

            async def _crawl_one(target: str) -> list[DiscoveredSource]:
                nonlocal done_count, sources_count
                async with sem:
                    result = await crawler.crawl(target)
                    done_count += 1
                    sources_count += len(result)
                    _progress(f"Crawling... {done_count}/{total_targets} targets | {sources_count} sources")
                    return result

            _progress(f"Crawling... 0/{total_targets} targets | 0 sources")

            crawl_results = await asyncio.gather(
                *[_crawl_one(t) for t in self.config.targets],
                return_exceptions=True,
            )
            for r in crawl_results:
                if isinstance(r, list):
                    all_sources.extend(r)

        _clear_progress()
        _status(self.config, f"  [cyan]>[/cyan] Crawled [bold]{total_targets}[/bold] targets | [bold]{len(all_sources)}[/bold] sources")

        # --- Phase 2: Wayback Machine (deduped by root domain) ---
        if self.config.wayback:
            async with self.session.client() as client:
                wayback = WaybackFetcher(client, self.config)

                def _wb_progress(done: int, total: int) -> None:
                    _progress(f"Wayback... {done}/{total} domains")

                before = len(all_sources)
                wb_sources = await wayback.fetch_for_targets(
                    self.config.targets, on_progress=_wb_progress
                )
                all_sources.extend(wb_sources)

            _clear_progress()
            added = len(all_sources) - before
            if added:
                _status(self.config, f"    [dim]+{added} from Wayback[/dim]")

        # --- Phase 3: Source maps + Webpack ---
        async with self.session.client() as client:
            js_urls = [s.url for s in all_sources if s.source_type == SourceType.JS_FILE]
            sm_done = 0
            total_js = len(js_urls)
            sm_tasks: list = []

            if self.config.sourcemaps and js_urls:
                sm_chaser = SourceMapChaser(client, self.config)

                async def _chase_one(js_url: str) -> list[DiscoveredSource]:
                    nonlocal sm_done
                    async with sem:
                        result = await sm_chaser.chase(js_url)
                        sm_done += 1
                        _progress(f"Sourcemaps... {sm_done}/{total_js}")
                        return result

                sm_tasks.extend([_chase_one(u) for u in js_urls])

            webpack = WebpackChunkFinder(client, self.config)

            if sm_tasks:
                _progress(f"Sourcemaps... 0/{total_js}")

                sm_results = await asyncio.gather(*sm_tasks, return_exceptions=True)
                extra_sm = 0
                for r in sm_results:
                    if isinstance(r, list):
                        all_sources.extend(r)
                        extra_sm += len(r)

                _clear_progress()
                if extra_sm:
                    _status(self.config, f"    [dim]+{extra_sm} from sourcemaps[/dim]")

            _progress("Webpack chunks...")
            wp_sources = await webpack.find_chunks(all_sources)
            all_sources.extend(wp_sources)
            _clear_progress()
            if wp_sources:
                _status(self.config, f"    [dim]+{len(wp_sources)} from webpack[/dim]")

        _status(self.config, f"  [green]+[/green] Total: [bold]{len(all_sources)}[/bold] sources\n")
        return all_sources, len(all_sources)

    def _extract(self, sources: list[DiscoveredSource]) -> list[ExtractedKey]:
        from concurrent.futures import ThreadPoolExecutor

        show = not self.config.quiet and not self.config.json_mode
        total = len(sources)
        deobfuscator = Deobfuscator()
        extractor = KeyExtractor()

        def _eprogress(msg: str) -> None:
            if show:
                sys.stderr.write(f"\r  > {msg}" + " " * 20)
                sys.stderr.flush()

        # Deobfuscate in parallel threads (CPU-bound)
        done = 0

        def _deobf_one(content: str) -> str:
            nonlocal done
            result = deobfuscator.process(content)
            done += 1
            if done % max(1, total // 20) == 0:
                _eprogress(f"Deobfuscating... {done}/{total}")
            return result

        _eprogress(f"Deobfuscating... 0/{total}")
        with ThreadPoolExecutor() as pool:
            processed = list(pool.map(_deobf_one, [s.content for s in sources]))

        # Extract keys with progress
        for i, (source, content) in enumerate(zip(sources, processed)):
            extractor.extract_from_source(source, content)
            if (i + 1) % max(1, total // 20) == 0:
                _eprogress(f"Extracting... {i + 1}/{total} | {extractor.count} keys")

        if show:
            sys.stderr.write("\r" + " " * 100 + "\r")
            sys.stderr.flush()

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
