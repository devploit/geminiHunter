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
MAX_SOURCEMAP_CANDIDATES = 64


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
        timings: dict[str, float] = {}

        needs_discovery = bool(self.config.targets or self.config.apk_paths)

        if self.config.is_key_mode and not needs_discovery:
            extracted = self._build_keys_from_input()
            sources_crawled = 0
        elif needs_discovery:
            t0 = time.monotonic()
            sources, sources_crawled = await self._discover()
            timings["discovery"] = round(time.monotonic() - t0, 2)

            t0 = time.monotonic()
            extracted = self._extract(sources)
            timings["extraction"] = round(time.monotonic() - t0, 2)

            # Merge direct keys if provided alongside APK/targets
            if self.config.keys:
                extracted.extend(self._build_keys_from_input())
        else:
            extracted = self._build_keys_from_input()
            sources_crawled = 0

        if not extracted:
            _status(self.config, "  [dim]No API keys found.[/dim]")
            return self._build_result([], [], sources_crawled, start, timings)

        _status(self.config, f"  [green]+[/green] Found [bold]{len(extracted)}[/bold] unique key(s)\n")

        t0 = time.monotonic()
        validated = await self._validate(extracted)
        timings["validation"] = round(time.monotonic() - t0, 2)

        working = [k for k in validated if k.status in (KeyStatus.VALID, KeyStatus.BYPASSED)]

        t0 = time.monotonic()
        intel = await self._gather_intel(working) if working else []
        timings["intelligence"] = round(time.monotonic() - t0, 2)

        # Add non-working keys to results for completeness
        non_working = [
            KeyIntelligence(
                key=k.key,
                status=k.status,
                target_domain=k.target_domain,
                sources=k.sources,
                bypass=k.bypass,
                detail=k.detail,
            )
            for k in validated
            if k.status not in (KeyStatus.VALID, KeyStatus.BYPASSED)
        ]
        all_results = intel + non_working

        # Always generate curls for JSON mode, or when --evidence is set
        if self.config.evidence or self.config.json_mode:
            for r in all_results:
                r.curl_commands = generate_curl_commands(r)

        result = self._build_result(all_results, validated, sources_crawled, start, timings)
        self._render(result)
        return result

    def _build_keys_from_input(self) -> list[ExtractedKey]:
        return [
            ExtractedKey(
                key=k,
                sources=["direct_input"],
                source_types=[SourceType.DIRECT_INPUT],
                target_domain="direct",
                target_domains=["direct"],
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

        # --- Phase 0: APK discovery (local, synchronous) ---
        if self.config.apk_paths:
            import os
            from geminihunter.discovery.apk import ApkScanner

            scanner = ApkScanner()
            engine_label = "[dim](jadx)[/dim]" if scanner.has_jadx else "[dim](zip)[/dim]"
            _status(self.config, f"  [cyan]>[/cyan] Scanning APK file(s) {engine_label}")

            for path in self.config.apk_paths:
                _progress(f"APK: {os.path.basename(path)}")
                apk_sources = scanner.scan(path)
                all_sources.extend(apk_sources)

            _clear_progress()
            _status(
                self.config,
                f"    [green]+[/green] {len(all_sources)} source(s) from APK",
            )

        if not self.config.targets:
            # APK-only mode: skip web discovery phases
            return all_sources, len(all_sources)

        # --- Phase 1: Crawl targets ---
        async with self.session.client() as client:
            crawler = Crawler(client, self.config, self.session)

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
                wayback = WaybackFetcher(client, self.config, self.session)

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
            js_sources = [
                (s.url, s.content)
                for s in all_sources
                if s.source_type == SourceType.JS_FILE
            ]
            js_sources = sorted(
                js_sources,
                key=lambda item: (
                    0 if "sourceMappingURL" in item[1] else 1,
                    len(item[1]),
                ),
            )[:MAX_SOURCEMAP_CANDIDATES]
            sm_done = 0
            total_js = len(js_sources)
            sm_tasks: list = []

            if self.config.sourcemaps and js_sources:
                sm_chaser = SourceMapChaser(client, self.config, self.session)

                async def _chase_one(js_url: str, js_content: str) -> list[DiscoveredSource]:
                    nonlocal sm_done
                    async with sem:
                        result = await sm_chaser.chase(js_url, js_content)
                        sm_done += 1
                        _progress(f"Sourcemaps... {sm_done}/{total_js}")
                        return result

                sm_tasks.extend([_chase_one(u, c) for u, c in js_sources])

            webpack = WebpackChunkFinder(client, self.config, self.session)

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
        import hashlib

        deobfuscator = Deobfuscator()
        extractor = KeyExtractor()

        candidate_sources = [
            source
            for source in sources
            if extractor.may_contain_key_material(source.content)
        ]
        total = len(candidate_sources)
        if not candidate_sources:
            if show:
                sys.stderr.write("\r" + " " * 100 + "\r")
                sys.stderr.flush()
            return []

        content_hashes = [
            hashlib.blake2s(source.content.encode(), digest_size=16).hexdigest()
            for source in candidate_sources
        ]
        unique_hashes = list(dict.fromkeys(content_hashes))
        content_by_hash: dict[str, str] = {}
        for content_hash, source in zip(content_hashes, candidate_sources):
            content_by_hash.setdefault(content_hash, source.content)
        total_unique = len(unique_hashes)

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
            if done % max(1, total_unique // 20) == 0:
                _eprogress(f"Deobfuscating... {done}/{total_unique}")
            return result

        _eprogress(f"Deobfuscating... 0/{total_unique}")
        with ThreadPoolExecutor() as pool:
            processed = list(pool.map(_deobf_one, [content_by_hash[h] for h in unique_hashes]))

        processed_by_hash = dict(zip(unique_hashes, processed))

        # Extract keys with progress
        for i, source in enumerate(candidate_sources):
            extractor.extract_from_source(source, processed_by_hash[content_hashes[i]])
            if (i + 1) % max(1, total // 20) == 0:
                _eprogress(f"Extracting... {i + 1}/{total} | {extractor.count} keys")

        if show:
            sys.stderr.write("\r" + " " * 100 + "\r")
            sys.stderr.flush()

        return extractor.all_keys

    async def _validate(self, keys: list[ExtractedKey]) -> list[ValidatedKey]:
        _status(self.config, f"  [cyan]>[/cyan] Validating {len(keys)} key(s)...")
        async with self.session.client() as client:
            validator = KeyValidator(client, self.config, self.session)
            results = await validator.validate_all(keys)

        # Print inline summary
        valid = sum(1 for r in results if r.status == KeyStatus.VALID)
        bypassed = sum(1 for r in results if r.status == KeyStatus.BYPASSED)
        rate_limited = sum(1 for r in results if r.status == KeyStatus.RATE_LIMITED)
        forbidden = sum(1 for r in results if r.status == KeyStatus.FORBIDDEN)
        invalid = sum(1 for r in results if r.status == KeyStatus.INVALID)

        parts = []
        if valid:
            parts.append(f"[green]{valid} valid[/green]")
        if bypassed:
            parts.append(f"[yellow]{bypassed} bypassed[/yellow]")
        if rate_limited:
            parts.append(f"[yellow]{rate_limited} rate-limited[/yellow]")
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
            recon = KeyRecon(client, self.config, self.session)
            results = await recon.gather_all(keys)
        _status(self.config, "")
        return results

    def _build_result(
        self,
        results: list[KeyIntelligence],
        validated: list[ValidatedKey],
        sources_crawled: int,
        start: float,
        timings: dict[str, float] | None = None,
    ) -> ScanResult:
        return ScanResult(
            targets_scanned=self.config.targets or ["direct_key_check"],
            sources_crawled=sources_crawled,
            keys_found=len(validated),
            keys_valid=sum(1 for r in results if r.status == KeyStatus.VALID),
            keys_bypassed=sum(1 for r in results if r.status == KeyStatus.BYPASSED),
            keys_rate_limited=sum(1 for r in results if r.status == KeyStatus.RATE_LIMITED),
            keys_forbidden=sum(1 for r in results if r.status == KeyStatus.FORBIDDEN),
            keys_invalid=sum(1 for r in results if r.status == KeyStatus.INVALID),
            duration_seconds=round(time.monotonic() - start, 2),
            phase_timings=timings or {},
            results=results,
        )

    def _render(self, result: ScanResult) -> None:
        if self.config.json_mode:
            output = render_json(result)
        else:
            output = render_table(result, self.config)

        if self.config.output_path:
            with open(self.config.output_path, "w") as f:
                if self.config.json_mode:
                    f.write(output)
                else:
                    from rich.console import Console as RichConsole

                    file_console = RichConsole(
                        record=True,
                        force_terminal=False,
                        color_system=None,
                    )
                    f.write(render_table(result, self.config, file_console))
            if not self.config.quiet:
                console.print(f"  [dim]Results written to {self.config.output_path}[/dim]")
        elif self.config.json_mode:
            click_echo = __import__("click").echo
            click_echo(output)
