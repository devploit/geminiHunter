"""CLI entry point for geminiHunter."""

import asyncio
import logging
import sys

import click
from rich.console import Console

from geminihunter import __version__
from geminihunter.config import Config
from geminihunter.pipeline import Pipeline

console = Console(stderr=True)

BANNER = r"""
                       _       _ _   _             _
   __ _  ___ _ __ ___ (_)_ __ (_) | | |_   _ _ __ | |_ ___ _ __
  / _` |/ _ \ '_ ` _ \| | '_ \| | |_| | | | | '_ \| __/ _ \ '__|
 | (_| |  __/ | | | | | | | | | |  _  | |_| | | | | ||  __/ |
  \__, |\___|_| |_| |_|_|_| |_|_|_| |_|\__,_|_| |_|\__\___|_|
  |___/
"""


def _setup_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
    )
    # Silence noisy third-party loggers always
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("hpack").setLevel(logging.WARNING)
    logging.getLogger("h2").setLevel(logging.WARNING)

    # Only show geminihunter logs in verbose mode
    gh_logger = logging.getLogger("geminihunter")
    gh_logger.setLevel(logging.DEBUG if verbose else logging.WARNING)


def _collect_targets(
    cli_targets: tuple[str, ...],
    target_file: str | None,
    scan_json: str | None = None,
) -> list[str]:
    """Collect and deduplicate targets from all input sources."""
    import json

    targets: list[str] = list(cli_targets)

    if target_file:
        with open(target_file) as f:
            targets.extend(
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            )

    # Import from scan JSON (gengar-style format)
    # Prefer services[] (httpx-probed URLs) over raw subdomains[]
    if scan_json:
        with open(scan_json) as f:
            data = json.load(f)

        services = data.get("services", [])
        if services:
            # Group URLs by host, prefer HTTPS over HTTP
            from collections import defaultdict

            by_host: dict[str, str] = {}
            for svc in services:
                url = svc.get("url", "").strip()
                host = svc.get("host", "").strip()
                if not url or not host:
                    continue
                existing = by_host.get(host)
                if existing is None:
                    by_host[host] = url
                elif url.startswith("https://") and existing.startswith("http://"):
                    # HTTPS wins over HTTP for the same host
                    by_host[host] = url
            targets.extend(by_host.values())
        else:
            # Fallback: raw subdomains
            for sub in data.get("subdomains", []):
                domain = sub.get("domain", "").strip()
                if domain:
                    targets.append(domain)
            if not data.get("subdomains"):
                for t in data.get("scan", {}).get("targets", []):
                    if t.strip():
                        targets.append(t.strip())

    if not sys.stdin.isatty() and not any(t == "-" for t in targets):
        targets.extend(
            line.strip()
            for line in sys.stdin
            if line.strip() and not line.startswith("#")
        )

    seen: set[str] = set()
    unique: list[str] = []
    for t in targets:
        normalized = t.rstrip("/")
        if normalized and normalized not in seen:
            seen.add(normalized)
            unique.append(normalized)
    return unique


def _collect_keys(key_input: str | None, key_file: str | None) -> list[str]:
    """Collect and deduplicate API keys from direct input."""
    keys: list[str] = []

    if key_input:
        if key_input == "-":
            if not sys.stdin.isatty():
                keys.extend(
                    line.strip()
                    for line in sys.stdin
                    if line.strip() and not line.startswith("#")
                )
        else:
            keys.extend(k.strip() for k in key_input.split(",") if k.strip())

    if key_file:
        with open(key_file) as f:
            keys.extend(
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            )

    return list(dict.fromkeys(keys))  # Dedup preserving order


@click.command()
@click.argument("targets", nargs=-1)
@click.option("-f", "--file", "target_file", type=click.Path(exists=True), help="File with targets (one per line)")
@click.option("-sj", "--scan-json", type=click.Path(exists=True), help="Scan JSON file (gengar-style: extracts subdomains)")
@click.option("-k", "--key", "key_input", default=None, help="API key(s) to check directly (comma-separated, or - for stdin)")
@click.option("--key-file", type=click.Path(exists=True), help="File with API keys (one per line)")
@click.option("--depth", default=2, type=int, show_default=True, help="Crawl depth")
@click.option("--wayback/--no-wayback", default=True, show_default=True, help="Include Wayback Machine JS")
@click.option("--sourcemaps/--no-sourcemaps", default=True, show_default=True, help="Chase .js.map files")
@click.option("--bypass/--no-bypass", default=True, show_default=True, help="Run 403 bypass engine")
@click.option("--proxy", default=None, help="Proxy URL or file with proxy list")
@click.option("--rate-limit", default=10.0, type=float, show_default=True, help="Max requests/second")
@click.option("--delay", default=0.0, type=float, show_default=True, help="Fixed delay between requests (seconds)")
@click.option("--timeout", default=15.0, type=float, show_default=True, help="HTTP timeout (seconds)")
@click.option("--concurrency", default=20, type=int, show_default=True, help="Max concurrent requests")
@click.option("--user-agent", default="rotate", show_default=True, help='Custom User-Agent or "rotate"')
@click.option("-o", "--output", "output_path", type=click.Path(), help="Write results to file")
@click.option("--json", "json_mode", is_flag=True, help="Output as JSON")
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
@click.option("-q", "--quiet", is_flag=True, help="Suppress banner and progress")
@click.option("--evidence", is_flag=True, help="Include curl reproduction commands")
@click.version_option(__version__)
def main(
    targets,
    target_file,
    scan_json,
    key_input,
    key_file,
    depth,
    wayback,
    sourcemaps,
    bypass,
    proxy,
    rate_limit,
    delay,
    timeout,
    concurrency,
    user_agent,
    output_path,
    json_mode,
    verbose,
    quiet,
    evidence,
):
    """Discover and validate Google Gemini API keys from web targets."""

    _setup_logging(verbose, quiet)

    if not quiet and not json_mode:
        console.print(BANNER, style="bold cyan")

    keys = _collect_keys(key_input, key_file)
    all_targets = _collect_targets(targets, target_file, scan_json) if not keys else []

    if not keys and not all_targets:
        console.print("[red]No targets or keys provided. Use --help for usage.[/red]")
        raise SystemExit(1)

    if not quiet and not json_mode:
        if keys:
            console.print(f"  [dim]Mode:[/dim]    Key check")
            console.print(f"  [dim]Keys:[/dim]    {len(keys)}")
        else:
            console.print(f"  [dim]Mode:[/dim]    Discovery")
            console.print(f"  [dim]Targets:[/dim] {len(all_targets)}")
        console.print()

    config = Config(
        targets=all_targets,
        keys=keys,
        depth=depth,
        wayback=wayback,
        sourcemaps=sourcemaps,
        bypass=bypass,
        proxy=proxy,
        rate_limit=rate_limit,
        delay=delay,
        timeout=timeout,
        concurrency=concurrency,
        user_agent=user_agent,
        json_mode=json_mode,
        verbose=verbose,
        quiet=quiet,
        evidence=evidence,
        output_path=output_path,
    )

    try:
        result = asyncio.run(Pipeline(config).execute())
    except KeyboardInterrupt:
        console.print("\n  [dim]Interrupted.[/dim]")
        raise SystemExit(130)
    raise SystemExit(0 if result.keys_valid > 0 or result.keys_bypassed > 0 else 1)
