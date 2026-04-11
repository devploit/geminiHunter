"""CLI entry point for geminiHunter."""

import asyncio
import logging
import sys

import click
from rich.console import Console
from rich.logging import RichHandler

from geminihunter import __version__
from geminihunter.config import Config
from geminihunter.pipeline import Pipeline

console = Console(stderr=True)


def _setup_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_time=False, show_path=False)],
    )

BANNER = """
   ╔═╗┌─┐┌┬┐┬┌┐┌┬╦ ╦┬ ┬┌┐┌┌┬┐┌─┐┬─┐
   ║ ╦├┤ ││││││││╠═╣│ ││││ │ ├┤ ├┬┘
   ╚═╝└─┘┘└┘┴┘└┘┴╩ ╩└─┘┘└┘ ┴ └─┘┴└─
"""


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
    if scan_json:
        with open(scan_json) as f:
            data = json.load(f)
        # Extract subdomains[].domain
        for sub in data.get("subdomains", []):
            domain = sub.get("domain", "").strip()
            if domain:
                targets.append(domain)
        # Also include scan.targets as fallback if no subdomains
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
        console.print(BANNER, style="bold red")

    keys = _collect_keys(key_input, key_file)
    all_targets = _collect_targets(targets, target_file, scan_json) if not keys else []

    if not keys and not all_targets:
        console.print("[red]No targets or keys provided. Use --help for usage.[/red]")
        raise SystemExit(1)

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

    result = asyncio.run(Pipeline(config).execute())
    raise SystemExit(0 if result.keys_valid > 0 or result.keys_bypassed > 0 else 1)
