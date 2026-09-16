"""CLI entry point for geminiHunter."""

import asyncio
import json
import logging
import os
import sys
import tomllib

import click
from rich.console import Console

from geminihunter import __version__
from geminihunter.config import Config
from geminihunter.pipeline import Pipeline

console = Console(stderr=True)

# --- Config file loader ---

CONFIG_FILENAMES = [".geminihunterrc", ".geminihunter.toml"]


def _load_config_file() -> dict:
    """Load defaults from .geminihunterrc or .geminihunter.toml."""
    for directory in (os.getcwd(), os.path.expanduser("~")):
        for name in CONFIG_FILENAMES:
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                try:
                    with open(path, "rb") as f:
                        return tomllib.load(f)
                except (OSError, tomllib.TOMLDecodeError) as exc:
                    raise click.UsageError(f"Cannot read configuration {path}: {exc}") from exc
    return {}

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
    targets: list[str] = list(cli_targets)

    if target_file:
        with open(target_file, encoding="utf-8") as f:
            targets.extend(
                line.strip()
                for line in f
                if line.strip() and not line.lstrip().startswith("#")
            )

    # Import from scan JSON (gengar-style format)
    # Prefer services[] (httpx-probed URLs) over raw subdomains[]
    if scan_json:
        with open(scan_json, encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            raise click.UsageError("Scan JSON must contain an object")
        for field, item_field in (("services", "url"), ("subdomains", "domain")):
            entries = data.get(field, [])
            if not isinstance(entries, list) or any(
                not isinstance(entry, dict)
                or not isinstance(entry.get(item_field, ""), str)
                or (field == "services" and not isinstance(entry.get("host", ""), str))
                for entry in entries
            ):
                raise click.UsageError(f"Scan JSON {field} must contain objects with string fields")
        scan = data.get("scan", {})
        if not isinstance(scan, dict) or not isinstance(scan.get("targets", []), list) or any(
            not isinstance(target, str) for target in scan.get("targets", [])
        ):
            raise click.UsageError("Scan JSON scan.targets must be an array of strings")

        services = data.get("services", [])
        if services:
            # Group URLs by host, prefer HTTPS over HTTP

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
            if line.strip() and not line.lstrip().startswith("#")
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
                    if line.strip() and not line.lstrip().startswith("#")
                )
        else:
            keys.extend(k.strip() for k in key_input.split(",") if k.strip())

    if key_file:
        with open(key_file, encoding="utf-8") as f:
            keys.extend(
                line.strip()
                for line in f
                if line.strip() and not line.lstrip().startswith("#")
            )

    return list(dict.fromkeys(keys))  # Dedup preserving order


@click.command()
@click.argument("targets", nargs=-1)
@click.option("-f", "--file", "target_file", type=click.Path(exists=True, dir_okay=False, readable=True), help="File with targets (one per line)")
@click.option("-sj", "--scan-json", type=click.Path(exists=True, dir_okay=False, readable=True), help="Scan JSON file (gengar-style: extracts subdomains)")
@click.option("-k", "--key", "key_input", default=None, help="API key(s) to check directly (comma-separated, or - for stdin)")
@click.option("--key-file", type=click.Path(exists=True, dir_okay=False, readable=True), help="File with API keys (one per line)")
@click.option("--apk", "apk_files", multiple=True, type=click.Path(exists=True, dir_okay=False, readable=True), help="APK/XAPK file(s) to decompile and scan")
@click.option("--depth", default=2, type=click.IntRange(min=0), show_default=True, help="Crawl depth")
@click.option("--wayback/--no-wayback", default=True, show_default=True, help="Include Wayback Machine JS")
@click.option("--sourcemaps/--no-sourcemaps", default=True, show_default=True, help="Chase .js.map files")
@click.option("--bypass/--no-bypass", default=True, show_default=True, help="Run 403 bypass engine")
@click.option("--proxy", default=None, help="Proxy URL or file with proxy list")
@click.option("--rate-limit", default=10.0, type=float, show_default=True, help="Max requests/second")
@click.option("--delay", default=0.0, type=float, show_default=True, help="Fixed delay between requests (seconds)")
@click.option("--timeout", default=15.0, type=float, show_default=True, help="HTTP timeout (seconds)")
@click.option("--concurrency", default=20, type=click.IntRange(min=1), show_default=True, help="Max concurrent requests")
@click.option("--user-agent", default="rotate", show_default=True, help='Custom User-Agent or "rotate"')
@click.option("--insecure", is_flag=True, help="Disable TLS certificate verification")
@click.option("-o", "--output", "output_path", type=click.Path(dir_okay=False), help="Write results to file (.json selects JSON)")
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
    apk_files,
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
    insecure,
    output_path,
    json_mode,
    verbose,
    quiet,
    evidence,
):
    """Discover and validate Google Gemini API keys from web targets."""

    # Apply config file defaults for options not explicitly set on CLI
    file_cfg = _load_config_file()
    ctx = click.get_current_context()
    supported = {
        "depth", "wayback", "sourcemaps", "bypass", "proxy", "rate-limit",
        "delay", "timeout", "concurrency", "user-agent", "insecure", "evidence",
    }
    unknown = file_cfg.keys() - supported
    if unknown:
        raise click.UsageError(f"Unknown configuration option(s): {', '.join(sorted(unknown))}")

    def _cfg(param_name: str, cli_val, toml_key: str | None = None):
        """Return CLI value if explicitly set, otherwise config file value, otherwise CLI default."""
        src = ctx.get_parameter_source(param_name)
        if src != click.core.ParameterSource.DEFAULT:
            return cli_val
        config_key = toml_key or param_name
        if config_key not in file_cfg:
            return cli_val
        value = file_cfg[config_key]
        parameter = next(p for p in ctx.command.params if p.name == param_name)
        return parameter.type.convert(value, parameter, ctx)

    depth = _cfg("depth", depth)
    wayback = _cfg("wayback", wayback)
    sourcemaps = _cfg("sourcemaps", sourcemaps)
    bypass = _cfg("bypass", bypass)
    proxy = _cfg("proxy", proxy)
    rate_limit = _cfg("rate_limit", rate_limit, "rate-limit")
    delay = _cfg("delay", delay)
    timeout = _cfg("timeout", timeout)
    concurrency = _cfg("concurrency", concurrency)
    user_agent = _cfg("user_agent", user_agent, "user-agent")
    insecure = _cfg("insecure", insecure)
    evidence = _cfg("evidence", evidence)

    _setup_logging(verbose, quiet)

    if not quiet and not json_mode:
        console.print(BANNER, style="bold cyan")

    try:
        keys = _collect_keys(key_input, key_file)
        apk_paths = list(apk_files)
        all_targets = _collect_targets(targets, target_file, scan_json)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise click.UsageError(f"Cannot read input: {exc}") from exc

    if not keys and not all_targets and not apk_paths:
        console.print("[red]No targets, keys, or APK files provided. Use --help for usage.[/red]")
        raise SystemExit(1)

    if not quiet and not json_mode:
        if apk_paths and all_targets:
            console.print("  [dim]Mode:[/dim]    APK + Discovery")
            console.print(f"  [dim]APKs:[/dim]    {len(apk_paths)}")
            console.print(f"  [dim]Targets:[/dim] {len(all_targets)}")
        elif apk_paths:
            mode_extra = f" + {len(keys)} key(s)" if keys else ""
            console.print(f"  [dim]Mode:[/dim]    APK scan{mode_extra}")
            console.print(f"  [dim]APKs:[/dim]    {len(apk_paths)}")
            for p in apk_paths:
                console.print(f"             [dim]{os.path.basename(p)}[/dim]")
        elif keys:
            console.print("  [dim]Mode:[/dim]    Key check")
            console.print(f"  [dim]Keys:[/dim]    {len(keys)}")
        else:
            console.print("  [dim]Mode:[/dim]    Discovery")
            console.print(f"  [dim]Targets:[/dim] {len(all_targets)}")
        console.print()

    try:
        config = Config(
            targets=all_targets,
            keys=keys,
            apk_paths=apk_paths,
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
            insecure=insecure,
            json_mode=json_mode,
            verbose=verbose,
            quiet=quiet,
            evidence=evidence,
            output_path=output_path,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc

    try:
        result = asyncio.run(Pipeline(config).execute())
    except (OSError, ValueError) as exc:
        raise click.ClickException(f"Scan failed: {exc}") from exc
    except KeyboardInterrupt:
        console.print("\n  [dim]Interrupted.[/dim]")
        raise SystemExit(130)
    raise SystemExit(
        0
        if result.keys_valid > 0 or result.keys_bypassed > 0 or result.keys_rate_limited > 0
        else 1
    )
